/*
FILE PATH: sequencer/committer.go

The singleton committer goroutine — the second half of the
sequencer's staged pipeline. Stage-1 workers (in loop.go) execute
the per-entry pre-commit work (MetaState guard, WAL read,
deserialize, Tessera AppendLeaf) in parallel and emit one tuple per
entry to commitCh. This file owns the receiving side: a min-heap
keyed by seq, a contiguous-prefix drain, and a batched atomic INSERT
into entry_index.

# WHY A SINGLE COMMITTER

The original sequencer ran processOne fully in stage-1 workers,
each opening its own per-entry Postgres transaction. That created
two structural problems:

 1. N+1 write path — N entries = N synchronous PG fsyncs. Capped
    end-to-end throughput at ~200 ent/sec even with parallel
    workers and parallel cosignatures (verified via per-batch
    telemetry; see commit 545af49).

 2. Commit-order inversions — concurrent stage-1 workers
    commit their per-entry transactions in arbitrary order under
    PG MVCC. A higher seq could become visible before a lower
    one, briefly leaving a hole in entry_index. The builder's
    BeginBatch (which assumes contiguous visibility) would then
    leapfrog past the hole and lose the missing seq forever
    (proved empirically; see the 19:43:39 log evidence in commit
    6386aa0).

This file's committer fixes both at once: ONE tx commits N rows
(eliminates the N+1 path), and the min-heap drains contiguous
prefixes only (eliminates the inversion-induced leapfrog).

# GAP-FREE INVARIANT

The committer enforces:

	For every seq Tessera has assigned, entry_index has a row.
	Visibility advances monotonically: when row at seq=N becomes
	visible, all rows for seqs 0..N-1 are already visible.

This is the property the builder's CursorReader relies on for
correctness. Without it, the cursor leapfrogs; with it, the cursor
can never advance past a seq that lacks a row.

# TOMBSTONES — THE STATEMANUAL DEADLOCK FIX

Tessera.AppendLeaf is irrevocable: once it returns seq=N for a hash,
N exists in the cryptographic log permanently. If a post-AppendLeaf
step fails permanently (a future code path discovers the entry is
unprojectable; a persistent batch-commit error; the deserialize-
after-AppendLeaf ordering some refactors might prefer), the seq is
"owed" to the committer but can never be filled normally.

Without tombstones, the heap's contiguous-prefix drain would stall
on N forever: seqs N+1, N+2, … pile up waiting for N. commitCh
fills, stage-1 workers block on send, drainOnce stops dispatching,
WAL saturates, admission 503s. Total deadlock.

With tombstones, stage-1 emits a stagedEntry with Tombstone=true
when post-AppendLeaf failure occurs. The committer treats tombstones
identically to normal entries for heap ordering — they advance
nextExpectedSeq, occupy a row in entry_index (with status=1 and
NULL-able metadata fields), and the heap never stalls.

Auditors querying /v1/entries/{seq=N} for a tombstoned seq get a
definitive "manual" status response rather than an infinite 404.

# CRASH RECOVERY

On startup, readNextExpectedSeq queries MAX(seq)+1 from entry_index
and stores it in nextExpectedSeq. Any seqs Tessera had assigned but
entry_index doesn't have are in WAL StatePending → drainOnce
re-fetches them → stage-1 re-runs AppendLeaf (idempotent — Tessera
antispam dedup returns the same seq) → committer sees them, fills
the gap, advances.

If a stage-1 worker crashes between AppendLeaf and emit-to-channel,
the entry stays WAL StatePending and is re-fetched on next boot.
No state is lost.

If the committer panics, the seqs in the heap and in `pending` are
lost from in-memory state, but their hashes are still WAL Pending.
Next boot re-fetches them. Idempotent.
*/
package sequencer

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/ledger/chaos"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/wal"
)

// stagedEntry is the unit emitted by stage-1 workers and consumed
// by the committer. Carries everything the committer needs to:
//
//	(a) order by Seq via the min-heap,
//	(b) build the entry_index row (Row),
//	(c) optionally insert commitment_split_id + 0x0A + 0x0C sidecar
//	    writes (gated on HasSplitID, Entry non-nil),
//	(d) transition WAL state to Sequenced / Manual after PG commit.
//
// Tombstone == true means Tessera assigned the seq but the entry
// cannot be projected. Row carries the tombstone shape (signer_did
// = TombstoneSignerDID, status = StatusTombstone, metadata NULLs).
// Entry is nil for tombstones — no sidecar writes are attempted.
type stagedEntry struct {
	Seq       uint64
	Hash      [32]byte
	Tombstone bool
	Reason    string // diagnostic, populated for tombstones

	// Row is the pre-built entry_index row (live or tombstone shape).
	Row store.EntryRow

	// Commitment-split-id sidecar payload. HasSplitID gates the
	// commitment_split_id INSERT + 0x0A index + 0x0C lookup. Never
	// set for tombstones.
	HasSplitID bool
	SplitID    [32]byte
	SchemaID   string

	// Entry is the deserialized envelope, needed for the 0x0C
	// entry-lookup write (canonical_bytes via envelope.Serialize)
	// and the 0x0A index entry (entry.Signatures[0].Bytes). nil for
	// tombstones.
	Entry *envelope.Entry

	// emittedAt is the wall-clock time the stage-1 worker pushed
	// this tuple into commitCh. Two derived histograms make the
	// race-window mechanism observable directly:
	//
	//   commitRaceWindow = time.Since(emittedAt) at successful
	//                      commit. The "how long did the original
	//                      take to commit" measurement, recorded
	//                      from applyPostCommitForOne.
	//   staleAge         = time.Since(emittedAt) at stale-discard.
	//                      The "how long after emit was this
	//                      duplicate detected" measurement, recorded
	//                      from drainHeapInto (sub-case A) and
	//                      committerStaleRecover (sub-case B).
	//
	// Hypothesis: if staleAge tracks commitRaceWindow run-over-run,
	// the in-batch-dup rate is driven by the race window the
	// committer's flush-latency creates. Run-over-run variance in
	// stale_pct should correlate with run-over-run variance in
	// commitRaceWindow distribution.
	//
	// Zero value (default time.Time{}) is treated as "unset"; the
	// observation callsites guard with !IsZero() so test-mode
	// tuples built outside the emit path don't pollute the
	// histogram.
	emittedAt time.Time
}

// committerHeap is a min-heap on Seq, used by the committer to
// reorder out-of-order stage-1 emissions into a strict ascending
// stream. Implements container/heap.Interface.
type committerHeap []stagedEntry

func (h committerHeap) Len() int            { return len(h) }
func (h committerHeap) Less(i, j int) bool  { return h[i].Seq < h[j].Seq }
func (h committerHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *committerHeap) Push(x interface{}) { *h = append(*h, x.(stagedEntry)) }
func (h *committerHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// committerLoop runs the singleton committer goroutine. Drains
// commitCh, reorders via min-heap, and flushes batches when:
//   - the in-memory batch reaches CommitMaxBatchSize, OR
//   - CommitMaxWait has elapsed since the first entry in the
//     current batch was added (catches a tail-end residual when
//     traffic ebbs).
//
// On ctx cancellation, attempts a final flush of the in-flight
// batch using a fresh background context (with timeout) so an
// in-progress tx can complete even though the parent ctx is
// cancelled — this preserves the WAL state-transition invariant
// for the last batch.
func (s *Sequencer) committerLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("sequencer: committer panic", "panic", fmt.Sprintf("%v", r))
		}
	}()

	s.logger.Info("sequencer: committer started",
		"next_expected_seq", s.nextExpectedSeq.Load(),
		"channel_buffer", s.cfg.CommitChannelBuffer,
		"max_batch_size", s.cfg.CommitMaxBatchSize,
		"max_wait", s.cfg.CommitMaxWait,
	)

	flushTimer := time.NewTimer(s.cfg.CommitMaxWait)
	if !flushTimer.Stop() {
		select {
		case <-flushTimer.C:
		default:
		}
	}
	timerActive := false
	pending := make([]stagedEntry, 0, s.cfg.CommitMaxBatchSize)

	// flushPending attempts a single batched commit. On success,
	// nextExpectedSeq advances by len(pending) and pending is reset.
	// On failure, the batch is re-pushed to the heap (preserves the
	// retry path) and pending is reset; nextExpectedSeq is not
	// advanced. Caller is responsible for backoff.
	flushPending := func(currentCtx context.Context) {
		if len(pending) == 0 {
			return
		}
		err := s.flushBatch(currentCtx, pending)
		if err != nil {
			s.metrics.commitBatchFailures.Add(1)
			firstSeq := pending[0].Seq
			s.logger.Error("sequencer: committer batch commit failed; re-pushing",
				"batch_size", len(pending),
				"first_seq", firstSeq,
				"last_seq", pending[len(pending)-1].Seq,
				"error", err,
			)
			// Identical-batch circuit breaker: three consecutive
			// failures with the SAME first_seq AND the SAME error
			// fingerprint indicate a deterministic batch-poisoning
			// condition (e.g., malformed bytea, a PG constraint we
			// can't satisfy, schema drift). Retrying forever is a
			// death spiral that grows the heap until OOM. Trip the
			// breaker → supervisor fatal → process restart with
			// clean state. The next-up committer will read MAX(seq)
			// from PG and skip past the poisoned batch only if the
			// poison was transient; otherwise it'll trip again and
			// the operator gets paged.
			if s.checkIdenticalBatchBreaker(firstSeq, err) {
				// Breaker tripped — do NOT re-push. The fatal channel
				// has been signalled; the supervisor will terminate.
				// Re-pushing would just re-fail in the next cycle
				// before the process exits, generating log noise.
				pending = pending[:0]
				return
			}
			for _, e := range pending {
				heap.Push(s.committerHeap, e)
			}
			pending = pending[:0]
			return
		}
		// Success path — clear the breaker state and advance.
		s.resetIdenticalBatchBreaker()
		batchSize := uint64(len(pending))
		s.nextExpectedSeq.Add(batchSize)
		s.metrics.committedBatches.Add(1)
		s.metrics.committedEntries.Add(batchSize)
		pending = pending[:0]
	}

	stopTimer := func() {
		if timerActive {
			timerActive = false
			if !flushTimer.Stop() {
				select {
				case <-flushTimer.C:
				default:
				}
			}
		}
	}

	armTimer := func() {
		if !timerActive && len(pending) > 0 {
			flushTimer.Reset(s.cfg.CommitMaxWait)
			timerActive = true
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown — use a fresh background context
			// (5s timeout) for the final flush so an in-flight tx
			// can complete even though the parent ctx is cancelled.
			pending = s.drainHeapInto(ctx, pending)
			stopTimer()
			if len(pending) > 0 {
				flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				flushPending(flushCtx)
				cancel()
			}
			s.logger.Info("sequencer: committer stopped",
				"next_expected_seq", s.nextExpectedSeq.Load(),
				"heap_remaining", s.committerHeap.Len(),
				"pending_remaining", len(pending),
			)
			return

		case tuple, ok := <-s.commitCh:
			if !ok {
				// Channel closed (defensive — current wiring never
				// closes commitCh).
				pending = s.drainHeapInto(ctx, pending)
				stopTimer()
				if len(pending) > 0 {
					flushPending(ctx)
				}
				return
			}
			heap.Push(s.committerHeap, tuple)

			// Track wait-on-gap: if the tuple's seq isn't at the
			// head OR the head isn't at the next expected, the
			// committer is waiting for a gap to fill.
			heapHeadSeq := (*s.committerHeap)[0].Seq
			expected := s.nextExpectedSeq.Load() + uint64(len(pending))
			if heapHeadSeq != expected {
				s.metrics.commitWaitOnGap.Add(1)
			}

			pending = s.drainHeapInto(ctx, pending)
			if len(pending) >= s.cfg.CommitMaxBatchSize {
				stopTimer()
				flushPending(ctx)
			} else {
				armTimer()
			}

		case <-flushTimer.C:
			timerActive = false
			flushPending(ctx)
		}
	}
}

// drainHeapInto pulls every contiguous-prefix tuple from the heap
// into pending and returns the updated pending slice. nextExpectedSeq
// is NOT advanced here — flushBatch advances it only after a
// successful PG commit, so a flush failure leaves the cursor
// untouched and a retry re-pushes the same prefix.
//
// # STALE-DUPLICATE DISCRIMINATION
//
// When the heap head's Seq is below the expected next seq it's a
// duplicate, but there are TWO structurally distinct sub-cases and
// conflating them produces the WAL.Sequence-after-commit WARN noise.
//
//	(A) IN-BATCH DUPLICATE: committed <= head.Seq < expected.
//	    The original tuple for head.Seq is already in the current
//	    `pending` slice and will be flushed in the very next
//	    flushPending call. The WAL state is still Pending — the
//	    original's WAL.Sequence call hasn't fired yet because
//	    flushPending hasn't run. If we called committerStaleRecover
//	    here, its MetaState probe would see Pending and incorrectly
//	    fire the crash-recovery path, racing the impending
//	    applyPostCommitForOne call. The recovery's WAL.Sequence wins
//	    (advances state to Sequenced → shipper picks it up → Shipped)
//	    and then the original's WAL.Sequence fails with
//	    "state shipped, want pending". Discard silently — the
//	    original will do the WAL transition.
//
//	(B) TRUE CROSS-BATCH STALE: head.Seq < committed. The original
//	    was committed in a PRIOR batch and the WAL state has already
//	    (or will soon) advance. Route to committerStaleRecover —
//	    its MetaState probe correctly distinguishes
//	    Sequenced/Shipped (silent discard) from Pending (the rare
//	    crash-recovery case).
//
// The discriminator is head.Seq < committed vs. head.Seq >= committed:
// precisely the "have we already advanced past this seq" question.
// committed == nextExpectedSeq.Load() at the start of each iteration;
// it doesn't shift during drain (flushPending is what advances it).
//
// Returns the (possibly grown) pending slice; the caller MUST take the
// returned value because Go's append-into-existing-slice semantics
// don't update the caller's slice header when capacity is exhausted.
func (s *Sequencer) drainHeapInto(ctx context.Context, pending []stagedEntry) []stagedEntry {
	for s.committerHeap.Len() > 0 {
		head := (*s.committerHeap)[0]
		committed := s.nextExpectedSeq.Load()
		expected := committed + uint64(len(pending))
		if head.Seq < expected {
			stale := heap.Pop(s.committerHeap).(stagedEntry)
			if stale.Seq >= committed {
				// Sub-case (A) — in-batch duplicate. The original is
				// in pending; silently discard.
				s.metrics.staleDuplicatesDiscarded.Add(1)
				s.metrics.staleInBatchDuplicates.Add(1)
				if !stale.emittedAt.IsZero() {
					s.metrics.staleAgeHistogram.Observe(time.Since(stale.emittedAt))
				}
				s.logger.Debug("sequencer: in-batch duplicate discarded",
					"seq", stale.Seq,
					"hash", hashPrefix(stale.Hash),
					"committed", committed,
					"pending_size", len(pending),
				)
				continue
			}
			// Sub-case (B) — true cross-batch stale.
			s.committerStaleRecover(ctx, stale, expected)
			continue
		}
		if head.Seq != expected {
			// Gap — wait. metrics.commitWaitOnGap is bumped by the
			// caller (committerLoop), since we don't know if this is a
			// fresh arrival or a re-check.
			return pending
		}
		pending = append(pending, heap.Pop(s.committerHeap).(stagedEntry))
	}
	return pending
}

// flushBatch commits all entries in batch to entry_index in a single
// transaction, then fires the per-entry post-commit hooks (WAL state
// transitions, sidecar writes). Returns an error if the PG tx fails;
// the caller is responsible for re-pushing the batch to the heap.
func (s *Sequencer) flushBatch(ctx context.Context, batch []stagedEntry) error {
	if len(batch) == 0 {
		return nil
	}

	if s.db == nil || s.store == nil {
		// Test mode: nil DB skips the INSERT entirely. WAL state
		// transitions and metrics still fire so tests see progress.
		for _, e := range batch {
			s.applyPostCommitForOne(ctx, e, false)
		}
		return nil
	}

	// Build the entry_index rows (already pre-built by stage-1; just
	// extract the Row field).
	rows := make([]store.EntryRow, len(batch))
	for i, e := range batch {
		rows[i] = e.Row
	}

	commitStart := time.Now()
	var insertResult store.InsertBatchResult
	commitErr := store.WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		// Batched INSERT into entry_index. ON CONFLICT DO NOTHING +
		// RETURNING surfaces three dispositions per row:
		//
		//   Inserted  — newly durable.
		//   SeqReplay — same (seq, hash) already in entry_index;
		//               benign idempotent retry. No action.
		//   HashColl  — same hash already at a DIFFERENT seq.
		//               Tessera dedup gap across a crash; route
		//               via committerStaleRecover with the
		//               EXISTING seq, dropping the duplicate
		//               Tessera leaf (the "Ghost Leaf" pattern).
		var err error
		insertResult, err = s.store.InsertBatch(ctx, tx, rows)
		if err != nil {
			return fmt.Errorf("entry_index batch insert (n=%d): %w", len(rows), err)
		}
		if insertResult.SeqReplays > 0 {
			s.logger.Info("sequencer: committer InsertBatch idempotent seq-replays",
				"input_rows", len(rows),
				"inserted", insertResult.Inserted,
				"seq_replays", insertResult.SeqReplays,
			)
		}
		// Per-entry commitment_split_id rows (only for live entries
		// with a split-id; tombstones are not commitment carriers).
		// SKIP entries whose hash collided — their canonical_hash
		// already has a commitment_split_id row at the ExistingSeq.
		collidedHashes := make(map[[32]byte]struct{}, len(insertResult.HashCollisions))
		for _, c := range insertResult.HashCollisions {
			collidedHashes[c.CanonicalHash] = struct{}{}
		}
		for _, e := range batch {
			if e.Tombstone || !e.HasSplitID {
				continue
			}
			if _, dup := collidedHashes[e.Hash]; dup {
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
				VALUES ($1, $2, $3)
				ON CONFLICT DO NOTHING`,
				e.Seq, e.SchemaID, e.SplitID[:],
			); err != nil {
				return fmt.Errorf("commitment_split_id insert seq=%d: %w", e.Seq, err)
			}
		}
		return nil
	})
	commitElapsed := time.Since(commitStart)

	if commitErr != nil {
		return commitErr
	}

	s.logger.Info("sequencer: committer batch committed",
		"batch_size", len(batch),
		"first_seq", batch[0].Seq,
		"last_seq", batch[len(batch)-1].Seq,
		"tombstones", countTombstones(batch),
		"hash_collisions", len(insertResult.HashCollisions),
		"elapsed", commitElapsed.Round(time.Microsecond),
	)

	// Chaos injection point #2 — "pre_commit_post_pg":
	// The PG transaction has committed (entry_index rows are
	// durable) but no WAL.Sequence call has fired yet. A kill
	// here is the exact failure mode committerStaleRecover was
	// written for: on restart, drainOnce re-fetches the hashes
	// still in StatePending, re-runs stage-1, AppendLeaf dedupes,
	// the duplicate stagedEntry hits the cross-batch stale path,
	// and committerStaleRecover calls Sequence to advance WAL
	// state without producing duplicate entry_index rows.
	chaos.Trigger("pre_commit_post_pg")

	// Hash-collision recovery — the Ghost Leaf path.
	//
	// For each row whose canonical_hash was already in entry_index
	// at a DIFFERENT seq, route through committerStaleRecover using
	// the EXISTING seq (the PG row is the authoritative answer).
	// The duplicate Tessera leaf at the AttemptedSeq becomes a
	// Ghost Leaf — mathematically valid in the log, dropped from
	// the projection. The WAL state for the hash is advanced under
	// the original seq so the shipper picks it up exactly once.
	//
	// Each collision bumps the dedicated SRE counter so operators
	// can distinguish "Tessera dedup gap" from "hostile replay".
	if len(insertResult.HashCollisions) > 0 {
		// expected here is the "next-expected" cursor the
		// committerStaleRecover diagnostic logs use. We're past the
		// flush so the cursor hasn't advanced yet; pass nextExpectedSeq
		// directly.
		expected := s.nextExpectedSeq.Load() + uint64(len(batch))
		// Build a fast lookup hash → *stagedEntry from this batch so
		// each collision can be matched to its original tuple
		// (preserves Tombstone flag + emittedAt for WAL transition
		// and histogram observation).
		byHash := make(map[[32]byte]stagedEntry, len(batch))
		for _, e := range batch {
			byHash[e.Hash] = e
		}
		for _, c := range insertResult.HashCollisions {
			orig, ok := byHash[c.CanonicalHash]
			if !ok {
				// Defensive: the collision is for a hash we don't
				// have in this batch. Should be impossible (PG only
				// returns rows we sent). Log and skip.
				s.logger.Error("sequencer: PG-collision hash not in batch (impossible state)",
					"existing_seq", c.ExistingSeq,
					"attempted_seq", c.AttemptedSeq,
					"hash", hashPrefix(c.CanonicalHash),
				)
				continue
			}
			// Substitute the EXISTING seq before routing. This is
			// the load-bearing semantic: WAL.Sequence is called with
			// the seq that's actually in entry_index, not the
			// duplicate Tessera leaf's seq.
			recover := orig
			recover.Seq = c.ExistingSeq
			recover.Row.SequenceNumber = c.ExistingSeq
			s.logger.Warn("sequencer: PG canonical_hash collision — routing duplicate through stale-recover (Ghost Leaf path)",
				"attempted_seq", c.AttemptedSeq,
				"existing_seq", c.ExistingSeq,
				"hash", hashPrefix(c.CanonicalHash),
				"tombstone", orig.Tombstone,
			)
			s.metrics.staleCrashRecoveriesAfterPGCollision.Add(1)
			s.committerStaleRecover(ctx, recover, expected)
		}
	}

	// Post-commit hooks per entry (WAL state, sidecar writes,
	// per-entry metrics, attempt-counter reset).
	//
	// CRITICAL: Skip ghost-leaf entries here.
	//
	// applyPostCommitForOne calls wal.Sequence(ctx, e.Hash, e.Seq)
	// unconditionally. For a ghost-leaf entry, e.Seq is the FRESH
	// Tessera seq (16 in the running example) — NOT the canonical
	// seq (8) that's actually in entry_index. Calling wal.Sequence
	// with the fresh seq would commit a hallucinated seq into WAL
	// metadata. The shipper tails the WAL for Sequenced items and
	// would then upload the payload to bytestore under path 16
	// while PG says the entry lives at 8. PG and bytestore diverge
	// permanently — auditors querying /v1/entries/8 get 404 from
	// the bytestore. That's a hard CQRS-parity violation.
	//
	// The ghost-leaf path ALREADY advanced WAL state under the
	// CANONICAL seq via the committerStaleRecover call above
	// (recover.Seq = c.ExistingSeq). Skipping the post-commit hook
	// here is the only correct disposition.
	collided := make(map[[32]byte]struct{}, len(insertResult.HashCollisions))
	for _, c := range insertResult.HashCollisions {
		collided[c.CanonicalHash] = struct{}{}
	}
	for _, e := range batch {
		if _, dup := collided[e.Hash]; dup {
			continue
		}
		s.applyPostCommitForOne(ctx, e, true)
	}
	return nil
}

// committerStaleRecover handles a stagedEntry whose seq is strictly
// less than nextExpectedSeq — i.e., a duplicate tuple for an entry
// whose row is already in entry_index from a prior commit. Two
// distinct scenarios produce duplicates; this method discriminates
// between them via a single MetaState probe.
//
// # Scenario 1 — Normal race (common; benign)
//
// drainOnce cycle N captures hash H (state=Pending), spawns stage-1
// worker A. A calls Tessera.AppendLeaf (~14ms) and emits a tuple.
// While A is in flight, drainOnce cycle N+1 (10ms later) ALSO
// captures H — the committer hasn't reached H's WAL.Sequence call
// yet, so H is still StatePending and re-appears in IterateInflight.
// Cycle N+1 spawns worker B for the same hash. B re-runs Tessera
// (which dedups and returns the same seq) and emits a duplicate
// tuple. By the time the committer pops B's tuple, A's tuple has
// already moved nextExpectedSeq past it.
//
// In this scenario the original commit path already called
// WAL.Sequence (state is StateSequenced, or further if the shipper
// got there). Re-firing Sequence here would race the shipper's
// state transitions and surface as "want pending" errors. The
// correct response is to silently discard the duplicate; the entry
// is fully processed.
//
// # Scenario 2 — Crash-recovery (rare; load-bearing)
//
// Process crashed (or Badger fsync transiently failed) between the
// committer's PG commit and its WAL.Sequence call. entry_index has
// the row, but the WAL state never advanced past Pending. On the
// next drainOnce cycle the hash is still in IterateInflight; stage-1
// re-runs and emits a duplicate tuple. The committer sees seq <
// nextExpectedSeq because PG already has the row.
//
// In this scenario the WAL state still needs to advance for the
// shipper to pick the entry up. The MetaState probe will report
// StatePending and this method calls Sequence (or MarkManual for
// tombstones) on the WAL. The WAL's own idempotency guard
// (StateSequenced + matching seq → no-op) makes a redundant call
// here safe in any case.
//
// # Metrics
//
// committedBatches / committedEntries / processed are NOT bumped
// here — the original commit path already counted the entry. The
// stale path increments one of two purpose-built counters:
//
//	staleDuplicatesDiscarded — Scenario 1 outcomes (silent discard).
//	staleCrashRecoveries     — Scenario 2 outcomes (WAL state advance).
//
// Ratio committedEntries : staleDuplicatesDiscarded is the
// "duplicate-work fraction" — quantifies the stage-1 race the
// architecture tolerates by design. Expected single-digit percent
// under burst; trends upward at high traffic and shrinks again as
// the committer keeps up.
//
// staleCrashRecoveries should be ~zero in steady state. Sustained
// non-zero values indicate Badger / WAL fsync pressure and warrant
// an operator alert.
//
// # Determinism / context cancellation
//
// A failed MetaState probe falls through to a Debug log + return.
// We do NOT propagate the error to the caller — the next drainOnce
// cycle will re-fetch the hash if there's actual recovery work
// pending. Bailing out silently on context errors avoids surfacing
// shutdown noise as a fault.
func (s *Sequencer) committerStaleRecover(ctx context.Context, e stagedEntry, expected uint64) {
	meta, err := s.wal.MetaState(ctx, e.Hash)
	if err != nil {
		if !isContextErr(err) {
			s.logger.Debug("sequencer: stale-recover MetaState probe failed; will retry next cycle",
				"seq", e.Seq,
				"hash", hashPrefix(e.Hash),
				"error", err,
			)
		}
		return
	}

	if meta.State != wal.StatePending {
		// Scenario 1 — normal race. Original commit path already
		// advanced WAL state. Nothing to do.
		s.metrics.staleDuplicatesDiscarded.Add(1)
		s.metrics.staleCrossBatchDuplicates.Add(1)
		if !e.emittedAt.IsZero() {
			s.metrics.staleAgeHistogram.Observe(time.Since(e.emittedAt))
		}
		s.logger.Debug("sequencer: stale duplicate discarded (WAL state already advanced)",
			"seq", e.Seq,
			"hash", hashPrefix(e.Hash),
			"state", meta.State,
			"next_expected", expected,
		)
		return
	}

	// Scenario 2 — crash-recovery. WAL state is still Pending; PG
	// has the row from the original commit. Advance the WAL so the
	// shipper can pick the entry up.
	s.metrics.staleCrashRecoveries.Add(1)
	s.logger.Warn("sequencer: stale-recover advancing WAL state (crash-recovery path)",
		"seq", e.Seq,
		"hash", hashPrefix(e.Hash),
		"tombstone", e.Tombstone,
	)
	if e.Tombstone {
		if err := s.wal.MarkManual(ctx, e.Hash); err != nil && !isContextErr(err) {
			s.logger.Error("sequencer: stale-recover MarkManual failed",
				"seq", e.Seq,
				"hash", hashPrefix(e.Hash),
				"error", err,
			)
		}
	} else {
		if err := s.wal.Sequence(ctx, e.Hash, e.Seq); err != nil && !isContextErr(err) {
			s.logger.Error("sequencer: stale-recover WAL.Sequence failed",
				"seq", e.Seq,
				"hash", hashPrefix(e.Hash),
				"error", err,
			)
		}
	}
	// resetAttempts is idempotent under a missing key, so calling
	// it again here is harmless even when the original commit path
	// already cleared the counter for this hash.
	s.resetAttempts(e.Hash)
}

// applyPostCommitForOne fires the per-entry post-commit work:
//   - WAL.Sequence (live) or WAL.MarkManual (tombstone)
//   - resetAttempts
//   - 0x0A splitid index + 0x0C entry lookup (live, best-effort)
//   - metrics.processed / metrics.manualCount
//
// dbCommitted == false means we're in test mode (nil DB) — we still
// transition WAL state and update metrics, but skip the sidecar
// writes (which usually depend on the entry_index row being durable).
func (s *Sequencer) applyPostCommitForOne(ctx context.Context, e stagedEntry, dbCommitted bool) {
	// commitRaceWindow observation — the time from stage-1 emit to
	// "the original committed". The structural pair to staleAge:
	// when the two distributions are read together, the in-batch-dup
	// mechanism is fully characterised (every successful commit is
	// observed here; every stale-discard is observed by the
	// staleAgeHistogram). For tombstones the measurement is equally
	// meaningful — they go through the same channel and the same
	// batch-flush cadence.
	if !e.emittedAt.IsZero() && s.metrics.commitRaceWindow != nil {
		s.metrics.commitRaceWindow.Observe(time.Since(e.emittedAt))
	}
	if e.Tombstone {
		if err := s.wal.MarkManual(ctx, e.Hash); err != nil {
			if !isContextErr(err) {
				s.logger.Error("sequencer: MarkManual after tombstone",
					"seq", e.Seq, "hash", hashPrefix(e.Hash), "error", err)
			}
		}
		s.resetAttempts(e.Hash)
		s.metrics.manualCount.Add(1)
		s.logger.Warn("sequencer: tombstone committed (StatusTombstone)",
			"seq", e.Seq, "hash", hashPrefix(e.Hash), "reason", e.Reason)
		return
	}

	if err := s.wal.Sequence(ctx, e.Hash, e.Seq); err != nil {
		if !isContextErr(err) {
			// At-least-once: the entry IS in entry_index and Tessera.
			// WAL state lag is recoverable — next drainOnce re-probes
			// and the state guard at MetaState short-circuits if
			// already past Pending.
			s.logger.Warn("sequencer: WAL.Sequence after commit failed",
				"seq", e.Seq, "error", err)
		}
	}
	s.resetAttempts(e.Hash)
	s.metrics.processed.Add(1)

	// Sidecar writes (0x0A, 0x0C) — best-effort, only after PG commit.
	if dbCommitted && e.HasSplitID && e.Entry != nil {
		if s.splitIDIndex != nil && len(e.Entry.Signatures) > 0 {
			idxEntry := SplitIDIndexEntry{
				EquivocatorDID: e.Entry.Header.SignerDID,
				CanonicalHash:  e.Hash,
				SigBytes:       append([]byte{}, e.Entry.Signatures[0].Bytes...),
			}
			if werr := s.splitIDIndex.WriteSplitIDIndexEntry(
				ctx, e.SchemaID, e.SplitID, e.Seq, idxEntry,
			); werr != nil && !isContextErr(werr) {
				s.logger.Warn("sequencer: splitid index write failed",
					"seq", e.Seq, "schema_id", e.SchemaID, "error", werr)
			}
		}
		if s.entryLookup != nil {
			canonical, serr := envelope.Serialize(e.Entry)
			if serr != nil {
				s.logger.Warn("sequencer: entry-lookup serialize failed",
					"seq", e.Seq, "schema_id", e.SchemaID, "error", serr)
			} else {
				lookupEntry := EntryLookupIndexEntry{
					CanonicalBytes: canonical,
					LogTimeMicros:  e.Entry.Header.EventTime,
					LogDID:         s.logDID,
				}
				if werr := s.entryLookup.WriteEntryLookupEntry(
					ctx, e.SchemaID, e.SplitID, e.Seq, lookupEntry,
				); werr != nil && !isContextErr(werr) {
					s.logger.Warn("sequencer: entry lookup projection write failed",
						"seq", e.Seq, "schema_id", e.SchemaID, "error", werr)
				}
			}
		}
	}

	s.logger.Debug("sequencer: entry sequenced",
		"seq", e.Seq, "hash", hashPrefix(e.Hash))
}

// readNextExpectedSeq queries entry_index for MAX(seq)+1 — the seq
// the committer expects to see next on the contiguous-prefix walk.
// On a fresh install (empty entry_index), returns 0.
//
// Called at Sequencer.Run startup, BEFORE the committer goroutine
// or any stage-1 worker fires, so the committer's initial state
// matches the persisted high-water mark and recovery is correct.
func (s *Sequencer) readNextExpectedSeq(ctx context.Context) (uint64, error) {
	if s.db == nil {
		// Test mode — start fresh.
		return 0, nil
	}
	var maxSeq int64
	if err := s.db.QueryRow(ctx,
		"SELECT COALESCE(MAX(sequence_number), -1)::bigint FROM entry_index",
	).Scan(&maxSeq); err != nil {
		return 0, fmt.Errorf("sequencer: read max(entry_index.seq): %w", err)
	}
	// maxSeq = -1 (empty table) → next = 0. Cast preserves the
	// value via int64→uint64 (non-negative case).
	return uint64(maxSeq + 1), nil
}

// countTombstones is a small helper for the batch-committed log
// line.
func countTombstones(batch []stagedEntry) int {
	n := 0
	for _, e := range batch {
		if e.Tombstone {
			n++
		}
	}
	return n
}

// isContextErr reports whether err is a context-cancellation error.
// Used in post-commit hook logging so a sigterm doesn't surface as
// a false error in the logs.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// identicalBatchBreakerThreshold is the number of consecutive
// failures with the same (first_seq, error-fingerprint) that trips
// the breaker. Three: enough to filter transient PG blips (one
// flake), drop one false-alarm retry margin, then escalate.
const identicalBatchBreakerThreshold = 3

// checkIdenticalBatchBreaker tracks consecutive identical-batch
// failures and returns true when the threshold is crossed. On
// trip, it pushes a sentinel error onto the fatal channel so the
// supervisor terminates the process.
//
// Fingerprint: (firstSeq, error string). The error string is
// stable enough for "same constraint failure on same batch
// prefix" while still distinguishing different failure modes on
// the same seq.
//
// Race-safe: identicalBatchMu guards the streak counters. The
// fatal-channel send is non-blocking (matches the lifecycle.SafeRun
// pattern) so a saturated channel doesn't hold the committer.
func (s *Sequencer) checkIdenticalBatchBreaker(firstSeq uint64, err error) bool {
	fp := err.Error()
	s.identicalBatchMu.Lock()
	if firstSeq == s.identicalBatchSeq && fp == s.identicalBatchErrFP {
		s.identicalBatchStreak++
	} else {
		s.identicalBatchSeq = firstSeq
		s.identicalBatchErrFP = fp
		s.identicalBatchStreak = 1
	}
	streak := s.identicalBatchStreak
	s.identicalBatchMu.Unlock()

	if streak < identicalBatchBreakerThreshold {
		return false
	}

	// Idempotent trip: only fire the fatal once even if the
	// committer somehow re-enters this branch before the
	// supervisor terminates the process.
	if !s.identicalBatchTripped.CompareAndSwap(false, true) {
		return true
	}

	s.logger.Error("sequencer: identical-batch circuit breaker TRIPPED — escalating to FATAL",
		"first_seq", firstSeq,
		"error_fingerprint", fp,
		"consecutive_failures", streak,
		"threshold", identicalBatchBreakerThreshold,
	)
	if s.fatalCh != nil {
		// Non-blocking send: lifecycle.SafeRun pattern. If the
		// channel is full/nil the panic still surfaces via the
		// next drainOnce cycle log spam, but the operator already
		// got the ERROR line above.
		select {
		case s.fatalCh <- fmt.Errorf(
			"sequencer: identical-batch breaker tripped at first_seq=%d after %d consecutive failures: %s",
			firstSeq, streak, fp):
		default:
		}
	}
	return true
}

// resetIdenticalBatchBreaker clears the streak counters on a
// successful flush. Called from flushPending after each batch that
// commits without error so a transient flake (1 or 2 consecutive
// failures) doesn't accumulate toward the breaker threshold.
func (s *Sequencer) resetIdenticalBatchBreaker() {
	s.identicalBatchMu.Lock()
	defer s.identicalBatchMu.Unlock()
	if s.identicalBatchStreak == 0 {
		return
	}
	s.identicalBatchSeq = 0
	s.identicalBatchErrFP = ""
	s.identicalBatchStreak = 0
}
