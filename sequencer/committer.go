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

	"github.com/clearcompass-ai/ledger/store"
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

	// drainHeapIntoPending pulls every contiguous-prefix tuple from
	// the heap into pending, until the next heap min isn't seq+1.
	// Note: nextExpectedSeq is NOT advanced here — flushBatch
	// advances it only after a successful PG commit, so a flush
	// failure leaves the cursor untouched and a retry re-pushes the
	// same prefix.
	drainHeapIntoPending := func() {
		for s.committerHeap.Len() > 0 {
			head := (*s.committerHeap)[0]
			expected := s.nextExpectedSeq.Load() + uint64(len(pending))
			// Discard stale entries (seq already committed in a
			// prior batch — happens on crash-recovery when stage-1
			// re-fetches a hash whose entry_index row is already
			// present). The WAL state still needs to advance, so
			// we route the stale entry through the post-commit
			// hook BEFORE discarding.
			if head.Seq < expected {
				stale := heap.Pop(s.committerHeap).(stagedEntry)
				s.logger.Debug("sequencer: committer discarding stale entry",
					"seq", stale.Seq, "expected", expected,
					"tombstone", stale.Tombstone,
				)
				s.applyPostCommitForOne(ctx, stale, false)
				continue
			}
			if head.Seq != expected {
				// Gap — wait. metrics.commitWaitOnGap is bumped by
				// the caller, since we don't know if this is a fresh
				// arrival or a re-check.
				return
			}
			pending = append(pending, heap.Pop(s.committerHeap).(stagedEntry))
		}
	}

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
			s.logger.Error("sequencer: committer batch commit failed; re-pushing",
				"batch_size", len(pending),
				"first_seq", pending[0].Seq,
				"last_seq", pending[len(pending)-1].Seq,
				"error", err,
			)
			for _, e := range pending {
				heap.Push(s.committerHeap, e)
			}
			pending = pending[:0]
			return
		}
		// Success — advance the cursor and reset.
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
			drainHeapIntoPending()
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
				drainHeapIntoPending()
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

			drainHeapIntoPending()
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
	commitErr := store.WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		// Batched INSERT into entry_index. ON CONFLICT (sequence_number)
		// DO NOTHING under the hood — idempotent under crash recovery
		// where a prior committer-run committed seqs we're re-presenting.
		rowsAffected, err := s.store.InsertBatch(ctx, tx, rows)
		if err != nil {
			return fmt.Errorf("entry_index batch insert (n=%d): %w", len(rows), err)
		}
		if rowsAffected != int64(len(rows)) {
			// Indicates ON CONFLICT skipped some rows (crash-recovery
			// idempotent path). Log INFO — informational, not an
			// error.
			s.logger.Info("sequencer: committer InsertBatch skipped pre-existing rows",
				"input_rows", len(rows),
				"affected", rowsAffected,
				"skipped_idempotent", int64(len(rows))-rowsAffected,
			)
		}

		// Per-entry commitment_split_id rows (only for live entries
		// with a split-id; tombstones are not commitment carriers).
		for _, e := range batch {
			if e.Tombstone || !e.HasSplitID {
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
		"elapsed", commitElapsed.Round(time.Microsecond),
	)

	// Post-commit hooks per entry (WAL state, sidecar writes,
	// per-entry metrics, attempt-counter reset).
	for _, e := range batch {
		s.applyPostCommitForOne(ctx, e, true)
	}
	return nil
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
