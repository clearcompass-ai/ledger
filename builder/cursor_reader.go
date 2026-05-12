/*
FILE PATH: builder/cursor_reader.go

CursorReader — the CT-native log-tailing batch reader. Reads pending
sequences from entry_index keyed off builder_cursor.last_processed_sequence.

DESIGN NOTES:
  - BatchReader exposes three methods only — BeginBatch /
    CommitBatch / RecoverOnStartup. Minimal surface the builder needs.
  - CursorReader holds an in-memory copy of the cursor that's
    seeded from store.SequenceCursor.Read at first use. This
    avoids a per-tick Read round-trip; CommitBatch keeps the
    in-memory copy and the database in sync.
  - BeginBatch ignores the tx parameter — SELECT against
    entry_index is fine outside any transaction because the
    cursor's source of truth is builder_cursor, not a
    SELECT FOR UPDATE lock.
  - CommitBatch advances the cursor to max(seqs) inside the
    caller's transaction. The builder's atomic commit groups this
    with the SMT mutations and delta-buffer save; if the tx rolls
    back the cursor stays where it was and the same sequences
    re-read on next tick. SMT writes are upserts → reprocessing
    is idempotent.
  - RecoverOnStartup is a no-op. Crash-recovery is implicit:
    the cursor was either advanced in a committed tx (the work
    is done) or it wasn't (we re-read).
*/
package builder

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/clearcompass-ai/ledger/store"
)

// BatchReader is the abstraction the builder loop uses to fetch
// pending sequences and acknowledge them after processing.
//
// Implemented by *CursorReader — the CT-native log-tailing path.
//
// Must:
//   - Return sequences in monotonically-increasing order.
//   - Be idempotent under tx rollback: if CommitBatch's tx
//     aborts, the next BeginBatch call returns the same
//     sequences. The builder relies on this for crash safety.
type BatchReader interface {
	// BeginBatch returns up to batchSize sequences ready for
	// processing. Returns an empty slice (NOT an error) when there
	// is no work — callers poll on a sleep timer.
	//
	// tx is the transaction CommitBatch will run inside. The cursor
	// reader ignores it (the builder's singleton-goroutine guarantee,
	// enforced by the ledger's advisory lock, makes per-row
	// locking unnecessary).
	BeginBatch(ctx context.Context, tx pgx.Tx, batchSize int) ([]uint64, error)

	// CommitBatch acknowledges that seqs have been fully processed.
	// Runs inside the caller's transaction so it commits atomically
	// with the SMT mutations and delta-buffer save.
	CommitBatch(ctx context.Context, tx pgx.Tx, seqs []uint64) error

	// RecoverOnStartup is called once when the builder starts.
	// Returns 0 for the cursor reader — crash recovery is implicit
	// (cursor either committed or didn't).
	RecoverOnStartup(ctx context.Context) (int64, error)
}

// ─────────────────────────────────────────────────────────────────
// CursorReader — the CT-native implementation
// ─────────────────────────────────────────────────────────────────

// CursorReader satisfies BatchReader by tailing entry_index by
// sequence_number, with the high-water mark recorded in
// builder_cursor.
//
// Goroutine-safe: the in-memory cursor is guarded by mu. The
// builder loop is single-goroutine by design, so contention is
// not expected in normal operation, but the lock keeps any future
// reader-introspection path (e.g., a /metrics endpoint reading
// the cursor) safe.
//
// Tombstone-aware:  BeginBatch walks the contiguous prefix returned
// by SequenceCursor.Next, separates live entries (which need SMT
// processing) from tombstones (Tessera-assigned seqs that the
// sequencer couldn't project), and stashes the prefix's max seq in
// pendingAdvanceTo. CommitBatch advances the cursor to that value
// rather than max(seqs) so the cursor moves past any tombstones at
// the tail of the prefix. When the prefix is ENTIRELY tombstones,
// BeginBatch advances the cursor out-of-band via
// AdvancePastTombstones and returns an empty slice — there's no SMT
// work to atomically couple a tx-bound advance to.
//
// Gap-free invariant: paired with the sequencer's staged committer,
// entry_index rows now become visible in strict monotonic order.
// BeginBatch's contiguity check used to be a correctness fix (the
// leapfrog bug); after this commit it's primarily a regression
// detector — if a non-contiguous prefix ever appears again, that's
// a sequencer-side bug surfacing.
type CursorReader struct {
	cursor *store.SequenceCursor

	mu         sync.Mutex
	current    int64 // in-memory cursor; -1 means "no sequences processed yet"
	initFromDB bool  // false until Read() bootstraps from the database

	// pendingAdvanceTo is the high-water mark from the most recent
	// BeginBatch — set when BeginBatch returns a non-empty live-seq
	// slice, cleared by CommitBatch. CommitBatch advances the cursor
	// to this value (NOT to max(seqs)) so the cursor moves past any
	// tombstones at the tail of the contiguous prefix.
	pendingAdvanceTo  uint64
	pendingAdvanceSet bool
}

// NewCursorReader constructs a reader over the supplied cursor.
// The in-memory cursor is bootstrapped lazily on the first
// BeginBatch call so the constructor itself stays infallible
// and synchronous.
func NewCursorReader(cursor *store.SequenceCursor) *CursorReader {
	return &CursorReader{cursor: cursor}
}

// BeginBatch returns up to batchSize LIVE sequence numbers ready for
// SMT processing. The returned slice is the live-entry subset of the
// contiguous prefix of entry_index rows past the cursor; tombstones
// in the prefix are not returned but DO factor into the cursor
// advance that CommitBatch will apply.
//
// Returns an empty slice (NOT an error) when:
//   - entry_index has no rows past the cursor, OR
//   - the first row past the cursor isn't cursor+1 (gap — wait), OR
//   - the contiguous prefix is entirely tombstones (in which case
//     BeginBatch advances the cursor out-of-band before returning).
//
// tx is ignored — the cursor reader does not need transactional
// locking; the ledger's advisory-lock-enforced singleton builder
// makes per-row locking redundant.
//
// Reads the cursor from Postgres on every call (this defends against
// the leaf-loss regression that the cached-cursor design hit, and
// the cost is one extra single-row indexed SELECT per batch).
func (r *CursorReader) BeginBatch(ctx context.Context, _ pgx.Tx, batchSize int) ([]uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq, err := r.cursor.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("builder/cursor: read: %w", err)
	}
	r.current = seq
	r.initFromDB = true

	entries, err := r.cursor.Next(ctx, seq, batchSize)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	// Compute the expected first seq. `seq + 1` is correct even for
	// the -1 sentinel (fresh install): int64(-1) + 1 == int64(0)
	// which converts cleanly to uint64(0).
	expectedFirst := uint64(seq + 1)
	if entries[0].Seq != expectedFirst {
		// First expected seq isn't visible in entry_index yet. This
		// is the structural defense against the sequencer's
		// per-entry-tx commit-order race: under the OLD sequencer
		// architecture, BeginBatch would have returned [..., 380, 381,
		// 382] missing seq=379, and the cursor would have leapfrogged
		// to 382. Under the NEW staged-committer architecture seqs
		// commit gap-free, so this branch should be rare (and is a
		// regression detector if it fires repeatedly).
		return nil, nil
	}

	// Walk to find the contiguous prefix length.
	contiguousLen := 1
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq != entries[i-1].Seq+1 {
			break
		}
		contiguousLen++
	}
	contiguous := entries[:contiguousLen]

	// Within the contiguous prefix, separate live (returned to the
	// builder for SMT processing) from tombstones (skipped, but the
	// cursor still advances past them).
	liveSeqs := make([]uint64, 0, contiguousLen)
	for _, e := range contiguous {
		if e.Status == store.StatusLive {
			liveSeqs = append(liveSeqs, e.Seq)
		}
	}
	advanceTo := contiguous[contiguousLen-1].Seq

	// All-tombstone prefix: no SMT work, but the cursor still needs
	// to move past so the next BeginBatch doesn't re-read the same
	// dead rows. AdvancePastTombstones runs in its own tx (no atomic
	// coupling with SMT state is needed because tombstones don't
	// have associated SMT state).
	if len(liveSeqs) == 0 {
		if err := r.cursor.AdvancePastTombstones(ctx, advanceTo); err != nil {
			return nil, fmt.Errorf("builder/cursor: advance past tombstones: %w", err)
		}
		return nil, nil
	}

	// Live work present. Stash advanceTo for CommitBatch — the
	// caller-supplied seqs slice would only let us advance to
	// max(liveSeqs), which can be < advanceTo if tombstones sit at
	// the tail of the prefix.
	r.pendingAdvanceTo = advanceTo
	r.pendingAdvanceSet = true
	return liveSeqs, nil
}

// CommitBatch advances the cursor to the high-water mark recorded
// by the most recent BeginBatch — NOT to max(seqs). Must be called
// inside the builder's atomic commit transaction so the cursor
// advance is grouped with the SMT mutations.
//
// Why not max(seqs)?  BeginBatch may have observed a contiguous
// prefix that ends in a tombstone (Tessera-assigned seq with no
// projectable entry). In that case the live-seq slice the builder
// processed stops short of the prefix's actual high-water mark.
// Advancing the cursor to max(seqs) would leave the tombstone
// floating at the head of the next BeginBatch's read window
// forever; advancing to the stashed pendingAdvanceTo moves past it.
//
// If seqs is empty AND no pending advance is stashed, CommitBatch
// is a no-op (defensive — the builder's processBatch checks
// len(seqs)==0 before calling, so this shouldn't fire).
//
// Does NOT update any in-memory cache. The cursor value the next
// BeginBatch returns comes from Postgres directly; if THIS tx rolls
// back, the next BeginBatch correctly sees the prior cursor value
// and the same seqs get re-processed. ProcessBatch is idempotent
// (smt_leaves UPSERT; smt_root_state UPSERT; bytestore
// content-addressed), so re-processing is safe.
func (r *CursorReader) CommitBatch(ctx context.Context, tx pgx.Tx, seqs []uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.pendingAdvanceSet {
		// No BeginBatch-stashed advance — fall back to max(seqs)
		// for callers that bypass the BeginBatch lifecycle (unit
		// tests, the rebuild tool's manual cursor advance).
		if len(seqs) == 0 {
			return nil
		}
		maxSeq := seqs[0]
		for _, s := range seqs[1:] {
			if s > maxSeq {
				maxSeq = s
			}
		}
		return r.cursor.AdvanceTx(ctx, tx, maxSeq)
	}

	advanceTo := r.pendingAdvanceTo
	r.pendingAdvanceTo = 0
	r.pendingAdvanceSet = false
	return r.cursor.AdvanceTx(ctx, tx, advanceTo)
}

// RecoverOnStartup is a no-op for the cursor reader. Crash
// recovery is implicit: the cursor was either advanced in a
// committed transaction (work is durable) or it wasn't (we
// re-read on next tick). There are no "in-flight processing"
// rows to clean up because the cursor mode never marks rows as
// in-flight.
func (r *CursorReader) RecoverOnStartup(_ context.Context) (int64, error) {
	return 0, nil
}

// Compile-time pin: *CursorReader satisfies BatchReader.
var _ BatchReader = (*CursorReader)(nil)
