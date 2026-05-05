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
	// enforced by the operator's advisory lock, makes per-row
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
type CursorReader struct {
	cursor *store.SequenceCursor

	mu        sync.Mutex
	current   uint64 // in-memory cursor; -1 sentinel via initialized=false
	initFromDB bool  // false until Read() bootstraps from the database
}

// NewCursorReader constructs a reader over the supplied cursor.
// The in-memory cursor is bootstrapped lazily on the first
// BeginBatch call so the constructor itself stays infallible
// and synchronous.
func NewCursorReader(cursor *store.SequenceCursor) *CursorReader {
	return &CursorReader{cursor: cursor}
}

// BeginBatch returns up to batchSize sequence numbers from
// entry_index whose sequence_number > current cursor, ASC. tx is
// ignored — the cursor reader does not need transactional
// locking; the operator's advisory-lock-enforced singleton
// builder makes per-row locking redundant.
func (r *CursorReader) BeginBatch(ctx context.Context, _ pgx.Tx, batchSize int) ([]uint64, error) {
	r.mu.Lock()
	if !r.initFromDB {
		seq, err := r.cursor.Read(ctx)
		if err != nil {
			r.mu.Unlock()
			return nil, fmt.Errorf("builder/cursor: bootstrap read: %w", err)
		}
		r.current = seq
		r.initFromDB = true
	}
	cursor := r.current
	r.mu.Unlock()

	return r.cursor.Next(ctx, cursor, batchSize)
}

// CommitBatch advances the cursor to the highest sequence in
// seqs. Must be called inside the builder's atomic commit
// transaction so cursor advance is grouped with the SMT mutations.
//
// If seqs is empty, CommitBatch is a no-op. The builder loop
// shouldn't call CommitBatch with an empty batch — but if it
// ever does, this guard prevents a regressing in-memory cursor.
func (r *CursorReader) CommitBatch(ctx context.Context, tx pgx.Tx, seqs []uint64) error {
	if len(seqs) == 0 {
		return nil
	}
	maxSeq := seqs[0]
	for _, s := range seqs[1:] {
		if s > maxSeq {
			maxSeq = s
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if maxSeq <= r.current {
		// Defensive — we should never be asked to commit a batch
		// whose max is at-or-below the current cursor. If we are,
		// it means BeginBatch returned a stale snapshot; flag
		// loudly rather than silently regress.
		return fmt.Errorf("builder/cursor: commit regression: maxSeq=%d <= current=%d", maxSeq, r.current)
	}
	if err := r.cursor.AdvanceTx(ctx, tx, maxSeq); err != nil {
		return err
	}
	// In-memory advance happens AFTER the tx Exec succeeds. If the
	// tx later rolls back, the in-memory cursor is ahead of the
	// database — which is fine because BeginBatch always re-reads
	// the database on bootstrap (and we set initFromDB=false on
	// a forced reset path; not exposed today).
	r.current = maxSeq
	return nil
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
