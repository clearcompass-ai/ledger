/*
FILE PATH: store/sequence_cursor.go

SequenceCursor — Postgres-backed implementation of the CT-native
"the log is the queue" pattern.

DESIGN:

	Admission writes only entry_index. The builder reads new
	sequences via
	  SELECT sequence_number FROM entry_index
	  WHERE sequence_number > $cursor
	  ORDER BY sequence_number ASC
	  LIMIT $batch
	using the entry_index PRIMARY KEY index. Cursor advance is one
	row UPDATE per batch in the builder's atomic commit, bounding
	dead tuples on builder_cursor by batches/sec instead of
	entries/sec — the load-bearing property at 10B+ scale.

CONTRACT:
  - Read returns []uint64 of next batch sequences in ASC order.
  - AdvanceTx updates the cursor row inside the caller's
    transaction. Caller MUST commit the transaction for the
    advance to persist. If the tx rolls back the cursor stays
    where it was — next read returns the same sequences and the
    builder reprocesses them. SMT writes are upserts, so
    reprocessing is idempotent.
  - The cursor row's CHECK (id = 1) constraint enforces the
    singleton invariant from the schema side; any future code
    path that tries to corrupt the cursor by INSERT-ing a second
    row fails at the database layer.

THREAD SAFETY:

	Cursor reads are stateless — Read and ReadFromCursor both query
	fresh values per call, so concurrent readers are safe. Writes
	must be serialized through the builder's singleton goroutine
	(the ledger already enforces single-builder-per-log via
	Postgres advisory_lock); SequenceCursor itself does not
	serialize writes.

NULL POINTERS:

	This type is constructible without a *pgxpool.Pool to ease
	test wiring. The Pool is only consulted at call time, so
	passing a nil pool to NewSequenceCursor produces a value that
	panics on first use — the caller (cmd/ledger/main.go)
	validates the pool before constructing.
*/
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SequenceCursor reads pending sequences from entry_index and
// advances builder_cursor.last_processed_sequence inside the
// builder's atomic commit transaction.
type SequenceCursor struct {
	db *pgxpool.Pool
}

// NewSequenceCursor constructs a cursor backed by the given pool.
func NewSequenceCursor(db *pgxpool.Pool) *SequenceCursor {
	return &SequenceCursor{db: db}
}

// Read returns the current cursor value (the highest sequence the
// builder has fully processed). Used at builder startup to bootstrap
// the in-memory cursor and by ops tooling to inspect builder
// progress without scraping logs.
//
// The cursor is INT64 (signed) so that the value -1 can encode the
// "no sequences processed yet" state on a fresh install. The
// `WHERE sequence_number > $1` query in Next then includes seq=0
// when cursor=-1, fixing the bootstrap off-by-one that previously
// dropped seq=0 forever (see migration 0004 for the full context).
// Real cursor values past bootstrap are always non-negative.
func (c *SequenceCursor) Read(ctx context.Context) (int64, error) {
	var seq int64
	err := c.db.QueryRow(ctx,
		"SELECT last_processed_sequence FROM builder_cursor WHERE id = 1",
	).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("store/cursor: read: %w", err)
	}
	return seq, nil
}

// CursorEntry is one row from SequenceCursor.Next — the sequence
// number plus its tombstone status. Callers must filter out
// tombstones (status == StatusTombstone) when building work lists
// but must STILL advance the cursor past them on commit, otherwise
// the next BeginBatch would re-read them.
type CursorEntry struct {
	Seq    uint64
	Status EntryStatus
}

// Next returns up to batchSize entry_index rows whose
// sequence_number > cursor, in ASC order. Each returned CursorEntry
// carries the row's tombstone status alongside the seq.
//
// cursor is supplied by the caller (typically from a prior Read or
// from an in-memory advancing counter the builder maintains across
// ticks); this avoids a database round-trip per Next call. The
// caller is responsible for ensuring cursor reflects the last
// successfully-committed advance — passing a stale cursor returns
// duplicate sequences, which the SMT's upsert-shaped write path
// handles idempotently.
//
// Returns an empty slice (NOT an error) when there are no new
// entries; callers poll on a sleep timer.
//
// cursor is INT64 to admit the -1 sentinel that Read returns on a
// fresh install. PG's signed BIGINT lets `WHERE sequence_number > -1`
// match seq=0; using uint64 here would silently roll -1 to maxUint64
// and the query would never return any rows.
//
// Both live and tombstone rows are returned; the caller is responsible
// for filtering. The status column was added in migration 0005 to
// support gap-free committer architecture (see migrations/0005 for
// the full rationale).
func (c *SequenceCursor) Next(ctx context.Context, cursor int64, batchSize int) ([]CursorEntry, error) {
	if batchSize <= 0 {
		return nil, fmt.Errorf("store/cursor: batchSize must be positive, got %d", batchSize)
	}
	rows, err := c.db.Query(ctx, `
		SELECT sequence_number, status FROM entry_index
		WHERE sequence_number > $1
		ORDER BY sequence_number ASC
		LIMIT $2`,
		cursor, batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("store/cursor: next: %w", err)
	}
	defer rows.Close()

	out := make([]CursorEntry, 0, batchSize)
	for rows.Next() {
		var (
			seq    uint64
			status int16
		)
		if err := rows.Scan(&seq, &status); err != nil {
			return nil, fmt.Errorf("store/cursor: scan: %w", err)
		}
		out = append(out, CursorEntry{Seq: seq, Status: EntryStatus(status)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/cursor: rows: %w", err)
	}
	return out, nil
}

// AdvanceTx updates builder_cursor.last_processed_sequence inside
// the supplied transaction. The caller (the builder loop) commits
// the transaction alongside its SMT and buffer-buffer mutations,
// so cursor advance is atomic with the work it represents.
//
// MUST be called with newCursor >= the cursor value passed to the
// matching Next call — otherwise the builder is going backwards.
// The function does NOT enforce monotonicity at the database
// layer (a future caller running cmd/rebuild-tiles legitimately
// resets the cursor backward); callers in the hot path are
// responsible for not calling this with a regressing value.
func (c *SequenceCursor) AdvanceTx(ctx context.Context, tx pgx.Tx, newCursor uint64) error {
	tag, err := tx.Exec(ctx,
		`UPDATE builder_cursor
		   SET last_processed_sequence = $1, updated_at = NOW()
		   WHERE id = 1`,
		newCursor,
	)
	if err != nil {
		return fmt.Errorf("store/cursor: advance: %w", err)
	}
	if tag.RowsAffected() != 1 {
		// Defensive: the singleton row should exist post-migration.
		// If it doesn't, the cursor would silently no-op forever
		// and the builder would loop on the same batch.
		return fmt.Errorf("store/cursor: advance affected %d rows, want 1 (builder_cursor row missing?)", tag.RowsAffected())
	}
	return nil
}

// Lag returns the number of admitted entries the builder has not yet
// processed, computed as MAX(entry_index.sequence_number) minus
// builder_cursor.last_processed_sequence. Empty entry_index returns 0.
//
// The DifficultyController consumes Lag as the load-pressure
// signal driving Mode B PoW difficulty. Single round-trip; uses
// the entry_index PRIMARY KEY for the MAX lookup and the singleton
// builder_cursor row for the cursor.
func (c *SequenceCursor) Lag(ctx context.Context) (int64, error) {
	var lag int64
	err := c.db.QueryRow(ctx, `
		SELECT COALESCE(
		         (SELECT MAX(sequence_number) FROM entry_index), 0
		       ) - last_processed_sequence
		FROM builder_cursor
		WHERE id = 1`,
	).Scan(&lag)
	if err != nil {
		return 0, fmt.Errorf("store/cursor: lag: %w", err)
	}
	if lag < 0 {
		// Defensive — cursor ahead of MAX entry_index implies a
		// regressing entry_index, which the schema does not permit.
		// Report 0 rather than a negative depth.
		return 0, nil
	}
	return lag, nil
}

// AdvancePastTombstones moves the cursor to newCursor outside of
// the builder's atomic commit. Used by the builder's BeginBatch
// when the contiguous prefix it observes is ENTIRELY tombstones —
// there is no SMT work to atomically couple the cursor advance to,
// but the cursor still needs to move past those seqs so the next
// BeginBatch doesn't re-read them.
//
// Safe to call from the builder's hot path because:
//   1. Tombstone rows in entry_index never participate in SMT state
//      (they have NULL signer_did_real / payload metadata and are
//      filtered out of leaf production).
//   2. The advance is naturally idempotent — re-running it sets the
//      cursor to the same value.
//   3. If the call fails (tx error), the next BeginBatch re-reads
//      the same tombstones and re-tries the advance.
//
// Distinct method name (rather than overloading AdvanceForRebuild)
// so the call site's intent is explicit and grep-able.
func (c *SequenceCursor) AdvancePastTombstones(ctx context.Context, newCursor uint64) error {
	tag, err := c.db.Exec(ctx,
		`UPDATE builder_cursor
		   SET last_processed_sequence = $1, updated_at = NOW()
		   WHERE id = 1 AND last_processed_sequence < $1`,
		newCursor,
	)
	if err != nil {
		return fmt.Errorf("store/cursor: advance-tombstones: %w", err)
	}
	// RowsAffected may be 0 if a concurrent advance already moved the
	// cursor past newCursor — that's fine, the invariant is preserved.
	_ = tag
	return nil
}

// AdvanceForRebuild resets the cursor to a caller-supplied value
// without going through the builder's atomic commit. Used ONLY by
// cmd/rebuild-tiles after a full SMT replay; not safe to call from
// the hot path because there's no transactional coupling with
// other state.
//
// Separate function name (rather than reusing AdvanceTx with a
// nil tx) so the rebuild path is grep-able and any future code
// review can flag inadvertent usage from the wrong site.
func (c *SequenceCursor) AdvanceForRebuild(ctx context.Context, newCursor uint64) error {
	tag, err := c.db.Exec(ctx,
		`UPDATE builder_cursor
		   SET last_processed_sequence = $1, updated_at = NOW()
		   WHERE id = 1`,
		newCursor,
	)
	if err != nil {
		return fmt.Errorf("store/cursor: advance-rebuild: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store/cursor: advance-rebuild affected %d rows, want 1", tag.RowsAffected())
	}
	return nil
}
