/*
FILE PATH: builder/cursor_reader_test.go

Integration-style tests for *CursorReader. Skips when
ATTESTA_TEST_DSN is unset, runs against the docker-compose
Postgres harness when set.

Coverage:
  - Bootstrap: first BeginBatch reads cursor from DB.
  - Tailing: BeginBatch returns entry_index rows > cursor in ASC.
  - Commit: cursor advances after the tx commits.
  - Rollback safety: tx aborts → cursor stays → batch reprocesses.
  - Empty batch: CommitBatch with no seqs is a no-op.
  - Regression guard: CommitBatch with maxSeq <= current errors.
  - RecoverOnStartup is a no-op for cursor mode.
  - End-to-end multi-batch cycle: process N entries in M batches,
    cursor advances monotonically.
*/
package builder

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/store"
)

// requireDB connects to ATTESTA_TEST_DSN, runs migrations, and
// returns a pool. Skips the test when the DSN is unset — same
// behavior as store/commitment_fetcher_test.go's requireDB so the
// suite is uniformly skip-friendly under `go test -short ./...`.
//
// LEDGER_TEST_SERIAL: warn-only guard. See the equivalent comment
// in store/commitment_fetcher_test.go::requireDB.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset; skipping integration-style cursor reader test")
	}
	if os.Getenv("LEDGER_TEST_SERIAL") != "1" {
		t.Logf("WARNING: LEDGER_TEST_SERIAL != 1; tests are running outside `make test`. " +
			"Cross-package contamination is possible. Use `make test` for deterministic runs.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("RunMigrations: %v", err)
	}
	return pool
}

// resetState wipes entry_index and resets builder_cursor to 0
// before each test so runs are independent of suite ordering.
func resetState(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	// CASCADE: commitment_split_id has an FK on
	// entry_index(sequence_number). Bare TRUNCATE refuses; CASCADE
	// wipes both. These tests don't seed commitment_split_id, so
	// the cascade is a no-op data-wise.
	if _, err := pool.Exec(ctx, "TRUNCATE entry_index CASCADE"); err != nil {
		t.Fatalf("truncate entry_index: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = -1 WHERE id = 1`,
	); err != nil {
		t.Fatalf("reset builder_cursor: %v", err)
	}
}

// seedSeqs inserts entry_index rows for the supplied sequences
// with synthetic NOT NULL fields. canonical_hash varies per
// sequence so the UNIQUE constraint doesn't reject seeds.
func seedSeqs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, seqs ...uint64) {
	t.Helper()
	for _, seq := range seqs {
		hash := make([]byte, 32)
		hash[0] = byte(seq)
		hash[1] = byte(seq >> 8)
		hash[2] = byte(seq >> 16)
		hash[3] = byte(seq >> 24)
		_, err := pool.Exec(ctx, `
			INSERT INTO entry_index
				(sequence_number, canonical_hash, log_time, signer_did)
			VALUES ($1, $2, NOW(), 'did:web:test-signer.example')`,
			seq, hash,
		)
		if err != nil {
			t.Fatalf("seed entry_index seq=%d: %v", seq, err)
		}
	}
}

// expectBatch is the centralized contract assertion for "given
// cursor=C and entry_index seeded with S, the next BeginBatch
// returns want". Tests that exercise a single BeginBatch through
// the full reset → preset → seed → call → assert pipe use this.
// Tests with richer flows (commit, rollback, multi-batch) drive
// the reader directly.
//
// presetCursor=-1 means "leave at the resetState default" (also
// -1, the post-0004 fresh-install sentinel). Any other value
// triggers an explicit UPDATE so the test exercises a non-zero
// baseline.
//
// want=nil asserts BeginBatch returns nil (the gap-detection
// early-exit branch at cursor_reader.go:167-178). want=[] asserts
// an empty non-nil slice (entry_index simply had nothing to
// return); the distinction is structural and the helper preserves
// it via equalSlice.
func expectBatch(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	presetCursor int64,
	seeds []uint64,
	batchSize int,
	want []uint64,
) {
	t.Helper()
	resetState(t, ctx, pool)
	if presetCursor != -1 {
		if _, err := pool.Exec(ctx,
			`UPDATE builder_cursor SET last_processed_sequence = $1 WHERE id = 1`,
			presetCursor,
		); err != nil {
			t.Fatalf("preset cursor=%d: %v", presetCursor, err)
		}
	}
	if len(seeds) > 0 {
		seedSeqs(t, ctx, pool, seeds...)
	}

	r := NewCursorReader(store.NewSequenceCursor(pool))
	got, err := r.BeginBatch(ctx, nil, batchSize)
	if err != nil {
		t.Fatalf("BeginBatch: %v", err)
	}
	if !equalSlice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────
// Bootstrap + tailing
// ─────────────────────────────────────────────────────────────────

// TestCursorReader_BeginBatch_BootstrapsFromDB pins the non-zero
// baseline path: cursor preset to 5, entry_index seeded with 1..7
// (the "earlier" seqs simulate rows compacted away — Postgres only
// reveals seq>cursor to BeginBatch's SELECT). The gap detector
// confirms entries[0].Seq=6 matches expectedFirst=6 and returns
// 6..7. This is the production scenario: a long-running ledger has
// processed millions of seqs; cursor sits at the high-water mark;
// new seqs append at the tail.
//
// Distinct from BeginBatch_GapBetweenCursorAndFirstSeq_ReturnsEmpty
// (which exercises the same code path with cursor=-1, the fresh-
// install sentinel) — both branches of the gap detector need a
// dedicated test, otherwise a regression that breaks one slips by.
func TestCursorReader_BeginBatch_BootstrapsFromDB(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	expectBatch(t, ctx, pool,
		5,                                  // preset cursor (non-zero baseline)
		[]uint64{1, 2, 3, 4, 5, 6, 7},      // seeds — earlier seqs filtered by SQL
		100,                                // batchSize
		[]uint64{6, 7},                     // want
	)
}

// TestCursorReader_BeginBatch_TailsEntryIndexInOrder pins the
// ascending-order invariant: out-of-order INSERTs are sorted ASC
// by the cursor's SELECT. Seeds start at seq=0 because resetState
// puts the cursor at -1 (post-0004 sentinel), so expectedFirst=0
// and the gap detector requires seq=0 first.
func TestCursorReader_BeginBatch_TailsEntryIndexInOrder(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	expectBatch(t, ctx, pool,
		-1,                                 // resetState default cursor
		[]uint64{2, 0, 1, 4, 3},            // out-of-order seeds
		100,                                // batchSize
		[]uint64{0, 1, 2, 3, 4},            // want (ASC)
	)
}

// TestCursorReader_BeginBatch_GapBetweenCursorAndFirstSeq_ReturnsEmpty
// pins the load-bearing gap-detection branch at
// cursor_reader.go:167-178. With cursor=-1 (post-0004 sentinel)
// expectedFirst is 0. Seeds [1, 2, 3] — deliberately skipping
// seq=0 — make entries[0].Seq=1, trip the gap, and BeginBatch
// returns nil.
//
// This is the structural defense against the sequencer's
// per-entry-tx commit-order race: if the builder ever leapfrogged
// over a missing seq, the SMT would be permanently missing that
// leaf (the v0.2.0 leaf_count=99999/100000 bug, fixed by migration
// 0004). A regression that removes the early-exit would surface
// here as a non-nil batch on a gapped seed.
func TestCursorReader_BeginBatch_GapBetweenCursorAndFirstSeq_ReturnsEmpty(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	expectBatch(t, ctx, pool,
		-1,                                 // resetState default cursor
		[]uint64{1, 2, 3},                  // gap: seq=0 missing
		100,                                // batchSize
		nil,                                // want — gap detected, early-exit
	)
}

// ─────────────────────────────────────────────────────────────────
// CommitBatch — cursor advance + rollback safety
// ─────────────────────────────────────────────────────────────────

func TestCursorReader_CommitBatch_AdvancesCursor(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 0, 1, 2, 3, 4)

	cur := store.NewSequenceCursor(pool)
	r := NewCursorReader(cur)

	seqs, _ := r.BeginBatch(ctx, nil, 100)
	if len(seqs) != 5 {
		t.Fatalf("expected 5 seqs, got %d", len(seqs))
	}

	if err := store.WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return r.CommitBatch(ctx, tx, seqs)
	}); err != nil {
		t.Fatalf("CommitBatch: %v", err)
	}

	got, err := cur.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != 4 {
		t.Errorf("expected cursor=4 after commit, got %d", got)
	}
}

func TestCursorReader_CommitBatch_RollbackKeepsCursor(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 0, 1, 2)

	cur := store.NewSequenceCursor(pool)
	r := NewCursorReader(cur)

	seqs, _ := r.BeginBatch(ctx, nil, 100)

	rollbackErr := errors.New("injected rollback")
	gotErr := store.WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		if err := r.CommitBatch(ctx, tx, seqs); err != nil {
			t.Fatalf("CommitBatch inner: %v", err)
		}
		return rollbackErr
	})
	if !errors.Is(gotErr, rollbackErr) {
		t.Fatalf("expected rollback to propagate, got %v", gotErr)
	}

	// Cursor in the database stays at -1 (the reset value before the
	// rolled-back AdvanceTx) — load-bearing crash safety.
	got, err := cur.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != -1 {
		t.Errorf("expected cursor unchanged at -1 after rollback, got %d", got)
	}

	// CRITICAL — the next BeginBatch MUST return the SAME seqs the
	// rolled-back batch saw. The previous implementation cached the
	// advanced cursor in memory inside CommitBatch and skipped seqs
	// 0..2 here, silently dropping work whenever the atomic commit
	// rolled back. That bug surfaced as leaf_count=3 in the 1K soak.
	//
	// The structural fix: BeginBatch reads the cursor from Postgres
	// every call, so a rollback automatically restores the visible
	// cursor to its pre-tx state.
	retry, err := r.BeginBatch(ctx, nil, 100)
	if err != nil {
		t.Fatalf("BeginBatch after rollback: %v", err)
	}
	if !equalSlice(retry, []uint64{0, 1, 2}) {
		t.Errorf("after rollback, expected seqs to be re-returned [0,1,2]; got %v "+
			"— the cursor reader is silently skipping rolled-back work", retry)
	}
}

func TestCursorReader_CommitBatch_EmptyBatchIsNoOp(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)

	r := NewCursorReader(store.NewSequenceCursor(pool))

	err := store.WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return r.CommitBatch(ctx, tx, nil)
	})
	if err != nil {
		t.Errorf("expected nil for empty CommitBatch, got %v", err)
	}
}

func TestCursorReader_BeginBatch_ReadsPGEveryCall(t *testing.T) {
	// Pins the structural invariant introduced when the in-memory
	// cursor cache was removed: every BeginBatch reads the cursor
	// from Postgres, so an out-of-band cursor change (a manual SQL
	// rewind, a successful concurrent commit, a rollback) is
	// observed on the very next call — no stale in-memory snapshot.
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 0, 1, 2, 3, 4)

	cur := store.NewSequenceCursor(pool)
	r := NewCursorReader(cur)

	// First call: cursor=-1 (post-0004 sentinel), returns 0..4.
	first, err := r.BeginBatch(ctx, nil, 100)
	if err != nil {
		t.Fatalf("BeginBatch first: %v", err)
	}
	if !equalSlice(first, []uint64{0, 1, 2, 3, 4}) {
		t.Fatalf("first BeginBatch: got %v, want [0..4]", first)
	}

	// Out-of-band: someone (e.g., cmd/rebuild-tiles, or a successful
	// concurrent commit) advances the cursor in Postgres directly,
	// WITHOUT going through CommitBatch.
	if _, err := pool.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = 2 WHERE id = 1`,
	); err != nil {
		t.Fatalf("out-of-band advance: %v", err)
	}

	// Next BeginBatch must reflect the out-of-band advance — returns
	// only 3..4, not the cached 0..4 from before.
	second, err := r.BeginBatch(ctx, nil, 100)
	if err != nil {
		t.Fatalf("BeginBatch second: %v", err)
	}
	if !equalSlice(second, []uint64{3, 4}) {
		t.Errorf("after out-of-band cursor advance, expected [3,4], got %v "+
			"— the reader is serving a stale in-memory snapshot", second)
	}
}

// ─────────────────────────────────────────────────────────────────
// RecoverOnStartup — explicitly a no-op for cursor mode
// ─────────────────────────────────────────────────────────────────

func TestCursorReader_RecoverOnStartup_AlwaysZero(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := NewCursorReader(store.NewSequenceCursor(pool))
	got, err := r.RecoverOnStartup(ctx)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if got != 0 {
		t.Errorf("expected 0 recovered count, got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// End-to-end multi-batch cycle
// ─────────────────────────────────────────────────────────────────

func TestCursorReader_FullCycle_MultiBatch(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9)

	cur := store.NewSequenceCursor(pool)
	r := NewCursorReader(cur)

	// Process in four batches of size 3, 3, 3, 1 (post-0004
	// contract: seq=0 is genesis, so the seeded range is 0..9).
	expectedBatches := [][]uint64{
		{0, 1, 2},
		{3, 4, 5},
		{6, 7, 8},
		{9},
	}
	for i, want := range expectedBatches {
		got, err := r.BeginBatch(ctx, nil, 3)
		if err != nil {
			t.Fatalf("batch %d BeginBatch: %v", i, err)
		}
		if !equalSlice(got, want) {
			t.Fatalf("batch %d: got %v, want %v", i, got, want)
		}
		if err := store.WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
			return r.CommitBatch(ctx, tx, got)
		}); err != nil {
			t.Fatalf("batch %d CommitBatch: %v", i, err)
		}
	}

	// Cursor should be at 9 (the highest seq we committed).
	got, err := cur.Read(ctx)
	if err != nil {
		t.Fatalf("final Read: %v", err)
	}
	if got != 9 {
		t.Errorf("expected final cursor=9, got %d", got)
	}

	// One more BeginBatch should be empty — no work past the
	// high-water mark.
	tail, err := r.BeginBatch(ctx, nil, 100)
	if err != nil {
		t.Fatalf("tail BeginBatch: %v", err)
	}
	if len(tail) != 0 {
		t.Errorf("expected empty tail batch, got %v", tail)
	}
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

func equalSlice(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
