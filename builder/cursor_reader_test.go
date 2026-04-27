/*
FILE PATH: builder/cursor_reader_test.go

Integration-style tests for *CursorReader. Skips when
ORTHOLOG_TEST_DSN is unset, runs against the docker-compose
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
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// requireDB connects to ORTHOLOG_TEST_DSN, runs migrations, and
// returns a pool. Skips the test when the DSN is unset — same
// behavior as store/commitment_fetcher_test.go's requireDB so the
// suite is uniformly skip-friendly under `go test -short ./...`.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ORTHOLOG_TEST_DSN")
	if dsn == "" {
		t.Skip("ORTHOLOG_TEST_DSN unset; skipping integration-style cursor reader test")
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
		`UPDATE builder_cursor SET last_processed_sequence = 0 WHERE id = 1`,
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
				(sequence_number, canonical_hash, log_time, sig_algorithm_id, signer_did)
			VALUES ($1, $2, NOW(), 1, 'did:web:test-signer.example')`,
			seq, hash,
		)
		if err != nil {
			t.Fatalf("seed entry_index seq=%d: %v", seq, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// Bootstrap + tailing
// ─────────────────────────────────────────────────────────────────

func TestCursorReader_BeginBatch_BootstrapsFromDB(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)

	// Pre-set cursor to 5 in the database. First BeginBatch must
	// honor that — entries 1..5 should NOT come back.
	if _, err := pool.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = 5 WHERE id = 1`,
	); err != nil {
		t.Fatalf("preset cursor: %v", err)
	}
	seedSeqs(t, ctx, pool, 1, 2, 3, 4, 5, 6, 7)

	r := NewCursorReader(store.NewSequenceCursor(pool))
	got, err := r.BeginBatch(ctx, nil, 100)
	if err != nil {
		t.Fatalf("BeginBatch: %v", err)
	}
	want := []uint64{6, 7}
	if !equalSlice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCursorReader_BeginBatch_TailsEntryIndexInOrder(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 3, 1, 2, 5, 4) // out-of-order insert

	r := NewCursorReader(store.NewSequenceCursor(pool))
	got, err := r.BeginBatch(ctx, nil, 100)
	if err != nil {
		t.Fatalf("BeginBatch: %v", err)
	}
	// Despite out-of-order INSERT, the cursor reader returns ASC.
	want := []uint64{1, 2, 3, 4, 5}
	if !equalSlice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
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
	seedSeqs(t, ctx, pool, 1, 2, 3, 4, 5)

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
	if got != 5 {
		t.Errorf("expected cursor=5 after commit, got %d", got)
	}
}

func TestCursorReader_CommitBatch_RollbackKeepsCursor(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 1, 2, 3)

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

	// Cursor in the database stays at 0 — load-bearing crash safety.
	got, err := cur.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != 0 {
		t.Errorf("expected cursor unchanged at 0 after rollback, got %d", got)
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

func TestCursorReader_CommitBatch_RegressionGuardRejectsStaleMax(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resetState(t, ctx, pool)
	seedSeqs(t, ctx, pool, 1, 2, 3)

	r := NewCursorReader(store.NewSequenceCursor(pool))

	// First commit advances to 3.
	if err := store.WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return r.CommitBatch(ctx, tx, []uint64{1, 2, 3})
	}); err != nil {
		t.Fatalf("first CommitBatch: %v", err)
	}

	// Second commit with max=2 (stale) MUST error.
	gotErr := store.WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return r.CommitBatch(ctx, tx, []uint64{2})
	})
	if gotErr == nil {
		t.Fatal("expected regression error on stale CommitBatch")
	}
	if !strings.Contains(gotErr.Error(), "regression") {
		t.Errorf("unexpected error: %v", gotErr)
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
	seedSeqs(t, ctx, pool, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

	cur := store.NewSequenceCursor(pool)
	r := NewCursorReader(cur)

	// Process in three batches of size 3, 3, 4.
	expectedBatches := [][]uint64{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
		{10},
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

	// Cursor should be at 10 (the highest seq we committed).
	got, err := cur.Read(ctx)
	if err != nil {
		t.Fatalf("final Read: %v", err)
	}
	if got != 10 {
		t.Errorf("expected final cursor=10, got %d", got)
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
