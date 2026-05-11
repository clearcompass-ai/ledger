/*
FILE PATH: store/sequence_cursor_test.go

Integration-style tests for SequenceCursor against a real Postgres.
Skips when ATTESTA_TEST_DSN is unset — same pattern as
commitment_fetcher_test.go's requireDB helper. The integration
docker-compose harness sets the DSN; local developers can point it
at any disposable database.

Coverage:
  - Empty / initial state.
  - Boundary conditions (batchSize, cursor at high-water mark).
  - Atomic advance + rollback inside the builder's transaction.
  - Singleton row enforcement at the schema layer.
  - The out-of-band rebuild path (AdvanceForRebuild).
*/
package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// resetCursorTestState truncates entry_index and resets the
// builder_cursor singleton row to zero so each test runs in a
// known state. Tables themselves stay in place; only data goes.
func resetCursorTestState(t *testing.T, ctx context.Context, c *SequenceCursor) {
	t.Helper()
	// CASCADE is required because commitment_split_id references
	// entry_index(sequence_number) via FK. Bare TRUNCATE refuses
	// to drop rows from a referenced table; CASCADE also wipes
	// commitment_split_id (which these tests don't seed, so the
	// cascade is a no-op data-wise but satisfies Postgres's FK
	// safety check).
	if _, err := c.db.Exec(ctx, "TRUNCATE entry_index CASCADE"); err != nil {
		t.Fatalf("truncate entry_index: %v", err)
	}
	if _, err := c.db.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = -1 WHERE id = 1`,
	); err != nil {
		t.Fatalf("reset builder_cursor: %v", err)
	}
}

// seedEntryIndex inserts entry_index rows with valid synthetic
// values for the NOT NULL columns. canonical_hash varies per
// sequence so the UNIQUE constraint doesn't reject seeds.
func seedEntryIndex(t *testing.T, ctx context.Context, c *SequenceCursor, seqs ...uint64) {
	t.Helper()
	for _, seq := range seqs {
		hash := make([]byte, 32)
		hash[0] = byte(seq)
		hash[1] = byte(seq >> 8)
		hash[2] = byte(seq >> 16)
		hash[3] = byte(seq >> 24)
		_, err := c.db.Exec(ctx, `
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

// ─────────────────────────────────────────────────────────────────
// Read — current cursor value
// ─────────────────────────────────────────────────────────────────

func TestSequenceCursor_Read_DefaultsToZeroAfterMigration(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)

	got, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != -1 {
		t.Errorf("expected default cursor = -1 (v0.3.0 'no seqs processed yet' sentinel), got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// Next — pulling pending sequences
// ─────────────────────────────────────────────────────────────────

func TestSequenceCursor_Next_EmptyEntryIndexReturnsEmptySlice(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)

	got, err := c.Next(ctx, 0, 100)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice on empty entry_index, got %v", got)
	}
}

func TestSequenceCursor_Next_ReturnsAscendingSequences(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)
	seedEntryIndex(t, ctx, c, 1, 2, 3, 4, 5)

	got, err := c.Next(ctx, 0, 100)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := []uint64{1, 2, 3, 4, 5}
	if !equalUint64Slice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSequenceCursor_Next_RespectsBatchSize(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)
	seedEntryIndex(t, ctx, c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

	got, err := c.Next(ctx, 0, 3)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := []uint64{1, 2, 3}
	if !equalUint64Slice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSequenceCursor_Next_FiltersAtOrBelowCursor(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)
	seedEntryIndex(t, ctx, c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

	got, err := c.Next(ctx, 5, 100)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := []uint64{6, 7, 8, 9, 10}
	if !equalUint64Slice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSequenceCursor_Next_AtHighWaterMarkReturnsEmpty(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)
	seedEntryIndex(t, ctx, c, 1, 2, 3)

	got, err := c.Next(ctx, 3, 100)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no work past high-water cursor, got %v", got)
	}
}

func TestSequenceCursor_Next_RejectsZeroBatchSize(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	_, err := c.Next(ctx, 0, 0)
	if err == nil {
		t.Fatal("expected error on batchSize=0")
	}
	if !strings.Contains(err.Error(), "batchSize must be positive") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// AdvanceTx — atomic advance inside builder's commit
// ─────────────────────────────────────────────────────────────────

func TestSequenceCursor_AdvanceTx_PersistsAfterCommit(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)

	err := WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return c.AdvanceTx(ctx, tx, 42)
	})
	if err != nil {
		t.Fatalf("WithReadCommittedTx: %v", err)
	}

	got, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != 42 {
		t.Errorf("expected cursor = 42 after commit, got %d", got)
	}
}

func TestSequenceCursor_AdvanceTx_RollsBackOnError(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)

	// Establish a non-zero baseline so we can detect rollback by
	// comparing against 10, not 0.
	if err := WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return c.AdvanceTx(ctx, tx, 10)
	}); err != nil {
		t.Fatalf("baseline advance: %v", err)
	}

	// Open a fresh tx, advance to 99, then return a sentinel error
	// so WithReadCommittedTx rolls back. Cursor should stay at 10.
	rollbackErr := errors.New("injected rollback")
	gotErr := WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		if err := c.AdvanceTx(ctx, tx, 99); err != nil {
			t.Fatalf("AdvanceTx inner: %v", err)
		}
		return rollbackErr
	})
	if !errors.Is(gotErr, rollbackErr) {
		t.Fatalf("expected rollback error to propagate, got %v", gotErr)
	}

	got, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != 10 {
		t.Errorf("expected cursor unchanged at 10 after rollback, got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// AdvanceForRebuild — out-of-band reset for cmd/rebuild-tiles
// ─────────────────────────────────────────────────────────────────

func TestSequenceCursor_AdvanceForRebuild_ResetsBackward(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)
	resetCursorTestState(t, ctx, c)

	// Advance forward via the hot-path API, then rebuild resets
	// backward — the supported forward-and-rewind shape used by
	// cmd/rebuild-tiles after a full SMT replay.
	if err := WithReadCommittedTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		return c.AdvanceTx(ctx, tx, 100)
	}); err != nil {
		t.Fatalf("advance to 100: %v", err)
	}

	if err := c.AdvanceForRebuild(ctx, 0); err != nil {
		t.Fatalf("AdvanceForRebuild: %v", err)
	}

	got, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != 0 {
		t.Errorf("expected cursor reset to 0, got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// Singleton enforcement (schema CHECK constraint)
// ─────────────────────────────────────────────────────────────────

func TestSequenceCursor_Singleton_DDLRejectsSecondRow(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := NewSequenceCursor(pool)

	// id=2 must fail the CHECK constraint (id=1 would fail PRIMARY
	// KEY since the migration seeds that row, but id=2 specifically
	// exercises the CHECK).
	_, err := c.db.Exec(ctx,
		`INSERT INTO builder_cursor (id, last_processed_sequence) VALUES (2, 0)`,
	)
	if err == nil {
		t.Fatal("expected CHECK constraint to reject id=2 row")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "check") && !strings.Contains(msg, "constraint") {
		t.Errorf("unexpected rejection cause: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

func equalUint64Slice(a, b []uint64) bool {
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
