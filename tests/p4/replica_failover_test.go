//go:build p4
// +build p4

// FILE PATH: tests/p4/replica_failover_test.go
//
// P4.3 — 2-replica failover. Pins the contract that when the
// active builder dies, the standby resumes from the persisted
// builder_cursor without going backwards or duplicating
// sequences. Layered atop P4.2's advisory-lock split-brain pin:
// P4.2 proves only one replica holds the lock at a time; P4.3
// proves the cursor's continuity property across the handoff.
//
// MATRIX (one row per test case):
//
//  1. CursorContinuity — A advances cursor; B reads the
//     persisted value via a fresh pool. The bare cursor
//     round-trip without any builder running.
//  2. LockReleaseAllowsResume — A acquires lock + advances
//     cursor + releases. B acquires + reads cursor at A's
//     value + advances further. End-to-end handoff.
//  3. ConcurrentAcquireOnlyOneAdvances — N pools race for the
//     lock; only the winner can advance the cursor. The
//     non-winner's AdvanceTx (run inside its own ctx) is never
//     reached because their lock acquire is bounded by ctx
//     timeout.
package p4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/clearcompass-ai/ledger/store"
)

// TestP4_ReplicaFailover_CursorContinuity: replica A advances
// builder_cursor inside a SerializableTx; replica B reads the
// SAME persisted value via a fresh connection pool. Pins the
// invariant that the cursor is durable across the connection-
// pool boundary — without which a "replica B" booting from a
// fresh pgxpool.Pool would re-process A's last batch.
func TestP4_ReplicaFailover_CursorContinuity(t *testing.T) {
	poolA := requirePostgres(t)
	defer poolA.Close()
	poolB := freshPool(t)
	defer poolB.Close()
	ctx := context.Background()

	// Reset to a known state. UPDATE not INSERT — the migration
	// creates the singleton row.
	if _, err := poolA.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset cursor: %v", err)
	}

	cursorA := store.NewSequenceCursor(poolA)
	cursorB := store.NewSequenceCursor(poolB)

	// A advances to 50.
	const advanceTo = uint64(50)
	err := store.WithSerializableTx(ctx, poolA, func(ctx context.Context, tx pgx.Tx) error {
		return cursorA.AdvanceTx(ctx, tx, advanceTo)
	})
	if err != nil {
		t.Fatalf("A advance to %d: %v", advanceTo, err)
	}

	// B reads via a different pool — must see the same value.
	got, err := cursorB.Read(ctx)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	if got != advanceTo {
		t.Fatalf("B read cursor = %d, want %d (replica A's persisted value) — "+
			"a fresh pgxpool that doesn't see A's commit would re-process the "+
			"same batch on failover", got, advanceTo)
	}
}

// TestP4_ReplicaFailover_LockReleaseAllowsResume: end-to-end
// handoff. A holds the builder lock + advances cursor + releases.
// B acquires the now-free lock, reads the cursor at A's value,
// advances further, and re-reads to confirm durability.
//
// This is the load-bearing rolling-update / supervisor-restart
// scenario: the previous pod's last advance MUST survive into
// the new pod's first batch.
func TestP4_ReplicaFailover_LockReleaseAllowsResume(t *testing.T) {
	poolA := requirePostgres(t)
	defer poolA.Close()
	poolB := freshPool(t)
	defer poolB.Close()
	ctx := context.Background()

	logger := silentLogger()

	if _, err := poolA.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset cursor: %v", err)
	}

	cursorA := store.NewSequenceCursor(poolA)
	cursorB := store.NewSequenceCursor(poolB)

	// A acquires the builder lock + advances cursor to 30.
	ctxA, cancelA := context.WithTimeout(ctx, 5*time.Second)
	defer cancelA()
	fatalA := make(chan error, 1)
	lockA, err := store.AcquireBuilderLock(ctxA, poolA, fatalA, logger)
	if err != nil {
		t.Fatalf("A acquire lock: %v", err)
	}
	if err := store.WithSerializableTx(ctx, poolA, func(ctx context.Context, tx pgx.Tx) error {
		return cursorA.AdvanceTx(ctx, tx, 30)
	}); err != nil {
		lockA.Release()
		t.Fatalf("A advance: %v", err)
	}

	// A releases. After Release returns, the lock is free
	// server-side (pg_advisory_unlock has run).
	lockA.Release()

	// B acquires + reads cursor at A's persisted value.
	ctxB, cancelB := context.WithTimeout(ctx, 5*time.Second)
	defer cancelB()
	fatalB := make(chan error, 1)
	lockB, err := store.AcquireBuilderLock(ctxB, poolB, fatalB, logger)
	if err != nil {
		t.Fatalf("B acquire lock after A released: %v", err)
	}
	defer lockB.Release()

	got, err := cursorB.Read(ctx)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	if got != 30 {
		t.Fatalf("B read cursor = %d, want 30 (A's persisted advance) — "+
			"data loss across handoff would replay or skip entries", got)
	}

	// B advances further; the cursor moves forward monotonically.
	if err := store.WithSerializableTx(ctx, poolB, func(ctx context.Context, tx pgx.Tx) error {
		return cursorB.AdvanceTx(ctx, tx, 40)
	}); err != nil {
		t.Fatalf("B advance: %v", err)
	}

	finalGot, err := cursorB.Read(ctx)
	if err != nil {
		t.Fatalf("B re-read: %v", err)
	}
	if finalGot != 40 {
		t.Errorf("post-handoff cursor = %d, want 40", finalGot)
	}

	// Defensive: A's heartbeat goroutine may have surfaced a
	// "lock lost" error after Release closed the held conn.
	// That's expected (Release cancels the heartbeat ctx); we
	// just drain the channel so the test doesn't leave the
	// goroutine blocked on send.
	select {
	case e := <-fatalA:
		if e != nil && !errors.Is(e, context.Canceled) {
			t.Logf("fatalA (informational): %v", e)
		}
	default:
	}
}

// TestP4_ReplicaFailover_ConcurrentAcquireOnlyOneAdvances: N
// replicas race for the builder lock simultaneously. Only the
// winner reaches the cursor-advance code path (the others'
// acquire bounded-times-out). Pins single-writer semantics for
// cursor mutations under contention.
func TestP4_ReplicaFailover_ConcurrentAcquireOnlyOneAdvances(t *testing.T) {
	const N = 4

	poolBootstrap := requirePostgres(t)
	defer poolBootstrap.Close()
	if _, err := poolBootstrap.Exec(context.Background(),
		`UPDATE builder_cursor SET last_processed_sequence = 0 WHERE id = 1`); err != nil {
		t.Fatalf("reset cursor: %v", err)
	}

	logger := silentLogger()

	type result struct {
		idx       int
		acquired  bool
		advanceOK bool
		err       error
	}
	out := make(chan result, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			pool := freshPool(t)
			defer pool.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			fatal := make(chan error, 1)
			lock, err := store.AcquireBuilderLock(ctx, pool, fatal, logger)
			if err != nil {
				out <- result{idx: i, err: err}
				return
			}
			defer lock.Release()

			cursor := store.NewSequenceCursor(pool)
			advanceErr := store.WithSerializableTx(context.Background(), pool,
				func(ctx context.Context, tx pgx.Tx) error {
					return cursor.AdvanceTx(ctx, tx, uint64(100+i))
				})
			out <- result{idx: i, acquired: true, advanceOK: advanceErr == nil, err: advanceErr}
		}(i)
	}
	wg.Wait()
	close(out)

	winners := 0
	for r := range out {
		if r.acquired {
			winners++
			if !r.advanceOK {
				t.Errorf("goroutine %d acquired but advance failed: %v", r.idx, r.err)
			}
			continue
		}
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Errorf("goroutine %d: unexpected non-timeout error: %v", r.idx, r.err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d winners under contention; want exactly 1 "+
			"(single-writer cursor mutation invariant)", winners)
	}
}
