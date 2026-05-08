//go:build p4
// +build p4

// FILE PATH: tests/p4/advisory_lock_test.go
//
// P4.2 — Builder-lock split-brain.
//
// Pins the contract that store.AcquireBuilderLock enforces SINGLE-
// WRITER semantics across two ledger processes pointed at the same
// Postgres. The lock uses pg_advisory_lock at SESSION scope; each
// pgxpool.Pool resolves to a distinct backend session, so two pools
// against one DSN model the cross-binary case faithfully.
//
// Each test case is one row of the matrix and asserts a single
// invariant. Failures point at the exact wire the regression cut.
//
//  1. Concurrent acquire — second acquire times out within
//     DefaultBuilderLockAcquireTimeout (default 30s, overridden in
//     this test to keep CI fast).
//  2. Release allows acquisition — first releases; second's NEXT
//     acquire succeeds within a small grace window.
//  3. LockID stability — pin BuilderLockID == 0x4F5254484F4C4F47
//     ("ATTESTA" big-endian) so a refactor that silently rotates
//     the magic number doesn't split-brain a fleet that still uses
//     the old value.
//  4. Default timeout invariant — pin the 30s default so a refactor
//     can't silently widen or zero out the rolling-update SLA.
//  5. Handoff sequence — A acquires, B blocks; A releases; B
//     completes within sub-second of A.Release.
//  6. Concurrent contention — N pools race; exactly 1 wins.
//
// The 30s default acquire timeout would dominate test runtime, so
// each test drives its own bounded context (typically 2–5s).
package p4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/store"
)

// TestP4_AdvisoryLock_LockIDInvariant pins the magic number. A
// refactor that "renames" or recomputes the lock ID silently
// produces a fleet split-brain: old binaries hold lock 0xATTESTA,
// new binaries acquire lock 0xWHATEVER, both think they're the
// sole writer.
func TestP4_AdvisoryLock_LockIDInvariant(t *testing.T) {
	const want = int64(0x4F5254484F4C4F47) // "ATTESTA" big-endian
	if store.BuilderLockID != want {
		t.Fatalf("BuilderLockID drift: got %#x, want %#x — a "+
			"changed lock ID would silently split-brain rolling "+
			"deployments mixing old and new builds",
			store.BuilderLockID, want)
	}
}

// TestP4_AdvisoryLock_DefaultTimeoutInvariant pins the production
// acquire-timeout default. If a refactor cuts this to 0 the
// rolling-update misconfig surface disappears (new pod hangs
// forever); if a refactor extends it, the new pod's "fail fast"
// fitness for k8s readiness probes degrades.
func TestP4_AdvisoryLock_DefaultTimeoutInvariant(t *testing.T) {
	if store.DefaultBuilderLockAcquireTimeout != 30*time.Second {
		t.Fatalf("DefaultBuilderLockAcquireTimeout drift: got %v, "+
			"want 30s — production rolling-update SLA depends on "+
			"this value", store.DefaultBuilderLockAcquireTimeout)
	}
}

// TestP4_AdvisoryLock_SecondAcquireBlocks: A holds the lock; B's
// acquire blocks until A releases or B's ctx fires. We assert the
// blocking property by giving B a 2-second deadline and confirming
// it returns the deadline error before A releases.
func TestP4_AdvisoryLock_SecondAcquireBlocks(t *testing.T) {
	poolA := requirePostgres(t)
	defer poolA.Close()
	poolB := freshPool(t)
	defer poolB.Close()

	logger := silentLogger()

	// Pool A acquires.
	ctxA, cancelA := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelA()
	fatalA := make(chan error, 1)
	lockA, err := store.AcquireBuilderLock(ctxA, poolA, fatalA, logger)
	if err != nil {
		t.Fatalf("pool A acquire: %v", err)
	}
	defer lockA.Release()

	// Pool B's acquire MUST NOT succeed while A holds the lock.
	// Bound the test to 2 seconds (well under the production 30s
	// default) — if pg_advisory_lock unblocks within 2s, A is
	// no longer the sole writer and the contract is broken.
	ctxB, cancelB := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelB()
	fatalB := make(chan error, 1)
	t0 := time.Now()
	lockB, err := store.AcquireBuilderLock(ctxB, poolB, fatalB, logger)
	elapsed := time.Since(t0)
	if err == nil {
		// Defensive: release if we accidentally acquired so the
		// test cleanup is sane.
		lockB.Release()
		t.Fatalf("pool B acquired the lock in %v while pool A holds it — "+
			"single-writer invariant violated", elapsed)
	}
	// elapsed must be ≥ ctxB's deadline (within tolerance for
	// scheduler jitter); shorter would mean pg_advisory_lock returned
	// without blocking, which would also violate the contract.
	if elapsed < 1500*time.Millisecond {
		t.Errorf("pool B's failed acquire returned in %v; expected to "+
			"block until ctxB deadline (~2s)", elapsed)
	}
	if !isDeadlineError(err) {
		t.Errorf("pool B's acquire error: got %v; want a deadline-"+
			"derived error (context.DeadlineExceeded chain)", err)
	}
}

// TestP4_AdvisoryLock_ReleaseAllowsAcquisition: A acquires, then
// releases; B's NEXT acquire succeeds within a small grace window.
// Pins the "lock follows the writer" property required by graceful
// rolling updates.
func TestP4_AdvisoryLock_ReleaseAllowsAcquisition(t *testing.T) {
	poolA := requirePostgres(t)
	defer poolA.Close()
	poolB := freshPool(t)
	defer poolB.Close()

	logger := silentLogger()

	// A acquires + releases. After Release returns, the server-
	// side lock is gone (pg_advisory_unlock has run).
	ctxA, cancelA := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelA()
	fatalA := make(chan error, 1)
	lockA, err := store.AcquireBuilderLock(ctxA, poolA, fatalA, logger)
	if err != nil {
		t.Fatalf("pool A acquire: %v", err)
	}
	lockA.Release()

	// B's acquire should return quickly. Generous 5s budget — the
	// actual call should be sub-100ms but CI environments
	// occasionally bursty.
	ctxB, cancelB := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelB()
	fatalB := make(chan error, 1)
	t0 := time.Now()
	lockB, err := store.AcquireBuilderLock(ctxB, poolB, fatalB, logger)
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("pool B acquire after A released: %v (elapsed=%v)",
			err, elapsed)
	}
	defer lockB.Release()
	if elapsed > time.Second {
		t.Errorf("pool B acquire took %v after A released; expected sub-second", elapsed)
	}
}

// TestP4_AdvisoryLock_HandoffSequence: A acquires while B is
// waiting (B's ctx is generous). When A releases, B's pending
// acquire MUST complete promptly — pg_advisory_lock's queueing
// semantics deliver the lock to the next waiter as soon as the
// holder releases.
func TestP4_AdvisoryLock_HandoffSequence(t *testing.T) {
	poolA := requirePostgres(t)
	defer poolA.Close()
	poolB := freshPool(t)
	defer poolB.Close()

	logger := silentLogger()

	ctxA, cancelA := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelA()
	fatalA := make(chan error, 1)
	lockA, err := store.AcquireBuilderLock(ctxA, poolA, fatalA, logger)
	if err != nil {
		t.Fatalf("pool A acquire: %v", err)
	}

	// Start B's acquire in a goroutine with a generous deadline; it
	// will block until A releases. Capture the latency and (on
	// success) the lock for cleanup.
	ctxB, cancelB := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelB()
	fatalB := make(chan error, 1)
	type bResult struct {
		lock    *store.BuilderLock
		err     error
		latency time.Duration
	}
	resultCh := make(chan bResult, 1)
	go func() {
		t0 := time.Now()
		l, e := store.AcquireBuilderLock(ctxB, poolB, fatalB, logger)
		resultCh <- bResult{lock: l, err: e, latency: time.Since(t0)}
	}()

	// Hold the lock for 500ms, then release. B should acquire
	// shortly after.
	time.Sleep(500 * time.Millisecond)
	releaseAt := time.Now()
	lockA.Release()

	// Wait for B's acquire to complete.
	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("pool B acquire after A released: %v", r.err)
		}
		defer r.lock.Release()
		// Effective handoff latency is from A.Release() to B
		// acquired. Should be sub-second.
		handoff := time.Since(releaseAt)
		if handoff > time.Second {
			t.Errorf("handoff latency %v from A.Release() to B acquired; "+
				"expected sub-second", handoff)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("pool B acquire didn't complete within 8s of A.Release")
	}
}

// TestP4_AdvisoryLock_ConcurrentAcquireOneWinsOneLoses spawns N
// goroutines that all try to acquire simultaneously. Exactly one
// MUST succeed; the rest MUST fail with deadline errors. Pins the
// mutual-exclusion property under contention.
func TestP4_AdvisoryLock_ConcurrentAcquireOneWinsOneLoses(t *testing.T) {
	const N = 4

	pools := make([]*pgxpool.Pool, N)
	for i := range pools {
		pools[i] = freshPool(t)
	}
	defer func() {
		for _, p := range pools {
			p.Close()
		}
	}()

	logger := silentLogger()

	type result struct {
		idx  int
		lock *store.BuilderLock
		err  error
	}
	out := make(chan result, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := range pools {
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			fatal := make(chan error, 1)
			l, e := store.AcquireBuilderLock(ctx, pools[i], fatal, logger)
			out <- result{idx: i, lock: l, err: e}
		}(i)
	}
	wg.Wait()
	close(out)

	winners := 0
	var heldLocks []*store.BuilderLock
	for r := range out {
		if r.err == nil {
			winners++
			// Collect winners' locks; release at function exit (a
			// defer inside the loop body would never run because
			// staticcheck SA9001 catches the no-fire-until-channel-
			// closed pattern).
			heldLocks = append(heldLocks, r.lock)
			continue
		}
		if !isDeadlineError(r.err) {
			t.Errorf("goroutine %d: unexpected error type: %v", r.idx, r.err)
		}
	}
	defer func() {
		for _, l := range heldLocks {
			l.Release()
		}
	}()
	if winners != 1 {
		t.Fatalf("got %d winners under contention; want exactly 1 "+
			"(single-writer invariant)", winners)
	}
}

// isDeadlineError returns true if err is or wraps
// context.DeadlineExceeded. AcquireBuilderLock wraps the pgx
// error when the bounded context fires.
func isDeadlineError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}
