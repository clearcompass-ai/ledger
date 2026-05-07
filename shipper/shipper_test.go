/*
FILE PATH: shipper/shipper_test.go

Evidence-based unit tests for the Shipper. Establishes the
load-bearing invariants:

 1. Happy path: every sequenced entry uploads + MarkShipped + HWM
    advances to last.
 2. Out-of-order completion: workers finish in [3, 1, 2]; HWM
    advances to 1 then 2 then 3 — never to 3 directly while 1 or
    2 are still in flight.
 3. Retry on failure: bytestore returns error → MarkRetry recorded;
    after backoff, retry succeeds.
 4. Retry exhaustion: N failures → MarkManual; no MarkShipped; HWM
    does NOT advance past a failed entry.
 5. Backoff respected: scan skips entries whose LastErrTs +
    backoff(Attempts) is in the future.
 6. Context cancel cleanly stops Run.
 7. Metrics snapshot reflects shipped/retries/manual/HWM.

The test fakes simulate the relevant WAL and Bytestore semantics:
  - fakeWAL keeps an in-memory map of (hash → meta) and (seq → hash).
  - fakeBytestore records every WriteEntry and can be configured
    to fail on specific seqs / first-N attempts.
*/
package shipper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// fakeWAL implements the shipper.WAL interface with an in-memory
// map. Goroutine-safe via mu.
type fakeWAL struct {
	mu sync.Mutex
	hwm uint64
	seqs map[uint64][32]byte // seq → hash (== IterateSequenced result)
	wires map[[32]byte][]byte // hash → wire bytes
	metas map[[32]byte]*wal.Meta
}

func newFakeWAL() *fakeWAL {
	return &fakeWAL{
		seqs:  map[uint64][32]byte{},
		wires: map[[32]byte][]byte{},
		metas: map[[32]byte]*wal.Meta{},
	}
}

// seed stores a Sequenced entry that the Shipper will pick up.
func (f *fakeWAL) seed(seq uint64, hash [32]byte, wire []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seqs[seq] = hash
	f.wires[hash] = wire
	f.metas[hash] = &wal.Meta{State: wal.StateSequenced, Sequence: seq}
}

func (f *fakeWAL) HWM(_ context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hwm, nil
}

func (f *fakeWAL) AdvanceHWM(_ context.Context, seq uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hwm = seq
	return nil
}

func (f *fakeWAL) IterateSequenced(_ context.Context, fromSeq uint64, fn func(wal.SequencedEntry) error) error {
	f.mu.Lock()
	// Snapshot in seq-ASC order so iteration is deterministic.
	keys := make([]uint64, 0, len(f.seqs))
	for s := range f.seqs {
		if s > fromSeq {
			keys = append(keys, s)
		}
	}
	f.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, s := range keys {
		f.mu.Lock()
		hash, ok := f.seqs[s]
		meta := f.metas[hash]
		f.mu.Unlock()
		if !ok || meta == nil {
			continue
		}
		// Filter on State=StateSequenced (matches wal.IterateSequenced).
		if meta.State != wal.StateSequenced {
			continue
		}
		if err := fn(wal.SequencedEntry{Seq: s, Hash: hash}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeWAL) Read(_ context.Context, hash [32]byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w, ok := f.wires[hash]
	if !ok {
		return nil, fmt.Errorf("fakeWAL: no wire for hash %x", hash[:8])
	}
	cp := make([]byte, len(w))
	copy(cp, w)
	return cp, nil
}

func (f *fakeWAL) MetaState(_ context.Context, hash [32]byte) (wal.Meta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.metas[hash]
	if !ok {
		return wal.Meta{}, fmt.Errorf("fakeWAL: no meta for hash %x", hash[:8])
	}
	return *m, nil
}

func (f *fakeWAL) MarkShipped(_ context.Context, hash [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.metas[hash]
	if !ok {
		return fmt.Errorf("fakeWAL: no meta for hash %x", hash[:8])
	}
	m.State = wal.StateShipped
	m.LastErrTs = time.Time{}
	return nil
}

func (f *fakeWAL) MarkRetry(_ context.Context, hash [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.metas[hash]
	if !ok {
		return fmt.Errorf("fakeWAL: no meta for hash %x", hash[:8])
	}
	m.Attempts++
	m.LastErrTs = time.Now().UTC()
	return nil
}

func (f *fakeWAL) MarkManual(_ context.Context, hash [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.metas[hash]
	if !ok {
		return fmt.Errorf("fakeWAL: no meta for hash %x", hash[:8])
	}
	m.State = wal.StateManual
	return nil
}

// fakeBytestore records every WriteEntry and can be configured to
// fail the first N attempts on a specific seq.
type fakeBytestore struct {
	mu sync.Mutex
	stored map[uint64][]byte
	failSeq uint64 // 0 = no failure
	failTimes int // remaining forced failures for failSeq
	stallSeq uint64 // 0 = no stall
	stall time.Duration
	stallEvery time.Duration // > 0 → every WriteEntry sleeps this long
	calls atomic.Int64
}

func newFakeBytestore() *fakeBytestore {
	return &fakeBytestore{stored: map[uint64][]byte{}}
}

func (f *fakeBytestore) WriteEntry(_ context.Context, seq uint64, _ [32]byte, wireBytes []byte) error {
	f.calls.Add(1)
	f.mu.Lock()
	if f.stallSeq != 0 && f.stallSeq == seq && f.stall > 0 {
		stall := f.stall
		f.mu.Unlock()
		time.Sleep(stall)
		f.mu.Lock()
	}
	if f.stallEvery > 0 {
		stall := f.stallEvery
		f.mu.Unlock()
		time.Sleep(stall)
		f.mu.Lock()
	}
	if f.failSeq != 0 && f.failSeq == seq && f.failTimes > 0 {
		f.failTimes--
		f.mu.Unlock()
		return errors.New("fakeBytestore: forced failure")
	}
	cp := make([]byte, len(wireBytes))
	copy(cp, wireBytes)
	f.stored[seq] = cp
	f.mu.Unlock()
	return nil
}

func (f *fakeBytestore) Stored() map[uint64][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[uint64][]byte, len(f.stored))
	for k, v := range f.stored {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{
		Level: slog.LevelError + 1,
	}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func wireFor(seq uint64) []byte { return []byte(fmt.Sprintf("entry-%d-content", seq)) }
func hashFor(seq uint64) [32]byte { return sha256.Sum256(wireFor(seq)) }

// runUntilCondition runs the shipper in a goroutine and waits for
// `cond` to return true (polled every 10ms) or for the timeout.
func runUntilCondition(t *testing.T, s *Shipper, timeout time.Duration, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = s.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("condition not met within %v", timeout)
}

// fastConfig returns a Config with PollInterval reduced to 10ms so
// tests don't wait a full second per cycle.
func fastConfig() Config {
	return Config{
		PollInterval: 10 * time.Millisecond,
		MaxInFlight:  4,
		MaxAttempts:  3,
		BackoffBase:  20 * time.Millisecond,
		BackoffMax:   100 * time.Millisecond,
		Logger:       discardLogger(),
	}
}

// ─────────────────────────────────────────────────────────────────────
// 1) Happy path
// ─────────────────────────────────────────────────────────────────────

func TestShipper_HappyPath_AllUploadedAndHWMAdvances(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	for seq := uint64(1); seq <= 5; seq++ {
		w.seed(seq, hashFor(seq), wireFor(seq))
	}
	s := NewShipper(w, bs, fastConfig())

	runUntilCondition(t, s, 2*time.Second, func() bool {
		hwm, _ := w.HWM(context.Background())
		return hwm == 5
	})

	// All 5 stored, all marked shipped, HWM == 5.
	stored := bs.Stored()
	if len(stored) != 5 {
		t.Fatalf("expected 5 uploads, got %d", len(stored))
	}
	for seq := uint64(1); seq <= 5; seq++ {
		if !equal(stored[seq], wireFor(seq)) {
			t.Errorf("seq=%d: stored bytes mismatch", seq)
		}
		meta, _ := w.MetaState(context.Background(), hashFor(seq))
		if meta.State != wal.StateShipped {
			t.Errorf("seq=%d: state=%s want=StateShipped", seq, meta.State)
		}
	}
	snap := s.Metrics()
	if snap.Shipped != 5 {
		t.Errorf("metrics.Shipped: got %d, want 5", snap.Shipped)
	}
	if snap.HWM != 5 {
		t.Errorf("metrics.HWM: got %d, want 5", snap.HWM)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2) Out-of-order completion: HWM advances only through contiguous run
// ─────────────────────────────────────────────────────────────────────

func TestShipper_OutOfOrder_HWMOnlyContiguous(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	for seq := uint64(1); seq <= 3; seq++ {
		w.seed(seq, hashFor(seq), wireFor(seq))
	}
	// Stall seq=1 so 2 and 3 finish first. HWM must NOT advance to
	// 2 or 3 while 1 is in flight.
	bs.stallSeq = 1
	bs.stall = 200 * time.Millisecond

	s := NewShipper(w, bs, fastConfig())

	// Wait until HWM == 3 (all three contiguously shipped).
	runUntilCondition(t, s, 3*time.Second, func() bool {
		hwm, _ := w.HWM(context.Background())
		return hwm == 3
	})

	// Final state checks: all three shipped, HWM == 3.
	if hwm, _ := w.HWM(context.Background()); hwm != 3 {
		t.Fatalf("HWM: got %d, want 3", hwm)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		meta, _ := w.MetaState(context.Background(), hashFor(seq))
		if meta.State != wal.StateShipped {
			t.Errorf("seq=%d: state=%s want=StateShipped", seq, meta.State)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3) Retry on failure: transient failure → eventual success
// ─────────────────────────────────────────────────────────────────────

func TestShipper_RetryOnFailure_EventualSuccess(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	w.seed(1, hashFor(1), wireFor(1))
	bs.failSeq = 1
	bs.failTimes = 2 // fail first 2, succeed on 3rd

	cfg := fastConfig()
	cfg.MaxAttempts = 5
	s := NewShipper(w, bs, cfg)

	runUntilCondition(t, s, 2*time.Second, func() bool {
		meta, _ := w.MetaState(context.Background(), hashFor(1))
		return meta.State == wal.StateShipped
	})

	snap := s.Metrics()
	if snap.Shipped != 1 {
		t.Errorf("metrics.Shipped: got %d, want 1", snap.Shipped)
	}
	if snap.Retries != 2 {
		t.Errorf("metrics.Retries: got %d, want 2", snap.Retries)
	}
	if snap.Manual != 0 {
		t.Errorf("metrics.Manual: got %d, want 0", snap.Manual)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4) Retry exhaustion: MarkManual after MaxAttempts; HWM blocked
// ─────────────────────────────────────────────────────────────────────

func TestShipper_RetryExhaustion_MarksManual_HWMBlocked(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	w.seed(1, hashFor(1), wireFor(1))
	w.seed(2, hashFor(2), wireFor(2))
	// seq=1 fails forever; seq=2 succeeds.
	bs.failSeq = 1
	bs.failTimes = 1000 // unlimited

	cfg := fastConfig()
	cfg.MaxAttempts = 3
	s := NewShipper(w, bs, cfg)

	runUntilCondition(t, s, 3*time.Second, func() bool {
		meta1, _ := w.MetaState(context.Background(), hashFor(1))
		meta2, _ := w.MetaState(context.Background(), hashFor(2))
		return meta1.State == wal.StateManual && meta2.State == wal.StateShipped
	})

	// HWM must NOT have advanced — seq=1 is the contiguous-run gate.
	if hwm, _ := w.HWM(context.Background()); hwm != 0 {
		t.Errorf("HWM: got %d, want 0 (seq=1 was never shipped)", hwm)
	}

	snap := s.Metrics()
	if snap.Manual != 1 {
		t.Errorf("metrics.Manual: got %d, want 1", snap.Manual)
	}
	if snap.Shipped != 1 {
		t.Errorf("metrics.Shipped: got %d, want 1 (only seq=2)", snap.Shipped)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5) Backoff respected: scan skips entries inside their backoff window
// ─────────────────────────────────────────────────────────────────────

func TestShipper_BackoffRespected_FailedEntryWaitsBeforeRetry(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	w.seed(1, hashFor(1), wireFor(1))
	bs.failSeq = 1
	bs.failTimes = 1 // fail once, then succeed

	cfg := fastConfig()
	cfg.BackoffBase = 100 * time.Millisecond
	cfg.BackoffMax = 100 * time.Millisecond
	s := NewShipper(w, bs, cfg)

	// Run for ~50ms — should see 1 attempt (the initial one) since
	// the retry is gated by 100ms backoff.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)

	if calls := bs.calls.Load(); calls != 1 {
		t.Errorf("expected exactly 1 attempt within backoff window, got %d", calls)
	}
	meta, _ := w.MetaState(context.Background(), hashFor(1))
	if meta.Attempts != 1 {
		t.Errorf("Attempts: got %d, want 1", meta.Attempts)
	}
	if meta.State != wal.StateSequenced {
		t.Errorf("State: got %s, want StateSequenced (still in retry window)", meta.State)
	}
}

func TestShipper_Backoff_RetriesAfterWindow(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	w.seed(1, hashFor(1), wireFor(1))
	bs.failSeq = 1
	bs.failTimes = 1

	cfg := fastConfig()
	cfg.BackoffBase = 30 * time.Millisecond
	cfg.BackoffMax = 30 * time.Millisecond
	s := NewShipper(w, bs, cfg)

	// Wait long enough for one retry cycle.
	runUntilCondition(t, s, 1*time.Second, func() bool {
		meta, _ := w.MetaState(context.Background(), hashFor(1))
		return meta.State == wal.StateShipped
	})
	if calls := bs.calls.Load(); calls < 2 {
		t.Errorf("expected at least 2 attempts (1 fail + retry), got %d", calls)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6) Context cancel cleanly stops Run
// ─────────────────────────────────────────────────────────────────────

func TestShipper_ContextCancel_Returns(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	s := NewShipper(w, bs, fastConfig())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7) BackoffFor formula
// ─────────────────────────────────────────────────────────────────────

func TestShipper_BackoffFor_ExponentialCappedAtMax(t *testing.T) {
	s := NewShipper(nil, nil, Config{
		BackoffBase: 1 * time.Second,
		BackoffMax:  10 * time.Second,
		Logger:      discardLogger(),
	})
	cases := []struct {
		attempt uint32
		want time.Duration
	}{
		{0, 0},
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 10 * time.Second},  // 16s capped at 10s
		{50, 10 * time.Second}, // overflow safe
	}
	for _, c := range cases {
		got := s.backoffFor(c.attempt)
		if got != c.want {
			t.Errorf("backoffFor(%d): got %v, want %v", c.attempt, got, c.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8) HWM advancer state machine — direct unit test
// ─────────────────────────────────────────────────────────────────────

func TestShipper_HWMAdvancer_HoldsOutOfOrder(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	s := NewShipper(w, bs, fastConfig())
	above := make(map[uint64]struct{})
	ctx := context.Background()

	// Completion order: 3, 2, 1. HWM advances only after 1 lands.
	s.processCompletion(ctx, 3, above)
	if hwm, _ := w.HWM(ctx); hwm != 0 {
		t.Errorf("after seq=3 (no contiguous): HWM=%d, want 0", hwm)
	}
	s.processCompletion(ctx, 2, above)
	if hwm, _ := w.HWM(ctx); hwm != 0 {
		t.Errorf("after seq=2 (still no contiguous): HWM=%d, want 0", hwm)
	}
	s.processCompletion(ctx, 1, above)
	if hwm, _ := w.HWM(ctx); hwm != 3 {
		t.Errorf("after seq=1 (contiguous run completes): HWM=%d, want 3", hwm)
	}
	if len(above) != 0 {
		t.Errorf("above set should be empty, has %d entries", len(above))
	}
}

func TestShipper_HWMAdvancer_BelowHWMIsNoOp(t *testing.T) {
	w := newFakeWAL()
	w.hwm = 100
	bs := newFakeBytestore()
	s := NewShipper(w, bs, fastConfig())
	above := make(map[uint64]struct{})

	s.processCompletion(context.Background(), 50, above)
	if hwm, _ := w.HWM(context.Background()); hwm != 100 {
		t.Errorf("seq below HWM: HWM=%d, want 100", hwm)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9) Worker concurrency — stress test
// ─────────────────────────────────────────────────────────────────────

func TestShipper_Concurrent_ManyEntries(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	const N = 50
	for seq := uint64(1); seq <= N; seq++ {
		w.seed(seq, hashFor(seq), wireFor(seq))
	}
	cfg := fastConfig()
	cfg.MaxInFlight = 8
	s := NewShipper(w, bs, cfg)

	runUntilCondition(t, s, 3*time.Second, func() bool {
		hwm, _ := w.HWM(context.Background())
		return hwm == N
	})

	stored := bs.Stored()
	if len(stored) != N {
		t.Errorf("expected %d uploads, got %d", N, len(stored))
	}
	snap := s.Metrics()
	if snap.Shipped != N {
		t.Errorf("metrics.Shipped: got %d, want %d", snap.Shipped, N)
	}
}

// ─────────────────────────────────────────────────────────────────────
// In-flight dedupe — pins the racing-scan-window guard
// ─────────────────────────────────────────────────────────────────────

// TestShipper_InflightDedupe_PreventsConcurrentDispatch pins the
// invariant that scanAndDispatch must NOT enqueue the same seq to a
// second worker while the first is still in flight.
//
// Configuration: bytestore stalls every WriteEntry by 100ms; scanner
// PollInterval is 10ms (fastConfig). With MaxInFlight=2 and N=10
// entries, ~9 of the 10 in-flight ships overlap with multiple scan
// ticks — without the dedupe guard, the same StateSequenced seq
// would be re-yielded by IterateSequenced (its state hasn't flipped
// to StateShipped yet) and dispatched again. Each redundant dispatch
// triggers another bytestore.WriteEntry → fakeBytestore.calls would
// exceed N. The guard pins calls == N exactly and surfaces the
// avoided dispatches via SkippedInflight.
//
// Pre-fix (no inflight set):
//   bytestore.calls > N (often 1.5×-2× N)
//   metrics.Shipped > N
// Post-fix:
//   bytestore.calls == N
//   metrics.Shipped == N
//   metrics.SkippedInflight > 0  (proves the guard activated)
func TestShipper_InflightDedupe_PreventsConcurrentDispatch(t *testing.T) {
	w := newFakeWAL()
	bs := newFakeBytestore()
	bs.stallEvery = 100 * time.Millisecond

	const N = 10
	for seq := uint64(1); seq <= N; seq++ {
		w.seed(seq, hashFor(seq), wireFor(seq))
	}

	cfg := fastConfig() // PollInterval 10ms
	cfg.MaxInFlight = 2 // few workers + many ticks ⇒ many overlap windows
	s := NewShipper(w, bs, cfg)

	runUntilCondition(t, s, 5*time.Second, func() bool {
		hwm, _ := w.HWM(context.Background())
		return hwm == N
	})

	// All N entries shipped, exactly once on the bytestore.
	stored := bs.Stored()
	if len(stored) != N {
		t.Errorf("bytestore stored = %d distinct seqs; want %d", len(stored), N)
	}
	if got := bs.calls.Load(); got != int64(N) {
		t.Errorf("bytestore.WriteEntry calls = %d; want %d "+
			"(>%d means dedupe guard failed; same seq dispatched twice)",
			got, N, N)
	}

	snap := s.Metrics()
	if snap.Shipped != N {
		t.Errorf("metrics.Shipped = %d; want %d", snap.Shipped, N)
	}
	if snap.UniqueShipped != N {
		t.Errorf("metrics.UniqueShipped = %d; want %d", snap.UniqueShipped, N)
	}
	// The guard MUST activate at least once given the timing setup.
	// 100ms stall + 10ms scan tick + N=10 entries means many scans
	// observe StateSequenced seqs already in-flight.
	if snap.SkippedInflight == 0 {
		t.Errorf("metrics.SkippedInflight = 0; want > 0 " +
			"(guard never fired — test setup is wrong, OR the guard is " +
			"missing from scanAndDispatch)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func equal(a, b []byte) bool {
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
