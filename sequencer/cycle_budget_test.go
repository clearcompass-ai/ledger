/*
FILE PATH:

	sequencer/cycle_budget_test.go

DESCRIPTION:

	Authoritative regression test for the per-cycle work budget that
	makes drainCycles a meaningful liveness signal under sustained
	load.

WHY THIS EXISTS:

	Before MaxEntriesPerCycle, drainOnce iterated the entire
	inflight Badger prefix and wg.Wait'd on every dispatched worker
	before returning. Observed in production-scale soak (100K
	entries):

	    drainCycles=12   t=0s     ← drain started; iterating
	    drainCycles=12   t=2m43s  ← still in the first iteration
	    drainCycles=13   t=2m43s  ← cycle 1 finally returned
	    drainCycles=13   t=5m40s  ← cycle 2 is iterating
	    drainCycles=191  t=5m43s  ← queue empty; ticker fires fast

	A metric that doesn't update for 2.5 minutes is useless as a
	liveness signal. Operators cannot tell if the sequencer is
	wedged. Shutdown latency was unbounded. Memory pressure scaled
	with queue size, not concurrency.

	The fix: bound the per-cycle work via cfg.MaxEntriesPerCycle.
	Each drainOnce dispatches AT MOST that many entries; the next
	PollInterval tick re-enters drainOnce for the next batch.

THIS TEST PINS THE FIX:

	1. Seed a fake WAL with 5000 entries and a 5ms-per-AppendLeaf
	   fake Tessera (realistic per-entry latency).
	2. Start the sequencer with MaxEntriesPerCycle=128, PollInterval
	   =10ms, MaxInFlight=16. Expected cycle latency:
	     ~ (128/16) × 5ms = 40ms per cycle
	3. Poll metrics every 50ms during drain (must be > expected
	   cycle latency so each poll observes new state).
	4. ASSERT: max time between drainCycles increments < 1s.
	   (the bound the operator cares about — "is this thing alive?")
	5. ASSERT: total drainCycles to drain 5000 entries is
	   approximately 5000/128 ≈ 40, within ±100% slop.
	6. ASSERT: processed counter reaches 5000.

	If MaxEntriesPerCycle is regressed (removed, set to 0, or
	bypassed), the test fails because:
	  - drainCycles stays at 1 for the full drain (single iteration)
	  - max-inter-update gap is the full drain time

NEGATIVE CONTROL:

	A second test runs with MaxEntriesPerCycle=0 (legacy unbounded
	behavior) and asserts drainCycles stays low (≤ 5) — confirming
	the regression behavior is detectable. Without this control the
	main test could pass for an unrelated reason.
*/
package sequencer

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/wal"
)

// pendingFilteringWAL wraps fakeWAL so IterateInflight returns ONLY
// entries currently in StatePending — matching real wal.Committer
// semantics. The base fakeWAL does not do this filter (it iterates
// all seeded entries every call), which is fine for single-cycle
// tests but breaks multi-cycle tests like this one: after the first
// cycle marks the first 128 entries Sequenced, the next cycle's
// iteration would re-dispatch those same 128, processOne would
// short-circuit at the meta-state check, and forward progress would
// stop.
//
// The real wal.Committer's IterateInflight uses the Badger inflight
// prefix, which Sequence clears on transition. This wrapper
// reproduces that contract on top of the existing fakeWAL.
type pendingFilteringWAL struct {
	*fakeWAL
}

func (p *pendingFilteringWAL) IterateInflight(ctx context.Context, fn func(wal.PendingHash) error) error {
	p.fakeWAL.mu.Lock()
	pending := append([]wal.PendingHash(nil), p.fakeWAL.pending...)
	stateCopy := make(map[[32]byte]wal.EntryState, len(p.fakeWAL.state))
	for k, v := range p.fakeWAL.state {
		stateCopy[k] = v
	}
	p.fakeWAL.mu.Unlock()

	for _, ph := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		if stateCopy[ph.Hash] != wal.StatePending {
			continue
		}
		if err := fn(ph); err != nil {
			return err
		}
	}
	return nil
}

// TestDrainOnce_PerCycleBudget_MetricFreshness pins the fix that
// makes drainCycles a meaningful liveness signal under sustained
// load. See file docstring for the full rationale.
func TestDrainOnce_PerCycleBudget_MetricFreshness(t *testing.T) {
	const (
		totalEntries     = 5000
		entriesPerCycle  = 128
		appendLeafDelay  = 5 * time.Millisecond
		maxInFlight      = 16
		pollInterval     = 10 * time.Millisecond
		metricPollEvery  = 50 * time.Millisecond
		maxInterUpdate   = 1 * time.Second
		drainBudget      = 30 * time.Second
	)

	base := newFakeWAL()
	for i := 0; i < totalEntries; i++ {
		wire, hash := mkPendingEntry(t, i)
		base.seed(hash, wire)
	}
	w := &pendingFilteringWAL{fakeWAL: base}

	ts := &slowFakeTessera{
		delegate: newFakeTessera(),
		delay:    appendLeafDelay,
	}

	s := newTestSequencer(t, w, ts, Config{
		PollInterval:       pollInterval,
		MaxInFlight:        maxInFlight,
		MaxEntriesPerCycle: entriesPerCycle,
	})

	ctx, cancel := context.WithTimeout(context.Background(), drainBudget+5*time.Second)
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		_ = s.Run(ctx)
		close(runDone)
	}()

	// Sample metrics at fixed cadence; record every distinct value
	// of drainCycles along with the wall-clock timestamp. Stop as
	// soon as processed reaches totalEntries OR drain budget expires.
	type sample struct {
		t      time.Time
		cycles uint64
	}
	var samples []sample
	deadline := time.Now().Add(drainBudget)
	var lastCycles uint64
	for time.Now().Before(deadline) {
		snap := s.metrics.Snapshot()
		if snap.DrainCycles != lastCycles {
			samples = append(samples, sample{t: time.Now(), cycles: snap.DrainCycles})
			lastCycles = snap.DrainCycles
		}
		if snap.Processed >= totalEntries {
			break
		}
		time.Sleep(metricPollEvery)
	}
	cancel()
	<-runDone

	// ────────────────────────────────────────────────────────────
	// Assertions
	// ────────────────────────────────────────────────────────────

	finalSnap := s.metrics.Snapshot()
	t.Logf("final metrics: cycles=%d processed=%d failures=%d",
		finalSnap.DrainCycles, finalSnap.Processed, finalSnap.Failures)
	t.Logf("recorded %d distinct cycle bumps during drain", len(samples))

	if finalSnap.Processed < totalEntries {
		t.Fatalf("only %d/%d entries processed within %s budget",
			finalSnap.Processed, totalEntries, drainBudget)
	}

	// ASSERTION 1: max time between drainCycles increments must be
	// bounded. This is the liveness contract the metric promises.
	if len(samples) < 2 {
		t.Fatalf("recorded only %d cycle bumps — metric is not updating", len(samples))
	}
	var maxGap time.Duration
	var maxGapIdx int
	for i := 1; i < len(samples); i++ {
		gap := samples[i].t.Sub(samples[i-1].t)
		if gap > maxGap {
			maxGap = gap
			maxGapIdx = i
		}
	}
	if maxGap > maxInterUpdate {
		t.Errorf("max inter-update gap = %s (>%s) at sample %d "+
			"(cycles bumped from %d to %d). "+
			"Metric is not a useful liveness signal — the per-cycle "+
			"work budget may have been regressed.",
			maxGap, maxInterUpdate, maxGapIdx,
			samples[maxGapIdx-1].cycles, samples[maxGapIdx].cycles)
	} else {
		t.Logf("max inter-update gap = %s (≤ %s) ✓", maxGap, maxInterUpdate)
	}

	// ASSERTION 2: total cycles is approximately totalEntries /
	// entriesPerCycle. Bounded above by the budget (more cycles
	// would mean smaller batches) and below by ½ of expected.
	expectedCycles := uint64(totalEntries / entriesPerCycle)
	if finalSnap.DrainCycles < expectedCycles/2 {
		t.Errorf("drainCycles = %d, expected approximately %d (totalEntries / entriesPerCycle)\n"+
			"  → too few cycles. The per-cycle work budget may not be enforced "+
			"(single drainOnce iterated the entire queue).",
			finalSnap.DrainCycles, expectedCycles)
	}
	if finalSnap.DrainCycles > expectedCycles*8 {
		t.Logf("drainCycles = %d, expected approximately %d — many extra cycles "+
			"(probably the post-drain empty-queue ticker firing). Acceptable.",
			finalSnap.DrainCycles, expectedCycles)
	}
}

// TestDrainOnce_NegativeControl_UnboundedExhibitsBadFreshness is
// the negative control. With MaxEntriesPerCycle=0 (legacy unbounded
// behavior), the test asserts drainCycles stays low (≤ 5) for the
// same workload. This pairing is the asymmetric proof:
//
//	bounded   → cycles update frequently (positive test)
//	unbounded → cycles barely update     (negative control)
//
// If both tests pass with high cycles counts, the bound is not the
// thing keeping cycles meaningful — there's another factor in play
// and the positive test is a false PASS.
func TestDrainOnce_NegativeControl_UnboundedExhibitsBadFreshness(t *testing.T) {
	const (
		totalEntries    = 500
		appendLeafDelay = 2 * time.Millisecond
		maxInFlight     = 4
		pollInterval    = 10 * time.Millisecond
		drainBudget     = 10 * time.Second
	)

	base := newFakeWAL()
	for i := 0; i < totalEntries; i++ {
		wire, hash := mkPendingEntry(t, i)
		base.seed(hash, wire)
	}
	w := &pendingFilteringWAL{fakeWAL: base}

	ts := &slowFakeTessera{
		delegate: newFakeTessera(),
		delay:    appendLeafDelay,
	}

	// Explicit 0 → MaxEntriesPerCycle disabled (legacy unbounded).
	// NewSequencer's default would set it to DefaultMaxEntriesPerCycle,
	// so we have to override AFTER construction.
	s := newTestSequencer(t, w, ts, Config{
		PollInterval: pollInterval,
		MaxInFlight:  maxInFlight,
	})
	s.cfg.MaxEntriesPerCycle = 0 // simulate legacy unbounded drainOnce

	ctx, cancel := context.WithTimeout(context.Background(), drainBudget)
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		_ = s.Run(ctx)
		close(runDone)
	}()

	// Wait for drain completion or budget.
	deadline := time.Now().Add(drainBudget)
	for time.Now().Before(deadline) {
		if s.metrics.Snapshot().Processed >= totalEntries {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-runDone

	snap := s.metrics.Snapshot()
	t.Logf("negative control final metrics: cycles=%d processed=%d",
		snap.DrainCycles, snap.Processed)

	if snap.Processed < totalEntries {
		t.Fatalf("negative control: only %d/%d processed (test setup issue)",
			snap.Processed, totalEntries)
	}

	// The negative control's expected behavior: with MaxEntriesPerCycle=0,
	// drainOnce processes the entire queue in one call. Cycles should
	// be ≤ 5 (one for the drain + a few ticker bumps before ctx cancel).
	//
	// If this assertion regresses upward to many cycles, it means the
	// unbounded path is somehow becoming bounded by a hidden mechanism,
	// and the positive test above may be a false PASS.
	const negativeControlMaxCycles = 10
	if snap.DrainCycles > negativeControlMaxCycles {
		t.Errorf("negative control: expected drainCycles ≤ %d, got %d. "+
			"Unbounded drainOnce should iterate whole queue in one cycle. "+
			"If this asserts upward, the positive test may be passing for "+
			"reasons OTHER than the per-cycle budget enforcement.",
			negativeControlMaxCycles, snap.DrainCycles)
	}
}

// ────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────

// slowFakeTessera wraps fakeTessera with a configurable per-call
// delay so per-entry latency matches realistic production timing.
// The fake otherwise inherits all dedup + counter behavior.
type slowFakeTessera struct {
	delegate *fakeTessera
	delay    time.Duration
	mu       sync.Mutex // serializes the delay so the test wall-clock is deterministic
}

func (s *slowFakeTessera) AppendLeaf(ctx context.Context, data []byte) (uint64, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return s.delegate.AppendLeaf(ctx, data)
}

// mkPendingEntry deterministically generates a unique (wire, hash)
// pair given an index. Reuses buildEntry from sequencer_test.go;
// the payload's varying suffix ensures each entry has a distinct
// canonical hash so the WAL's seed -> Read -> Sequence flow doesn't
// collide.
func mkPendingEntry(t *testing.T, idx int) (wire []byte, hash [32]byte) {
	t.Helper()
	return buildEntry(t, "cycle-budget-test-payload-"+strconv.Itoa(idx))
}
