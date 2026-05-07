//go:build chaos
// +build chaos

/*
FILE PATH:
    tests/chaos/inject_test.go

DESCRIPTION:
    J4 — Smoke tests for the inject package. The injectors are
    the load-bearing primitives every other chaos test consumes;
    if they don't fault when expected, the rest of the suite
    is a false-positive vacuum.
*/
package chaos

import (
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/tests/chaos/inject"
)

// TestInject_LatencyAlwaysFires pins inject.Latency with
// inject.Always(): every Apply blocks for the configured delay.
func TestInject_LatencyAlwaysFires(t *testing.T) {
	lat := inject.NewLatency(20*time.Millisecond, inject.Always())
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		lat.Apply()
	}
	elapsed := time.Since(t0)
	if elapsed < 100*time.Millisecond {
		t.Errorf("5 × 20ms latency = %v; want ≥100ms", elapsed)
	}
	if lat.Faults() != 5 {
		t.Errorf("faults = %d; want 5", lat.Faults())
	}
}

// TestInject_LatencyNeverFires pins inject.Latency with
// inject.Never(): no calls block.
func TestInject_LatencyNeverFires(t *testing.T) {
	lat := inject.NewLatency(20*time.Millisecond, inject.Never())
	t0 := time.Now()
	for i := 0; i < 100; i++ {
		lat.Apply()
	}
	elapsed := time.Since(t0)
	if elapsed > 50*time.Millisecond {
		t.Errorf("100 calls with Never trigger took %v; should be near-instant", elapsed)
	}
	if lat.Faults() != 0 {
		t.Errorf("faults = %d; want 0 with Never trigger", lat.Faults())
	}
	if lat.Calls() != 100 {
		t.Errorf("calls = %d; want 100", lat.Calls())
	}
}

// TestInject_AfterCallsTrigger pins AfterCalls(K): first K-1
// pass through; from K onwards every call fires.
func TestInject_AfterCallsTrigger(t *testing.T) {
	errf := inject.NewErrorf(inject.ErrInjectedFailure, inject.AfterCalls(3))
	results := make([]error, 0, 5)
	for i := 0; i < 5; i++ {
		results = append(results, errf.Apply())
	}
	// Calls 1, 2 should be nil; calls 3, 4, 5 should fire.
	for i, r := range results {
		shouldFire := i+1 >= 3
		fired := errors.Is(r, inject.ErrInjectedFailure)
		if fired != shouldFire {
			t.Errorf("call %d: fired=%v want=%v", i+1, fired, shouldFire)
		}
	}
}

// TestInject_FirstNCallsTrigger pins FirstNCalls(N): first N
// calls fire; subsequent calls are clean.
func TestInject_FirstNCallsTrigger(t *testing.T) {
	errf := inject.NewErrorf(inject.ErrInjectedTimeout, inject.FirstNCalls(2))
	for i := 0; i < 5; i++ {
		err := errf.Apply()
		shouldFire := i+1 <= 2
		fired := errors.Is(err, inject.ErrInjectedTimeout)
		if fired != shouldFire {
			t.Errorf("call %d: fired=%v want=%v", i+1, fired, shouldFire)
		}
	}
}

// TestInject_ProbNDistribution pins ProbN(3) over a large
// sample: ~33% fire rate, no extreme outliers.
func TestInject_ProbNDistribution(t *testing.T) {
	const N = 10000
	errf := inject.NewErrorf(inject.ErrInjectedFailure, inject.ProbN(3))
	for i := 0; i < N; i++ {
		errf.Apply()
	}
	// Expect ~3333 ± 5%. Generous tolerance for math/rand
	// distribution variance.
	got := errf.Faults()
	low, high := uint64(N/3-N/20), uint64(N/3+N/20)
	if got < low || got > high {
		t.Errorf("ProbN(3) over %d calls: %d faults; want %d±%d",
			N, got, N/3, N/20)
	}
}
