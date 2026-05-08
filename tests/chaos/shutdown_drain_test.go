//go:build chaos
// +build chaos

/*
FILE PATH:

	tests/chaos/shutdown_drain_test.go

DESCRIPTION:

	J4 — Chaos test: lifecycle.ShutdownChain runs every step in
	spec order, with per-component bounded ctx, even when one
	step times out. Pins I1+I2+I3:
	  - Spec order respected even on slow steps
	  - Per-component timeout caps each step independently
	  - Final summary captures every step's duration + error
	  - Slow step doesn't consume the budget for downstream steps
*/
package chaos

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/lifecycle"
)

// TestChaos_ShutdownChainSlowStepDoesNotStarveDownstream pins
// the I2 per-component-timeout invariant: a 50ms-budget step
// that takes 200ms gets cancelled at 50ms; subsequent steps
// run with their FULL budget.
func TestChaos_ShutdownChainSlowStepDoesNotStarveDownstream(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(quietWriter{}, nil))
	sc := lifecycle.NewShutdownChain(logger)

	var step1Took, step2Took, step3Took atomic.Int64

	sc.Add("slow-step-1", 50*time.Millisecond, func(ctx context.Context) error {
		t0 := time.Now()
		select {
		case <-time.After(200 * time.Millisecond):
			step1Took.Store(int64(time.Since(t0)))
			return nil
		case <-ctx.Done():
			step1Took.Store(int64(time.Since(t0)))
			return ctx.Err()
		}
	})
	sc.Add("fast-step-2", 200*time.Millisecond, func(ctx context.Context) error {
		t0 := time.Now()
		// Quick step — should complete well within budget.
		time.Sleep(10 * time.Millisecond)
		step2Took.Store(int64(time.Since(t0)))
		return nil
	})
	sc.Add("normal-step-3", 100*time.Millisecond, func(ctx context.Context) error {
		t0 := time.Now()
		time.Sleep(20 * time.Millisecond)
		step3Took.Store(int64(time.Since(t0)))
		return nil
	})

	t0 := time.Now()
	sc.Run()
	totalElapsed := time.Since(t0)

	// Total wall time should be ~50ms + ~10ms + ~20ms = ~80ms,
	// NOT 200+10+20=230ms (which would imply step 1 ran past
	// its timeout).
	if totalElapsed > 200*time.Millisecond {
		t.Errorf("Run took %v; per-step timeouts should have capped it under 200ms",
			totalElapsed)
	}

	// Step 1 should have been cancelled at ~50ms.
	step1 := time.Duration(step1Took.Load())
	if step1 < 40*time.Millisecond || step1 > 100*time.Millisecond {
		t.Errorf("step 1 ran for %v; expected ~50ms cancellation", step1)
	}

	// Step 2 + 3 should have run quickly (no leaked budget
	// consumed by step 1).
	step2 := time.Duration(step2Took.Load())
	if step2 > 50*time.Millisecond {
		t.Errorf("step 2 ran for %v; expected ~10ms", step2)
	}
	step3 := time.Duration(step3Took.Load())
	if step3 > 50*time.Millisecond {
		t.Errorf("step 3 ran for %v; expected ~20ms", step3)
	}

	// Summary captures each step's outcome.
	summary := sc.Summary()
	if len(summary) != 3 {
		t.Fatalf("summary len = %d; want 3", len(summary))
	}
	// Step 1 must show DeadlineExceeded.
	if !errors.Is(summary[0].Err, context.DeadlineExceeded) {
		t.Errorf("summary[0].Err = %v; want DeadlineExceeded", summary[0].Err)
	}
	// Steps 2 + 3 must be clean.
	if summary[1].Err != nil {
		t.Errorf("summary[1].Err = %v; want nil", summary[1].Err)
	}
	if summary[2].Err != nil {
		t.Errorf("summary[2].Err = %v; want nil", summary[2].Err)
	}
	// All three must have run.
	for i, s := range summary {
		if !s.Ran {
			t.Errorf("summary[%d].Ran = false; chain must execute every step", i)
		}
	}
}
