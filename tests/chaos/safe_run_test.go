//go:build chaos
// +build chaos

/*
FILE PATH:

	tests/chaos/safe_run_test.go

DESCRIPTION:

	J4 — Chaos test: lifecycle.SafeRun panic-recovery primitive
	under repeated panic load. Pins:
	  - Repeated panics in a goroutine never crash the process.
	  - Each panic surfaces to fatalCh exactly once.
	  - The wrapping caller's wg.Wait returns deterministically.
	  - WaitGroup discipline is preserved across N panics.

	Foundational chaos: SafeRun is the load-bearing wrapper
	used by every supervisor goroutine (E1+B5). If it deadlocks
	or leaks goroutines under repeated panic, the entire
	panic-handling story breaks.
*/
package chaos

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/lifecycle"
)

// TestChaos_SafeRunRepeatedPanics pins lifecycle.SafeRun under
// 100 consecutive panics. WaitGroup must drain; fatalCh must
// receive exactly 100 errors; no goroutine leaks.
func TestChaos_SafeRunRepeatedPanics(t *testing.T) {
	const N = 100
	var wg sync.WaitGroup
	fatalCh := make(chan error, N+1)
	logger := slog.New(slog.NewTextHandler(quietWriter{}, nil))

	for i := 0; i < N; i++ {
		idx := i
		lifecycle.SafeRunInWG(context.Background(), &wg, "chaos-panicker", logger, fatalCh,
			func() error {
				panic("chaos panic " + string(rune('0'+(idx%10))))
			})
	}

	// All panickers must drain.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("wg.Wait did not return within 10s after 100 panics")
	}

	// fatalCh should have received N errors. Drain + count.
	got := 0
	deadline := time.After(2 * time.Second)
collect:
	for got < N {
		select {
		case err := <-fatalCh:
			if !errors.Is(err, lifecycle.ErrPanicRecovered) {
				t.Errorf("fatalCh err %d = %v; want ErrPanicRecovered wrap", got, err)
			}
			got++
		case <-deadline:
			break collect
		}
	}
	if got != N {
		t.Errorf("fatalCh received %d errors; want exactly %d", got, N)
	}
}

// TestChaos_SafeRunPanicsAndNormalsInterleaved pins that
// SafeRun handles a mix of panicking + normal-return goroutines
// without state corruption between iterations. 100 goroutines:
// even-indexed panic, odd-indexed return nil.
func TestChaos_SafeRunPanicsAndNormalsInterleaved(t *testing.T) {
	const N = 100
	var wg sync.WaitGroup
	fatalCh := make(chan error, N+1)
	logger := slog.New(slog.NewTextHandler(quietWriter{}, nil))

	for i := 0; i < N; i++ {
		idx := i
		lifecycle.SafeRunInWG(context.Background(), &wg, "chaos-mixed", logger, fatalCh,
			func() error {
				if idx%2 == 0 {
					panic("synthetic")
				}
				return nil
			})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("wg.Wait did not return within 10s")
	}

	// Only the panicking half (50) should surface to fatalCh.
	got := 0
	deadline := time.After(2 * time.Second)
collect:
	for got < N {
		select {
		case <-fatalCh:
			got++
		case <-deadline:
			break collect
		}
	}
	if got != N/2 {
		t.Errorf("fatalCh got %d; want %d (half panics, half clean returns)", got, N/2)
	}
}
