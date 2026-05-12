// FILE PATH: chaos/trigger_chaos_test.go
//
// Chaos-tagged unit tests for the chaos.Trigger panic-injection
// path. Only built with -tags=chaos so the production build
// stays free of the runtime checks these tests exercise. The
// default-build no-op variant is type-checked implicitly by the
// rest of the codebase calling chaos.Trigger.

//go:build chaos
// +build chaos

package chaos

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTrigger_NoEnvVar_NoPanic(t *testing.T) {
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "")
	// Must not panic when env var is empty.
	Trigger("post_appendleaf")
}

func TestTrigger_NameMismatch_NoPanic(t *testing.T) {
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "some_other_point")
	Trigger("post_appendleaf") // different name, no panic
}

func TestTrigger_NameMatch_Panics(t *testing.T) {
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "post_appendleaf")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value type = %T, want string", r)
		}
		if !strings.HasPrefix(msg, Marker) {
			t.Errorf("panic msg = %q, want prefix %q (test harness scrapes Marker)",
				msg, Marker)
		}
		if !strings.Contains(msg, "name=post_appendleaf") {
			t.Errorf("panic msg = %q, missing name=post_appendleaf", msg)
		}
	}()
	Trigger("post_appendleaf")
}

func TestTrigger_CommaSeparatedList_Panics(t *testing.T) {
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "first, post_appendleaf , third")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on middle list entry")
		}
	}()
	Trigger("post_appendleaf")
}

func TestTrigger_AfterN_GatesUntilThreshold(t *testing.T) {
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "step")
	t.Setenv("LEDGER_CHAOS_PANIC_AFTER_N", "3")

	// First two calls must not panic.
	for i := 1; i <= 2; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("call %d unexpectedly panicked: %v", i, r)
				}
			}()
			Trigger("step")
		}()
	}

	// Third call MUST panic.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("third call did not panic; AFTER_N threshold not enforced")
		}
	}()
	Trigger("step")
}

func TestTrigger_PerNameCounters_Independent(t *testing.T) {
	// Counters must be per-name so adding a new injection point
	// doesn't shift the AFTER_N count of an unrelated point.
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "alpha,beta")
	t.Setenv("LEDGER_CHAOS_PANIC_AFTER_N", "2")

	// First alpha — no panic (count=1 < threshold=2).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("alpha #1 unexpectedly panicked: %v", r)
			}
		}()
		Trigger("alpha")
	}()
	// First beta — also no panic (its own counter starts at 1).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("beta #1 unexpectedly panicked: %v", r)
			}
		}()
		Trigger("beta")
	}()
	// Second alpha — panic (count=2 >= threshold=2).
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("alpha #2 did not panic; per-name counter broken")
		}
	}()
	Trigger("alpha")
}

func TestTrigger_ConcurrentMatchingCallers_Panic(t *testing.T) {
	resetCaches(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "race")

	var panicked atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicked.Add(1)
				}
			}()
			Trigger("race")
		}()
	}
	wg.Wait()
	// All 16 must have panicked (no AFTER_N gate).
	if got := panicked.Load(); got != 16 {
		t.Errorf("panicked count = %d, want 16 (concurrent triggers must all fire)", got)
	}
}

// resetCaches clears the package-level caches between tests so
// LEDGER_CHAOS_PANIC_AT and LEDGER_CHAOS_PANIC_AFTER_N changes via
// t.Setenv actually take effect. Without this the first test's
// env value is cached and every subsequent test reads stale state.
func resetCaches(t *testing.T) {
	t.Helper()
	matchSetCache.Store(nil)
	afterNCache.Store(0)
	afterNLoaded.Store(false)
	counters.Range(func(k, _ any) bool {
		counters.Delete(k)
		return true
	})
	// Defensive: clear any inherited env values from the test
	// runner. t.Setenv in each test sets fresh values.
	_ = os.Unsetenv("LEDGER_CHAOS_PANIC_AT")
	_ = os.Unsetenv("LEDGER_CHAOS_PANIC_AFTER_N")
}
