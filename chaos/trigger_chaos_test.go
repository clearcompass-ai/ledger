// FILE PATH: chaos/trigger_chaos_test.go
//
// Chaos-tagged unit tests for the chaos.Trigger termination
// injection path. Only built with -tags=chaos so the production
// build stays free of the runtime checks these tests exercise.
// The default-build no-op variant is type-checked implicitly by
// the rest of the codebase calling chaos.Trigger.
//
// HOW WE TEST A FUNCTION THAT CALLS os.Exit
//
// chaos.Trigger ends in exitFn(2). In production exitFn is
// os.Exit, which the test runner cannot recover from — calling it
// would kill the test process before t.Errorf could report.
//
// We intercept it: replace exitFn with a shim that records the
// requested exit code and panics with a sentinel value. The test
// recovers that sentinel and asserts on the recorded code +
// captured stderr marker. This mirrors the standard Go pattern
// for testing os.Exit-calling code (cf. stdlib's flag package
// tests, which override flag.CommandLine.Output and exit).
//
// We also redirect stderr via stderrFn so the marker line goes
// into a buffer the test can read back, rather than polluting the
// test runner's stderr output.

//go:build chaos
// +build chaos

package chaos

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// errExitIntercepted is the sentinel value the test-only exitFn
// shim panics with so Trigger's call stack can unwind back to the
// test, which then recovers it. Stable string for identity checks.
type errExitIntercepted struct{ code int }

func (e *errExitIntercepted) Error() string {
	return fmt.Sprintf("test-intercepted exit code=%d", e.code)
}

// triggerHarness installs interceptors for exitFn and stderrFn so
// a single Trigger call is fully observable in-process. Returns:
//   - exitCalls: number of times exitFn was invoked
//   - exitCode: code passed to the last exitFn call
//   - stderr: bytes Trigger wrote via stderrFn (the marker line)
//
// The shim panics with *errExitIntercepted on exitFn invocation
// so the goroutine running Trigger unwinds cleanly back to the
// test's deferred recover. The harness restores the originals on
// t.Cleanup.
type triggerHarness struct {
	exitCalls *atomic.Int64
	exitCode  *atomic.Int64
	stderr    *syncBuffer
}

func newTriggerHarness(t *testing.T) *triggerHarness {
	t.Helper()
	h := &triggerHarness{
		exitCalls: &atomic.Int64{},
		exitCode:  &atomic.Int64{},
		stderr:    &syncBuffer{},
	}
	// Snapshot originals so cleanup restores even if the test
	// panics for reasons unrelated to our sentinel.
	origExit := exitFn
	origEmit := emitMarker

	exitFn = func(code int) {
		h.exitCalls.Add(1)
		h.exitCode.Store(int64(code))
		panic(&errExitIntercepted{code: code})
	}
	// emitMarker writes directly into the synchronous buffer. No
	// pipe, no drain goroutine — by the time Trigger calls exitFn
	// the bytes are already in h.stderr, observable immediately
	// after the recover.
	emitMarker = func(line string) {
		_, _ = h.stderr.Write([]byte(line))
	}

	t.Cleanup(func() {
		exitFn = origExit
		emitMarker = origEmit
	})
	return h
}

// callTrigger invokes Trigger in the current goroutine and
// recovers any *errExitIntercepted sentinel panic. Returns:
//   - intercepted: true if Trigger called exitFn
//   - code: the code passed to exitFn, or 0 if not intercepted
//   - other: any non-sentinel panic value (test should fail)
func callTrigger(name string) (intercepted bool, code int, other any) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		sentinel, ok := r.(*errExitIntercepted)
		if !ok {
			other = r
			return
		}
		intercepted = true
		code = sentinel.code
	}()
	Trigger(name)
	return false, 0, nil
}

// syncBuffer is a minimal concurrent-safe bytes.Buffer for
// capturing stderr writes from inside Trigger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// -------------------------------------------------------------------------------------------------
// Behavior tests
// -------------------------------------------------------------------------------------------------

func TestTrigger_NoEnvVar_NoExit(t *testing.T) {
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "")

	intercepted, _, other := callTrigger("post_appendleaf")
	if other != nil {
		t.Fatalf("unexpected non-sentinel panic: %v", other)
	}
	if intercepted {
		t.Fatal("expected no exit; Trigger should be a no-op when env var is empty")
	}
	if got := h.exitCalls.Load(); got != 0 {
		t.Errorf("exitCalls = %d, want 0", got)
	}
}

func TestTrigger_NameMismatch_NoExit(t *testing.T) {
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "some_other_point")

	intercepted, _, other := callTrigger("post_appendleaf")
	if other != nil {
		t.Fatalf("unexpected non-sentinel panic: %v", other)
	}
	if intercepted {
		t.Fatal("expected no exit; name mismatch should be a no-op")
	}
	if got := h.exitCalls.Load(); got != 0 {
		t.Errorf("exitCalls = %d, want 0", got)
	}
}

func TestTrigger_NameMatch_Exits(t *testing.T) {
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "post_appendleaf")

	intercepted, code, other := callTrigger("post_appendleaf")
	if other != nil {
		t.Fatalf("unexpected non-sentinel panic: %v", other)
	}
	if !intercepted {
		t.Fatal("expected exitFn to be invoked, got nothing")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (chaos kill exit code)", code)
	}
	// Marker MUST be in stderr — the harness uses this to confirm
	// the kill fired at the intended injection point.
	got := h.stderr.String()
	if !strings.HasPrefix(got, Marker) {
		t.Errorf("stderr = %q, want prefix %q (harness scrapes Marker)", got, Marker)
	}
	if !strings.Contains(got, "name=post_appendleaf") {
		t.Errorf("stderr = %q, missing name=post_appendleaf", got)
	}
	if !strings.Contains(got, "count=1") {
		t.Errorf("stderr = %q, missing count=1 (first match)", got)
	}
}

func TestTrigger_CommaSeparatedList_Exits(t *testing.T) {
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "first, post_appendleaf , third")

	intercepted, code, other := callTrigger("post_appendleaf")
	if other != nil {
		t.Fatalf("unexpected non-sentinel panic: %v", other)
	}
	if !intercepted {
		t.Fatal("expected exitFn on middle list entry, got nothing")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if got := h.stderr.String(); !strings.Contains(got, "name=post_appendleaf") {
		t.Errorf("stderr = %q, missing name=post_appendleaf", got)
	}
}

func TestTrigger_AfterN_GatesUntilThreshold(t *testing.T) {
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "step")
	t.Setenv("LEDGER_CHAOS_PANIC_AFTER_N", "3")

	// First two calls must not exit.
	for i := 1; i <= 2; i++ {
		intercepted, _, other := callTrigger("step")
		if other != nil {
			t.Fatalf("call %d non-sentinel panic: %v", i, other)
		}
		if intercepted {
			t.Fatalf("call %d unexpectedly exited; AFTER_N=3 threshold should gate", i)
		}
	}

	// Third call MUST exit.
	intercepted, code, other := callTrigger("step")
	if other != nil {
		t.Fatalf("third call non-sentinel panic: %v", other)
	}
	if !intercepted {
		t.Fatal("third call did not exit; AFTER_N threshold not enforced")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if got := h.stderr.String(); !strings.Contains(got, "count=3") {
		t.Errorf("stderr = %q, expected count=3 (the threshold-crossing call)", got)
	}
}

func TestTrigger_PerNameCounters_Independent(t *testing.T) {
	// Counters must be per-name so adding a new injection point
	// doesn't shift the AFTER_N count of an unrelated point.
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "alpha,beta")
	t.Setenv("LEDGER_CHAOS_PANIC_AFTER_N", "2")

	// First alpha — no exit (count=1 < threshold=2).
	if intercepted, _, _ := callTrigger("alpha"); intercepted {
		t.Fatal("alpha #1 unexpectedly exited")
	}
	// First beta — also no exit (its own counter starts at 1).
	if intercepted, _, _ := callTrigger("beta"); intercepted {
		t.Fatal("beta #1 unexpectedly exited")
	}
	// Second alpha — exit (count=2 >= threshold=2).
	intercepted, code, other := callTrigger("alpha")
	if other != nil {
		t.Fatalf("alpha #2 non-sentinel panic: %v", other)
	}
	if !intercepted {
		t.Fatal("alpha #2 did not exit; per-name counter broken")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if got := h.stderr.String(); !strings.Contains(got, "name=alpha") {
		t.Errorf("stderr = %q, expected name=alpha (the exiting call)", got)
	}
}

// TestTrigger_ConcurrentMatchingCallers_AllRecord pins that 16
// concurrent callers all observe the intercepted exit. With the
// real os.Exit the FIRST caller would terminate the process, but
// with the in-test interceptor (panic-based) each goroutine sees
// its own exit independently. The point of this test is to pin
// that the counter increments under contention and the matchSet
// lookup is thread-safe.
func TestTrigger_ConcurrentMatchingCallers_AllRecord(t *testing.T) {
	resetCaches(t)
	h := newTriggerHarness(t)
	t.Setenv("LEDGER_CHAOS_PANIC_AT", "race")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine has its own recover via callTrigger.
			_, _, _ = callTrigger("race")
		}()
	}
	wg.Wait()
	if got := h.exitCalls.Load(); got != 16 {
		t.Errorf("exitCalls = %d, want 16 (all concurrent triggers must fire)", got)
	}
}

// TestTrigger_ProductionDefault_IsOsExit pins that without test
// interception the package-level exitFn defaults to os.Exit.
// Without this assertion, a refactor that silently changes the
// default would let production chaos kills go through panic()
// (caught by lifecycle.SafeRun) instead of os.Exit (bypasses
// recover), reintroducing the original bug.
func TestTrigger_ProductionDefault_IsOsExit(t *testing.T) {
	// Take a function-value identity comparison via reflection-free
	// pointer trick: both exitFn and os.Exit are function values;
	// fmt.Sprintf("%p", v) on a function value prints the pointer.
	// Equal pointers means same underlying function.
	got := fmt.Sprintf("%p", exitFn)
	want := fmt.Sprintf("%p", os.Exit)
	if got != want {
		t.Errorf("default exitFn = %s, want os.Exit (%s); a chaos kill in production would be recoverable",
			got, want)
	}
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

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
