/*
FILE PATH:

	tests/chaos/inject/inject.go

DESCRIPTION:

	J4 — Fault-injection primitives for the chaos test suite.
	Each helper wraps a production primitive with a configurable
	fault behavior so chaos tests can exercise specific failure
	paths without modifying the production primitive itself.

KEY ARCHITECTURAL DECISIONS:
  - One injector per failure SHAPE, not per failure SOURCE.
    Timeout / latency / error / disconnect / partial-write
    are universal shapes; we apply them to PG / GCS / Tessera
    via small adapter shims.
  - Probabilistic AND deterministic modes. Each injector
    accepts a Trigger that decides per-call whether to fault.
    Use ProbN(N) for "1 in N", AfterCalls(K) for "starting at
    call K", or Custom(func) for arbitrary patterns.
  - State exposed via atomic counters: Calls() returns total
    invocations; Faults() returns total fault-triggers. Tests
    assert specific counts to confirm the chaos actually fired.

OVERVIEW:

	Typical pattern in a chaos test:

	    latency := inject.NewLatency(50*time.Millisecond, inject.ProbN(3))
	    gcs := inject.WrapGCS(realGCS, latency, nil)
	    // ... drive the system through gcs ...
	    if latency.Faults() == 0 {
	        t.Fatal("expected at least one latency injection")
	    }
*/
package inject

import (
	"errors"
	"math/rand"
	"sync/atomic"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) Triggers — decide per-call whether to fire
// -------------------------------------------------------------------------------------------------

// Trigger returns true if the current call should fault.
type Trigger func() bool

// Always returns a Trigger that always fires.
func Always() Trigger {
	return func() bool { return true }
}

// Never returns a Trigger that never fires.
func Never() Trigger {
	return func() bool { return false }
}

// ProbN returns a Trigger that fires for 1 in N calls,
// uniformly distributed via math/rand. Not seedable here;
// tests that need determinism use Custom.
func ProbN(n int) Trigger {
	if n <= 1 {
		return Always()
	}
	return func() bool {
		return rand.Intn(n) == 0
	}
}

// AfterCalls returns a Trigger that fires starting at the kth
// call (1-indexed). The first k-1 calls succeed; from call k
// onwards every call faults.
func AfterCalls(k int) Trigger {
	var calls atomic.Int64
	return func() bool {
		return calls.Add(1) >= int64(k)
	}
}

// FirstNCalls returns a Trigger that fires for the first N
// calls then never again. Useful for "transient outage"
// scenarios.
func FirstNCalls(n int) Trigger {
	var calls atomic.Int64
	return func() bool {
		return calls.Add(1) <= int64(n)
	}
}

// Custom wraps an arbitrary func.
func Custom(fn func() bool) Trigger {
	return fn
}

// -------------------------------------------------------------------------------------------------
// 2) Fault types
// -------------------------------------------------------------------------------------------------

// Errors used by injectors. Tests errors.Is against these to
// confirm the chaos fired the way they expected.
var (
	ErrInjectedTimeout = errors.New("inject: synthetic timeout")
	ErrInjectedFailure = errors.New("inject: synthetic failure")
	ErrInjectedClosed  = errors.New("inject: synthetic connection closed")
)

// -------------------------------------------------------------------------------------------------
// 3) Latency injector
// -------------------------------------------------------------------------------------------------

// Latency adds a fixed delay before the wrapped operation
// returns. Useful for "Tessera stall", "GCS slow", "PG slow"
// scenarios.
type Latency struct {
	delay   time.Duration
	trigger Trigger

	calls  atomic.Uint64
	faults atomic.Uint64
}

func NewLatency(delay time.Duration, trigger Trigger) *Latency {
	if trigger == nil {
		trigger = Never()
	}
	return &Latency{delay: delay, trigger: trigger}
}

// Apply blocks for the configured delay if the trigger fires.
// Returns true if the latency was injected.
func (l *Latency) Apply() bool {
	l.calls.Add(1)
	if !l.trigger() {
		return false
	}
	l.faults.Add(1)
	time.Sleep(l.delay)
	return true
}

func (l *Latency) Calls() uint64  { return l.calls.Load() }
func (l *Latency) Faults() uint64 { return l.faults.Load() }

// -------------------------------------------------------------------------------------------------
// 4) Error injector
// -------------------------------------------------------------------------------------------------

// Errorf returns the configured error if the trigger fires,
// nil otherwise. Wrap a production primitive's error path with
// it to inject failures.
type Errorf struct {
	err     error
	trigger Trigger

	calls  atomic.Uint64
	faults atomic.Uint64
}

func NewErrorf(err error, trigger Trigger) *Errorf {
	if err == nil {
		err = ErrInjectedFailure
	}
	if trigger == nil {
		trigger = Never()
	}
	return &Errorf{err: err, trigger: trigger}
}

// Apply returns the configured err if the trigger fires, nil
// otherwise.
func (e *Errorf) Apply() error {
	e.calls.Add(1)
	if !e.trigger() {
		return nil
	}
	e.faults.Add(1)
	return e.err
}

func (e *Errorf) Calls() uint64  { return e.calls.Load() }
func (e *Errorf) Faults() uint64 { return e.faults.Load() }
