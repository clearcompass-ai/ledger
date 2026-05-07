/*
FILE PATH:
    store/breaker_test.go

DESCRIPTION:
    Tests for the inline circuit breaker state machine. Pool
    acquisitions are simulated via the recordResult path directly
    so tests are fast (no real Postgres) and deterministic
    (no timing flakes).

KEY ARCHITECTURAL DECISIONS:
    - Tests exercise the state machine via the public Acquire-
      shape contract (gate + recordResult) using a no-pool
      Breaker. The actual pool.Acquire round-trip is integration-
      tested via the postgres.go round-trip suite when an
      ATTESTA_TEST_DSN is configured.
    - Each test pins ONE invariant. No table-driven hybrid that
      masks which assertion failed.
    - Time progression uses synthetic openedAt mutation rather
      than time.Sleep so tests run in sub-millisecond and do not
      flake under load.
*/
package store

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// quietLogger returns a logger that swallows everything; used to
// suppress test-time output. A bytes.Buffer-backed logger is used
// when a test needs to assert log output.
func quietLogger() *slog.Logger {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil))
}

// -------------------------------------------------------------------------------------------------
// 1) Closed state — successful acquisitions reset consecutive count
// -------------------------------------------------------------------------------------------------

func TestBreaker_StartsClosed(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 5, time.Second, quietLogger())
	if b.state != breakerClosed {
		t.Errorf("initial state = %v, want closed", stateName(b.state))
	}
}

func TestBreaker_SuccessResetsConsecutiveCount(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 5, time.Second, quietLogger())
	b.recordResult(false)
	b.recordResult(false)
	b.recordResult(true)
	if b.consecutiveErr != 0 {
		t.Errorf("consecutiveErr = %d, want 0 after success", b.consecutiveErr)
	}
	if b.state != breakerClosed {
		t.Errorf("state = %v, want closed", stateName(b.state))
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Threshold — N consecutive failures opens the breaker
// -------------------------------------------------------------------------------------------------

func TestBreaker_OpensAfterThresholdFailures(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 3, time.Second, quietLogger())
	for i := 0; i < 3; i++ {
		b.recordResult(false)
	}
	if b.state != breakerOpen {
		t.Errorf("state = %v after 3 failures with threshold 3, want open", stateName(b.state))
	}
}

func TestBreaker_DoesNotOpenBelowThreshold(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 5, time.Second, quietLogger())
	for i := 0; i < 4; i++ {
		b.recordResult(false)
	}
	if b.state == breakerOpen {
		t.Errorf("state = open after 4 failures with threshold 5, want closed")
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Open state — gate fails fast within cooldown
// -------------------------------------------------------------------------------------------------

func TestBreaker_OpenGateFailsFast(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 1, time.Second, quietLogger())
	b.recordResult(false) // → open
	state, allowProbe := b.gate()
	if state != breakerOpen || allowProbe {
		t.Errorf("gate = (%v, allowProbe=%v) within cooldown; want (open, false)",
			stateName(state), allowProbe)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Cooldown elapsed — gate promotes to half-open and grants probe
// -------------------------------------------------------------------------------------------------

func TestBreaker_AfterCooldownPromotesToHalfOpen(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 1, 10*time.Millisecond, quietLogger())
	b.recordResult(false) // → open

	// Synthetic time progression: rewind openedAt past the cooldown
	// window. Cleaner than time.Sleep — sub-millisecond + flake-free.
	b.mu.Lock()
	b.openedAt = time.Now().Add(-1 * time.Hour)
	b.mu.Unlock()

	state, allowProbe := b.gate()
	if state != breakerHalfOpen || !allowProbe {
		t.Errorf("gate = (%v, allowProbe=%v) after cooldown; want (half_open, true)",
			stateName(state), allowProbe)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Half-open single-flight — only one probe goroutine gets through
// -------------------------------------------------------------------------------------------------

func TestBreaker_HalfOpenSingleFlight(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 1, 10*time.Millisecond, quietLogger())
	b.recordResult(false)

	b.mu.Lock()
	b.openedAt = time.Now().Add(-1 * time.Hour)
	b.mu.Unlock()

	// First gate call claims the probe.
	_, allowProbe1 := b.gate()
	if !allowProbe1 {
		t.Fatal("first gate call should be granted the probe slot")
	}
	// Second gate call sees the probe in flight → fail fast.
	state2, allowProbe2 := b.gate()
	if state2 != breakerOpen || allowProbe2 {
		t.Errorf("second gate during in-flight probe = (%v, %v); want (open, false)",
			stateName(state2), allowProbe2)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Half-open success closes the breaker
// -------------------------------------------------------------------------------------------------

func TestBreaker_HalfOpenSuccessClosesBreaker(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 1, 10*time.Millisecond, quietLogger())
	b.recordResult(false)

	b.mu.Lock()
	b.openedAt = time.Now().Add(-1 * time.Hour)
	b.mu.Unlock()

	b.gate() // claim probe
	b.recordResult(true)

	if b.state != breakerClosed {
		t.Errorf("state = %v after half-open success; want closed", stateName(b.state))
	}
	if b.probeInFlight {
		t.Error("probeInFlight should clear on success")
	}
}

// -------------------------------------------------------------------------------------------------
// 7) Half-open failure re-opens with fresh cooldown
// -------------------------------------------------------------------------------------------------

func TestBreaker_HalfOpenFailureReopensBreaker(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 1, 10*time.Millisecond, quietLogger())
	b.recordResult(false)

	b.mu.Lock()
	originalOpenedAt := b.openedAt
	b.openedAt = time.Now().Add(-1 * time.Hour)
	b.mu.Unlock()

	b.gate() // claim probe
	b.recordResult(false)

	if b.state != breakerOpen {
		t.Errorf("state = %v after probe failure; want open", stateName(b.state))
	}
	b.mu.Lock()
	openedAtAfter := b.openedAt
	b.mu.Unlock()
	if !openedAtAfter.After(originalOpenedAt) {
		t.Error("openedAt should be reset on probe failure")
	}
}

// -------------------------------------------------------------------------------------------------
// 8) Defaults applied when zero
// -------------------------------------------------------------------------------------------------

func TestBreaker_DefaultsApplied(t *testing.T) {
	t.Parallel()
	b := NewBreaker(nil, 0, 0, quietLogger())
	if b.failureThreshold != DefaultBreakerFailureThreshold {
		t.Errorf("failureThreshold = %d, want %d default",
			b.failureThreshold, DefaultBreakerFailureThreshold)
	}
	if b.cooldown != DefaultBreakerCooldown {
		t.Errorf("cooldown = %v, want %v default", b.cooldown, DefaultBreakerCooldown)
	}
}

// -------------------------------------------------------------------------------------------------
// 9) ErrDBUnavailable sentinel surface
// -------------------------------------------------------------------------------------------------

// TestBreaker_ErrDBUnavailableIsRecognizable pins that callers
// can errors.Is against the sentinel — the api/ HTTP handler
// dispatches to ErrorClassDBUnavailable + 503 + Retry-After
// based on this exact match.
func TestBreaker_ErrDBUnavailableIsRecognizable(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrDBUnavailable, ErrDBUnavailable) {
		t.Fatal("errors.Is on the sentinel itself failed")
	}
}
