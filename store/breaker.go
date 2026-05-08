/*
FILE PATH:

	store/breaker.go

DESCRIPTION:

	Minimal circuit breaker over the Postgres connection pool.
	After N consecutive pool-acquisition failures the breaker
	opens; subsequent Acquire calls fail fast with ErrDBUnavailable
	until the cooldown elapses. After cooldown the breaker enters
	half-open, where ONE acquisition is allowed: success closes
	the breaker, failure re-opens it for another cooldown.

KEY ARCHITECTURAL DECISIONS:
  - Inline implementation (~80 LOC) instead of pulling
    sony/gobreaker. KISS + zero new dependencies. The behavior
    we need is small enough that an external library is
    cosmetic.
  - Trips on POOL-LEVEL failures only (Acquire). Per-query
    failures (a missing row, a syntax error, a transient
    Serializable retry) MUST NOT trip the breaker — those are
    query-specific, the pool is fine. Distinguishing here
    keeps the breaker focused on "is the DB reachable".
  - Half-open probe is single-flight: only one goroutine gets
    the trial acquisition. Others see ErrDBUnavailable until
    the probe resolves.
  - State machine is mutex-guarded; the hot path is one mutex
    lock + one atomic compare. At 1K TPS the breaker overhead
    is sub-microsecond, well under any pgxpool acquire latency.
  - No metrics emitted from inside the breaker — the api/
    writeError site classifies ErrDBUnavailable into the
    ErrorCounter (D-shape), keeping the breaker free of OTel
    coupling. Administrators see the breaker state via two log
    lines: "circuit breaker opened" and "circuit breaker
    closed", grep-able from the supervisor's slog stream.

OVERVIEW:

	Construct ONE breaker per *pgxpool.Pool at boot. Wrap pool
	acquisitions via:

	    conn, err := breaker.Acquire(ctx)
	    if errors.Is(err, ErrDBUnavailable) {
	        // 503 + Retry-After
	    }

	Inside store/ functions that take a *pgxpool.Pool and call
	pool.Acquire directly, the public Store wrapper takes the
	breaker so the call site is unchanged structurally. Functions
	that operate on *pgx.Tx (already-acquired) do not interact
	with the breaker at all — the transaction was acquired before
	the breaker tripped.

KEY DEPENDENCIES:
  - pgxpool: the pool we wrap.
  - sync.Mutex: state-machine guard.
  - time: cooldown timekeeping.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants + sentinel error
// -------------------------------------------------------------------------------------------------

// DefaultBreakerFailureThreshold is the number of consecutive
// pool-acquisition failures before the breaker opens. 5 is small
// enough to react quickly (one bad request batch trips it) but
// large enough that a single transient blip doesn't.
const DefaultBreakerFailureThreshold = 5

// DefaultBreakerCooldown is how long the breaker stays open
// before a half-open probe is allowed. 5 seconds gives a
// recovering DB room to get its TCP listener back up + serve
// connections, without forcing on-call to wait minutes for the
// breaker to retest.
const DefaultBreakerCooldown = 5 * time.Second

// ErrDBUnavailable is returned by Breaker.Acquire when the
// breaker is open. Maps to apitypes.ErrorClassDBUnavailable +
// HTTP 503 + Retry-After at the api/ layer.
var ErrDBUnavailable = errors.New("store: database unavailable (circuit breaker open)")

// -------------------------------------------------------------------------------------------------
// 2) Breaker state machine
// -------------------------------------------------------------------------------------------------

type breakerState int

const (
	breakerClosed breakerState = iota
	breakerOpen
	breakerHalfOpen
)

// Breaker wraps a *pgxpool.Pool with a fail-fast circuit. Safe
// for concurrent use — the state machine is mutex-guarded.
type Breaker struct {
	pool *pgxpool.Pool

	failureThreshold int
	cooldown         time.Duration
	logger           *slog.Logger

	mu             sync.Mutex
	state          breakerState
	consecutiveErr int
	openedAt       time.Time
	probeInFlight  bool
}

// NewBreaker constructs a Breaker. failureThreshold and cooldown
// fall back to the Default* constants when 0. logger is required
// for state-transition visibility (nil panics on use — callers
// MUST pass a real logger).
func NewBreaker(pool *pgxpool.Pool, failureThreshold int, cooldown time.Duration, logger *slog.Logger) *Breaker {
	if failureThreshold <= 0 {
		failureThreshold = DefaultBreakerFailureThreshold
	}
	if cooldown <= 0 {
		cooldown = DefaultBreakerCooldown
	}
	return &Breaker{
		pool:             pool,
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
		logger:           logger,
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Public API
// -------------------------------------------------------------------------------------------------

// Acquire wraps pool.Acquire. When the breaker is open, returns
// ErrDBUnavailable immediately. When closed, attempts the
// acquisition and updates state on result. Half-open allows one
// probe; success closes the breaker, failure re-opens it.
//
// D3 — emits attesta_postgres_pool_acquire_seconds for every
// acquisition (success or failure paths both observed; failure
// timings show pool-saturation back-pressure).
func (b *Breaker) Acquire(ctx context.Context) (*pgxpool.Conn, error) {
	state, allowProbe := b.gate()
	if state == breakerOpen && !allowProbe {
		return nil, ErrDBUnavailable
	}
	t0 := time.Now()
	conn, err := b.pool.Acquire(ctx)
	recordPoolAcquireDuration(ctx, time.Since(t0))
	b.recordResult(err == nil)
	if err != nil {
		return nil, fmt.Errorf("store: acquire: %w", err)
	}
	return conn, nil
}

// Pool returns the underlying *pgxpool.Pool for callers that need
// to pass the raw pool through (e.g., advisory-lock acquisition,
// migrations, txn helpers — operations outside the breaker's
// scope). Use sparingly; the breaker only fires on acquisitions
// it sees.
func (b *Breaker) Pool() *pgxpool.Pool {
	return b.pool
}

// -------------------------------------------------------------------------------------------------
// 4) State machine internals
// -------------------------------------------------------------------------------------------------

// gate decides whether to allow this acquisition. Returns the
// POST-transition state + a bool indicating whether the caller
// has been granted the half-open probe slot. Callers see
// (breakerOpen, false) when the breaker is open within cooldown
// and should fail fast with ErrDBUnavailable.
func (b *Breaker) gate() (breakerState, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case breakerClosed:
		return breakerClosed, false
	case breakerHalfOpen:
		// In half-open mode, ONLY the goroutine that owns the
		// probe is allowed through. Others fail fast.
		if b.probeInFlight {
			return breakerOpen, false
		}
		b.probeInFlight = true
		return breakerHalfOpen, true
	case breakerOpen:
		if time.Since(b.openedAt) < b.cooldown {
			return breakerOpen, false
		}
		// Cooldown elapsed — promote to half-open + claim probe.
		b.state = breakerHalfOpen
		b.probeInFlight = true
		return breakerHalfOpen, true
	default:
		return breakerClosed, false
	}
}

// recordResult updates the breaker state after an acquisition
// completes (success or failure). Called from Acquire's
// post-call path.
func (b *Breaker) recordResult(ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if ok {
		// Reset on success regardless of prior state.
		if b.state != breakerClosed {
			b.logger.Info("store: circuit breaker closed (db reachable)",
				"prev_state", stateName(b.state))
			b.state = breakerClosed
		}
		b.consecutiveErr = 0
		b.probeInFlight = false
		return
	}

	// Failure path.
	if b.state == breakerHalfOpen {
		// Probe failed — re-open and reset cooldown.
		b.state = breakerOpen
		b.openedAt = time.Now()
		b.probeInFlight = false
		b.logger.Warn("store: circuit breaker re-opened (probe failed)")
		return
	}

	b.consecutiveErr++
	if b.state == breakerClosed && b.consecutiveErr >= b.failureThreshold {
		b.state = breakerOpen
		b.openedAt = time.Now()
		b.logger.Warn("store: circuit breaker opened",
			"consecutive_errors", b.consecutiveErr,
			"threshold", b.failureThreshold,
			"cooldown", b.cooldown)
	}
}

func stateName(s breakerState) string {
	switch s {
	case breakerClosed:
		return "closed"
	case breakerOpen:
		return "open"
	case breakerHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}
