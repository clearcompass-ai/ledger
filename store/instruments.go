/*
FILE PATH:

	store/instruments.go

DESCRIPTION:

	D3 — Postgres pool acquire duration histogram + D5 metrics
	helpers exposed for the cmd/ledger composition root.

	    attesta_postgres_pool_acquire_seconds

	Records the wall time of every pool.Acquire call, going
	through the Breaker. SREs alert on this when the pool is
	saturated (acquire p99 spikes mean the queue is growing).

KEY ARCHITECTURAL DECISIONS:
  - Recorded inside Breaker.Acquire so EVERY production
    acquisition path is captured, including the sequencer +
    shipper hot loops.
  - No labels. The pool is a singleton in the process; per-
    tenant or per-route breakdown belongs upstream.
  - Buckets tuned for 100us-1s typical (warm pool sub-ms;
    cold-start on a fresh boot tens of ms).
*/
package store

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
)

var poolAcquireDurationState struct {
	mu        sync.RWMutex
	histogram metric.Float64Histogram
}

// InstallPoolAcquireDurationHistogram wires the pool-acquire
// duration histogram from an OTel meter. Idempotent on second
// call.
func InstallPoolAcquireDurationHistogram(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	poolAcquireDurationState.mu.Lock()
	defer poolAcquireDurationState.mu.Unlock()
	if poolAcquireDurationState.histogram != nil {
		return false
	}
	h, err := meter.Float64Histogram(
		"attesta_postgres_pool_acquire_seconds",
		metric.WithDescription("pgxpool.Acquire wall time (queue wait + connection check-out)."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
		),
	)
	if err != nil {
		return false
	}
	poolAcquireDurationState.histogram = h
	return true
}

func recordPoolAcquireDuration(ctx context.Context, d time.Duration) {
	poolAcquireDurationState.mu.RLock()
	h := poolAcquireDurationState.histogram
	poolAcquireDurationState.mu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds())
}
