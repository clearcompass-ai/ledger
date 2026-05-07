/*
FILE PATH:
    wal/instruments.go

DESCRIPTION:
    D3 — wal Submit duration histogram.

        attesta_wal_submit_duration_seconds{outcome}

    Records the wall time of every wal.Committer.Submit call:
    queue-wait + group-commit batch-window + Badger txn + fsync.
    Drives the SRE alert "WAL is the bottleneck" — submit p99
    spiking is the earliest signal of disk-pressure or
    fsync-latency degradation.

KEY ARCHITECTURAL DECISIONS:
    - One label, "outcome", with bounded cardinality 2:
        outcome="committed" — group commit completed; submitter
                              got a definitive (nil or err) result.
        outcome="canceled"  — submitter ctx expired before the
                              group commit completed. The
                              submission may have flushed
                              afterwards, but the SUBMITTER
                              observed a deadline.
      Without this label, the histogram has a blind spot in the
      saturated case (clients time out → no observation → p99
      looks artificially healthy under WAL backlog). With it,
      administrators alert on canceled-rate spikes AND compare
      committed-p99 to canceled-p99 to distinguish "WAL is slow"
      from "clients have aggressive timeouts".
    - Buckets tuned for 1ms-2s typical fsync windows (NVMe = sub-
      ms; spinning rust = double-digit ms). Outliers >2s flag a
      stuck batcher.
    - nil histogram is no-op. Tests + dev runs without metrics
      pass through with zero overhead.
*/
package wal

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Submit-outcome label values. Bounded set of 2; total
// cardinality of the histogram = 2 series × N buckets.
const (
	OutcomeCommitted = "committed"
	OutcomeCanceled  = "canceled"
)

var submitDurationState struct {
	mu        sync.RWMutex
	histogram metric.Float64Histogram
}

// InstallSubmitDurationHistogram wires the wal Submit duration
// histogram from an OTel meter. Idempotent on second call.
// Returns true on first install, false otherwise.
func InstallSubmitDurationHistogram(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	submitDurationState.mu.Lock()
	defer submitDurationState.mu.Unlock()
	if submitDurationState.histogram != nil {
		return false
	}
	h, err := meter.Float64Histogram(
		"attesta_wal_submit_duration_seconds",
		metric.WithDescription("wal.Committer.Submit wall time (queue + batch + fsync), by outcome."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5,
		),
	)
	if err != nil {
		return false
	}
	submitDurationState.histogram = h
	return true
}

// recordSubmitDuration is called from Submit on BOTH the
// success path (outcome=committed) AND the cancel path
// (outcome=canceled). The cancel-path observation is the
// load-bearing one for SRE alerting: it captures the saturated
// case where the WAL is so slow the submitter's ctx expired
// first. Without the cancel-path observation, p99 stays
// artificially healthy precisely when WAL pressure is
// hurting clients.
//
// nil histogram is a no-op.
func recordSubmitDuration(ctx context.Context, outcome string, d time.Duration) {
	submitDurationState.mu.RLock()
	h := submitDurationState.histogram
	submitDurationState.mu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds(),
		metric.WithAttributes(attribute.String("outcome", outcome)),
	)
}
