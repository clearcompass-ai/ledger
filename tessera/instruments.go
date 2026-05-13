/*
FILE PATH:

	tessera/instruments.go

DESCRIPTION:

	D3 — Tessera AppendLeaf duration histogram.

	    attesta_tessera_append_duration_seconds

	Records the wall time of every AppendLeaf call. The
	integration future resolves when Tessera's batcher includes
	the entry in the next checkpoint cycle, so this histogram
	captures both the in-process append cost AND the wait for
	the next batch boundary.

	D4 — Close drain-budget residual gauge.

	    attesta_tessera_close_drain_residual_goroutines

	Sampled at Close exit. Records the delta between current
	runtime.NumGoroutine() and the construction-time baseline,
	after the drain budget has elapsed. Persistent non-zero
	values indicate upstream tessera.NewAppender's background
	goroutines (Follower / followerStats / updateStats; see
	embedded_appender.go::EmbeddedAppender lifecycle invariant)
	did not exit within the drain window — the operational
	signal that the upstream WaitGroup gap (tessera@v1.0.2
	/append_lifecycle.go:278-282 — bare `go`, no sync primitive)
	is hurting the deployment. Page on persistent positive
	values; the long-term fix is the upstream PR.

KEY ARCHITECTURAL DECISIONS:
  - Single histogram, no labels. Tessera is a singleton; per-
    tenant or per-route breakdown belongs upstream.
  - Buckets tuned for 100ms-10s typical: BatchMaxAge defaults
    to 250 ms in the SDK, so most appends land between 0 and
    that bound. Outliers >5s flag a stuck batcher.
  - Drain-residual is an Int64Gauge (point-in-time sample at
    Close), not a counter — operators alert on the value
    itself, not the rate. Process restart resets it to zero
    via the next NewEmbeddedAppender's baseline.
*/
package tessera

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
)

var appendDurationState struct {
	mu        sync.RWMutex
	histogram metric.Float64Histogram
}

var closeDrainResidualState struct {
	mu    sync.RWMutex
	gauge metric.Int64Gauge
}

// InstallAppendDurationHistogram wires the AppendLeaf duration
// histogram from an OTel meter. Idempotent on second call.
func InstallAppendDurationHistogram(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	appendDurationState.mu.Lock()
	defer appendDurationState.mu.Unlock()
	if appendDurationState.histogram != nil {
		return false
	}
	h, err := meter.Float64Histogram(
		"attesta_tessera_append_duration_seconds",
		metric.WithDescription("Tessera AppendLeaf wall time (in-process append + integration-future wait)."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
		),
	)
	if err != nil {
		return false
	}
	appendDurationState.histogram = h
	return true
}

// InstallCloseDrainResidualGauge wires the Close drain-residual
// goroutine gauge from an OTel meter. Idempotent on second call.
// Returns false if the meter is nil or the gauge was already
// installed.
func InstallCloseDrainResidualGauge(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	closeDrainResidualState.mu.Lock()
	defer closeDrainResidualState.mu.Unlock()
	if closeDrainResidualState.gauge != nil {
		return false
	}
	g, err := meter.Int64Gauge(
		"attesta_tessera_close_drain_residual_goroutines",
		metric.WithDescription("Goroutine count delta vs construction baseline at EmbeddedAppender.Close exit, after drain budget. Persistent positive = upstream Tessera goroutines did not exit within drain window (see embedded_appender.go for lifecycle rationale)."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	closeDrainResidualState.gauge = g
	return true
}

func recordAppendDuration(ctx context.Context, d time.Duration) {
	appendDurationState.mu.RLock()
	h := appendDurationState.histogram
	appendDurationState.mu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds())
}

// recordCloseDrainResidual samples the goroutine-residual gauge at
// EmbeddedAppender.Close exit. Negative values are recorded as 0 —
// they indicate the baseline was inflated by goroutines that have
// since exited unrelated to Tessera, and the gauge's "residual"
// semantic only applies to positive values.
func recordCloseDrainResidual(ctx context.Context, residual int) {
	closeDrainResidualState.mu.RLock()
	g := closeDrainResidualState.gauge
	closeDrainResidualState.mu.RUnlock()
	if g == nil {
		return
	}
	if residual < 0 {
		residual = 0
	}
	g.Record(ctx, int64(residual))
}
