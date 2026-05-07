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

KEY ARCHITECTURAL DECISIONS:
    - Single histogram, no labels. Tessera is a singleton; per-
      tenant or per-route breakdown belongs upstream.
    - Buckets tuned for 100ms-10s typical: BatchMaxAge defaults
      to 250 ms in the SDK, so most appends land between 0 and
      that bound. Outliers >5s flag a stuck batcher.
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

func recordAppendDuration(ctx context.Context, d time.Duration) {
	appendDurationState.mu.RLock()
	h := appendDurationState.histogram
	appendDurationState.mu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds())
}
