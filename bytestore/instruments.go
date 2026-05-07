/*
FILE PATH:
    bytestore/instruments.go

DESCRIPTION:
    D3 — bytestore PUT/GET duration histogram.

        attesta_bytestore_put_duration_seconds{op}

    Records the wall time of every WriteEntry / ReadEntry call.
    The `op` label is "put" or "get". Drives the SRE alert
    "bytestore is the bottleneck" — PUT p99 spiking is the
    earliest signal of GCS / S3 / network degradation.

KEY ARCHITECTURAL DECISIONS:
    - Single histogram with `op` label. Cardinality 2 — minimal.
    - Buckets tuned for 10ms-10s (GCS PUT typical 50-200ms;
      large objects + cold connections occasionally seconds).
    - Recorded by the *GCS adapter (and a future S3 adapter)
      directly. Centralized here so multiple backends share one
      metric.
*/
package bytestore

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var putDurationState struct {
	mu        sync.RWMutex
	histogram metric.Float64Histogram
}

// InstallPutDurationHistogram wires the bytestore put duration
// histogram from an OTel meter. Idempotent on second call.
func InstallPutDurationHistogram(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	putDurationState.mu.Lock()
	defer putDurationState.mu.Unlock()
	if putDurationState.histogram != nil {
		return false
	}
	h, err := meter.Float64Histogram(
		"attesta_bytestore_put_duration_seconds",
		metric.WithDescription("bytestore PUT/GET wall time, by op."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
		),
	)
	if err != nil {
		return false
	}
	putDurationState.histogram = h
	return true
}

// recordPutDuration is exported so each bytestore adapter
// records its own writes/reads. nil histogram is a no-op.
func recordPutDuration(ctx context.Context, op string, d time.Duration) {
	putDurationState.mu.RLock()
	h := putDurationState.histogram
	putDurationState.mu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds(),
		metric.WithAttributes(attribute.String("op", op)),
	)
}
