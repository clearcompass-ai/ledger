/*
FILE PATH: shipper/metrics.go

Atomic counters + an immutable snapshot type. Ops integrators that
want Prometheus exposition wire MetricsSnapshot fields to gauges /
counters at the composition root; this package stays free of
prom-client dependencies.
*/
package shipper

import "sync/atomic"

// Metrics holds the Shipper's atomic counters. All operations are
// goroutine-safe by virtue of sync/atomic. Read snapshots via
// Snapshot.
type Metrics struct {
	shipped              atomic.Uint64 // entries that completed bytestore upload + MarkShipped
	retries              atomic.Uint64 // failed-and-MarkRetry events
	manual               atomic.Uint64 // entries that hit MaxAttempts and were marked manual
	markShippedFailures  atomic.Uint64 // bytestore succeeded but MarkShipped failed
	hwm                  atomic.Uint64 // most recent HWM committed by hwmAdvancer
	shipLatencyNanos     atomic.Int64  // sum of Read+Upload+MarkShipped wall-clock
	shipLatencySamples   atomic.Int64  // count of contributing samples
}

// MetricsSnapshot is an immutable view of the Shipper's counters.
type MetricsSnapshot struct {
	// Shipped is the count of entries successfully migrated from
	// the WAL to the bytestore (bytestore upload returned nil AND
	// wal.MarkShipped returned nil).
	Shipped uint64

	// Retries is the count of retried-after-failure events.
	// Increments once per failed bytestore upload (or WAL read
	// failure on re-attempt).
	Retries uint64

	// Manual is the count of entries that exhausted MaxAttempts
	// and were transitioned to StateManual. Bytes for these stay
	// in the WAL pending operator review.
	Manual uint64

	// MarkShippedFailures is the count of bytestore-uploaded
	// entries whose subsequent wal.MarkShipped errored. Recoverable
	// (next scan re-uploads; bytestore is content-addressed) but
	// surfaced for diagnostic visibility.
	MarkShippedFailures uint64

	// HWM is the most recent high-water mark the advancer
	// committed. Lags wal.HWM by at most one completion.
	HWM uint64

	// ShipLatencyMeanMillis is the mean per-entry shipping latency
	// in milliseconds. Computed from the accumulated nanosecond
	// total / sample count.
	ShipLatencyMeanMillis float64
}

// Snapshot atomically reads every counter into a single struct.
// Field-by-field reads are NOT individually atomic (no sync.Mutex
// across them) — this is fine for ops dashboards that don't need
// cross-counter consistency. For per-sample correctness, callers
// query a specific atomic via the (unexported) Metrics struct's
// methods directly, which is reserved for tests.
func (m *Metrics) Snapshot() MetricsSnapshot {
	out := MetricsSnapshot{
		Shipped:             m.shipped.Load(),
		Retries:             m.retries.Load(),
		Manual:              m.manual.Load(),
		MarkShippedFailures: m.markShippedFailures.Load(),
		HWM:                 m.hwm.Load(),
	}
	if samples := m.shipLatencySamples.Load(); samples > 0 {
		nanos := m.shipLatencyNanos.Load()
		out.ShipLatencyMeanMillis = float64(nanos) / float64(samples) / 1e6
	}
	return out
}
