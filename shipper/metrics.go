/*
FILE PATH: shipper/metrics.go

Atomic counters + an immutable snapshot type. Ops integrators that
want Prometheus exposition wire MetricsSnapshot fields to gauges /
counters at the composition root; this package stays free of
prom-client dependencies.
*/
package shipper

import (
	"sync"
	"sync/atomic"
)

// Metrics holds the Shipper's atomic counters. All operations are
// goroutine-safe by virtue of sync/atomic. Read snapshots via
// Snapshot.
type Metrics struct {
	shipped             atomic.Uint64 // ship-complete events (includes idempotent re-ships)
	uniqueShipped       atomic.Uint64 // distinct seqs that completed (1-per-seq)
	shippedSeen         sync.Map      // seq → struct{}{} ; powers uniqueShipped dedupe
	skippedInflight     atomic.Uint64 // scan-yield events filtered by inflight dedupe
	retries             atomic.Uint64 // failed-and-MarkRetry events
	manual              atomic.Uint64 // entries that hit MaxAttempts and were marked manual
	markShippedFailures atomic.Uint64 // bytestore succeeded but MarkShipped failed
	hwm                 atomic.Uint64 // most recent HWM committed by hwmAdvancer
	shipLatencyNanos    atomic.Int64  // sum of Read+Upload+MarkShipped wall-clock
	shipLatencySamples  atomic.Int64  // count of contributing samples
}

// MetricsSnapshot is an immutable view of the Shipper's counters.
type MetricsSnapshot struct {
	// Shipped is the count of ship-complete events: bytestore
	// upload returned nil AND wal.MarkShipped returned nil. NOTE:
	// MarkShipped is idempotent (returns nil on already-shipped
	// state), so concurrent scans + workers can re-process the
	// same seq before its first MarkShipped commit and double-
	// count this counter. Use UniqueShipped for the distinct-seq
	// count; the difference is the ship-event-amplification
	// factor under concurrent scan windows.
	Shipped uint64

	// UniqueShipped is the count of DISTINCT sequence numbers that
	// completed the ship pipeline. Always <= Shipped. The gap
	// (Shipped - UniqueShipped) measures how many ship events were
	// idempotent re-completions of an already-shipped entry —
	// useful for detecting scanner/worker-window racing without
	// crashing the test (correctness is unaffected; bytestore is
	// content-addressed and MarkShipped is idempotent).
	UniqueShipped uint64

	// SkippedInflight is the count of scan-yield events that were
	// filtered by the in-flight dedupe guard (Shipper.inflight).
	// > 0 indicates the racing-scan-window pathology was averted:
	// scanAndDispatch saw a StateSequenced seq that was already
	// dispatched to a worker but not yet completed. Each
	// SkippedInflight increment represents one avoided redundant
	// dispatch — and therefore one avoided potential GCS 429 or
	// Badger MVCC conflict. Zero on idle systems and on systems
	// where shipOne completes faster than PollInterval.
	SkippedInflight uint64

	// Retries is the count of retried-after-failure events.
	// Increments once per failed bytestore upload (or WAL read
	// failure on re-attempt).
	Retries uint64

	// Manual is the count of entries that exhausted MaxAttempts
	// and were transitioned to StateManual. Bytes for these stay
	// in the WAL pending ledger review.
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
		UniqueShipped:       m.uniqueShipped.Load(),
		SkippedInflight:     m.skippedInflight.Load(),
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
