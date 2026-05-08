/*
FILE PATH:

	shipper/instruments_counters.go

DESCRIPTION:

	Shipper cumulative-counter OTel instruments. Pairs with the
	pending-count gauge in instruments.go (D5).

	Five instruments, each an Int64ObservableCounter that reads
	from the corresponding atomic in shipper.Metrics at scrape
	time (zero hot-path cost):

	  attesta_shipper_shipped_total
	    Total ship-complete events. Includes the ~0.14% residual
	    idempotent re-ships from the racing-scan-window guard's
	    small race window. Pair with attesta_shipper_shipped_unique
	    _total to compute amplification ratio.

	  attesta_shipper_shipped_unique_total
	    Distinct seqs that completed the ship pipeline (1 per
	    seq). Always <= shipped_total. The gap is the ship-event
	    amplification factor.

	  attesta_shipper_skipped_inflight_total
	    Scan-yield events that the in-flight dedupe guard
	    averted. > 0 indicates the racing-scan-window pathology
	    is being suppressed (shipOne latency > scan poll
	    interval). Each increment is one avoided redundant GCS
	    WriteEntry.

	  attesta_shipper_retries_total
	    Failed-and-retried bytestore upload events. > 0 / sec
	    sustained means GCS is degraded (auth, prefix hotspot,
	    per-object rate limit). Routed through MarkRetry; backoff
	    kicks in via meta.LastErrTs.

	  attesta_shipper_mark_failures_total
	    bytestore upload succeeded but wal.MarkShipped errored
	    (Badger MVCC conflict OR WAL transport failure). Self-
	    recovers (next scan picks up StateSequenced and re-uploads
	    — bytestore is content-addressed so this is idempotent),
	    but ANY non-zero value indicates write contention worth
	    investigating.

ALERT THRESHOLDS (canonical):

	Metric                                Alert / SLO
	────────────────────────────────────  ─────────────────────────
	shipped_total / unique_shipped_total  > 1.01 for 5 min →
	                                      dedupe regression (racing
	                                      returning at scale)
	retries_total rate                    > 0 / sec sustained 5 min
	                                      → bytestore degraded
	mark_failures_total                   any > 0 → page on-call
	                                      (Badger contention is
	                                      usually a code regression)
	shipper_pending_total (existing)      > 10000 for 10 min →
	                                      shipper undersized for
	                                      current admission rate;
	                                      bump LEDGER_SHIPPER_MAX_IN_FLIGHT
	sequencer_drain_lag_seconds (exists)  > 60s sustained → sequencer
	                                      backlog growing faster than
	                                      it drains; capacity event

KEY ARCHITECTURAL DECISIONS:
  - Int64ObservableCounter (not Int64Counter) — same pattern
    as the pending gauge. Reads from existing atomics at
    scrape time → zero overhead on the hot path. Counters are
    already maintained for the test-time MetricsSnapshot
    surface; this just exposes them through OTel.
  - Single InstallCounters entrypoint — five separate Install
    functions would be five separate idempotency-flag pairs
    and five separate audit surfaces. The five counters are
    always installed together.
*/
package shipper

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/metric"
)

var countersState struct {
	mu        sync.Mutex
	installed bool
}

// InstallCounters wires the shipper's cumulative counters as
// OTel Int64ObservableCounters from the supplied meter. Reads
// the per-counter values from s.metrics at scrape time. Idempotent
// — second call returns false without re-registering.
//
// Returns false on nil meter, nil shipper, or already-installed.
func InstallCounters(meter metric.Meter, s *Shipper) bool {
	if meter == nil || s == nil {
		return false
	}
	countersState.mu.Lock()
	defer countersState.mu.Unlock()
	if countersState.installed {
		return false
	}

	shipped, err := meter.Int64ObservableCounter(
		"attesta_shipper_shipped_total",
		metric.WithDescription("Total ship-complete events. Pair with shipped_unique_total for amplification ratio."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	uniqueShipped, err := meter.Int64ObservableCounter(
		"attesta_shipper_shipped_unique_total",
		metric.WithDescription("Distinct seqs that completed the ship pipeline."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	skippedInflight, err := meter.Int64ObservableCounter(
		"attesta_shipper_skipped_inflight_total",
		metric.WithDescription("Scan-yield events averted by the in-flight dedupe guard."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	retries, err := meter.Int64ObservableCounter(
		"attesta_shipper_retries_total",
		metric.WithDescription("Failed-and-retried bytestore upload events. Sustained > 0 / sec → GCS degraded."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	markFailures, err := meter.Int64ObservableCounter(
		"attesta_shipper_mark_failures_total",
		metric.WithDescription("Bytestore upload succeeded but wal.MarkShipped errored. Any > 0 → investigate."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}

	_, err = meter.RegisterCallback(
		func(_ context.Context, obs metric.Observer) error {
			obs.ObserveInt64(shipped, int64(s.metrics.shipped.Load()))
			obs.ObserveInt64(uniqueShipped, int64(s.metrics.uniqueShipped.Load()))
			obs.ObserveInt64(skippedInflight, int64(s.metrics.skippedInflight.Load()))
			obs.ObserveInt64(retries, int64(s.metrics.retries.Load()))
			obs.ObserveInt64(markFailures, int64(s.metrics.markShippedFailures.Load()))
			return nil
		},
		shipped,
		uniqueShipped,
		skippedInflight,
		retries,
		markFailures,
	)
	if err != nil {
		return false
	}

	countersState.installed = true
	return true
}
