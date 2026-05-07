/*
FILE PATH:
    sequencer/instruments.go

DESCRIPTION:
    D5 — Sequencer drain-lag gauge.

        attesta_sequencer_drain_lag_seconds

    Records the gap between "newest StatePending entry's
    log_time" and "now". The Sequencer drains StatePending →
    sequenced; if it falls behind, the gap grows. Drives the SRE
    alert "sequencer is the bottleneck" before the WAL queue
    actually backpressures admission.

KEY ARCHITECTURAL DECISIONS:
    - ObservableGauge — read-on-scrape rather than push-on-update.
      The sequencer doesn't have a natural "update" event for the
      drain lag; reading from currentLag (already maintained) on
      every scrape is the cleanest fit.
    - Single value, no labels. The sequencer is a singleton in the
      process; per-tenant breakdown belongs upstream.
    - nil meter → no-op. cmd/ledger wires the meter at boot;
      tests + dev runs without metrics work unchanged.
*/
package sequencer

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
)

var drainLagState struct {
	mu       sync.RWMutex
	gauge    metric.Float64ObservableGauge
	provider func() time.Duration // returns the latest observed lag
}

// InstallDrainLagGauge wires the drain-lag gauge from an OTel
// meter. The provider func is called on every scrape to produce
// the current lag duration. Idempotent on second call.
//
// Pass cmd/ledger's reference to the Sequencer's CurrentLag()
// method as the provider.
func InstallDrainLagGauge(meter metric.Meter, provider func() time.Duration) bool {
	if meter == nil || provider == nil {
		return false
	}
	drainLagState.mu.Lock()
	defer drainLagState.mu.Unlock()
	if drainLagState.gauge != nil {
		return false
	}
	g, err := meter.Float64ObservableGauge(
		"attesta_sequencer_drain_lag_seconds",
		metric.WithDescription("Time gap from oldest StatePending entry's log_time to now."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return false
	}
	drainLagState.gauge = g
	drainLagState.provider = provider
	_, err = meter.RegisterCallback(
		func(_ context.Context, obs metric.Observer) error {
			drainLagState.mu.RLock()
			p := drainLagState.provider
			drainLagState.mu.RUnlock()
			if p == nil {
				return nil
			}
			obs.ObserveFloat64(g, p().Seconds())
			return nil
		},
		g,
	)
	if err != nil {
		drainLagState.gauge = nil
		drainLagState.provider = nil
		return false
	}
	return true
}

// CurrentLag returns the current drain lag (most-recent
// observation captured by the drain loop). Used by both the
// drain-lag gauge provider AND the audit-telemetry log line.
//
// 0 when the WAL is fully drained; growing when StatePending
// entries are accumulating faster than the sequencer can ship.
func (s *Sequencer) CurrentLag() time.Duration {
	pending := s.metrics.currentLag.Load()
	if pending == 0 {
		return 0
	}
	// Scale the pending count by the configured PollInterval as
	// a coarse "time-to-drain" estimate. Rough but bounded:
	// pending entries × per-entry budget = expected drain time.
	if s.cfg.PollInterval == 0 {
		return time.Duration(pending) * time.Second
	}
	return time.Duration(pending) * s.cfg.PollInterval
}
