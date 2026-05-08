/*
FILE PATH:

	shipper/instruments.go

DESCRIPTION:

	D5 — Shipper pending-count gauge.

	    attesta_shipper_pending_total

	Records the count of StateSequenced entries waiting to be
	shipped to the bytestore. Drives the SRE alert "shipper is
	falling behind" — long-tail backlog growth indicates either
	bytestore degradation OR insufficient shipper workers.

KEY ARCHITECTURAL DECISIONS:
  - ObservableGauge — read-on-scrape from a provider.
  - Single value, no labels. The shipper is a singleton.
*/
package shipper

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/metric"
)

var pendingState struct {
	mu       sync.RWMutex
	gauge    metric.Int64ObservableGauge
	provider func() int64
}

// InstallPendingGauge wires the shipper-pending gauge from an
// OTel meter. provider returns the current pending count.
// Idempotent on second call.
func InstallPendingGauge(meter metric.Meter, provider func() int64) bool {
	if meter == nil || provider == nil {
		return false
	}
	pendingState.mu.Lock()
	defer pendingState.mu.Unlock()
	if pendingState.gauge != nil {
		return false
	}
	g, err := meter.Int64ObservableGauge(
		"attesta_shipper_pending_total",
		metric.WithDescription("Count of StateSequenced entries waiting on bytestore upload."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	pendingState.gauge = g
	pendingState.provider = provider
	_, err = meter.RegisterCallback(
		func(_ context.Context, obs metric.Observer) error {
			pendingState.mu.RLock()
			p := pendingState.provider
			pendingState.mu.RUnlock()
			if p == nil {
				return nil
			}
			obs.ObserveInt64(g, p())
			return nil
		},
		g,
	)
	if err != nil {
		pendingState.gauge = nil
		pendingState.provider = nil
		return false
	}
	return true
}

// PendingCount returns an estimate of entries waiting on
// bytestore upload, computed from the WAL HWM minus the
// Shipper's last-committed HWM. Not exact (an entry can be
// in-flight in a worker without having advanced HWM yet) but
// suitable for the gauge's "is the shipper falling behind"
// question.
func (s *Shipper) PendingCount() int64 {
	if s == nil || s.wal == nil {
		return 0
	}
	walHWM, err := s.wal.HWM(context.Background())
	if err != nil {
		return 0
	}
	shipperHWM := s.metrics.hwm.Load()
	if shipperHWM > walHWM {
		return 0
	}
	return int64(walHWM - shipperHWM)
}
