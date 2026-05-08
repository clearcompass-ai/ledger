/*
FILE PATH: builder/instruments.go

OTel counters owned by the builder loop. The witness-quorum-failure
counter is the load-bearing SRE signal for the Backpressure Stall:
when it climbs, the builder is refusing to advance because K-of-N
witnesses are not signing. Combined with sequencer
backpressure_stalls and HTTP 503 admission rates, ops can pinpoint
exactly which clock (commit vs. transparency) is jammed.

KEY ARCHITECTURAL DECISIONS:
  - Single counter, no labels. Quorum failures are atomic events;
    per-witness breakdown belongs in the gossip / cosign telemetry,
    not in this loop's hot path.
  - nil meter → no-op. cmd/ledger wires the meter at boot; tests
  - dev runs without metrics work unchanged.
  - Increment is concurrent-safe via the meter's internal locking;
    the counter has no atomic shadow on the package side.
*/
package builder

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/metric"
)

var quorumFailureState struct {
	mu      sync.RWMutex
	counter metric.Int64Counter
}

// InstallWitnessQuorumFailureCounter wires
// attesta_witness_quorum_failures_total from an OTel meter. Returns
// true on success, false on no-op (nil meter or already installed).
//
// Pass cmd/ledger's process meter at boot. Idempotent on second
// call.
func InstallWitnessQuorumFailureCounter(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	quorumFailureState.mu.Lock()
	defer quorumFailureState.mu.Unlock()
	if quorumFailureState.counter != nil {
		return false
	}
	c, err := meter.Int64Counter(
		"attesta_witness_quorum_failures_total",
		metric.WithDescription("Builder cycles aborted because witness K-of-N quorum could not be collected (Backpressure Stall trigger)."),
	)
	if err != nil {
		return false
	}
	quorumFailureState.counter = c
	return true
}

// incWitnessQuorumFailures increments the counter; safe to call
// before InstallWitnessQuorumFailureCounter (no-op when unwired).
func incWitnessQuorumFailures(ctx context.Context) {
	quorumFailureState.mu.RLock()
	c := quorumFailureState.counter
	quorumFailureState.mu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1)
}
