/*
FILE PATH:

	gossipnet/instruments.go

DESCRIPTION:

	D4 — Witness-quorum + equivocation detection counters.

	    attesta_witness_quorum_failures_total{network_id}
	    attesta_equivocation_detected_total{kind, originator}

	Both fire on transparency-log integrity events. SREs alert
	on quorum failures (witnesses unreachable / disagreeing) and
	equivocation events (a peer ledger forked).

KEY ARCHITECTURAL DECISIONS:
  - Bounded label cardinality. network_id is a single value
    per deployment (1 series). kind is the gossip Kind enum
    (~10 values); originator is the peer DID (~75 max in the
    principle's "75 peering networks" target). Total
    cardinality < 1000.
  - Two separate Install funcs so cmd/ledger can wire only
    one if the other is structurally absent (e.g., witness-
    free deployment skips the quorum counter).
  - nil meter is a no-op.
*/
package gossipnet

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var quorumFailureState struct {
	mu      sync.RWMutex
	counter metric.Int64Counter
}

// InstallWitnessQuorumFailureCounter wires the witness quorum
// failure counter from an OTel meter. Idempotent.
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
		metric.WithDescription("Count of witness K-of-N quorum failures, by network_id."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	quorumFailureState.counter = c
	return true
}

// IncWitnessQuorumFailure records one observation. networkIDHex
// is the deployment's NetworkID (hex prefix; bounded cardinality 1).
func IncWitnessQuorumFailure(ctx context.Context, networkIDHex string) {
	quorumFailureState.mu.RLock()
	c := quorumFailureState.counter
	quorumFailureState.mu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1,
		metric.WithAttributes(attribute.String("network_id", networkIDHex)),
	)
}

var equivocationDetectedState struct {
	mu      sync.RWMutex
	counter metric.Int64Counter
}

// InstallEquivocationDetectedCounter wires the equivocation-
// detected counter from an OTel meter. Idempotent.
func InstallEquivocationDetectedCounter(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	equivocationDetectedState.mu.Lock()
	defer equivocationDetectedState.mu.Unlock()
	if equivocationDetectedState.counter != nil {
		return false
	}
	c, err := meter.Int64Counter(
		"attesta_equivocation_detected_total",
		metric.WithDescription("Count of equivocation findings, by kind + originator."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return false
	}
	equivocationDetectedState.counter = c
	return true
}

// IncEquivocationDetected records one observation. kind is the
// gossip.Kind value (e.g., "equivocation_finding",
// "entry_commitment_equivocation"); originator is the peer DID
// the finding implicates.
func IncEquivocationDetected(ctx context.Context, kind, originator string) {
	equivocationDetectedState.mu.RLock()
	c := equivocationDetectedState.counter
	equivocationDetectedState.mu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("kind", kind),
			attribute.String("originator", originator),
		),
	)
}
