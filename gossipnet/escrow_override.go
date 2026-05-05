/*
FILE PATH: gossipnet/escrow_override.go

EscrowOverrideService — operator-side endpoint for collecting K-of-N
witness cosignatures over a cosign.EscrowOverridePayload, then
broadcasting the cosigned authorization as a
KindEscrowOverrideAuth gossip event.

# WHEN USED

An escrow override is a quorum-attested instruction to release or
redirect escrowed artifacts outside the normal lifecycle path —
typically in response to legal process or a dispute resolution
outcome. The operator runs the K-of-N collection (same witness
peer set used for tree heads — cosign Purpose separation makes
the signatures non-replayable across roles) and broadcasts the
resulting authorization to the gossip network for transparency.

# WHY GOSSIP-PUBLISHED, NOT JUST HTTP-RESPONDED

Returning the cosigned authorization to the caller via HTTP is
not enough — without gossip transparency, an operator could
issue an override to one party while denying its existence to
another. Publishing as KindEscrowOverrideAuth makes the
authorization auditable: any party with the witness key set can
verify the authorization from the gossip event alone, without
going through the operator.

# COMPONENT FLOW

  HTTP POST /v1/escrow-override
    │   {escrow_id, decision_hash, effective}
    ▼
  EscrowOverrideService.ProcessOverride
    ├── cosign.NewEscrowOverridePayload(escrowID, decisionHash, effective)
    ├── collector.Collect(ctx, payload) → K-of-N witness sigs
    ├── findings.NewEscrowOverrideFinding(payload, sigs)
    ├── gossip.Sign as KindEscrowOverrideAuth
    ├── gossip.Store.Append (local persistence)
    └── gossip.Sink.Broadcast (fan out)
    ▼
  Returns: EventID + the K signatures

# PERSISTENCE

The gossip event itself IS the persistence record: immutable,
content-addressed (EventID = SHA-256 of canonical bytes),
append-only in the local Store. Auditors read overrides from
/v1/gossip/by-kind?kind=OL-GOSSIP-ESCROW-V1. No separate
Postgres table is required — the gossip Store covers the role.
*/
package gossipnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// EscrowOverrideServiceConfig configures the service.
type EscrowOverrideServiceConfig struct {
	// Collector is the K-of-N witness cosignature collector.
	// Required. Operators reuse witness.HeadSync.Collector() so
	// the same witness peer pool serves tree-head + override
	// roles.
	Collector *sdkcosign.WitnessCollector

	// Store is the local gossip Store. Required.
	Store sdkgossip.Store

	// Sink is the fan-out destination. Required.
	Sink sdkgossip.Sink

	// Signer signs the KindEscrowOverrideAuth gossip events
	// (the operator's own DID's signing key, same as STH).
	Signer sdkcosign.WitnessSigner

	// NetworkID binds every event to the deployment's network.
	NetworkID sdkcosign.NetworkID

	// Originator is the operator's own DID.
	Originator string

	Logger *slog.Logger
}

// EscrowOverrideService runs the operator-side override flow.
type EscrowOverrideService struct {
	collector  *sdkcosign.WitnessCollector
	store      sdkgossip.Store
	sink       sdkgossip.Sink
	signer     sdkcosign.WitnessSigner
	networkID  sdkcosign.NetworkID
	originator string
	logger     *slog.Logger
}

// NewEscrowOverrideService constructs the service. Returns an
// error when any required field is missing.
func NewEscrowOverrideService(cfg EscrowOverrideServiceConfig) (*EscrowOverrideService, error) {
	if cfg.Collector == nil {
		return nil, fmt.Errorf("gossipnet/escrow_override: Collector required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/escrow_override: Store required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/escrow_override: Sink required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/escrow_override: Signer required")
	}
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/escrow_override: NetworkID required (non-zero)")
	}
	if cfg.Originator == "" {
		return nil, fmt.Errorf("gossipnet/escrow_override: Originator required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &EscrowOverrideService{
		collector:  cfg.Collector,
		store:      cfg.Store,
		sink:       cfg.Sink,
		signer:     cfg.Signer,
		networkID:  cfg.NetworkID,
		originator: cfg.Originator,
		logger:     cfg.Logger,
	}, nil
}

// ProcessOverrideResult is the successful outcome of an override
// request.
// ProcessOverrideResult lives in apitypes/ so api/escrow_override.go
// can consume it without importing gossipnet (which transitively
// imports sequencer + pgx via PT-4). Re-exported here as a type
// alias for backwards compatibility with internal call sites.
type ProcessOverrideResult = apitypes.EscrowOverrideResult

// ProcessOverride runs the full escrow-override flow:
//
//  1. Build cosign.EscrowOverridePayload from the inputs.
//  2. Collect K-of-N witness cosignatures.
//  3. Build a findings.EscrowOverrideFinding for the gossip
//     transport layer.
//  4. Sign the finding under the operator's own DID at the
//     next chain position.
//  5. Append locally and broadcast.
//
// Returns the EventID for the caller's records.
func (s *EscrowOverrideService) ProcessOverride(
	ctx context.Context, escrowID, decisionHash [32]byte, effective uint64,
) (ProcessOverrideResult, error) {
	if s == nil {
		return ProcessOverrideResult{}, fmt.Errorf("gossipnet/escrow_override: nil service")
	}

	payload := sdkcosign.NewEscrowOverridePayload(escrowID, decisionHash, effective)
	collected, err := s.collector.Collect(ctx, payload)
	if err != nil {
		return ProcessOverrideResult{}, fmt.Errorf("gossipnet/escrow_override: collect K-of-N: %w", err)
	}

	finding, err := findings.NewEscrowOverrideFinding(payload, collected.Signatures)
	if err != nil {
		return ProcessOverrideResult{}, fmt.Errorf("gossipnet/escrow_override: build finding: %w", err)
	}

	prev, lamport, err := s.store.Head(ctx, s.originator)
	if err != nil {
		return ProcessOverrideResult{}, fmt.Errorf("gossipnet/escrow_override: read chain head: %w", err)
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1
	}

	signed, err := sdkgossip.Sign(ctx, finding,
		s.signer, s.networkID, s.originator, prev, nextLamport)
	if err != nil {
		return ProcessOverrideResult{}, fmt.Errorf("gossipnet/escrow_override: sign event: %w", err)
	}

	if err := s.store.Append(ctx, signed); err != nil {
		// Idempotent re-receive returns nil per I9; other Append
		// errors signal a state-machine bug — propagate.
		if errors.Is(err, sdkgossip.ErrChainBreak) || errors.Is(err, sdkgossip.ErrLamportRegression) {
			return ProcessOverrideResult{}, fmt.Errorf(
				"gossipnet/escrow_override: local Append rejected (head moved underneath): %w", err)
		}
		return ProcessOverrideResult{}, fmt.Errorf(
			"gossipnet/escrow_override: local Append: %w", err)
	}

	// Fan out best-effort. The local Append is the source of
	// truth for the operator's chain; peers catch up via
	// /v1/gossip/since on the next anti-entropy tick if the
	// broadcast drops.
	if err := s.sink.Broadcast(ctx, signed); err != nil {
		s.logger.Warn("escrow override: fan-out failed (peers will catch up via /since)",
			"error", err)
	}

	eventID, err := sdkgossip.EventIDOf(signed)
	if err != nil {
		// Defensive — Append succeeded so EventIDOf must succeed
		// (it's deterministic over the same fields).
		return ProcessOverrideResult{}, fmt.Errorf(
			"gossipnet/escrow_override: derive eventID: %w", err)
	}

	s.logger.Info("ESCROW OVERRIDE AUTHORIZED",
		"escrow_id", fmt.Sprintf("%x", escrowID[:8]),
		"effective", effective,
		"signatures", len(collected.Signatures),
		"event_id", fmt.Sprintf("%x", eventID[:8]),
		"lamport", nextLamport,
	)
	return ProcessOverrideResult{
		EventID:    eventID,
		Signatures: len(collected.Signatures),
		Lamport:    nextLamport,
	}, nil
}
