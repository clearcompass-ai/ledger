/*
FILE PATH: gossipnet/equivocation_publisher.go

EquivocationPublisher signs + broadcasts a KindEquivocationFinding
event for a detected equivocation. Gates publishing through the
SDK's VerifiedEquivocationFinding type-safety wrapper so the
network can only ever receive cryptographically-verified proofs.

# WHY VERIFY BEFORE PUBLISHING

The SDK's findings.EquivocationFinding is the wire-shape adapter;
NOT cryptographic evidence by itself. A peer producing two
unsigned conflicting heads + claiming "equivocation" is denial-of-
service noise, not a proof. The Verify method runs cosign.Verify
against both heads' signatures + a known WitnessKeySet, and ONLY
on success returns a *VerifiedEquivocationFinding. The verified
type's unexported fields make it impossible to construct without
running the verification.

This publisher takes only the verified type as input. Constructing
the verified type elsewhere in the ledger (the equivocation
monitor) is the entry point; this publisher is the egress point.
That separation closes the "I have an EquivocationFinding, let me
just publish it" trap.

# OPERATIONAL FLOW

	monitor (witness/equivocation_monitor.go)
	  │   detects local-vs-peer disagreement
	  │   reconstructs witness.EquivocationProof
	  │   constructs findings.NewEquivocationFinding(proof, ourEndpoint)
	  │   calls finding.Verify(witnessKeySet, K)
	  │     ↓ (only on cryptographic verification success)
	  │   *findings.VerifiedEquivocationFinding
	  └── EquivocationPublisher.Publish(verified)
	        ├── extracts the inner *EquivocationFinding via verified.AsEvent()
	        ├── reads gossip.Store.Head() for chain-discipline state
	        ├── gossip.Sign as KindEquivocationFinding
	        ├── gossip.Store.Append (local persistence)
	        └── gossip.Sink.Broadcast (fan-out via BufferedSink)

# RECONSTRUCTION FROM EXISTING MONITOR

The current witness.EquivocationMonitor (ledger side) detects
divergence by comparing tree_size + root_hash but does NOT capture
peer cosignatures. To produce a *VerifiedEquivocationFinding the
monitor needs full types.CosignedTreeHead values for both sides;
the cleanest path is to fetch /v1/gossip/sth/latest from the peer
(which carries full sigs) instead of /v1/tree/head.

The monitor upgrade is a follow-up; this publisher provides the
egress mechanism so when the upgrade lands the wiring is one
config field.
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
)

// EquivocationPublisher emits KindEquivocationFinding events to
// the gossip Sink for cryptographically-verified equivocation
// proofs. Stateless — chain-discipline state is read from the
// Store on every publish.
type EquivocationPublisher struct {
	store sdkgossip.Store
	sink sdkgossip.Sink
	signer sdkcosign.WitnessSigner
	networkID sdkcosign.NetworkID
	originator string
	logger *slog.Logger
}

// EquivocationPublisherConfig configures the publisher.
//
// All fields parallel STHPublisher's config — the publisher is
// the same shape but emits a different Kind. Config values
// SHOULD be the same as STHPublisher (same originator, same
// signing key) so the ledger's chain in the gossip Store
// covers all of its own emissions.
type EquivocationPublisherConfig struct {
	Store sdkgossip.Store
	Sink sdkgossip.Sink
	Signer sdkcosign.WitnessSigner
	NetworkID sdkcosign.NetworkID

	// Originator is the ledger's own DID. Same DID used for
	// STHPublisher; the gossip Store maintains one chain per
	// originator regardless of Kind.
	Originator string

	Logger *slog.Logger
}

// NewEquivocationPublisher constructs the publisher. Returns an
// error when any required field is missing.
func NewEquivocationPublisher(cfg EquivocationPublisherConfig) (*EquivocationPublisher, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/equivocation: Store required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/equivocation: Sink required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/equivocation: Signer required")
	}
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/equivocation: NetworkID required (non-zero)")
	}
	if cfg.Originator == "" {
		return nil, fmt.Errorf("gossipnet/equivocation: Originator required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &EquivocationPublisher{
		store:      cfg.Store,
		sink:       cfg.Sink,
		signer:     cfg.Signer,
		networkID:  cfg.NetworkID,
		originator: cfg.Originator,
		logger:     cfg.Logger,
	}, nil
}

// Publish signs the verified equivocation finding as a
// KindEquivocationFinding event, appends it to the local Store,
// and broadcasts it to peers via the Sink.
//
// Errors are logged + swallowed: the verification (already
// performed by the caller to obtain the verified type) is the
// authoritative event; gossip transport is best-effort.
//
// Takes the verified type by pointer. Passing nil is a programmer
// error and panics — there is no safe interpretation of "publish
// a nil verified equivocation".
func (p *EquivocationPublisher) Publish(ctx context.Context, verified *findings.VerifiedEquivocationFinding) {
	if p == nil {
		return
	}
	if verified == nil {
		panic("gossipnet/equivocation: nil verified finding (programmer error)")
	}

	finding := verified.AsEvent()

	prev, lamport, err := p.store.Head(ctx, p.originator)
	if err != nil {
		p.logger.Warn("equivocation publisher: read head failed", "error", err)
		return
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1
	}

	signed, err := sdkgossip.Sign(ctx, finding,
		p.signer, p.networkID, p.originator, prev, nextLamport)
	if err != nil {
		p.logger.Warn("equivocation publisher: sign failed", "error", err)
		return
	}

	if err := p.store.Append(ctx, signed); err != nil {
		if errors.Is(err, sdkgossip.ErrChainBreak) || errors.Is(err, sdkgossip.ErrLamportRegression) {
			p.logger.Warn("equivocation publisher: local Append rejected; head moved underneath",
				"error", err)
			return
		}
		p.logger.Warn("equivocation publisher: local Append failed", "error", err)
		return
	}

	if err := p.sink.Broadcast(ctx, signed); err != nil {
		p.logger.Warn("equivocation publisher: fan-out failed (peers will catch up via /since)",
			"error", err)
		return
	}

	p.logger.Error("EQUIVOCATION PUBLISHED",
		"verified_quorum", verified.VerifiedAtQuorum(),
		"ledger_endpoint", verified.LedgerEndpoint(),
		"lamport", nextLamport,
	)
}
