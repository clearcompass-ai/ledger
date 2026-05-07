/*
FILE PATH: gossipnet/equivocation_publisher.go

EquivocationPublisher signs + broadcasts a KindEquivocationFinding
event for a detected, cryptographically-verified equivocation.
The publisher is the egress mechanism only; the verification
discipline lives at the call site (the EquivocationMonitor below).

# WHY VERIFY BEFORE PUBLISHING

The SDK's findings.EquivocationFinding is the wire-shape adapter;
NOT cryptographic evidence by itself. A peer producing two
unsigned conflicting heads + claiming "equivocation" is denial-of-
service noise, not a proof. The Verify(set) method runs
cosign.VerifyTreeHeadCosignatures against both heads' signatures
+ the network's *cosign.WitnessKeySet (K-of-N read from
set.Quorum()) and returns nil only on success.

# v0.1.1 API SHAPE

The previous *VerifiedEquivocationFinding phantom-typed wrapper
was removed in v0.1.1. The Verify(set) call returns error-only;
type-safety is replaced by the developer discipline of "publish
only after Verify returned nil." The EquivocationMonitor below
enforces that discipline at the only construction site; this
publisher is the egress and accepts *findings.EquivocationFinding
directly. Calling Publish without first Verify-ing is a programmer
error caught by code review and the load-bearing tests in
gossipnet/equivocation_monitor_test.go.

# OPERATIONAL FLOW

	monitor (gossipnet/equivocation_monitor.go)
	  │   detects local-vs-peer disagreement
	  │   reconstructs witness.EquivocationProof
	  │   constructs findings.NewEquivocationFinding(proof, ourEndpoint)
	  │   calls finding.Verify(set)
	  │     ↓ (only on cryptographic verification success — err == nil)
	  └── EquivocationPublisher.Publish(finding)
	        ├── reads gossip.Store.Head() for chain-discipline state
	        ├── gossip.Sign as KindEquivocationFinding
	        ├── gossip.Store.Append (local persistence)
	        └── gossip.Sink.Broadcast (fan-out via BufferedSink)
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
	store      sdkgossip.Store
	sink       sdkgossip.Sink
	signer     sdkcosign.WitnessSigner
	networkID  sdkcosign.NetworkID
	originator string
	logger     *slog.Logger
}

// EquivocationPublisherConfig configures the publisher.
//
// All fields parallel STHPublisher's config — the publisher is
// the same shape but emits a different Kind. Config values
// SHOULD be the same as STHPublisher (same originator, same
// signing key) so the ledger's chain in the gossip Store
// covers all of its own emissions.
type EquivocationPublisherConfig struct {
	Store     sdkgossip.Store
	Sink      sdkgossip.Sink
	Signer    sdkcosign.WitnessSigner
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
	// NetworkID FIRST — see NewSTHPublisher for the same rationale
	// (T-9 cryptographic domain separation is the security
	// invariant; everything else is correctness).
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/equivocation: NetworkID required (non-zero)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/equivocation: Store required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/equivocation: Sink required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/equivocation: Signer required")
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

// Publish signs the (already-verified) equivocation finding as a
// KindEquivocationFinding event, appends it to the local Store,
// and broadcasts it to peers via the Sink.
//
// Errors are logged + swallowed: the verification (already
// performed by the caller before calling Publish) is the
// authoritative event; gossip transport is best-effort.
//
// Takes the finding by pointer. Passing nil is a programmer
// error and panics — there is no safe interpretation of "publish
// a nil equivocation finding".
//
// CONTRACT: callers MUST have called finding.Verify(set) and
// observed nil before invoking Publish. The v0.1.1 SDK collapsed
// the phantom-typed VerifiedEquivocationFinding wrapper; this
// publisher trusts the call site instead of the type system.
// The only call site is gossipnet/equivocation_monitor.go's
// checkPeer flow — which always Verify-s before publishing.
func (p *EquivocationPublisher) Publish(ctx context.Context, finding *findings.EquivocationFinding) {
	if p == nil {
		return
	}
	if finding == nil {
		panic("gossipnet/equivocation: nil finding (programmer error)")
	}

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
		"valid_sigs_a", finding.Proof.ValidSigsA,
		"valid_sigs_b", finding.Proof.ValidSigsB,
		"tree_size", finding.Proof.TreeSize,
		"ledger_endpoint", finding.LedgerEndpoint,
		"lamport", nextLamport,
	)
}
