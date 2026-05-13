/*
FILE PATH: gossipnet/publisher.go

STHPublisher publishes a KindCosignedTreeHead event into the
ledger's gossip Sink after each successful K-of-N collection.

# WHY A SEPARATE COMPONENT

The witness/head_sync.go's RequestCosignatures call already has
access to the cosigned tree head and the per-witness signatures.
Pushing the gossip-publish call into that path keeps a single
"after commit + cosign" hook for the builder loop.

Building a separate Publisher component (rather than baking gossip
publishing directly into HeadSync) preserves the option of
disabling gossip per-deployment without changing HeadSync's logic
— the publisher is nil when gossip is disabled, and the HeadSync
no-ops the publish call.

# WHAT GETS PUBLISHED

Per successful K-of-N:

	Kind:        KindCosignedTreeHead
	Body:        CosignedTreeHeadFinding {Head, LedgerEndpoint}
	Originator:  ledger's own DID
	PrevHash:    last STH event's EventID for this originator
	               (read from gossipstore.LatestSTH)
	Lamport:     last STH lamport + 1
	               (so monotonicity holds inside the
	                KindCosignedTreeHead chain even when other
	                Kinds also use this originator's lamport space)

# CHAIN-DISCIPLINE NOTE

Per the SDK's gossip.Store contract, all events from one
originator share a single lamport space, NOT a per-Kind
lamport space. The publisher reads Head() from the Store and uses
that — every event the ledger publishes (STH, equivocation,
escrow override) advances the same chain.

# FAILURE MODE

A publish that fails is logged + dropped, never propagated to the
caller. The ledger's commit path is the source of truth; gossip
fan-out is best-effort. Anti-entropy in peer ledgers (read-side
catchup via /v1/gossip/since) covers transient publish failures.
*/
package gossipnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// STHPublisher emits KindCosignedTreeHead events to the gossip
// Sink after successful K-of-N collection. Stateless — chain
// discipline state is read from the Store on every publish so
// the ledger's two append paths (the gossip handler's inbound
// publishes and the publisher's outbound) stay coherent.
type STHPublisher struct {
	store          sdkgossip.Store
	sink           sdkgossip.Sink
	signer         sdkcosign.WitnessSigner
	networkID      sdkcosign.NetworkID
	originator     string
	ledgerEndpoint string
	logger         *slog.Logger

	// lastCosignedAtUnixNano is the unix-nanos timestamp of the
	// most-recent successful PublishCosignedHead. 0 means "no
	// cosigned head ever published" (fresh boot, no witness
	// quorum yet). Read via LastCosignedAt() / CosignAgeSeconds()
	// — H2 telemetry: drives the
	// `attesta_checkpoint_cosig_age_seconds` gauge consumed by
	// the SRE observability stack to alert when witness fan-out
	// has stalled.
	lastCosignedAtUnixNano atomic.Int64
}

// PublisherConfig configures STHPublisher.
type PublisherConfig struct {
	// Store is the gossip Store the publisher reads chain state
	// from (Head, LatestSTH) and the gossip handler appends to.
	// Required.
	Store sdkgossip.Store

	// Sink is the fan-out destination. Required (use NopSink for
	// single-process deployments to disable fan-out without
	// disabling publishing — Append still happens via the local
	// Store).
	Sink sdkgossip.Sink

	// Signer signs the KindCosignedTreeHead events. Typically the
	// same signer used elsewhere in the ledger for cosign
	// operations; the Purpose separation in cosign means signing
	// keys can be safely shared across /v1/cosign and /v1/gossip.
	Signer sdkcosign.WitnessSigner

	// NetworkID binds every event to the deployment's network.
	NetworkID sdkcosign.NetworkID

	// Originator is the ledger's own DID. Inbound
	// authentication on /v1/gossip resolves this DID via the
	// did.VerifierRegistry; the same registry MUST be able to
	// verify our own outbound events.
	Originator string

	// LedgerEndpoint is the ledger's public base URL, embedded in
	// the finding body for diagnostics. Not part of the
	// cryptographic content. Passed to the SDK's
	// findings.NewCosignedTreeHeadFinding which exposes it as a
	// public field (LedgerEndpoint) — v0.1.1 collapsed the
	// VerifiedCosignedTreeHeadFinding wrapper, so it's a direct
	// struct field rather than an accessor method now.
	LedgerEndpoint string

	// Logger receives publish diagnostics. nil ⇒ slog.Default.
	Logger *slog.Logger
}

// NewSTHPublisher constructs the publisher. Returns an error when
// any required field is missing.
func NewSTHPublisher(cfg PublisherConfig) (*STHPublisher, error) {
	// NetworkID FIRST — it's the cryptographic-domain-separation
	// invariant (T-9). A zero NetworkID would let signatures from
	// "Network A" verify on "Network B", breaking cross-network
	// replay defense. Other "required" checks below are
	// correctness gates; this one is security-critical.
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/publisher: NetworkID required (non-zero)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/publisher: Store required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/publisher: Sink required (use NopSink to disable fan-out)")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/publisher: Signer required")
	}
	if cfg.Originator == "" {
		return nil, fmt.Errorf("gossipnet/publisher: Originator required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &STHPublisher{
		store:          cfg.Store,
		sink:           cfg.Sink,
		signer:         cfg.Signer,
		networkID:      cfg.NetworkID,
		originator:     cfg.Originator,
		ledgerEndpoint: cfg.LedgerEndpoint,
		logger:         cfg.Logger,
	}, nil
}

// PublishCosignedHead constructs a KindCosignedTreeHead SignedEvent
// from the supplied CosignedTreeHead, appends it to the local
// Store, and broadcasts it via the Sink.
//
// Errors are logged + swallowed: the commit path is the source of
// truth; gossip fan-out is best-effort. Returns nil even on Sink
// failure so callers don't get false-positive failures back into
// the builder loop.
func (p *STHPublisher) PublishCosignedHead(ctx context.Context, head types.CosignedTreeHead) {
	if p == nil {
		return
	}
	finding, err := findings.NewCosignedTreeHeadFinding(head, p.ledgerEndpoint)
	if err != nil {
		p.logger.Warn("gossip publisher: build finding failed", "error", err)
		return
	}

	// Read chain head from Store. The Lamport advances by 1 from
	// the originator's last event regardless of Kind — all events
	// from one originator share a single lamport space (per SDK
	// contract).
	prev, lamport, err := p.store.Head(ctx, p.originator)
	if err != nil {
		p.logger.Warn("gossip publisher: read head failed", "error", err)
		return
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1 // first event in chain
	}

	signed, err := sdkgossip.Sign(ctx, finding,
		p.signer, p.networkID, p.originator, prev, nextLamport)
	if err != nil {
		p.logger.Warn("gossip publisher: sign failed", "error", err)
		return
	}

	// Append locally first; gossip's chain-discipline contract is
	// "originator-locally-monotonic" and the Store is the
	// authoritative state for our own chain. Skipping the local
	// Append would let the next publish observe a stale Head.
	if err := p.store.Append(ctx, signed); err != nil {
		// Idempotency note: if a peer already pushed our event
		// back to us via fan-out (rare under bounded transport),
		// Append is a no-op (I9 idempotency). Other Append
		// errors (chain break, lamport regression) signal a real
		// state-machine bug — log + drop.
		if errors.Is(err, sdkgossip.ErrChainBreak) || errors.Is(err, sdkgossip.ErrLamportRegression) {
			p.logger.Warn("gossip publisher: local Append rejected; head moved underneath",
				"error", err, "tree_size", head.TreeSize)
			return
		}
		p.logger.Warn("gossip publisher: local Append failed",
			"error", err, "tree_size", head.TreeSize)
		return
	}

	// Fan-out to peers. BufferedSink is non-blocking so this
	// doesn't pin the commit path even when peers are slow.
	if err := p.sink.Broadcast(ctx, signed); err != nil {
		p.logger.Warn("gossip publisher: fan-out failed (peers will catch up via /since)",
			"error", err, "tree_size", head.TreeSize)
		return
	}

	// H2: record successful-publish timestamp for the
	// `attesta_checkpoint_cosig_age_seconds` freshness gauge.
	// SREs alert on stale cosignatures (witness fan-out
	// stalled). The gauge reads `now - LastCosignedAt()`.
	p.lastCosignedAtUnixNano.Store(time.Now().UnixNano())

	p.logger.Info("gossip publisher: STH published",
		"tree_size", head.TreeSize,
		"root_hash", fmt.Sprintf("%x", head.RootHash[:8]),
		"smt_root", fmt.Sprintf("%x", head.SMTRoot[:8]),
		"signatures", len(head.Signatures),
		"lamport", nextLamport,
	)
}

// LastCosignedAt returns the unix-nanos timestamp of the most-
// recent successful PublishCosignedHead. Returns 0 when no
// cosigned head has ever been published from this process —
// the gauge consumer should treat 0 as "no data yet" and not
// emit a stale-cosig alert until a real value lands.
func (p *STHPublisher) LastCosignedAt() int64 {
	if p == nil {
		return 0
	}
	return p.lastCosignedAtUnixNano.Load()
}

// CosignAgeSeconds returns the seconds since the last successful
// PublishCosignedHead. Returns -1 when no cosigned head has been
// published yet (so callers can distinguish "fresh boot, no data"
// from "very old data"). Drives the
// `attesta_checkpoint_cosig_age_seconds` gauge consumed by SRE
// dashboards.
func (p *STHPublisher) CosignAgeSeconds() float64 {
	t := p.LastCosignedAt()
	if t == 0 {
		return -1
	}
	return time.Since(time.Unix(0, t)).Seconds()
}
