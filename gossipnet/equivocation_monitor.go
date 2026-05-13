/*
FILE PATH: gossipnet/equivocation_monitor.go

EquivocationMonitor compares the local view of an originator's
latest STH against each peer's view. On divergence it constructs
a *findings.EquivocationFinding, verifies it (K-of-N from
*cosign.WitnessKeySet) and hands it to the EquivocationPublisher.

# WHY THIS REPLACES witness/equivocation_monitor.go

The legacy ledger monitor fetched /v1/tree/head — an endpoint
that returns tree_size + root_hash but NO witness signatures.
Without the cosignatures, the legacy monitor could detect SUSPECT
equivocation but could not produce cryptographic evidence — a
mere finger-pointing JSON document with no quorum-witness backing.

The /v1/gossip/sth/latest endpoint mounted in W5 returns the full
SignedEvent, whose body carries the complete types.CosignedTreeHead
including K-of-N signatures. Building the monitor on the gossip
feed gives us cryptographic proofs from the wire — no manual sig
plumbing on our side.

# v0.1.1 API SHAPE

The witness keys, NetworkID, K-of-N quorum, and BLS verifier
are all encapsulated in *cosign.WitnessKeySet (constructed at
boot in cmd/ledger/main.go from LEDGER_WITNESS_QUORUM_K +
genesis witness DIDs). The previous (witnessKeys, quorumK,
networkID, blsVerifier) parameter group is collapsed into one
field. witness.DetectEquivocation, finding.Verify, and the
underlying cosign.Verify primitive all read K from set.Quorum().

# DETECTION ALGORITHM

For each (peer, originator) pair where:

  - peer is one of LEDGER_GOSSIP_PEER_ENDPOINTS
  - originator is the peer's own DID (the peer might equivocate
    by publishing different heads to different audiences)

Per tick:

 1. Fetch peer.LatestSTH(originatorDID) via gossip.Client. Decode
    the SignedEvent body to extract types.CosignedTreeHead with
    full signatures.
 2. Fetch our local Store.LatestSTH(originatorDID). Decode same
    way.
 3. If both exist, both at the same tree_size, but different
    root_hash → call witness.DetectEquivocation(headA, headB, set).
    The SDK helper verifies BOTH heads against the WitnessKeySet
    at K-of-N (read from set.Quorum()) and returns
    *witness.EquivocationProof on success.
 4. Wrap in findings.NewEquivocationFinding, call .Verify(set)
    to confirm cryptographic admissibility of the wire-shape
    finding (independent of step 3 — Verify guards the publish
    contract; DetectEquivocation guards the detection contract).
 5. Publish via EquivocationPublisher (signs as
    KindEquivocationFinding + appends + broadcasts).

# FALSE-POSITIVE GATE

DetectEquivocation returns nil for:

  - Equal root hashes (no equivocation)
  - Different tree sizes (not equivocation; out-of-sync clocks
    or just different commit progress)
  - Heads with insufficient signatures (cannot prove anything)

The verification gate also fires on:

  - Heads signed under a different NetworkID
  - Heads with signatures from non-witness-set keys
  - Heads where K-of-N is not reached for either side

This monitor only ever publishes verified evidence. The Verify-
before-Publish contract (see EquivocationPublisher.Publish doc)
is enforced by this monitor's checkPeer flow.

# CADENCE

Default 60s tick. Slower than anti-entropy because equivocation
is a rare-but-catastrophic event; rapid polling would consume
peer-side rate-limit budget without proportional value.
*/
package gossipnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
	sdkwitness "github.com/clearcompass-ai/attesta/witness"
)

// DefaultEquivocationInterval is the default poll period.
const DefaultEquivocationInterval = 60 * time.Second

// EquivocationMonitorConfig configures the equivocation monitor.
//
// v0.1.1 SHAPE: WitnessKeys / QuorumK / NetworkID / BLSVerifier
// are collapsed into a single WitnessSet *cosign.WitnessKeySet
// field. The constructor at cmd/ledger/main.go calls
// cosign.NewWitnessKeySet(witKeys, networkID, quorumK, blsVerifier)
// once at boot and passes the result here.
type EquivocationMonitorConfig struct {
	// Store is the local gossip Store. Required. Used for
	// LatestSTH(originator) lookups against the ledger's own
	// chain history.
	Store sdkgossip.Store

	// Peers is the set of peers to compare against. Same shape
	// as the anti-entropy config; reusing the type keeps the
	// ledger's peer config consistent across the two loops.
	// Empty disables the monitor (Run returns immediately).
	Peers []AntiEntropyPeer

	// WitnessSet is the *cosign.WitnessKeySet the monitor verifies
	// cosignatures against. Encapsulates witness public keys,
	// NetworkID, K-of-N quorum threshold, and BLS aggregate
	// verifier. Required (non-nil).
	WitnessSet *sdkcosign.WitnessKeySet

	// Publisher is the egress hook. nil disables publishing —
	// detected equivocations are logged but not broadcast (useful
	// for observe-only monitors).
	Publisher *EquivocationPublisher

	// Interval is the tick period. 0 ⇒ DefaultEquivocationInterval.
	Interval time.Duration

	// HTTPClient overrides the per-peer HTTP client. nil ⇒
	// sdklog.DefaultClient(20s).
	HTTPClient *http.Client

	Logger *slog.Logger
}

// EquivocationMonitor polls peers for STH divergence.
type EquivocationMonitor struct {
	store      sdkgossip.Store
	peers      []equivocationPeerInternal
	witnessSet *sdkcosign.WitnessKeySet
	publisher  *EquivocationPublisher
	interval   time.Duration
	logger     *slog.Logger
}

type equivocationPeerInternal struct {
	did    string
	url    string
	client sdkgossip.Client
}

// NewEquivocationMonitor constructs the monitor. Returns an error
// when any required field is missing.
func NewEquivocationMonitor(cfg EquivocationMonitorConfig) (*EquivocationMonitor, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_monitor: Store required")
	}
	if cfg.WitnessSet == nil {
		return nil, fmt.Errorf(
			"gossipnet/equivocation_monitor: WitnessSet required " +
				"(construct via cosign.NewWitnessKeySet at boot)")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultEquivocationInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = sdklog.DefaultClient(20 * time.Second)
	}

	peers := make([]equivocationPeerInternal, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if p.DID == "" || p.BaseURL == "" {
			return nil, fmt.Errorf(
				"gossipnet/equivocation_monitor: peer DID and BaseURL required (got %+v)", p)
		}
		client, err := sdkgossip.NewClient(p.BaseURL,
			sdkgossip.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf(
				"gossipnet/equivocation_monitor: NewClient(%s): %w", p.BaseURL, err)
		}
		peers = append(peers, equivocationPeerInternal{
			did: p.DID, url: p.BaseURL, client: client,
		})
	}

	return &EquivocationMonitor{
		store:      cfg.Store,
		peers:      peers,
		witnessSet: cfg.WitnessSet,
		publisher:  cfg.Publisher,
		interval:   cfg.Interval,
		logger:     cfg.Logger,
	}, nil
}

// Run drives the monitor until ctx is cancelled. Returns ctx.Err()
// on cancellation. No-op when no peers are configured.
func (m *EquivocationMonitor) Run(ctx context.Context) error {
	if len(m.peers) == 0 {
		m.logger.Info("equivocation monitor: no peers configured; loop disabled")
		return nil
	}
	m.logger.Info("equivocation monitor: started",
		"peers", len(m.peers),
		"interval", m.interval,
		"quorum_k", m.witnessSet.Quorum(),
		"witness_set_size", m.witnessSet.Size(),
		"publisher_wired", m.publisher != nil,
	)

	t := time.NewTicker(m.interval)
	defer t.Stop()

	// Initial tick on startup so a fresh boot doesn't wait the
	// full interval before the first comparison.
	m.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("equivocation monitor: stopped")
			return ctx.Err()
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// tick runs one comparison pass over every peer. Per-peer errors
// are logged but never propagated; one bad peer cannot break
// detection on healthy peers.
func (m *EquivocationMonitor) tick(ctx context.Context) {
	for _, p := range m.peers {
		m.checkPeer(ctx, p)
	}
}

// checkPeer fetches one peer's view of its own STH and compares
// against our local view of the same originator. On divergence
// → run DetectEquivocation, then verify-then-publish.
func (m *EquivocationMonitor) checkPeer(ctx context.Context, p equivocationPeerInternal) {
	peerEvent, peerFound, err := p.client.LatestSTH(ctx, p.did)
	if err != nil {
		if errors.Is(err, sdkgossip.ErrRateLimited) {
			retryAfter, _ := sdkgossip.RetryAfterFromError(err)
			m.logger.Info("equivocation monitor: peer rate-limited",
				"peer", p.url, "retry_after", retryAfter)
			return
		}
		m.logger.Warn("equivocation monitor: peer LatestSTH failed",
			"peer", p.url, "error", err)
		return
	}
	if !peerFound {
		return // peer has no STH for that originator yet
	}
	peerHead, err := decodeSTHFromEvent(peerEvent)
	if err != nil {
		m.logger.Warn("equivocation monitor: decode peer STH failed",
			"peer", p.url, "error", err)
		return
	}

	localEvent, localFound, err := m.store.LatestSTH(ctx, p.did)
	if err != nil {
		m.logger.Warn("equivocation monitor: local LatestSTH failed",
			"peer", p.url, "error", err)
		return
	}
	if !localFound {
		// We don't have any STH for this peer yet — anti-entropy
		// will fetch the peer's chain over time. No comparison
		// possible this tick.
		return
	}
	localHead, err := decodeSTHFromEvent(localEvent)
	if err != nil {
		m.logger.Warn("equivocation monitor: decode local STH failed",
			"peer", p.url, "error", err)
		return
	}

	// Compare. DetectEquivocation handles the "same root" and
	// "different sizes" cases internally — we don't pre-filter.
	// v0.1.1: K, networkID, blsVerifier all live in m.witnessSet.
	proof, err := sdkwitness.DetectEquivocation(localHead, peerHead, m.witnessSet)
	if err != nil {
		// A non-equivocation outcome is signalled by err == nil
		// + proof == nil. err != nil means a verification or
		// structural failure on at least one head.
		if errors.Is(err, sdkwitness.ErrDifferentSizes) {
			return // not equivocation; expected during normal sync
		}
		m.logger.Warn("equivocation monitor: DetectEquivocation failed",
			"peer", p.url, "error", err)
		return
	}
	if proof == nil {
		return // no divergence
	}

	// Hand the proof to the wire-shape constructor + verifier.
	// Verify(set) returns nil iff cosignatures pass K-of-N on
	// both heads. The publish contract requires the caller to
	// have observed Verify == nil before invoking Publish; we
	// enforce that here.
	finding, err := findings.NewEquivocationFinding(*proof, p.url)
	if err != nil {
		m.logger.Warn("equivocation monitor: NewEquivocationFinding rejected proof",
			"peer", p.url, "error", err)
		return
	}
	if err := finding.Verify(m.witnessSet); err != nil {
		m.logger.Warn("equivocation monitor: Verify rejected finding",
			"peer", p.url, "error", err)
		return
	}

	// Surface SMTRoot in the equivocation alarm too: a divergence
	// between local + peer SMTRoot at the same TreeSize is an
	// equivocation in its own right — two parties cannot have
	// consistent ledger projections diverge at the same chronological
	// position. The witness K-of-N cosignature binds both roots
	// (SDK v0.8.0+), so the underlying cosign.Verify path already
	// rejects a forged pair; logging both fields helps SREs
	// distinguish RootHash drift (Tessera/log-side) from SMTRoot
	// drift (state-projection-side) during forensics.
	m.logger.Error("EQUIVOCATION DETECTED",
		"peer", p.url,
		"originator", p.did,
		"tree_size", proof.TreeSize,
		"local_root", fmt.Sprintf("%x", localHead.RootHash[:8]),
		"peer_root", fmt.Sprintf("%x", peerHead.RootHash[:8]),
		"local_smt_root", fmt.Sprintf("%x", localHead.SMTRoot[:8]),
		"peer_smt_root", fmt.Sprintf("%x", peerHead.SMTRoot[:8]),
		"valid_sigs_a", proof.ValidSigsA,
		"valid_sigs_b", proof.ValidSigsB,
	)

	if m.publisher != nil {
		m.publisher.Publish(ctx, finding)
	}
}

// decodeSTHFromEvent extracts the types.CosignedTreeHead from a
// SignedEvent of Kind=KindCosignedTreeHead. The body is the
// gossip.WireCosignedTreeHeadBody shape; pass through the
// findings.CosignedTreeHeadFromWire decoder.
func decodeSTHFromEvent(ev sdkgossip.SignedEvent) (types.CosignedTreeHead, error) {
	if ev.Kind != sdkgossip.KindCosignedTreeHead {
		return types.CosignedTreeHead{}, fmt.Errorf(
			"expected KindCosignedTreeHead, got %s", ev.Kind)
	}
	var wire sdkgossip.WireCosignedTreeHeadBody
	if err := json.Unmarshal(ev.Body, &wire); err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("decode wire body: %w", err)
	}
	finding, err := findings.CosignedTreeHeadFromWire(wire)
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("CosignedTreeHeadFromWire: %w", err)
	}
	return finding.Head, nil
}
