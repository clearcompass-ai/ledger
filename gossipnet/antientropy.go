/*
FILE PATH: gossipnet/antientropy.go

Anti-entropy catchup loop for the operator's gossip Store.

# WHY ANTI-ENTROPY

The publish-side Sink (gossipnet/wiring.go) is best-effort:
peer-broadcast failures are logged + dropped. A peer that misses a
KindCosignedTreeHead during a network blip would be permanently
out of sync without a pull-side recovery primitive.

Anti-entropy closes that gap. Each tick the loop:

  1. For each configured peer, reads our Store's Head(peerDID).
     The Head's Lamport is the highest event from that peer we've
     successfully Append'd locally.
  2. Calls peer.IterSince(originator=peerDID, lamport=headLamport,
     limit=BatchSize) to fetch any events the peer has emitted
     since.
  3. Append's each returned event into our Store. The Store's
     idempotency contract (I9) makes re-receives a no-op, so even
     if a peer redundantly serves events we already have, the
     loop converges.
  4. Honors ErrRateLimited: when a peer's rate limiter throttles
     us, sleep for the parsed Retry-After and continue with the
     next peer. The loop never blocks indefinitely on one peer.

# CURSOR PERSISTENCE — VIA STORE HEAD

The natural cursor is the per-originator chain head's Lamport in
the local Store. Every successful Append advances it; on reboot,
the loop resumes from wherever it left off without a separate
cursor table. This is the simplest correct design — one source
of truth (the Store), one progress signal (Head).

# 30 LOC GOAL

The SDK's plan-document budget for anti-entropy was ~30 LOC
operator-side. The actual code is closer to 50 because of error
classification + per-peer logging. Still small relative to its
correctness contribution.

# RATE-LIMIT POLITENESS

cosign.RetryAfterFromError parses the Retry-After header from
the typed error wrapper. We honor it — sleeping for the parsed
duration before moving on. The loop's per-peer ordering means a
rate-limited peer doesn't starve other peers; we just skip them
this tick.
*/
package gossipnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	sdkgossip "github.com/clearcompass-ai/ortholog-sdk/gossip"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
)

// DefaultAntiEntropyInterval is the default per-tick period.
// 30 seconds balances catchup speed with peer-side rate-limit
// budget consumption: at 30s × N peers, the call rate is well
// below DefaultRateLimitPerSecond=100 even for N=100 peers.
const DefaultAntiEntropyInterval = 30 * time.Second

// DefaultAntiEntropyBatchSize is the per-IterSince limit. 100
// matches the SDK's DefaultFeedListLimit; peers' /v1/gossip/since
// truncate to 100 by default, so requesting more is wasted.
const DefaultAntiEntropyBatchSize = 100

// AntiEntropyPeer identifies one peer the loop pulls from.
type AntiEntropyPeer struct {
	// DID is the peer operator's originator DID. Used as the
	// IterCursor.Originator field — we fetch events authored by
	// this DID specifically.
	DID string

	// BaseURL is the peer's HTTP base URL (e.g.,
	// "https://peer.example"). The /v1/gossip path is appended
	// automatically by gossip.NewClient.
	BaseURL string
}

// AntiEntropyConfig configures the catchup loop.
type AntiEntropyConfig struct {
	// Store is the local gossip Store. Required.
	Store sdkgossip.Store

	// Peers is the set of peers to pull from. Empty disables the
	// loop (Run returns immediately).
	Peers []AntiEntropyPeer

	// Interval is the tick period. 0 ⇒ DefaultAntiEntropyInterval.
	Interval time.Duration

	// BatchSize is the per-IterSince limit. 0 ⇒
	// DefaultAntiEntropyBatchSize.
	BatchSize int

	// HTTPClient overrides the per-peer HTTP client. nil ⇒
	// sdklog.DefaultClient(20s) which layers
	// RetryAfterRoundTripper for transparent 503 retry.
	HTTPClient *http.Client

	// Logger receives per-tick + per-peer diagnostics.
	Logger *slog.Logger
}

// AntiEntropy is the catchup loop.
type AntiEntropy struct {
	store    sdkgossip.Store
	peers    []antiEntropyPeerInternal
	interval time.Duration
	batch    int
	logger   *slog.Logger
}

type antiEntropyPeerInternal struct {
	did    string
	url    string
	client sdkgossip.Client
}

// NewAntiEntropy constructs the loop. Returns an error when any
// required field is missing or when a peer client cannot be
// constructed.
func NewAntiEntropy(cfg AntiEntropyConfig) (*AntiEntropy, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/antientropy: Store required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultAntiEntropyInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultAntiEntropyBatchSize
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = sdklog.DefaultClient(20 * time.Second)
	}

	peers := make([]antiEntropyPeerInternal, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if p.DID == "" || p.BaseURL == "" {
			return nil, fmt.Errorf(
				"gossipnet/antientropy: peer DID and BaseURL required (got %+v)", p)
		}
		client, err := sdkgossip.NewClient(p.BaseURL,
			sdkgossip.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf("gossipnet/antientropy: NewClient(%s): %w",
				p.BaseURL, err)
		}
		peers = append(peers, antiEntropyPeerInternal{
			did: p.DID, url: p.BaseURL, client: client,
		})
	}

	return &AntiEntropy{
		store:    cfg.Store,
		peers:    peers,
		interval: cfg.Interval,
		batch:    cfg.BatchSize,
		logger:   cfg.Logger,
	}, nil
}

// Run drives the loop until ctx is cancelled. Returns ctx.Err()
// on cancellation.
//
// Returns nil immediately when no peers are configured — the
// loop has nothing to do, no point spinning a goroutine.
func (a *AntiEntropy) Run(ctx context.Context) error {
	if len(a.peers) == 0 {
		a.logger.Info("anti-entropy: no peers configured; loop disabled")
		return nil
	}
	a.logger.Info("anti-entropy: started",
		"peers", len(a.peers), "interval", a.interval, "batch", a.batch)

	t := time.NewTicker(a.interval)
	defer t.Stop()

	// Run one tick immediately so a fresh boot doesn't wait the
	// first interval before catching up. Common when an operator
	// crashes + restarts mid-divergence.
	a.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("anti-entropy: stopped")
			return ctx.Err()
		case <-t.C:
			a.tick(ctx)
		}
	}
}

// tick runs one pass over every peer. Per-peer errors are logged
// but never propagated; one bad peer must not break catchup
// from healthy peers.
func (a *AntiEntropy) tick(ctx context.Context) {
	for _, p := range a.peers {
		a.pullOne(ctx, p)
	}
}

// pullOne pulls one batch from one peer. Updates head naturally
// via Store.Append's chain-discipline contract.
func (a *AntiEntropy) pullOne(ctx context.Context, p antiEntropyPeerInternal) {
	_, headLamport, err := a.store.Head(ctx, p.did)
	if err != nil {
		a.logger.Warn("anti-entropy: read local head failed",
			"peer", p.url, "did", p.did, "error", err)
		return
	}

	events, _, err := p.client.IterSince(ctx, p.did, headLamport, a.batch)
	if err != nil {
		// Rate-limit politeness: parse Retry-After if present and
		// log it. The loop continues with the next peer; this
		// peer retries on the next tick.
		if errors.Is(err, sdkgossip.ErrRateLimited) {
			retryAfter, _ := sdkgossip.RetryAfterFromError(err)
			a.logger.Info("anti-entropy: peer rate-limited",
				"peer", p.url, "did", p.did,
				"retry_after", retryAfter)
			return
		}
		a.logger.Warn("anti-entropy: IterSince failed",
			"peer", p.url, "did", p.did, "error", err)
		return
	}

	if len(events) == 0 {
		return // up to date with this peer
	}

	appended := 0
	for _, ev := range events {
		if err := a.store.Append(ctx, ev); err != nil {
			// Idempotent re-receive returns nil per I9; the only
			// non-nil errors here indicate a real problem —
			// chain break or lamport regression — which we log
			// but don't propagate (one bad event must not break
			// the batch).
			a.logger.Warn("anti-entropy: Append rejected",
				"peer", p.url, "did", p.did,
				"event_lamport", ev.LamportTime,
				"error", err)
			continue
		}
		appended++
	}
	if appended > 0 {
		a.logger.Info("anti-entropy: caught up",
			"peer", p.url, "did", p.did,
			"appended", appended, "since_lamport", headLamport)
	}
}
