/*
FILE PATH: gossipnet/wiring.go

Ledger-side gossip plumbing: connects the SDK's gossip handler /
feed handler / cached DID verifier / buffered sink to the
ledger's BadgerStore-backed gossip.Store and the cmd/ledger
main.go startup sequence.

# WHY THIS PACKAGE

The SDK ships every gossip primitive (Store interface, Handler,
FeedHandler, Sink, OriginatorVerifier) as an independent component.
The ledger owns the choices a single-deployment binary makes:

  - Which Store implementation? (gossipstore.BadgerStore)
  - Which DID verifiers are in scope? (did:key today; did:web later)
  - What rate-limit policy? (crypto/middleware token bucket)
  - What sink topology? (BufferedSink → MultiSink over peer
    ledgers, or NopSink in single-process tests)
  - What cache TTL on the originator key resolver?

Bundling these decisions into one wiring helper keeps
cmd/ledger/main.go from carrying ~200 lines of plumbing for a
sub-feature.

# RATE LIMITING

The cosign endpoint and the gossip endpoint are independently
rate-limited. Sharing a single middleware instance (and therefore
a single token bucket per peer-IP) would let a noisy gossip
publisher starve cosign requests from the same peer. Two
middleware instances keep the budgets independent.

# ORIGINATOR-VERIFIER CACHE

CachedDIDOriginatorVerifier wraps the base DIDOriginatorVerifier
with an LRU+TTL of resolved PubKeyIDs. The handler invokes
Invalidate(originator) automatically after a successful
KindOriginatorRotation Append, so cached entries that rotated mid-
session don't poison subsequent verifies. TTL is the failure
budget for a rotation that bypasses the gossip publishing path
(should not happen, but bounded staleness is the safe default).

# FAN-OUT TOPOLOGY

Single-network deployments use NopSink — the ledger's own
BadgerStore is the only consumer; nothing to fan out to.

Multi-network deployments wrap a MultiSink over an HTTPSink per
peer ledger's /v1/gossip endpoint. The MultiSink is wrapped in a
BufferedSink so the publish call site (builder loop hot path)
never blocks on slow peers. Drop policy = DropOldest so a
persistently-slow peer doesn't accumulate unbounded backlog.
*/
package gossipnet

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/middleware"
	"github.com/clearcompass-ai/attesta/did"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"go.opentelemetry.io/otel/metric"
)

// Config bundles everything gossipnet.Build needs to wire the
// ledger's gossip stack.
type Config struct {
	// Store is the persistent gossip store. Required.
	Store sdkgossip.Store

	// NetworkID is the deployment's cosign-domain identifier.
	// Required (non-zero).
	NetworkID sdkcosign.NetworkID

	// PeerEndpoints is the set of base URLs of peer ledgers
	// running their own /v1/gossip endpoint. Empty ⇒ NopSink
	// (no fan-out; single-process or single-ledger deployment).
	PeerEndpoints []string

	// RateLimitRPS is the per-peer-IP rate limit on /v1/gossip.
	// 0 ⇒ middleware default (100 RPS). Negative ⇒ no rate
	// limiting (only for trusted-network test rigs).
	RateLimitRPS float64

	// RateLimitBurst is the per-peer-IP burst cap. 0 ⇒ middleware
	// default (200).
	RateLimitBurst int

	// FeedRateLimitRPS is the per-peer-IP rate limit on
	// /v1/gossip/{since,sth/latest,event,by-kind}. Audit
	// consumers fan out reads more than writers fan out writes;
	// this is typically higher than RateLimitRPS. 0 ⇒ middleware
	// default (100 RPS).
	FeedRateLimitRPS float64

	// VerifierCacheTTL is the LRU+TTL of resolved PubKeyIDs in the
	// CachedDIDOriginatorVerifier. 0 ⇒ SDK default (5 minutes).
	VerifierCacheTTL time.Duration

	// VerifierCacheSize is the max entries in the LRU. 0 ⇒ SDK
	// default (4096).
	VerifierCacheSize int

	// SinkQueueSize sizes the BufferedSink queue. Only consulted
	// when PeerEndpoints is non-empty. 0 ⇒ DefaultSinkQueueSize.
	SinkQueueSize int

	// HTTPClient overrides the HTTP client used by the per-peer
	// gossip clients. nil ⇒ SDK default (with retry on 503).
	HTTPClient *http.Client

	// Meter, if non-nil, drives the gossip subsystem's OTel
	// instruments (received_total, published_total,
	// verify_duration_seconds, queue_depth, drops_total). When
	// nil, gossip.NewInstruments is skipped and the handler /
	// sink run un-instrumented.
	Meter metric.Meter

	// Logger receives diagnostics. nil ⇒ slog.Default().
	Logger *slog.Logger
}

// DefaultSinkQueueSize is the BufferedSink queue depth when
// Config.SinkQueueSize is zero. 1024 absorbs ~1 second of peak
// (1K TPS) commits before drop-oldest kicks in; longer than that
// the sink is genuinely overwhelmed and dropping is the right
// call (lower-priority finding events shouldn't block the commit
// path).
const DefaultSinkQueueSize = 1024

// Bundle holds the constructed gossip components. The caller mounts
// PostHandler at POST /v1/gossip and FeedHandler at GET
// /v1/gossip/{since,sth/latest,event,by-kind}.
//
// Sink is the fan-out destination for ledger-published events
// (KindCosignedTreeHead from the commit hot path,
// KindEquivocationFinding from the equivocation monitor). It is
// safe to publish into Sink even when no peers are configured —
// the wiring sets it to NopSink in that case.
//
// Closeables groups every component the caller should Close on
// shutdown, in the right order (sink first to drain queues, then
// the handlers to release ServeHTTP refs, then the store to flush
// in-flight Appends — though the underlying *badger.DB is owned
// by wal/ and closed there).
type Bundle struct {
	PostHandler http.Handler
	FeedHandler http.Handler
	Sink        sdkgossip.Sink

	// Verifier is the rotation-aware, LRU-cached originator
	// verifier. Implements:
	//   - sdkgossip.OriginatorVerifier (for handler verification)
	//   - sdkgossip.OriginatorKeyManager (so handler.applyRotation
	//     can record KindOriginatorRotation events into the
	//     rotated-key map)
	//   - sdkgossip.PubKeyResolver (so handler can cross-check
	//     SignedEvent.PubKeyID against the resolved key — H3)
	//   - cacheInvalidator (Invalidate(originator)) — so
	//     handler post-rotation evicts the stale cached key
	Verifier *RotationCachedVerifier

	// Closeables are the gossip-side Closeable instances. The
	// caller's shutdown ordering should Close these in slice
	// order (sink → post handler → feed handler → store).
	Closeables []sdkgossip.Closeable
}

// RotationCachedVerifier composes:
//
//   - DIDOriginatorVerifier (resolves did:key →
//     types.WitnessPublicKey + verifies signatures)
//   - CachedDIDOriginatorVerifier (LRU+TTL on resolved
//     PubKeyIDs)
//   - InMemoryKeyManager (rotation override map; falls
//     through to the cached verifier when no rotation is
//     present)
//
// The composition is the single value the gossip Handler holds
// as Verifier. Without composing all three, the SDK Handler's
// type-assertions for OriginatorKeyManager + cacheInvalidator
// would fail and KindOriginatorRotation events would store but
// not actually rotate keys — leaving subsequent verifications
// against the old key (a stale-key attack window).
type RotationCachedVerifier struct {
	keyMgr *sdkgossip.InMemoryKeyManager
	cached *sdkgossip.CachedDIDOriginatorVerifier
}

// VerifyOriginator implements sdkgossip.OriginatorVerifier.
// Routes through the keyMgr so rotation overrides apply
// before falling through to the cached resolver.
func (v *RotationCachedVerifier) VerifyOriginator(
	ctx context.Context, originator string, digest [32]byte, sigBytes []byte, schemeTag uint8,
) error {
	return v.keyMgr.VerifyOriginator(ctx, originator, digest, sigBytes, schemeTag)
}

// ResolvePubKeyID implements sdkgossip.PubKeyResolver. The
// keyMgr's ResolvePubKeyID either returns the rotated PubKeyID
// or delegates to its wrapped verifier (cached) which provides
// LRU+TTL.
func (v *RotationCachedVerifier) ResolvePubKeyID(ctx context.Context, originator string) ([32]byte, error) {
	return v.keyMgr.ResolvePubKeyID(ctx, originator)
}

// RotateOriginator implements sdkgossip.OriginatorKeyManager.
// Called by the SDK Handler's applyRotation after a successful
// KindOriginatorRotation Append.
func (v *RotationCachedVerifier) RotateOriginator(
	ctx context.Context, originator string, newPublicKey []byte, checkpoint [32]byte,
) error {
	return v.keyMgr.RotateOriginator(ctx, originator, newPublicKey, checkpoint)
}

// Invalidate implements the cacheInvalidator interface the SDK
// Handler casts to. Called post-rotation to evict any cached
// pre-rotation PubKeyID for this originator (B7 stale-key
// attack closure).
func (v *RotationCachedVerifier) Invalidate(originator string) {
	v.cached.Invalidate(originator)
}

// Build constructs the ledger's gossip stack from cfg. Returns
// the Bundle and any construction error.
func Build(cfg Config) (*Bundle, error) {
	// NetworkID FIRST — security-critical (T-9 domain separation).
	// Other "required" checks below are correctness-critical.
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet: Config.NetworkID required (non-zero)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet: Config.Store required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	verifier, err := buildVerifier(cfg)
	if err != nil {
		return nil, err
	}

	// gossip.Instruments — wire OTel observability when a Meter
	// is supplied. nil cfg.Meter is the no-op path; downstream
	// gossip components tolerate nil instruments by design.
	var instruments *sdkgossip.Instruments
	if cfg.Meter != nil {
		instruments, err = sdkgossip.NewInstruments(cfg.Meter, cfg.Store)
		if err != nil {
			return nil, fmt.Errorf("gossipnet: NewInstruments: %w", err)
		}
	}

	sink, sinkClose, err := buildSink(cfg, instruments)
	if err != nil {
		return nil, err
	}

	postHandler, err := sdkgossip.NewHandler(sdkgossip.HandlerConfig{
		Store:           cfg.Store,
		Verifier:        verifier,
		AllowedNetworks: map[sdkcosign.NetworkID]struct{}{cfg.NetworkID: {}},
		Sink:            sink,
		Logger:          cfg.Logger,
		Instruments:     instruments,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewHandler: %w", err)
	}

	// Instruments is shared with the POST handler (constructed
	// above): attesta SDK v0.5.0 added an Instruments field to
	// FeedHandlerConfig so feed-side panics flow into the same
	// attesta_gossip_panic_total counter as the POST side. Nil-
	// tolerant when LEDGER_METRICS_ENABLE=false (instruments is
	// nil in that case); the SDK's recoverPanic accepts a nil
	// receiver.
	feedHandler, err := sdkgossip.NewFeedHandler(sdkgossip.FeedHandlerConfig{
		Store:       cfg.Store,
		Logger:      cfg.Logger,
		Instruments: instruments,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewFeedHandler: %w", err)
	}

	postWithMiddleware := wrapRateLimit(
		postHandler,
		cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.Logger,
	)
	feedWithMiddleware := wrapRateLimit(
		feedHandler,
		cfg.FeedRateLimitRPS, cfg.RateLimitBurst, cfg.Logger,
	)

	closeables := []sdkgossip.Closeable{}
	if sinkClose != nil {
		closeables = append(closeables, sinkClose)
	}
	closeables = append(closeables, postHandler, feedHandler)

	return &Bundle{
		PostHandler: postWithMiddleware,
		FeedHandler: feedWithMiddleware,
		Sink:        sink,
		Verifier:    verifier,
		Closeables:  closeables,
	}, nil
}

// buildVerifier constructs the rotation-aware, LRU-cached
// originator verifier. Composition order (innermost → outermost):
//
//  1. DIDOriginatorVerifier(registry) — knows did:key today;
//     additional methods register alongside.
//  2. CachedDIDOriginatorVerifier(base) — LRU+TTL on
//     ResolvePubKeyID. Caches the (originator → PubKeyID)
//     mapping so the gossip handler's H3 cross-check is O(1)
//     after warmup.
//  3. InMemoryKeyManager(cached) — rotation override map.
//     Tracks (originator → rotated key) entries written via
//     RotateOriginator after a verified KindOriginatorRotation
//     event lands.
//
// The composed RotationCachedVerifier exposes the union of the
// three packages' interfaces (Verify + Resolve + Rotate +
// Invalidate) on a single value the SDK Handler can type-assert
// against. Decomposing into three returns + asking the ledger
// to pass each individually would require Handler API changes
// upstream; composing here keeps the SDK boundary stable.
func buildVerifier(cfg Config) (*RotationCachedVerifier, error) {
	registry := did.NewVerifierRegistry()
	if err := registry.Register("key", did.NewKeyVerifier()); err != nil {
		return nil, fmt.Errorf("gossipnet: register did:key: %w", err)
	}
	base, err := sdkgossip.NewDIDOriginatorVerifier(registry)
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewDIDOriginatorVerifier: %w", err)
	}

	opts := []sdkgossip.CachedOption{}
	if cfg.VerifierCacheTTL > 0 {
		opts = append(opts, sdkgossip.WithCachedTTL(cfg.VerifierCacheTTL))
	}
	if cfg.VerifierCacheSize > 0 {
		opts = append(opts, sdkgossip.WithCachedMaxEntries(cfg.VerifierCacheSize))
	}
	cached, err := sdkgossip.NewCachedDIDOriginatorVerifier(base, opts...)
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewCachedDIDOriginatorVerifier: %w", err)
	}
	keyMgr, err := sdkgossip.NewInMemoryKeyManager(cached)
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewInMemoryKeyManager: %w", err)
	}
	return &RotationCachedVerifier{keyMgr: keyMgr, cached: cached}, nil
}

// buildSink constructs the fan-out sink. Returns NopSink + nil
// closeable when no peers are configured; otherwise wires
// MultiSink(over HTTPSink-per-peer) inside a BufferedSink.
//
// The second return value is the Closeable for the BufferedSink
// (caller's shutdown drains the queue). For NopSink the
// closeable is nil — nothing to flush.
func buildSink(cfg Config, instruments *sdkgossip.Instruments) (sdkgossip.Sink, sdkgossip.Closeable, error) {
	if len(cfg.PeerEndpoints) == 0 {
		return sdkgossip.NopSink, nil, nil
	}
	peerSinks := make([]sdkgossip.Sink, 0, len(cfg.PeerEndpoints))
	for _, ep := range cfg.PeerEndpoints {
		opts := []sdkgossip.ClientOption{}
		if cfg.HTTPClient != nil {
			opts = append(opts, sdkgossip.WithHTTPClient(cfg.HTTPClient))
		}
		client, err := sdkgossip.NewClient(ep, opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("gossipnet: NewClient(%s): %w", ep, err)
		}
		sink, err := sdkgossip.NewHTTPSink(client)
		if err != nil {
			return nil, nil, fmt.Errorf("gossipnet: NewHTTPSink(%s): %w", ep, err)
		}
		peerSinks = append(peerSinks, sink)
	}
	multiOpts := []sdkgossip.MultiSinkOption{}
	if instruments != nil {
		multiOpts = append(multiOpts, sdkgossip.WithMultiSinkInstruments(instruments))
	}
	multi, err := sdkgossip.NewMultiSink(peerSinks, multiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("gossipnet: NewMultiSink: %w", err)
	}

	queueSize := cfg.SinkQueueSize
	if queueSize <= 0 {
		queueSize = DefaultSinkQueueSize
	}
	buffered, err := sdkgossip.NewBufferedSink(sdkgossip.BufferedSinkConfig{
		Underlying:  multi,
		QueueSize:   queueSize,
		Workers:     1,
		Policy:      sdkgossip.DropPolicyDropOldest,
		Logger:      cfg.Logger,
		Instruments: instruments,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("gossipnet: NewBufferedSink: %w", err)
	}
	return buffered, buffered, nil
}

// wrapRateLimit applies the rate-limit middleware unless rps is
// negative (test/trusted-network bypass).
func wrapRateLimit(h http.Handler, rps float64, burst int, logger *slog.Logger) http.Handler {
	if rps < 0 {
		return h
	}
	cfg := middleware.RateLimitConfig{
		RatePerSecond: rps,
		BurstSize:     burst,
	}
	return middleware.NewRateLimitMiddleware(cfg)(h)
}
