/*
FILE PATH: witness/head_sync.go

K-of-N cosignature collection over the SDK's universal cosign wire
surface. Implements builder.WitnessCosigner.

# WHY THIS WRAPPER EXISTS

The SDK ships cosign.WitnessClient (per-endpoint HTTP client) and
cosign.WitnessCollector (K-of-N parallel collector with short-circuit
cancellation on the K-th valid signature). HeadSync glues those to:

  - The ledger's TreeHeadStore — persists the (head + per-witness
    signatures) tuple so downstream readers (api/, anchor publisher,
    audit consumers) see a single materialized record per signed
    head.
  - builder.WitnessCosigner — the builder loop calls
    RequestCosignatures(ctx, head) after each successful commit;
    this file maps that call into the universal cosign primitive.

# 429 / RATE-LIMIT BACKPRESSURE

Per-endpoint rate-limit rejections surface as cosign.ErrRateLimited;
RetryAfterFromError reads the parsed Retry-After. The collector
treats them as per-endpoint failures and continues fanning out to
the remaining endpoints — quorum still has K-1 other tries. The
collector returns ErrQuorumCollectionFailed only if the
unrecoverable failures (rate-limit + network + 5xx aggregate) leave
fewer than K endpoints capable of returning a valid signature.

The ledger-side action on rate-limit failure is to log and
continue; the next builder cycle re-requests cosignatures on a
larger tree head. This is correct because cosignatures are
per-head; the witness signing the next cycle's head is identical
work.

# 503 / Retry-After BACKPRESSURE

cosign.WithHTTPClient(sdklog.DefaultClient(timeout)) layers
RetryAfterRoundTripper underneath; transient 503s with a
Retry-After header are transparently retried by the transport
before the cosign client sees them. The 429-rate-limit and
5xx-witness-failure paths above run only after the transport
retries are exhausted.
*/
package witness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// CosignedHeadPublisher is the interface HeadSync calls after a
// successful K-of-N collection to fan out a KindCosignedTreeHead
// gossip event. nil is acceptable — when no publisher is wired,
// HeadSync skips the publish step.
type CosignedHeadPublisher interface {
	PublishCosignedHead(ctx context.Context, head types.CosignedTreeHead)
}

// HeadSyncConfig configures witness cosignature collection.
type HeadSyncConfig struct {
	// WitnessEndpoints is the set of peer witness base URLs (one
	// per witness in the N-of-N set). Each endpoint is wrapped in
	// a cosign.WitnessClient at startup; clients are reused across
	// every RequestCosignatures call.
	WitnessEndpoints []string

	// QuorumK is the minimum number of valid signatures required
	// to consider a head "cosigned". 1 <= QuorumK <= N (where N is
	// len(WitnessEndpoints)). The collector short-circuits as soon
	// as the K-th valid signature arrives.
	QuorumK int

	// PerWitnessTimeout caps the per-endpoint HTTP request. The
	// collector's per-call ctx is whatever the builder loop passed
	// in; setting a per-witness timeout floors it so a single slow
	// peer cannot stall the cycle past PerWitnessTimeout regardless
	// of the parent ctx's deadline.
	PerWitnessTimeout time.Duration

	// NetworkID binds every cosign request to the deployment's
	// network. Witnesses for the same network share this value;
	// signatures produced under one NetworkID never satisfy quorum
	// under another.
	NetworkID cosign.NetworkID

	// GossipPublisher, when non-nil, is invoked after each
	// successful K-of-N collection with the assembled
	// CosignedTreeHead. The publisher is responsible for signing
	// the event as a KindCosignedTreeHead and broadcasting it to
	// peers via the gossip Sink. Optional; nil disables the
	// publish step (useful for read-only ledgers or trimmed
	// test rigs).
	GossipPublisher CosignedHeadPublisher
}

// HeadSync manages tree head cosignature collection.
// Implements builder.WitnessCosigner.
type HeadSync struct {
	cfg HeadSyncConfig
	collector *cosign.WitnessCollector
	endpoints []string // parallel to collector's clients; for persistence labels
	store *store.TreeHeadStore
	logger *slog.Logger
	publisher CosignedHeadPublisher
}

// NewHeadSync constructs the head sync manager. Returns an error
// if the SDK collector rejects the witness configuration (zero
// NetworkID, K > N, K <= 0, empty endpoints, etc.).
func NewHeadSync(cfg HeadSyncConfig, treeStore *store.TreeHeadStore, logger *slog.Logger) (*HeadSync, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(cfg.WitnessEndpoints) == 0 {
		return nil, fmt.Errorf("witness/head_sync: WitnessEndpoints required")
	}
	if cfg.QuorumK <= 0 {
		return nil, fmt.Errorf("witness/head_sync: QuorumK must be > 0")
	}
	if cfg.PerWitnessTimeout <= 0 {
		cfg.PerWitnessTimeout = 30 * time.Second
	}

	// SDK transport with RetryAfterRoundTripper for transparent
	// 503-Retry-After honoring. The 429-rate-limit case surfaces
	// as cosign.ErrRateLimited (handled per-call below); 503 is
	// retried inside the transport before the cosign client sees
	// it.
	httpClient := sdklog.DefaultClient(cfg.PerWitnessTimeout)

	clients := make([]*cosign.WitnessClient, 0, len(cfg.WitnessEndpoints))
	for _, ep := range cfg.WitnessEndpoints {
		c, err := cosign.NewWitnessClient(ep, cfg.NetworkID,
			cosign.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf("witness/head_sync: build client %s: %w", ep, err)
		}
		clients = append(clients, c)
	}

	collector, err := cosign.NewWitnessCollector(clients, cfg.QuorumK)
	if err != nil {
		return nil, fmt.Errorf("witness/head_sync: build collector: %w", err)
	}

	return &HeadSync{
		cfg:       cfg,
		collector: collector,
		endpoints: append([]string{}, cfg.WitnessEndpoints...),
		store:     treeStore,
		logger:    logger,
		publisher: cfg.GossipPublisher,
	}, nil
}

// Collector exposes the underlying K-of-N collector so other
// services (escrow override endpoint, future rotation publisher)
// can submit alternate CosignPayload types — e.g.,
// cosign.EscrowOverridePayload or cosign.RotationPayload —
// against the same witness peer set without standing up a
// parallel client pool. The collector is purpose-agnostic: each
// Collect call's payload determines the cosign canonical bytes
// being signed.
func (hs *HeadSync) Collector() *cosign.WitnessCollector {
	if hs == nil {
		return nil
	}
	return hs.collector
}

// RequestCosignatures implements builder.WitnessCosigner.
// Collects K-of-N cosignatures via the SDK collector and persists
// the (head + per-witness signatures) tuple. Non-fatal: the builder
// loop continues even on quorum failure (the next cycle re-requests
// against a larger head).
func (hs *HeadSync) RequestCosignatures(ctx context.Context, head types.TreeHead) error {
	if hs == nil || hs.collector == nil {
		return nil
	}

	payload := cosign.NewTreeHeadPayload(head)
	result, err := hs.collector.Collect(ctx, payload)
	if err != nil {
		hs.logQuorumFailure(err, result, head)
		return fmt.Errorf("witness/head_sync: collect: %w", err)
	}

	// Persist the head fact (idempotent) before any per-witness
	// signature so the FK on tree_head_sigs.tree_size is satisfied.
	const hashAlgo = uint16(1) // SHA-256 — the deployment-lifetime default.
	if perr := hs.store.InsertHead(ctx, head.TreeSize, head.RootHash, hashAlgo); perr != nil {
		return fmt.Errorf("witness/head_sync: persist head: %w", perr)
	}

	// Persist each per-witness signature. The signer label is the
	// endpoint URL of the witness that returned the signature; the
	// SDK collector preserves endpoint ordering in CollectionResult
	// when the K-th signature arrives, but the slice is K-of-N so
	// we look up the originating endpoint via the per-endpoint
	// outcome map.
	if perr := hs.persistSignatures(ctx, head, result, hashAlgo); perr != nil {
		return perr
	}

	hs.store.Invalidate()
	hs.logger.Info("cosigned tree head",
		"tree_size", head.TreeSize,
		"signatures", len(result.Signatures),
		"quorum_k", hs.cfg.QuorumK,
		"quorum_n", len(hs.endpoints),
	)

	// Gossip publish (best-effort; never fails the commit path).
	// Composing the CosignedTreeHead here from the just-collected
	// signatures keeps the publish payload synchronized with the
	// persisted state — both rows in tree_head_sigs and the gossip
	// finding's body carry the same K-of-N evidence.
	if hs.publisher != nil {
		cosignedHead := types.CosignedTreeHead{
			TreeHead:   head,
			Signatures: result.Signatures,
		}
		hs.publisher.PublishCosignedHead(ctx, cosignedHead)
	}
	return nil
}

// persistSignatures inserts each collected signature into
// tree_head_sigs. Each row is (tree_size, hash_algo, signer,
// sig_algo, signature_bytes).
//
// The SDK collector's CollectionResult.Signatures slice contains the
// K successfully-collected signatures; PerEndpoint[i].Err == nil
// identifies which endpoints contributed. The signature payload is
// JSON-encoded for the row's `signature` BYTEA column — the SDK type
// fields are opaque to the ledger's persistence layer; downstream
// consumers parse it back via json.Unmarshal into
// types.WitnessSignature.
func (hs *HeadSync) persistSignatures(
	ctx context.Context,
	head types.TreeHead,
	result *cosign.CollectionResult,
	hashAlgo uint16,
) error {
	if result == nil {
		return nil
	}
	contributingEndpoints := make([]string, 0, len(result.Signatures))
	for i, ep := range result.PerEndpoint {
		if ep.Err == nil && i < len(hs.endpoints) {
			contributingEndpoints = append(contributingEndpoints, hs.endpoints[i])
		}
		if len(contributingEndpoints) >= len(result.Signatures) {
			break
		}
	}

	for i, sig := range result.Signatures {
		signer := fmt.Sprintf("witness:%d", i)
		if i < len(contributingEndpoints) {
			signer = contributingEndpoints[i]
		}
		raw, encErr := json.Marshal(sig)
		if encErr != nil {
			return fmt.Errorf("witness/head_sync: encode sig %s: %w", signer, encErr)
		}
		if perr := hs.store.InsertSig(ctx, head.TreeSize, hashAlgo,
			signer, uint16(sig.SchemeTag), raw); perr != nil {
			return fmt.Errorf("witness/head_sync: persist sig %s: %w", signer, perr)
		}
	}
	return nil
}

// logQuorumFailure emits a structured per-endpoint diagnostic when
// the SDK collector returns ErrQuorumCollectionFailed. ErrRateLimited
// causes are tagged separately so ledgers reading logs can
// distinguish "everyone's overloaded" from "everyone's broken".
func (hs *HeadSync) logQuorumFailure(err error, result *cosign.CollectionResult, head types.TreeHead) {
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		return
	}
	if result == nil {
		return
	}
	rateLimited := 0
	otherFail := 0
	for _, ep := range result.PerEndpoint {
		if ep.Err == nil {
			continue
		}
		if errors.Is(ep.Err, cosign.ErrRateLimited) {
			rateLimited++
		} else {
			otherFail++
		}
	}
	hs.logger.Warn("witness quorum failed",
		"tree_size", head.TreeSize,
		"got_sigs", len(result.Signatures),
		"need_k", hs.cfg.QuorumK,
		"rate_limited", rateLimited,
		"other_failures", otherFail,
	)
}
