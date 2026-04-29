/*
FILE PATH: anchor/publisher.go

Periodic anchor entry publisher. Creates commentary entries containing tree
head references, submitting them to the parent log's admission API.
Decision 44: anchors are standard entries, no special handling.

KEY ARCHITECTURAL DECISIONS:
  - Commentary entries: Target_Root=null, Authority_Path=null → zero SMT impact.
  - Destination-bound (SDK v0.3.0+): anchor entries are published to THIS log,
    so Destination = LogDID. NewUnsignedEntry rejects empty destination at
    write time.
  - Domain Payload: source_log_did, tree_head_ref (SHA-256), tree_size, timestamp.
  - Submits to the local operator's admission pipeline via submitFn.
  - Configurable interval: default 1 hour.

SDK ALIGNMENT:
  - v0.3.0: envelope.NewEntry required Destination via ValidateDestination.
  - v7.75 split entry construction into two constructors:
      envelope.NewEntry(header, payload, signatures)        — fully signed
      envelope.NewUnsignedEntry(header, payload)            — sign-then-attach
    The publisher's flow is "construct, then submit through admission",
    so it uses NewUnsignedEntry. Whatever path actually signs the
    commentary (operator's admission pipeline, SubmitViaHTTP, or a future
    operator-as-dealer signing surface) is responsible for populating
    entry.Signatures before envelope.Serialize is invoked. An entry
    without signatures fails entry.Validate() at admission, which is
    the correct failure mode for a misconfigured deployment.
*/
package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// PublisherConfig configures the anchor publisher.
type PublisherConfig struct {
	OperatorDID   string
	LogDID        string // NEW (v0.3.0): destination-binding for self-published anchors.
	Interval      time.Duration
	AnchorSources []AnchorSource
}

// AnchorSource is a remote log to anchor.
type AnchorSource struct {
	LogDID      string
	EndpointURL string // Base URL with /v1/tree/head
}

// MerkleHeadProvider returns the current Merkle tree head.
type MerkleHeadProvider interface {
	Head() (types.TreeHead, error)
}

// Publisher periodically anchors remote tree heads to the local log.
type Publisher struct {
	cfg    PublisherConfig
	merkle MerkleHeadProvider
	// submitFn submits a signed entry to the local admission pipeline.
	submitFn func(entry *envelope.Entry) error
	client   *http.Client
	logger   *slog.Logger
}

// NewPublisher creates an anchor publisher. LogDID in cfg MUST be non-empty —
// the SDK's NewUnsignedEntry will reject anchor commentary construction
// otherwise.
func NewPublisher(
	cfg PublisherConfig,
	merkle MerkleHeadProvider,
	submitFn func(entry *envelope.Entry) error,
	logger *slog.Logger,
) *Publisher {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	return &Publisher{
		cfg:      cfg,
		merkle:   merkle,
		submitFn: submitFn,
		// Tier-3 alignment: SDK's DefaultClient supplies the same
		// MaxIdleConnsPerHost=100 connection pool and 503-Retry-After
		// backpressure middleware that the SDK's submitter uses.
		// Stdlib's bare http.Client gives MaxIdleConnsPerHost=2 and
		// no 503 honoring — both biting under sustained operator
		// load.
		client: sdklog.DefaultClient(30 * time.Second),
		logger: logger,
	}
}

// Run starts the anchor publishing loop.
func (p *Publisher) Run(ctx context.Context) {
	if len(p.cfg.AnchorSources) == 0 {
		p.logger.Info("anchor: no sources configured, exiting")
		return
	}

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.publishAll(ctx)
		}
	}
}

func (p *Publisher) publishAll(ctx context.Context) {
	for _, source := range p.cfg.AnchorSources {
		if err := p.publishOne(ctx, source); err != nil {
			p.logger.Warn("anchor: publish failed",
				"source_log", source.LogDID, "error", err)
		}
	}
}

func (p *Publisher) publishOne(ctx context.Context, source AnchorSource) error {
	// Fetch remote tree head.
	req, err := http.NewRequestWithContext(ctx, "GET", source.EndpointURL+"/v1/tree/head", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch tree head: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Build anchor payload. tree_head_ref is a plain SHA-256 of the remote
	// HTTP body — this is arbitrary bytes, NOT an Entry, so crypto.HashBytes
	// is the correct primitive (envelope.EntryIdentity is for Entry-shaped
	// input only).
	treeHeadRef := crypto.HashBytes(body)
	payload, _ := json.Marshal(map[string]any{
		"anchor_type":    "tree_head_ref",
		"source_log_did": source.LogDID,
		"tree_head_ref":  fmt.Sprintf("%x", treeHeadRef[:]),
		"anchored_at":    time.Now().UTC().Format(time.RFC3339),
	})

	// Build commentary entry (Decision 44: standard entry, no special handling).
	// Destination = LogDID (the anchor lands in THIS operator's log).
	//
	// NewUnsignedEntry per the v7.75 envelope API split:
	// fully-signed callers use envelope.NewEntry(header, payload, sigs);
	// build-then-sign callers use envelope.NewUnsignedEntry. The
	// signing step happens in submitFn / SubmitViaHTTP downstream.
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.cfg.OperatorDID,
		Destination: p.cfg.LogDID,
		// EventTime: SDK exchange/policy.CheckFreshness reads
		// this via time.UnixMicro despite the doc comment
		// claiming Unix seconds. Following the doc would make
		// every self-anchor 56 years stale.
		EventTime: time.Now().UTC().UnixMicro(),
		// Target_Root=nil, Authority_Path=nil → commentary.
	}, payload)
	if err != nil {
		return fmt.Errorf("build entry: %w", err)
	}

	// Submit through local admission pipeline.
	if p.submitFn != nil {
		if err := p.submitFn(entry); err != nil {
			return fmt.Errorf("submit anchor: %w", err)
		}
	}

	p.logger.Info("anchor published",
		"source_log", source.LogDID,
		"tree_head_ref", fmt.Sprintf("%x", treeHeadRef[:8]),
	)
	return nil
}

// SubmitViaHTTP creates a submitFn that POSTs an entry's wire bytes
// to a URL. The entry MUST be signed before this function is called —
// envelope.Serialize fails on entries with empty Signatures, and
// admission rejects unsigned bytes regardless. Wrap with
// SignAndSubmit at the composition root to get a signed-and-submit
// pipeline.
func SubmitViaHTTP(targetURL string) func(entry *envelope.Entry) error {
	// Tier-3 alignment: see Publisher constructor comment for rationale.
	// Re-using the SDK's DefaultClient gives self-submit traffic the
	// same 503-Retry-After honoring the SDK's own submitter uses, so
	// the WAL-pressure 503 → wait → retry loop closes locally without
	// reinventing the policy.
	client := sdklog.DefaultClient(30 * time.Second)
	return func(entry *envelope.Entry) error {
		canonical := envelope.Serialize(entry)
		resp, err := client.Post(targetURL+"/v1/entries", "application/octet-stream",
			bytes.NewReader(canonical))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
		}
		return nil
	}
}

// SignAndSubmit wraps a submitFn (typically SubmitViaHTTP) with the
// per-entry ECDSA signing step. The returned function:
//
//  1. Verifies entry.Header.SignerDID matches signerDID — admission
//     would reject a mismatch on signature verify, so we fail fast
//     with a useful error here.
//  2. Computes sha256(envelope.SigningPayload(entry)).
//  3. Signs the hash with priv via signatures.SignEntry.
//  4. Populates entry.Signatures with one envelope.Signature whose
//     SignerDID matches Header.SignerDID and AlgoID is ECDSA.
//  5. Calls submit(entry).
//
// Used by the anchor and commitment publishers. Both call
// envelope.NewUnsignedEntry to build their entries; SignAndSubmit
// closes the contract so envelope.Serialize and admission are
// happy.
func SignAndSubmit(
	priv *ecdsa.PrivateKey,
	signerDID string,
	submit func(*envelope.Entry) error,
) func(*envelope.Entry) error {
	return func(entry *envelope.Entry) error {
		if entry.Header.SignerDID != signerDID {
			return fmt.Errorf(
				"anchor/SignAndSubmit: Header.SignerDID %q != signer DID %q (caller bug)",
				entry.Header.SignerDID, signerDID,
			)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(entry))
		sig, err := signatures.SignEntry(signingHash, priv)
		if err != nil {
			return fmt.Errorf("anchor/SignAndSubmit: SignEntry: %w", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		}}
		return submit(entry)
	}
}
