/*
FILE PATH: witness/commitment_equivocation_alert.go

Webhook publisher for cryptographic-commitment equivocation
incidents per Wave 1 v3 §S3.

Decoupled from the detector (witness/commitment_equivocation_monitor.go)
so a transient webhook outage does not block evidence persistence.
The monitor records evidence in commitment_equivocation_proofs the
moment a SplitID collision is detected; this publisher drains the
"undelivered alerts" backlog at its own cadence and marks each row
alert_dispatched_at = NOW() once the webhook acknowledges.

Wave 1 v3 §S3 contract:

  - Structured webhook publication to a configurable governance
    endpoint with the canonical bytes of both (or all N)
    equivocating entries plus their tree-head references.
  - Documented payload schema (see CommitmentEquivocationAlertPayload
    below) so downstream governance integrations have a stable
    contract.
  - ClearCompass governance consumer ships in Wave 2; this file is
    just the publisher + payload schema.

Failure handling: a non-2xx HTTP response or a transport error
leaves alert_dispatched_at NULL; the next scan picks the row back
up. Backoff on repeated failures is intentionally simple (a single
PollInterval) — operators inspecting the partial index see the
backlog and can investigate. Sophisticated retry policy is a
deployment concern, not a publisher concern.

Schema bind: the payload's `entries` array carries (sequence_number,
canonical_bytes_hex) tuples sourced from Tessera via the supplied
EntryByteFetcher. Canonical bytes ARE included here (unlike the
evidence row itself which holds only sequence numbers) because
governance endpoints often live outside the operator's network and
cannot fetch from Tessera directly. The hex inflation is acceptable
for an alert payload that fires at most once per equivocation
incident.
*/
package witness

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// CommitmentEquivocationAlertConfig configures the publisher.
type CommitmentEquivocationAlertConfig struct {
	// WebhookURL is the governance endpoint that receives
	// CommitmentEquivocationAlertPayload via HTTP POST. Empty
	// disables the publisher (Run returns immediately) — useful
	// in dev and test deployments where evidence is collected but
	// not escalated.
	WebhookURL string

	// PollInterval is the wait between successive backlog drains.
	// Defaults to 60 seconds when zero. The unalerted-incidents
	// partial index in store/postgres.go means the scan cost is
	// O(unalerted) regardless of total incident count.
	PollInterval time.Duration

	// HTTPTimeout is the per-request timeout for the webhook call.
	// Defaults to 30 seconds when zero. Long enough to accommodate
	// distant governance endpoints, short enough that a single
	// hung endpoint does not back up the publisher loop.
	HTTPTimeout time.Duration

	// LogDID identifies this operator in the alert payload so
	// governance can attribute equivocation reports to the right
	// log without out-of-band correlation.
	LogDID string
}

// EntryByteFetcher returns the canonical wire bytes for a sequence
// number. Implementations include the operator's existing
// bytestore.Reader and lifecycle/archive_reader.go for entries
// in archived shards. The publisher accepts the interface (rather
// than a concrete type) so test deployments can substitute a stub.
type EntryByteFetcher interface {
	FetchCanonicalBytes(ctx context.Context, sequence uint64) ([]byte, error)
}

// ─────────────────────────────────────────────────────────────────────
// Wire payload — stable governance contract
// ─────────────────────────────────────────────────────────────────────

// CommitmentEquivocationAlertEntry is one element of the payload's
// entries array, carrying the sequence number and canonical wire
// bytes of one equivocating entry.
type CommitmentEquivocationAlertEntry struct {
	SequenceNumber    uint64 `json:"sequence_number"`
	CanonicalBytesHex string `json:"canonical_bytes_hex"`
}

// CommitmentEquivocationAlertPayload is the JSON body POSTed to the
// configured webhook for each newly-detected equivocation incident.
//
// Field set is the governance contract:
//
//   - LogDID         — which operator detected the incident
//   - SchemaID       — pre-grant-commitment-v1 OR
//                      escrow-split-commitment-v1
//   - SplitIDHex     — 64-char lowercase hex of the colliding
//                      32-byte SplitID
//   - Entries        — every equivocating entry's (sequence,
//                      canonical_bytes_hex). Length always >= 2.
//   - FirstDetectedAt — RFC3339Nano UTC timestamp of the first
//                       detection scan that surfaced the incident
//   - DispatchedAt   — RFC3339Nano UTC timestamp of this dispatch
//                      attempt (governance can use this to dedupe
//                      retries triggered by transient failures)
//
// The payload is intentionally flat — no nested envelopes — so
// governance endpoints can write a one-line schema validator
// (e.g. JSONSchema) without arming for arbitrary nesting depth.
type CommitmentEquivocationAlertPayload struct {
	LogDID          string                             `json:"log_did"`
	SchemaID        string                             `json:"schema_id"`
	SplitIDHex      string                             `json:"split_id_hex"`
	Entries         []CommitmentEquivocationAlertEntry `json:"entries"`
	FirstDetectedAt string                             `json:"first_detected_at"`
	DispatchedAt    string                             `json:"dispatched_at"`
}

// ─────────────────────────────────────────────────────────────────────
// Publisher
// ─────────────────────────────────────────────────────────────────────

// CommitmentEquivocationAlertPublisher drains the unalerted-
// incidents backlog and POSTs each to the configured webhook.
type CommitmentEquivocationAlertPublisher struct {
	cfg     CommitmentEquivocationAlertConfig
	db      *pgxpool.Pool
	fetcher EntryByteFetcher
	client  *http.Client
	logger  *slog.Logger
}

// NewCommitmentEquivocationAlertPublisher constructs a publisher.
// Returns nil if WebhookURL is empty — the caller can still wire
// it into the operator's lifecycle without branching, and Run
// becomes a no-op.
func NewCommitmentEquivocationAlertPublisher(
	cfg CommitmentEquivocationAlertConfig,
	db *pgxpool.Pool,
	fetcher EntryByteFetcher,
	logger *slog.Logger,
) *CommitmentEquivocationAlertPublisher {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	return &CommitmentEquivocationAlertPublisher{
		cfg:     cfg,
		db:      db,
		fetcher: fetcher,
		// Tier-3 alignment: SDK's DefaultClient gives connection
		// pooling and 503-Retry-After honoring. Webhook receivers
		// are typically governance endpoints fronted by load
		// balancers that surface 503 + Retry-After under burst
		// load; honoring it locally avoids dropping equivocation
		// alerts during exactly the windows when they're most
		// urgent to deliver.
		client: sdklog.DefaultClient(cfg.HTTPTimeout),
		logger: logger,
	}
}

// Run drains the backlog on PollInterval until ctx is cancelled.
// MUST be called from a single goroutine per operator instance —
// concurrent runs would compete for the same UPDATE rows and waste
// webhook calls on already-dispatched incidents.
//
// If WebhookURL is empty, Run logs that the publisher is disabled
// and returns immediately. Evidence collection in
// commitment_equivocation_proofs continues regardless; the unalerted
// backlog grows until a future deployment configures a webhook.
func (p *CommitmentEquivocationAlertPublisher) Run(ctx context.Context) {
	if p.cfg.WebhookURL == "" {
		p.logger.Info("commitment equivocation alert publisher disabled (no webhook URL)")
		return
	}

	p.logger.Info("commitment equivocation alert publisher started",
		"webhook", p.cfg.WebhookURL,
		"poll_interval", p.cfg.PollInterval)

	// Drain on first iteration so any backlog accumulated during
	// downtime escalates promptly on restart.
	if err := p.drain(ctx); err != nil {
		if !isContextError(err) {
			p.logger.Error("commitment equivocation alert drain failed",
				"error", err)
		}
	}

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("commitment equivocation alert publisher stopped")
			return
		case <-ticker.C:
			if err := p.drain(ctx); err != nil {
				if isContextError(err) {
					p.logger.Info("commitment equivocation alert publisher stopped during drain")
					return
				}
				p.logger.Error("commitment equivocation alert drain failed",
					"error", err)
			}
		}
	}
}

// drain reads every commitment_equivocation_proofs row with
// alert_dispatched_at IS NULL and POSTs each to the webhook. On
// success, marks alert_dispatched_at = NOW(). On failure, leaves
// the row unchanged for the next iteration.
//
// Per-row failure does NOT abort the drain — the publisher
// continues to subsequent rows so a single misbehaving incident
// does not block escalation of unrelated incidents.
func (p *CommitmentEquivocationAlertPublisher) drain(ctx context.Context) error {
	rows, err := p.db.Query(ctx, `
		SELECT schema_id, split_id, entry_seqs, first_detected_at
		FROM commitment_equivocation_proofs
		WHERE alert_dispatched_at IS NULL
		ORDER BY first_detected_at ASC`)
	if err != nil {
		return fmt.Errorf("witness/alert: read backlog: %w", err)
	}
	defer rows.Close()

	type pending struct {
		schemaID        string
		splitID         [32]byte
		entrySeqs       []uint64
		firstDetectedAt time.Time
	}
	var queue []pending
	for rows.Next() {
		var (
			schemaID        string
			splitIDRaw      []byte
			entrySeqsRaw    []int64
			firstDetectedAt time.Time
		)
		if scanErr := rows.Scan(&schemaID, &splitIDRaw, &entrySeqsRaw, &firstDetectedAt); scanErr != nil {
			return fmt.Errorf("witness/alert: scan row: %w", scanErr)
		}
		if len(splitIDRaw) != 32 {
			p.logger.Warn("commitment equivocation alert: malformed split_id length",
				"schema_id", schemaID,
				"split_id_len", len(splitIDRaw))
			continue
		}
		var splitID [32]byte
		copy(splitID[:], splitIDRaw)
		queue = append(queue, pending{
			schemaID:        schemaID,
			splitID:         splitID,
			entrySeqs:       int64sToUint64s(entrySeqsRaw),
			firstDetectedAt: firstDetectedAt,
		})
	}
	if iterErr := rows.Err(); iterErr != nil {
		return fmt.Errorf("witness/alert: iterate backlog: %w", iterErr)
	}
	rows.Close()

	for _, item := range queue {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.dispatchOne(ctx, item.schemaID, item.splitID, item.entrySeqs, item.firstDetectedAt); err != nil {
			p.logger.Error("commitment equivocation alert dispatch failed",
				"schema_id", item.schemaID,
				"split_id_prefix", fmt.Sprintf("%x", item.splitID[:8]),
				"error", err)
			// Do not return — continue to the next row.
		}
	}
	return nil
}

// dispatchOne assembles the CommitmentEquivocationAlertPayload for
// one incident, POSTs it to the webhook, and marks the row dispatched
// on a 2xx response.
//
// Order is "build payload (fetch canonical bytes from Tessera)
// → POST → DB UPDATE". A failure at any stage leaves
// alert_dispatched_at NULL so the next drain retries.
func (p *CommitmentEquivocationAlertPublisher) dispatchOne(
	ctx context.Context,
	schemaID string,
	splitID [32]byte,
	entrySeqs []uint64,
	firstDetectedAt time.Time,
) error {
	if p.fetcher == nil {
		return errors.New("witness/alert: nil EntryByteFetcher")
	}

	payload := CommitmentEquivocationAlertPayload{
		LogDID:          p.cfg.LogDID,
		SchemaID:        schemaID,
		SplitIDHex:      hex.EncodeToString(splitID[:]),
		Entries:         make([]CommitmentEquivocationAlertEntry, 0, len(entrySeqs)),
		FirstDetectedAt: firstDetectedAt.UTC().Format(time.RFC3339Nano),
		DispatchedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	for _, seq := range entrySeqs {
		raw, fetchErr := p.fetcher.FetchCanonicalBytes(ctx, seq)
		if fetchErr != nil {
			return fmt.Errorf("witness/alert: fetch seq=%d: %w", seq, fetchErr)
		}
		payload.Entries = append(payload.Entries, CommitmentEquivocationAlertEntry{
			SequenceNumber:    seq,
			CanonicalBytesHex: hex.EncodeToString(raw),
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("witness/alert: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("witness/alert: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ortholog-operator/commitment-equivocation-alert")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("witness/alert: HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("witness/alert: webhook returned HTTP %d", resp.StatusCode)
	}

	// Mark dispatched. On UPDATE failure the row remains in the
	// backlog and gets re-attempted; the webhook side may receive
	// a duplicate, which it MUST handle idempotently per the
	// governance contract documented above.
	_, err = p.db.Exec(ctx, `
		UPDATE commitment_equivocation_proofs
		SET alert_dispatched_at = NOW()
		WHERE schema_id = $1 AND split_id = $2`,
		schemaID, splitID[:])
	if err != nil {
		return fmt.Errorf("witness/alert: mark dispatched: %w", err)
	}

	p.logger.Info("commitment equivocation alert dispatched",
		"schema_id", schemaID,
		"split_id_prefix", fmt.Sprintf("%x", splitID[:8]),
		"entry_count", len(entrySeqs))
	return nil
}

// pgxConnUnusedAlert pins the pgx import in case a future refactor
// inlines the QueryRow / Query call sites.
var pgxConnUnusedAlert = (*pgx.Conn)(nil)
