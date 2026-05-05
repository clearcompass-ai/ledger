/*
Command bootstrap-v775-schemas — F4 schema-entry bootstrap script.

Wave 1 v3 §F4. Idempotent script that publishes the two v7.75
cryptographic-commitment schema-marker entries
(pre-grant-commitment-v1, escrow-split-commitment-v1) on the
operator's log so downstream consumers can locate them via the
output YAML's (sequence_number, canonical_hash) map. Run once at
cutover; safe to re-run.

Why bootstrap? The C2 admission dispatcher in api/submission.go
recognizes commitment payloads by their embedded schema_id field
and does NOT require any schema entry on log to admit a
commitment entry. The bootstrap exists for downstream tooling that
wants to discover "what v7.75 schemas does this log declare?" via
a stable (schema_id → log position) map.

Why commentary, not BuildSchemaEntry? Wave 1 v3's §F4 originally
called for builder.BuildSchemaEntry, on the assumption that
SchemaParameters could carry a schema_id discriminator. The actual
v7.75 SchemaParameters type (types/schema_parameters.go) has no
schema_id field — its CommutativeOperations slot is []uint32, not
[]string, and none of the other declared fields (ActivationDelay,
MigrationPolicy, GrantAuthorizationMode, etc.) naturally encode a
string label. Forcing one in would be a semantic abuse that the
SDK schema parsers and verifier code paths would not interpret
correctly.

This script switches to builder.BuildCommentary with an explicit
JSON payload carrying the schema_id. The two resulting entries
have distinct canonical bytes (different payloads ⇒ different
canonical hashes) and the schema_id is plainly visible in the
payload for any consumer that wants to enumerate. The output YAML
is unchanged — consumers still resolve a schema_id to its
sequence_number via the YAML map this script writes.

Idempotency model:

  - The script writes its results to a YAML output file
    (--output, default config/v775_schemas.yaml). On every run, it
    loads the file first; if both schemas are already recorded with
    valid sequence numbers, it exits success without contacting the
    operator. This is the fast-path for production deploys where
    the bootstrap has already run.
  - If the output file is missing or incomplete, the script builds
    fresh commentary entries and submits them via POST /v1/entries/batch.
    The operator's UNIQUE constraint on canonical_hash means a
    duplicate submission (same content) returns HTTP 409; the script
    aborts and operators reconcile manually (rare — only happens
    when the YAML was deleted while the operator state survived).

Usage:

	bootstrap-v775-schemas \
	    --operator-url http://localhost:8080 \
	    --signer-did   did:web:operator.example \
	    --log-did      did:web:log.example \
	    --key-path     /etc/attesta/operator-key.hex \
	    --output       config/v775_schemas.yaml

Run order in deploy: schema bootstrap → service start. The operator
itself does NOT need the schemas to start (commitment admission
works without them); the bootstrap is a separate cutover step.
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

type config struct {
	OperatorURL string
	SignerDID   string
	LogDID      string
	KeyPath     string
	OutputPath  string
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.OperatorURL, "operator-url", "",
		"base URL of the operator HTTP API (e.g. http://localhost:8080)")
	flag.StringVar(&cfg.SignerDID, "signer-did", "",
		"DID that signs the schema-marker entries (operator institutional DID)")
	flag.StringVar(&cfg.LogDID, "log-did", "",
		"destination log DID for the schema entries (must equal operator's LogDID)")
	flag.StringVar(&cfg.KeyPath, "key-path", "",
		"path to a hex-encoded 32-byte secp256k1 private key file")
	flag.StringVar(&cfg.OutputPath, "output", "config/v775_schemas.yaml",
		"path to write the bootstrap result YAML")
	flag.Parse()

	missing := []string{}
	if cfg.OperatorURL == "" {
		missing = append(missing, "--operator-url")
	}
	if cfg.SignerDID == "" {
		missing = append(missing, "--signer-did")
	}
	if cfg.LogDID == "" {
		missing = append(missing, "--log-did")
	}
	if cfg.KeyPath == "" {
		missing = append(missing, "--key-path")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "missing required flags: %v\n", missing)
		flag.Usage()
		os.Exit(2)
	}
	return cfg
}

// ─────────────────────────────────────────────────────────────────────
// Output schema
// ─────────────────────────────────────────────────────────────────────

// bootstrapResult is the YAML output shape. Hand-rolled minimal
// YAML emitter below — the only YAML dependency for this script
// would be gopkg.in/yaml.v3, which the operator already pulls in
// transitively, but for a single-file output the hand-roll is
// dead-simple and avoids the indirect dep being promoted to direct.
type bootstrapResult struct {
	GeneratedAt string           `yaml:"generated_at"`
	OperatorDID string           `yaml:"operator_did"`
	LogDID      string           `yaml:"log_did"`
	Schemas     []bootstrapEntry `yaml:"schemas"`
}

type bootstrapEntry struct {
	SchemaID       string `yaml:"schema_id"`
	SequenceNumber uint64 `yaml:"sequence_number"`
	CanonicalHash  string `yaml:"canonical_hash"`
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────

func main() {
	cfg := parseFlags()
	logger := log.New(os.Stderr, "bootstrap-v775-schemas: ", log.LstdFlags)

	// Idempotency check: if output file exists and has both schemas,
	// exit success without contacting the operator. This is the
	// fast-path for re-runs in production.
	if existing, ok := readExisting(cfg.OutputPath); ok && hasBothSchemas(existing) {
		logger.Printf("schemas already bootstrapped at %s; nothing to do",
			cfg.OutputPath)
		return
	}

	// Load operator's signing key.
	priv, err := loadPrivateKey(cfg.KeyPath)
	if err != nil {
		logger.Fatalf("load key: %v", err)
	}

	// Build + sign + serialize each schema marker entry.
	preWire, err := buildAndSign(cfg, priv, artifact.PREGrantCommitmentSchemaID)
	if err != nil {
		logger.Fatalf("build pre-grant schema marker: %v", err)
	}
	escrowWire, err := buildAndSign(cfg, priv, escrow.EscrowSplitCommitmentSchemaID)
	if err != nil {
		logger.Fatalf("build escrow-split schema marker: %v", err)
	}

	// Submit batch.
	results, err := submitBatch(cfg.OperatorURL, [][]byte{preWire, escrowWire})
	if err != nil {
		logger.Fatalf("submit batch: %v", err)
	}
	if len(results) != 2 {
		logger.Fatalf("expected 2 results, got %d", len(results))
	}

	// Write output.
	out := bootstrapResult{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		OperatorDID: cfg.SignerDID,
		LogDID:      cfg.LogDID,
		Schemas: []bootstrapEntry{
			{
				SchemaID:       artifact.PREGrantCommitmentSchemaID,
				SequenceNumber: results[0].SequenceNumber,
				CanonicalHash:  results[0].CanonicalHash,
			},
			{
				SchemaID:       escrow.EscrowSplitCommitmentSchemaID,
				SequenceNumber: results[1].SequenceNumber,
				CanonicalHash:  results[1].CanonicalHash,
			},
		},
	}
	if err := writeYAML(cfg.OutputPath, out); err != nil {
		logger.Fatalf("write output: %v", err)
	}

	logger.Printf("bootstrap complete: %s", cfg.OutputPath)
	logger.Printf("  pre-grant-commitment-v1     seq=%d hash=%s",
		results[0].SequenceNumber, results[0].CanonicalHash)
	logger.Printf("  escrow-split-commitment-v1  seq=%d hash=%s",
		results[1].SequenceNumber, results[1].CanonicalHash)
}

// ─────────────────────────────────────────────────────────────────────
// Build + sign
// ─────────────────────────────────────────────────────────────────────

// schemaMarkerPayload is the JSON shape this bootstrap publishes as
// the Domain Payload of each commentary entry. Carries the
// schema_id explicitly so any consumer reading the entry's payload
// can identify which v7.75 schema this marker stands in for.
type schemaMarkerPayload struct {
	MarkerType string `json:"marker_type"`
	SchemaID   string `json:"schema_id"`
	V775       bool   `json:"v775"`
}

// buildAndSign constructs a commentary marker entry for the supplied
// schema_id, signs it with the operator's key, and returns the wire
// bytes ready for batch submission.
//
// Why commentary instead of BuildSchemaEntry: see the file docblock.
// Two distinct schema_ids produce two distinct payloads, and
// envelope.Serialize hashes the payload bytes into the canonical
// hash, so the two resulting entries are guaranteed to have distinct
// canonical_hash values without abusing any SchemaParameters field.
func buildAndSign(cfg config, priv *ecdsa.PrivateKey, schemaID string) ([]byte, error) {
	payload, err := json.Marshal(schemaMarkerPayload{
		MarkerType: "v775_commitment_schema",
		SchemaID:   schemaID,
		V775:       true,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal marker payload: %w", err)
	}

	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: cfg.LogDID,
		SignerDID:   cfg.SignerDID,
		Payload:     payload,
		// EventTime in microseconds — matches what the SDK's
		// freshness check (exchange/policy.CheckFreshness) reads
		// via time.UnixMicro, not what the docstring claims.
		// Same fix as cmd/submit-stamp, anchor/publisher,
		// builder/commitment_publisher.
		EventTime: time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		return nil, fmt.Errorf("BuildCommentary: %w", err)
	}

	// Sign the canonical signing payload per the v7 entry signing
	// flow documented in entry_builders.go:
	//   hash := sha256(SigningPayload(entry))
	//   sig := signatures.SignEntry(hash, priv)
	//   entry.Signatures = [{SignerDID, AlgoID, sig}]
	signingBytes := envelope.SigningPayload(entry)
	hash := sha256.Sum256(signingBytes)
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		return nil, fmt.Errorf("SignEntry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: cfg.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("Validate: %w", err)
	}

	return envelope.Serialize(entry), nil
}

// ─────────────────────────────────────────────────────────────────────
// Batch submission
// ─────────────────────────────────────────────────────────────────────

type batchResultEntry struct {
	SequenceNumber uint64 `json:"sequence_number"`
	CanonicalHash  string `json:"canonical_hash"`
	LogTime        string `json:"log_time"`
}

type batchResponse struct {
	Results []batchResultEntry `json:"results"`
}

type batchEntry struct {
	WireBytesHex string `json:"wire_bytes_hex"`
}

type batchRequest struct {
	Entries []batchEntry `json:"entries"`
}

// submitBatch POSTs the wire bytes to /v1/entries/batch and returns
// the per-entry results. On HTTP 409 (duplicate hash from a prior
// successful run that failed to write the YAML), the script aborts
// — re-running with the existing YAML output file in place would
// catch this case via the idempotency fast-path. If the YAML is
// missing AND the operator has the schemas, the operator state
// disagrees with the bootstrap state and an operator needs to
// reconcile manually.
func submitBatch(operatorURL string, wires [][]byte) ([]batchResultEntry, error) {
	req := batchRequest{Entries: make([]batchEntry, 0, len(wires))}
	for _, w := range wires {
		req.Entries = append(req.Entries, batchEntry{
			WireBytesHex: hex.EncodeToString(w),
		})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST",
		operatorURL+"/v1/entries/batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("operator returned HTTP %d: %s",
			resp.StatusCode, string(rawBody))
	}

	var br batchResponse
	if err := json.Unmarshal(rawBody, &br); err != nil {
		return nil, fmt.Errorf("decode response: %w (body=%s)",
			err, string(rawBody))
	}
	return br.Results, nil
}

// ─────────────────────────────────────────────────────────────────────
// Key loading (hex-encoded 32-byte file)
// ─────────────────────────────────────────────────────────────────────

// loadPrivateKey reads a hex-encoded 32-byte secp256k1 scalar from
// disk and returns an *ecdsa.PrivateKey. The hex file is the
// operator's institutional governance key for v7.75 deployments;
// HSM-backed key custody is Wave 2.
//
// File format: a single line of 64 lowercase hex characters
// (optional trailing newline). Any other content is rejected.
//
// SECURITY NOTE: this script is operator-side tooling running with
// access to the institutional key. It is NOT exposed to network
// callers. Wave 2 replaces direct file-based key access with HSM
// integration; the bootstrap script's interface (--key-path) becomes
// --hsm-handle or similar at that point.
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	hexStr := string(bytes.TrimSpace(raw))
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("key file must contain exactly 64 hex chars (got %d)",
			len(hexStr))
	}
	scalar, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	priv, err := signatures.PrivKeyFromBytes(scalar)
	if err != nil {
		return nil, fmt.Errorf("parse scalar: %w", err)
	}
	return priv, nil
}

// ─────────────────────────────────────────────────────────────────────
// Idempotency: read existing YAML
// ─────────────────────────────────────────────────────────────────────

// readExisting attempts to parse the YAML output file. Returns
// (parsed, true) if the file exists and parses; (zero, false)
// otherwise. Parse failures are silently treated as "no existing
// state" so a corrupted file is overwritten on the next successful
// bootstrap.
func readExisting(path string) (bootstrapResult, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return bootstrapResult{}, false
	}
	parsed, ok := parseMinimalYAML(raw)
	if !ok {
		return bootstrapResult{}, false
	}
	return parsed, true
}

// hasBothSchemas reports whether the parsed YAML carries entries
// for both v7.75 commitment schemas with non-zero sequence numbers.
// A partial state (one schema bootstrapped, one missing) returns
// false so the script re-bootstraps both — duplicate submissions
// for the already-bootstrapped one will catch on canonical_hash
// uniqueness and the operator will need manual reconciliation. A
// future iteration can do a per-schema submission to handle the
// partial case more gracefully.
func hasBothSchemas(b bootstrapResult) bool {
	wantPRE := false
	wantEscrow := false
	for _, s := range b.Schemas {
		if s.SequenceNumber == 0 {
			continue
		}
		switch s.SchemaID {
		case artifact.PREGrantCommitmentSchemaID:
			wantPRE = true
		case escrow.EscrowSplitCommitmentSchemaID:
			wantEscrow = true
		}
	}
	return wantPRE && wantEscrow
}

// ─────────────────────────────────────────────────────────────────────
// Hand-rolled minimal YAML I/O
// ─────────────────────────────────────────────────────────────────────

// writeYAML emits the bootstrapResult in a fixed canonical YAML
// shape. Hand-rolled to avoid pulling gopkg.in/yaml.v3 into the
// operator's direct dependencies just for this one-shot script.
func writeYAML(path string, b bootstrapResult) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "generated_at: %q\n", b.GeneratedAt)
	fmt.Fprintf(&buf, "operator_did: %q\n", b.OperatorDID)
	fmt.Fprintf(&buf, "log_did: %q\n", b.LogDID)
	buf.WriteString("schemas:\n")
	for _, s := range b.Schemas {
		fmt.Fprintf(&buf, "  - schema_id: %q\n", s.SchemaID)
		fmt.Fprintf(&buf, "    sequence_number: %d\n", s.SequenceNumber)
		fmt.Fprintf(&buf, "    canonical_hash: %q\n", s.CanonicalHash)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// parseMinimalYAML is a deliberately tiny YAML reader that only
// understands the bootstrapResult shape this script writes. NOT a
// general YAML parser — fed anything else, it returns (zero, false).
//
// Format expectations (matching writeYAML's output):
//
//	generated_at: "..."
//	operator_did: "..."
//	log_did: "..."
//	schemas:
//	  - schema_id: "..."
//	    sequence_number: 123
//	    canonical_hash: "..."
//	  - schema_id: "..."
//	    sequence_number: 456
//	    canonical_hash: "..."
func parseMinimalYAML(raw []byte) (bootstrapResult, bool) {
	out := bootstrapResult{}
	lines := bytes.Split(raw, []byte("\n"))
	var current *bootstrapEntry
	for _, line := range lines {
		s := string(line)
		switch {
		case len(s) == 0 || s[0] == '#':
			continue
		case startsWith(s, "generated_at: "):
			out.GeneratedAt = unquote(s[len("generated_at: "):])
		case startsWith(s, "operator_did: "):
			out.OperatorDID = unquote(s[len("operator_did: "):])
		case startsWith(s, "log_did: "):
			out.LogDID = unquote(s[len("log_did: "):])
		case s == "schemas:":
			// Header; entries follow as list items.
		case startsWith(s, "  - schema_id: "):
			out.Schemas = append(out.Schemas, bootstrapEntry{})
			current = &out.Schemas[len(out.Schemas)-1]
			current.SchemaID = unquote(s[len("  - schema_id: "):])
		case startsWith(s, "    sequence_number: ") && current != nil:
			var n uint64
			fmt.Sscanf(s, "    sequence_number: %d", &n)
			current.SequenceNumber = n
		case startsWith(s, "    canonical_hash: ") && current != nil:
			current.CanonicalHash = unquote(s[len("    canonical_hash: "):])
		}
	}
	return out, len(out.Schemas) > 0
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
