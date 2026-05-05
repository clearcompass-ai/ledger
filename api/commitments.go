/*
FILE PATH: api/commitments.go

GET /v1/commitments/by-split-id/{schema_id}/{hex} — 
cryptographic-commitment lookup endpoint per Wave 1 v3 §C7 +
Decision 4.

Path parameters:

	{schema_id}  one of:
	               pre-grant-commitment-v1
	               escrow-split-commitment-v1
	{hex}        32-byte SplitID, hex-encoded (lowercase, no 0x prefix)

Response shape (Decision 4):

	{
	  "entries": [
	    {
	      "canonical_bytes_hex": "...",
	      "log_time": "2026-04-25T14:32:00Z",
	      "position": {
	        "sequence_number": 7234891,
	        "log_did": "did:web:..."
	      }
	    }
	  ]
	}

Length contract:

  - 404 Not Found → zero rows matched the (schema_id, split_id)
    tuple. SDK consumers treat this as "no commitment
    on log" — a normal recovery / history-replay
    outcome.
  - 200 OK len=1 → normal case. SDK's FetchPREGrantCommitment /
    FetchEscrowSplitCommitment consume entries[0]
    and proceed.
  - 200 OK len=2+  → cryptographic equivocation. The dealer signed
    two distinct commitment entries under the same
    SplitID; both are returned in ascending sequence
    order. SDK consumers receive
    *artifact.CommitmentEquivocationError carrying
    every entry the ledger returned, and MUST NOT
    proceed with reconstruction or decryption.

Domain disambiguation: this file serves cryptographic Pedersen
commitments (escrow + PRE). SMT batch derivation commitments live at
GET /v1/derivation-commitments?seq=N (api/derivation_commitments.go).
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Allowed schemas
// ─────────────────────────────────────────────────────────────────────────────

// allowedCommitmentSchemas is the set of schema_id values the lookup
// endpoint will accept on the URL path. Restricting the set prevents
// callers from probing the commitment_split_id index under arbitrary
// schema strings — a defensive measure that costs nothing because
// only the two commitment schemas can ever populate that
// index in the first place (api/submission.go stage 4-Schema
// dispatch is closed-set).
var allowedCommitmentSchemas = map[string]struct{}{
	artifact.PREGrantCommitmentSchemaID:  {},
	escrow.EscrowSplitCommitmentSchemaID: {},
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Wire types
// ─────────────────────────────────────────────────────────────────────────────

// CommitmentLookupPosition mirrors types.LogPosition in JSON form
// for the GET response. Kept as a separate struct so the API shape
// is stable across SDK refactors of the underlying type.
type CommitmentLookupPosition struct {
	SequenceNumber uint64 `json:"sequence_number"`
	LogDID string `json:"log_did"`
}

// CommitmentLookupEntry is one element of the entries array returned
// by GET /v1/commitments/by-split-id. Field set is the strict subset
// of types.EntryWithMetadata required to reconstruct the SDK
// EntryWithMetadata at the consumer (CanonicalBytes, LogTime,
// Position) per Wave 1 v3 changelog item "EntryWithMetadata
// Corrected" — sidecar fields like signatures and tree-head hashes
// are NOT included.
type CommitmentLookupEntry struct {
	CanonicalBytesHex string `json:"canonical_bytes_hex"`
	LogTime string `json:"log_time"`
	Position CommitmentLookupPosition `json:"position"`
}

// CommitmentLookupResponse is the JSON response body shape on success.
// Length 1 in the normal case, length 2+ on dealer equivocation. Even
// the single-row case is wrapped in the entries array so consumers do
// not need to branch on result shape.
type CommitmentLookupResponse struct {
	Entries []CommitmentLookupEntry `json:"entries"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Handler dependencies
// ─────────────────────────────────────────────────────────────────────────────

// CryptographicCommitmentDeps groups the lookup handler dependencies.
// Distinct from DerivationCommitmentDeps (which serves the
// fraud-proof lookup endpoint over SMT batch commitments) per the
// C1 naming-disambiguation pass.
//
// CQRS DISCIPLINE (P8): Fetcher is the SDK's types.CommitmentFetcher
// interface — NOT the concrete *store.PostgresCommitmentFetcher.
// Production wiring uses gossipstore.BadgerCommitmentFetcher, which
// reads from the 0x0C entry-lookup projection populated by the
// sequencer. The api/ package therefore takes no transitive
// dependency on github.com/jackc/pgx/v5 for this endpoint —
// verifiable via go list -deps ./api/.
type CryptographicCommitmentDeps struct {
	Fetcher types.CommitmentFetcher
	Logger *slog.Logger
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Handler constructor
// ─────────────────────────────────────────────────────────────────────────────

// NewCommitmentLookupHandler returns the GET
// /v1/commitments/by-split-id/{schema_id}/{hex} handler.
//
// The handler relies on Go 1.22+ http.ServeMux path-value extraction
// (r.PathValue) and is intended to be registered as:
//
//	mux.HandleFunc("GET /v1/commitments/by-split-id/{schema_id}/{hex}",
//	    api.NewCommitmentLookupHandler(deps))
//
// Panics if Fetcher is nil — without a fetcher the handler can do
// no useful work and the ledger should refuse to start.
func NewCommitmentLookupHandler(deps *CryptographicCommitmentDeps) http.HandlerFunc {
	if deps == nil || deps.Fetcher == nil {
		panic("api: CryptographicCommitmentDeps.Fetcher must be non-nil")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		schemaID := r.PathValue("schema_id")
		hexStr := r.PathValue("hex")

		if schemaID == "" {
			writeTypedError(ctx, w, apitypes.ErrorClassMissingPathParam,
				http.StatusBadRequest, "schema_id path segment required")
			return
		}
		if _, ok := allowedCommitmentSchemas[schemaID]; !ok {
			writeTypedError(ctx, w, apitypes.ErrorClassUnsupportedSchema,
				http.StatusBadRequest,
				fmt.Sprintf("unsupported schema_id %q", schemaID))
			return
		}

		// SplitID is exactly 32 bytes ⇒ exactly 64 hex chars.
		if len(hexStr) != 64 {
			writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
				http.StatusBadRequest,
				fmt.Sprintf("split_id hex must be 64 chars, got %d", len(hexStr)))
			return
		}
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassBadHexEncoding,
				http.StatusBadRequest,
				fmt.Sprintf("split_id hex decode: %s", err))
			return
		}
		var splitID [32]byte
		copy(splitID[:], raw)

		entries, err := deps.Fetcher.FindCommitmentEntries(schemaID, splitID)
		if err != nil {
			deps.Logger.Error("commitment lookup",
				"schema_id", schemaID,
				"split_id_prefix", hexStr[:16],
				"error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassFetcherFailed,
				http.StatusInternalServerError,
				"commitment lookup failed")
			return
		}

		// Decision 4: 404 when the result is empty; the array is
		// always non-empty when 200 is returned. SDK consumers
		// treat 404 as "no commitment on log" — a normal recovery
		// outcome.
		if len(entries) == 0 {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound,
				"no commitment for this (schema_id, split_id)")
			return
		}

		// Detect equivocation early so it shows up in the access
		// log even if the SDK consumer is the one that ultimately
		// flags it. Ledgers monitoring this log line can act on
		// it independently of the SDK pathway.
		if len(entries) > 1 {
			deps.Logger.Warn("commitment equivocation surfaced via lookup",
				"schema_id", schemaID,
				"split_id_prefix", hexStr[:16],
				"entry_count", len(entries))
		}

		out := CommitmentLookupResponse{
			Entries: make([]CommitmentLookupEntry, 0, len(entries)),
		}
		for _, e := range entries {
			out.Entries = append(out.Entries, marshalLookupEntry(e))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Marshalling helpers
// ─────────────────────────────────────────────────────────────────────────────

// marshalLookupEntry converts an SDK EntryWithMetadata to the
// API-layer wire form. Kept as a tight pure function so the schema
// is easy to keep in sync with Decision 4 if the response shape
// evolves.
func marshalLookupEntry(e *types.EntryWithMetadata) CommitmentLookupEntry {
	if e == nil {
		// Defensive: a nil entry from the fetcher would be a
		// fetcher bug, but the handler should not panic on it.
		// An empty wire entry is harmless to the consumer — the
		// SDK will fail to deserialize zero canonical bytes and
		// surface a clear error.
		return CommitmentLookupEntry{}
	}
	return CommitmentLookupEntry{
		CanonicalBytesHex: hex.EncodeToString(e.CanonicalBytes),
		LogTime:           e.LogTime.UTC().Format(time.RFC3339Nano),
		Position: CommitmentLookupPosition{
			SequenceNumber: e.Position.Sequence,
			LogDID:         e.Position.LogDID,
		},
	}
}
