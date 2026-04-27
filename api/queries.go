/*
FILE PATH: api/queries.go

DESCRIPTION:

	Read-side query handlers for the operator's HTTP API. Fetches entries
	by sequence range, by hash, and by signer DID. Returns EntryResponse
	structures with canonical hash + metadata + payload byte-size.

	Also hosts the thin query handlers the read-write and read-only
	operator both serve (CosignatureOf, TargetRoot, SignerDID, SchemaRef,
	Scan) plus the difficulty endpoint. These delegate to PostgresQueryAPI
	or to DiffController — zero business logic, just HTTP → internal-API
	adapters.

SDK v0.3.0 ALIGNMENT:
  - toEntryResponses computes the canonical hash via envelope.EntryIdentity(entry)
    when deserialization succeeds. Byte-identical to sha256.Sum256(ewm.CanonicalBytes)
    but the vocabulary is explicit: the returned hash IS the Tessera
    dedup key / Entry.Identity().
  - Fallback to crypto.HashBytes(ewm.CanonicalBytes) when deserialize
    fails (shouldn't happen post-admission, but belt-and-braces).

DEPENDENCY SHAPE:

	Consumes PostgresQueryAPI (store/indexes/query_api.go). That type
	does Postgres metadata lookup + EntryReader byte hydration and
	returns []types.EntryWithMetadata. We do NOT talk to the byte store
	directly.
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
)

// ─────────────────────────────────────────────────────────────────────
// Dependencies
// ─────────────────────────────────────────────────────────────────────

// QueryDeps is the dependency surface for the query + difficulty handlers.
//
//	EntryStore     — hash → sequence lookup (FetchByHash).
//	QueryAPI       — joined metadata + byte view. Hydrates bytes via
//	                 tessera.EntryReader internally.
//	DiffController — live difficulty source for /v1/admission/difficulty.
//	                 Nil-safe: the handler responds 503 when absent, which
//	                 is what the read-only operator wants.
//	Logger         — slog handle.
type QueryDeps struct {
	EntryStore     *store.EntryStore
	QueryAPI       *indexes.PostgresQueryAPI
	DiffController *middleware.DifficultyController
	Logger         *slog.Logger
}

// ─────────────────────────────────────────────────────────────────────
// Response shape
// ─────────────────────────────────────────────────────────────────────

// EntryResponse is the JSON shape returned by query handlers.
//
// sig_algorithm_id is intentionally absent: surfacing it here forces a
// per-row Deserialize (or, post-shipper, a per-row bytestore Get) on
// list endpoints, which turns metadata queries into payload-fetching
// storms. Auditors who need the algorithm dereference the entry via
// GET /v1/entries/{seq} and inspect the envelope locally.
type EntryResponse struct {
	SequenceNumber uint64 `json:"sequence_number"`
	CanonicalHash  string `json:"canonical_hash"`
	LogTime        string `json:"log_time"`
	SignerDID      string `json:"signer_did,omitempty"`
	ProtocolVer    uint16 `json:"protocol_version"`
	PayloadSize    int    `json:"payload_size"`
	CanonicalSize  int    `json:"canonical_size"`
}

// ─────────────────────────────────────────────────────────────────────
// toEntryResponses — central hash-computation site
// ─────────────────────────────────────────────────────────────────────

// toEntryResponses converts []types.EntryWithMetadata into API responses.
// Single site where canonical hashes are computed for the read path.
//
// SignerDID lives inside CanonicalBytes (v6 multi-sig section) and
// surfaces via envelope.Deserialize; we deserialize once per entry
// to extract it alongside protocol version and payload size.
func toEntryResponses(metas []types.EntryWithMetadata) []EntryResponse {
	out := make([]EntryResponse, 0, len(metas))
	for _, ewm := range metas {
		resp := EntryResponse{
			SequenceNumber: ewm.Position.Sequence,
			LogTime:        ewm.LogTime.Format(time.RFC3339Nano),
			CanonicalSize:  len(ewm.CanonicalBytes),
		}

		entry, err := envelope.Deserialize(ewm.CanonicalBytes)
		if err != nil {
			// Malformed bytes in the byte store — degrade gracefully.
			h := crypto.HashBytes(ewm.CanonicalBytes)
			resp.CanonicalHash = hex.EncodeToString(h[:])
		} else {
			id := envelope.EntryIdentity(entry)
			resp.CanonicalHash = hex.EncodeToString(id[:])
			resp.ProtocolVer = entry.Header.ProtocolVersion
			resp.PayloadSize = len(entry.DomainPayload)
			resp.SignerDID = entry.Header.SignerDID
		}

		out = append(out, resp)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries?from=N&to=M — range query
// ─────────────────────────────────────────────────────────────────────

// NewRangeQueryHandler returns entries in [from, to] by sequence number.
func NewRangeQueryHandler(deps *QueryDeps) http.HandlerFunc {
	const maxRange = 1000
	return func(w http.ResponseWriter, r *http.Request) {
		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")
		from, err := strconv.ParseUint(fromStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'from' parameter")
			return
		}
		to, err := strconv.ParseUint(toStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'to' parameter")
			return
		}
		if to < from {
			writeError(w, http.StatusBadRequest, "'to' must be >= 'from'")
			return
		}
		span := to - from + 1
		if span > maxRange {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("range %d exceeds max %d", span, maxRange))
			return
		}

		entries, err := deps.QueryAPI.ScanFromPosition(from, int(span))
		if err != nil {
			deps.Logger.Error("range query failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}

		// ScanFromPosition returns seqs >= from; filter any > to defensively.
		filtered := entries[:0:len(entries)]
		for _, e := range entries {
			if e.Position.Sequence > to {
				break
			}
			filtered = append(filtered, e)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": toEntryResponses(filtered),
			"from":    from,
			"to":      to,
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/hash/{hash_hex} — hash lookup
// ─────────────────────────────────────────────────────────────────────

// NewHashLookupHandler returns a single entry by its canonical hash.
func NewHashLookupHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		hashHex := r.URL.Path[len("/v1/entries/hash/"):]
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil || len(hashBytes) != 32 {
			writeError(w, http.StatusBadRequest, "invalid canonical hash")
			return
		}
		var hash [32]byte
		copy(hash[:], hashBytes)

		seq, found, err := deps.EntryStore.FetchByHash(ctx, hash)
		if err != nil {
			deps.Logger.Error("hash lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "entry not found")
			return
		}

		entries, err := deps.QueryAPI.ScanFromPosition(seq, 1)
		if err != nil || len(entries) == 0 || entries[0].Position.Sequence != seq {
			deps.Logger.Error("hash lookup hydrate", "seq", seq, "got", len(entries), "err", err)
			writeError(w, http.StatusInternalServerError, "fetch failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(entries)[0])
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/{seq}/raw — raw wire bytes
// ─────────────────────────────────────────────────────────────────────

// NewRawEntryHandler returns the entry's full wire bytes as a single
// byte stream. Under v7.75 the wire bytes ARE the canonical bytes —
// the multi-sig section is appended INSIDE the canonical form by
// envelope.Serialize, so EntryWithMetadata.CanonicalBytes already
// carries the signatures. Consumers feed this directly into
// envelope.Deserialize then envelope.EntryIdentity to verify.
func NewRawEntryHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		seqStr := r.URL.Path[len("/v1/entries/"):]
		if i := len(seqStr) - len("/raw"); i > 0 && seqStr[i:] == "/raw" {
			seqStr = seqStr[:i]
		}
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid sequence")
			return
		}

		entries, err := deps.QueryAPI.ScanFromPosition(seq, 1)
		if err != nil {
			deps.Logger.Error("raw entry fetch", "seq", seq, "error", err)
			writeError(w, http.StatusInternalServerError, "fetch failed")
			return
		}
		if len(entries) == 0 || entries[0].Position.Sequence != seq {
			writeError(w, http.StatusNotFound, "entry not found")
			return
		}
		ewm := entries[0]

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Sequence", strconv.FormatUint(seq, 10))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ewm.CanonicalBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Index-backed query handlers (ControlHeader field lookups)
// ─────────────────────────────────────────────────────────────────────
//
// These five handlers expose the PostgresQueryAPI's "query by control
// header field" methods. Referenced by api/server.go as
// Handlers.CosignatureOf / .TargetRoot / .SignerDID / .SchemaRef / .Scan
// and wired by both the read-write operator (cmd/operator) and the
// read-only operator (cmd/operator-reader).
//
// Uniform HTTP surface on purpose: one parsing rule, one response shape.

// NewQueryCosignatureOfHandler — GET /v1/query/cosignature_of/{pos}.
// {pos} encodes a LogPosition as "did:sequence".
func NewQueryCosignatureOfHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pos, err := parseLogPosition(r.PathValue("pos"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		entries, err := deps.QueryAPI.QueryByCosignatureOf(pos)
		if err != nil {
			deps.Logger.Error("query cosignature_of", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQueryTargetRootHandler — GET /v1/query/target_root/{pos}.
func NewQueryTargetRootHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pos, err := parseLogPosition(r.PathValue("pos"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		entries, err := deps.QueryAPI.QueryByTargetRoot(pos)
		if err != nil {
			deps.Logger.Error("query target_root", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQuerySignerDIDHandler — GET /v1/query/signer_did/{did}.
// {did} is the URL-encoded signer DID string.
func NewQuerySignerDIDHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		did := r.PathValue("did")
		if did == "" {
			writeError(w, http.StatusBadRequest, "signer DID required")
			return
		}
		entries, err := deps.QueryAPI.QueryBySignerDID(did)
		if err != nil {
			deps.Logger.Error("query signer_did", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQuerySchemaRefHandler — GET /v1/query/schema_ref/{pos}.
func NewQuerySchemaRefHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pos, err := parseLogPosition(r.PathValue("pos"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		entries, err := deps.QueryAPI.QueryBySchemaRef(pos)
		if err != nil {
			deps.Logger.Error("query schema_ref", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQueryScanHandler — GET /v1/query/scan?start=N&count=M.
// Flat scan from sequence N returning up to M entries (capped at MaxScanCount).
func NewQueryScanHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")
		start, err := strconv.ParseUint(startStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid start parameter")
			return
		}
		count := indexes.DefaultScanCount
		if countStr != "" {
			parsed, err := strconv.Atoi(countStr)
			if err != nil || parsed <= 0 {
				writeError(w, http.StatusBadRequest, "invalid count parameter")
				return
			}
			count = parsed
		}
		entries, err := deps.QueryAPI.ScanFromPosition(start, count)
		if err != nil {
			deps.Logger.Error("query scan", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/admission/difficulty
// ─────────────────────────────────────────────────────────────────────

// NewDifficultyHandler returns the live Mode B stamp difficulty + hash
// function. Nil-safe: responds 503 when DiffController is absent (the
// read-only reader's case).
func NewDifficultyHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.DiffController == nil {
			writeError(w, http.StatusServiceUnavailable,
				"difficulty controller not configured")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"difficulty":    deps.DiffController.CurrentDifficulty(),
			"hash_function": deps.DiffController.HashFunction(),
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// parseLogPosition splits "did:sequence" into a typed LogPosition. The
// DID itself may contain colons (did:web:x, did:ortholog:a:b:c) so we
// split on the LAST colon to isolate the sequence.
func parseLogPosition(s string) (types.LogPosition, error) {
	if s == "" {
		return types.LogPosition{}, fmt.Errorf("log position required")
	}
	idx := -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			idx = i
			break
		}
	}
	if idx <= 0 || idx == len(s)-1 {
		return types.LogPosition{}, fmt.Errorf("log position must be 'did:sequence'")
	}
	seq, err := strconv.ParseUint(s[idx+1:], 10, 64)
	if err != nil {
		return types.LogPosition{}, fmt.Errorf("invalid sequence in log position: %w", err)
	}
	return types.LogPosition{LogDID: s[:idx], Sequence: seq}, nil
}

// writeEntriesJSON is the shared success envelope for the five header-field
// query handlers.
func writeEntriesJSON(w http.ResponseWriter, entries []types.EntryWithMetadata) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entries": toEntryResponses(entries),
		"count":   len(entries),
	})
}
