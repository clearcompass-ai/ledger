/*
FILE PATH: api/queries.go

DESCRIPTION:

	Read-side query handlers for the ledger's HTTP API. Fetches entries
	by sequence range, by hash, and by signer DID. Returns EntryResponse
	structures with canonical hash + metadata + payload byte-size.

	Also hosts the thin query handlers the read-write and read-only
	ledger both serve (CosignatureOf, TargetRoot, SignerDID, SchemaRef,
	Scan) plus the difficulty endpoint. These delegate to PostgresQueryAPI
	or to DiffController — zero business logic, just HTTP → internal-API
	adapters.

CANONICAL HASH:
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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/apitypes"
	"github.com/clearcompass-ai/ledger/wal"
)

// defaultScanCount mirrors store/indexes.DefaultScanCount;
// duplicated here so api/ holds zero pgx imports.
const defaultScanCount = 100

// ─────────────────────────────────────────────────────────────────────
// Dependencies
// ─────────────────────────────────────────────────────────────────────

// QueryDeps is the dependency surface for the query + difficulty handlers.
//
//	EntryStore — hash → sequence lookup (FetchByHash).
//	QueryAPI — joined metadata + byte view. Hydrates bytes via
//	                 bytestore.Reader internally.
//	DiffController — live difficulty source for /v1/admission/difficulty.
//	                 Nil-safe: the handler responds 503 when absent, which
//	                 is what the read-only ledger wants.
//	Logger — slog handle.
type QueryDeps struct {
	EntryStore EntryStore
	QueryAPI QueryAPI
	DiffController *middleware.DifficultyController
	Logger *slog.Logger

	// WAL is the optional WAL probe surface used by
	// NewHashLookupHandler to detect entries that have been
	// admitted (durable in WAL) but not yet sequenced
	// (entry_index INSERT happens in the background sequencer).
	// Nil-safe: when WAL is nil the handler skips the probe and
	// the v1 hash lookup behaves as it always did. The read-only
	// ledger-reader binary leaves this nil — it has no WAL.
	WAL EntryWALReader
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
	CanonicalHash string `json:"canonical_hash"`
	LogTime string `json:"log_time"`
	SignerDID string `json:"signer_did,omitempty"`
	ProtocolVer uint16 `json:"protocol_version"`
	PayloadSize int `json:"payload_size"`
	CanonicalSize int `json:"canonical_size"`
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
		ctx := r.Context()
		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")
		from, err := strconv.ParseUint(fromStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid 'from' parameter")
			return
		}
		to, err := strconv.ParseUint(toStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid 'to' parameter")
			return
		}
		if to < from {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "'to' must be >= 'from'")
			return
		}
		span := to - from + 1
		if span > maxRange {
			writeTypedError(ctx, w, apitypes.ErrorClassBatchTooLarge,
				http.StatusBadRequest,
				fmt.Sprintf("range %d exceeds max %d", span, maxRange))
			return
		}

		entries, err := deps.QueryAPI.ScanFromPosition(from, int(span))
		if err != nil {
			deps.Logger.Error("range query failed", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
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
// GET /v1/entries-hash/{hash_hex} — hash lookup
// ─────────────────────────────────────────────────────────────────────

// NewHashLookupHandler returns a single entry by its canonical hash.
//
// Routing decision matrix:
//
//	WAL.MetaState (when configured)   entry_index Outcome
//	───────────────────────────────   ──────────     ──────────────────
//	StatePending —              200 {state:pending}
//	StateManual —              200 {state:manual}
//	StateSequenced / StateShipped row exists 200 + full metadata
//	StateSequenced / StateShipped no row 500 (state machine
//	                                                    desync; sequencer
//	                                                    will catch up)
//	wal.ErrNotFound row exists 200 + full metadata
//	                                                    (post-GC-retention
//	                                                    case; sequencer
//	                                                    processed long ago)
//	wal.ErrNotFound no row 404
//	WAL transport error —              500
//
// When deps.WAL is nil (read-only ledger), the WAL probe is
// skipped and the handler falls through to entry_index directly.
func NewHashLookupHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		hashHex := r.URL.Path[len("/v1/entries-hash/"):]
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil || len(hashBytes) != 32 {
			writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
				http.StatusBadRequest, "invalid canonical hash")
			return
		}
		var hash [32]byte
		copy(hash[:], hashBytes)

		// Step 1: probe WAL (when configured) — catches entries
		// that are durable in WAL but not yet in entry_index. The
		// background sequencer eventually transitions them to
		// StateSequenced and INSERTs the entry_index row; until
		// then the truthful response is "pending", not 404.
		if deps.WAL != nil {
			meta, walErr := deps.WAL.MetaState(ctx, hash)
			switch {
			case walErr == nil:
				// State machine determines whether to short-circuit
				// or fall through to entry_index.
				switch meta.State {
				case wal.StatePending:
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"state":          "pending",
						"canonical_hash": hashHex,
					})
					return
				case wal.StateManual:
					// Sequencer gave up after MaxAttempts. Bytes
					// are durable in WAL but never reached
					// entry_index; consumer needs ledger
					// intervention.
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"state":          "manual",
						"canonical_hash": hashHex,
					})
					return
				case wal.StateSequenced, wal.StateShipped:
					// Fall through — the row should be in entry_index.
				}
			case errors.Is(walErr, wal.ErrNotFound):
				// Either never admitted, or admitted-and-GC'd. If
				// entry_index has the row we'll find it below; if
				// not, 404.
			default:
				deps.Logger.Error("hash lookup: WAL probe", "error", walErr)
				writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
					http.StatusInternalServerError, "WAL probe failed")
				return
			}
		}

		// Step 2: entry_index lookup (the original v1 code path).
		seq, found, err := deps.EntryStore.FetchByHash(ctx, hash)
		if err != nil {
			deps.Logger.Error("hash lookup failed", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		if !found {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "entry not found")
			return
		}

		entries, err := deps.QueryAPI.ScanFromPosition(seq, 1)
		if err != nil || len(entries) == 0 || entries[0].Position.Sequence != seq {
			deps.Logger.Error("hash lookup hydrate", "seq", seq, "got", len(entries), "err", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "fetch failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(entries)[0])
	}
}

// The raw-bytes endpoint (GET /v1/entries/{seq}/raw) lives in
// api/entries_read.go (NewRawEntryHandler). It does WAL-aware
// routing: 200 OK + inline body for un-shipped entries, 302
// Found + presigned URL for shipped entries past WAL retention.
// See entries_read.go's docblock for the full state machine.

// ─────────────────────────────────────────────────────────────────────
// Index-backed query handlers (ControlHeader field lookups)
// ─────────────────────────────────────────────────────────────────────
//
// These five handlers expose the PostgresQueryAPI's "query by control
// header field" methods. Referenced by api/server.go as
// Handlers.CosignatureOf / .TargetRoot / .SignerDID / .SchemaRef / .Scan
// and wired by both the read-write ledger (cmd/ledger) and the
// read-only ledger (cmd/ledger-reader).
//
// Uniform HTTP surface on purpose: one parsing rule, one response shape.

// NewQueryCosignatureOfHandler — GET /v1/query/cosignature_of/{pos}.
// {pos} encodes a LogPosition as "did:sequence".
func NewQueryCosignatureOfHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		pos, err := parseLogPosition(r.PathValue("pos"))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, err.Error())
			return
		}
		entries, err := deps.QueryAPI.QueryByCosignatureOf(pos)
		if err != nil {
			deps.Logger.Error("query cosignature_of", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQueryTargetRootHandler — GET /v1/query/target_root/{pos}.
func NewQueryTargetRootHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		pos, err := parseLogPosition(r.PathValue("pos"))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, err.Error())
			return
		}
		entries, err := deps.QueryAPI.QueryByTargetRoot(pos)
		if err != nil {
			deps.Logger.Error("query target_root", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQuerySignerDIDHandler — GET /v1/query/signer_did/{did}.
// {did} is the URL-encoded signer DID string.
func NewQuerySignerDIDHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		did := r.PathValue("did")
		if did == "" {
			writeTypedError(ctx, w, apitypes.ErrorClassMissingPathParam,
				http.StatusBadRequest, "signer DID required")
			return
		}
		entries, err := deps.QueryAPI.QueryBySignerDID(did)
		if err != nil {
			deps.Logger.Error("query signer_did", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQuerySchemaRefHandler — GET /v1/query/schema_ref/{pos}.
func NewQuerySchemaRefHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		pos, err := parseLogPosition(r.PathValue("pos"))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, err.Error())
			return
		}
		entries, err := deps.QueryAPI.QueryBySchemaRef(pos)
		if err != nil {
			deps.Logger.Error("query schema_ref", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}

// NewQueryScanHandler — GET /v1/query/scan?start=N&count=M.
// Flat scan from sequence N returning up to M entries (capped at MaxScanCount).
func NewQueryScanHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")
		start, err := strconv.ParseUint(startStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid start parameter")
			return
		}
		count := defaultScanCount
		if countStr != "" {
			parsed, err := strconv.Atoi(countStr)
			if err != nil || parsed <= 0 {
				writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
					http.StatusBadRequest, "invalid count parameter")
				return
			}
			count = parsed
		}
		entries, err := deps.QueryAPI.ScanFromPosition(start, count)
		if err != nil {
			deps.Logger.Error("query scan", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
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
			writeTypedError(r.Context(), w, apitypes.ErrorClassDBQueryFailed,
				http.StatusServiceUnavailable,
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
// DID itself may contain colons (did:web:x, did:attesta:a:b:c) so we
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
