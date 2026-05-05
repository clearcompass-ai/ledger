/*
FILE PATH: api/entries_read.go

Entry fetch-by-position endpoints. Three routes:

  GET /v1/entries/{seq}             → JSON metadata (no bytes)
  GET /v1/entries/batch?start&count → JSON list of metadata
  GET /v1/entries/{seq}/raw         → wire bytes
                                       200 OK inline (un-shipped)
                                       302 Found redirect (shipped)

THE 302 ROUTE — design summary:

  Under WAL-first admission, an entry's wire bytes live in one of
  two places at any moment:
    - the WAL (local NVMe, fast) — for pending/sequenced/manual
      states AND for shipped entries within the GC retention window
    - the byte store (network, GCS/S3) — for shipped entries past
      the GC retention window

  Serving inline from the operator (proxy-mode) for shipped entries
  doubles the egress bandwidth — the operator reads from GCS, then
  re-streams to the consumer. At 10B+ entries × ~1 MB each, this is
  petabytes of pointless re-transfer. The 302 redirect cuts the
  operator out of the byte path entirely: the consumer's HTTP client
  follows Location: <presigned URL> and fetches directly from the
  byte store, validated by SigV4 / V4 signatures bound to the
  hash-suffixed key.

  Routing decision matrix (computed inside the handler):

    Postgres entry_index        WAL meta state      Outcome
    ─────────────────────────   ─────────────────   ──────────────────
    no row at seq                —                   404
    row at seq                   StateSequenced      200 + wal.Read
    row at seq                   StateManual         200 + wal.Read
    row at seq                   StatePending        200 + wal.Read   *defensive*
    row at seq                   StateShipped        302 + presigned
    row at seq                   wal.ErrNotFound     302 + presigned   *post-GC*
    row at seq                   transport error     500
    no Presigner configured + StateShipped/post-GC   500   *misconfig*

  The handler is opaque to envelope structure — wire bytes go out
  raw. Consumers feed the response body to envelope.Deserialize and
  recover signatures via entry.Signatures.

KEY ARCHITECTURAL DECISIONS:
  - JSON-metadata endpoint (NewEntryBySequenceHandler) keeps its
    existing shape — backward-compatible for clients that only want
    the canonical_hash + log_time + signer_did.
  - Raw-bytes endpoint (NewRawEntryHandler) is the WAL-aware route.
  - Decoupled WAL surface: EntryWALReader and Presigner are
    interfaces; *wal.Committer satisfies the former, *bytestore.GCS
    or *bytestore.S3 satisfy the latter.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/apitypes"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Interfaces
// ─────────────────────────────────────────────────────────────────────

// EntryFetcher fetches a single entry by log position.
// Satisfied by store.PostgresEntryFetcher.
type EntryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// EntryWALReader is the WAL surface the raw-bytes handler needs.
// *wal.Committer satisfies it.
type EntryWALReader interface {
	Read(ctx context.Context, hash [32]byte) ([]byte, error)
	MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error)
}

// SeqHashLookup resolves seq → canonical_hash + log_time via Postgres entry_index.
// *store.EntryStore satisfies it.
type SeqHashLookup interface {
	FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, time.Time, bool, error)
}

// Presigner issues a time-bounded GET URL for a (seq, hash) tuple.
// bytestore.GCS and bytestore.S3 both satisfy this. nil = no
// redirect mode (the handler returns 500 when it would otherwise
// have redirected, so misconfiguration surfaces loudly rather than
// silently proxying through the WAL composite).
type Presigner interface {
	PresignGet(ctx context.Context, seq uint64, hash [32]byte, ttl time.Duration) (string, error)
}

// EntryReadDeps holds dependencies for entry read handlers.
type EntryReadDeps struct {
	Fetcher    EntryFetcher
	QueryAPI   QueryAPI
	EntryStore SeqHashLookup
	WAL        EntryWALReader
	Presigner  Presigner
	LogDID     string
	Logger     *slog.Logger

	// PresignTTL caps the lifetime of redirect URLs the handler
	// issues. Defaults to 1 hour. Capped at 7 days by the underlying
	// adapter (V4 / SigV4 ceiling).
	PresignTTL time.Duration
}

const maxBatchSize = 1000

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/{sequence} — JSON metadata
// ─────────────────────────────────────────────────────────────────────

// NewEntryBySequenceHandler creates GET /v1/entries/{sequence}.
// Returns metadata only (no bytes). For wire bytes use the /raw
// subroute.
func NewEntryBySequenceHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		seqStr := r.PathValue("sequence")
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid sequence number")
			return
		}

		pos := types.LogPosition{LogDID: deps.LogDID, Sequence: seq}
		entry, err := deps.Fetcher.Fetch(pos)
		if err != nil {
			deps.Logger.Error("entry fetch", "sequence", seq, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassFetcherFailed,
				http.StatusInternalServerError, "fetch failed")
			return
		}
		if entry == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "entry not found")
			return
		}

		responses := toEntryResponses([]types.EntryWithMetadata{*entry})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses[0])
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/batch?start&count — JSON metadata list
// ─────────────────────────────────────────────────────────────────────

func NewEntryBatchHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")
		if startStr == "" || countStr == "" {
			writeTypedError(ctx, w, apitypes.ErrorClassMissingQueryParam,
				http.StatusBadRequest, "start and count parameters required")
			return
		}

		start, err := strconv.ParseUint(startStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid start parameter")
			return
		}
		count, err := strconv.ParseUint(countStr, 10, 64)
		if err != nil || count == 0 {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid count parameter")
			return
		}
		if count > maxBatchSize {
			count = maxBatchSize
		}

		entries, err := deps.QueryAPI.ScanFromPosition(start, int(count))
		if err != nil {
			deps.Logger.Error("batch entry fetch", "start", start, "count", count, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "batch fetch failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(entries))
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/{seq}/raw — wire bytes (200 inline OR 302 redirect)
// ─────────────────────────────────────────────────────────────────────

// NewRawEntryHandler creates GET /v1/entries/{sequence}/raw.
// See file docblock for the routing decision matrix.
func NewRawEntryHandler(deps *EntryReadDeps) http.HandlerFunc {
	ttl := deps.PresignTTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Path: /v1/entries/{seq}/raw — strip prefix + suffix
		// (path-router patterns differ between Go versions; do
		// it manually here for portability).
		path := r.URL.Path
		if !strings.HasPrefix(path, "/v1/entries/") {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "invalid path")
			return
		}
		rest := strings.TrimPrefix(path, "/v1/entries/")
		rest = strings.TrimSuffix(rest, "/raw")
		seq, err := strconv.ParseUint(rest, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid sequence")
			return
		}

		// Step 1: seq → canonical_hash + log_time via Postgres entry_index.
		hash, logTime, found, err := deps.EntryStore.FetchHashBySeq(ctx, seq)
		if err != nil {
			deps.Logger.Error("raw entry: seq lookup", "seq", seq, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "lookup failed")
			return
		}
		if !found {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "entry not found")
			return
		}

		// Step 2: probe WAL meta to decide route.
		// Read-only operator (cmd/operator-reader) has no WAL —
		// serve everything via 302 redirect to the byte store.
		// Un-shipped entries surface as bytestore 404; consumers
		// retry against the writer or wait for the Shipper to
		// migrate them.
		if deps.WAL == nil {
			deps.serveBytestoreRedirect(w, r, seq, hash, logTime, ttl)
			return
		}

		meta, metaErr := deps.WAL.MetaState(ctx, hash)
		if metaErr != nil {
			if errors.Is(metaErr, wal.ErrNotFound) {
				// Post-GC: WAL has dropped the entry. The byte store
				// is the only source of truth.
				deps.serveBytestoreRedirect(w, r, seq, hash, logTime, ttl)
				return
			}
			deps.Logger.Error("raw entry: WAL meta probe",
				"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]), "error", metaErr)
			writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, "WAL probe failed")
			return
		}

		switch meta.State {
		case wal.StateSequenced, wal.StateManual, wal.StatePending:
			// Bytes still in the WAL — serve inline.
			deps.serveWALInline(w, r, seq, hash, logTime)
		case wal.StateShipped:
			// Bytes have migrated to the byte store. Redirect.
			deps.serveBytestoreRedirect(w, r, seq, hash, logTime, ttl)
		default:
			deps.Logger.Error("raw entry: unknown WAL state",
				"seq", seq, "state", meta.State)
			writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, "WAL state machine corrupted")
		}
	}
}

// setRawHeaders writes the SDK-canonical /raw response headers:
// X-Sequence (uint64 decimal) and X-Log-Time (RFC-3339Nano UTC). The
// SDK's log.HTTPEntryFetcher reads both; pre-this-fix the operator
// only stamped X-Sequence, so consumers that needed LogTime had to
// round-trip to the JSON metadata endpoint (Tier-2 alignment).
//
// X-Log-Time is omitted (rather than stamping a zero-time string)
// when the operator does not have a log_time on file — older
// entry_index rows pre-dating the column population may exist; the
// SDK fetcher tolerates absence with a zero-valued LogTime.
func setRawHeaders(w http.ResponseWriter, seq uint64, logTime time.Time) {
	w.Header().Set("X-Sequence", strconv.FormatUint(seq, 10))
	if !logTime.IsZero() {
		w.Header().Set("X-Log-Time", logTime.UTC().Format(time.RFC3339Nano))
	}
}

// serveWALInline writes the WAL's wire bytes directly to the response.
// 200 OK with Content-Type: application/octet-stream.
func (deps *EntryReadDeps) serveWALInline(w http.ResponseWriter, r *http.Request, seq uint64, hash [32]byte, logTime time.Time) {
	wire, err := deps.WAL.Read(r.Context(), hash)
	if err != nil {
		// WAL had meta but lost the entry between probe and read —
		// concurrent GC, in principle. Fall through to bytestore
		// redirect if available; otherwise 500.
		if errors.Is(err, wal.ErrNotFound) && deps.Presigner != nil {
			deps.serveBytestoreRedirect(w, r, seq, hash, logTime, deps.PresignTTL)
			return
		}
		deps.Logger.Error("raw entry: WAL read", "seq", seq, "error", err)
		writeTypedError(r.Context(), w, apitypes.ErrorClassReadProjectionFailed,
			http.StatusInternalServerError, "WAL read failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	setRawHeaders(w, seq, logTime)
	w.Header().Set("X-Source", "wal")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wire)
}

// serveBytestoreRedirect issues a 302 with a presigned URL pointing
// at the byte store object. If no Presigner is configured, returns
// 500 — silent fallback to inline streaming would defeat the egress-
// reduction purpose of the redirect.
func (deps *EntryReadDeps) serveBytestoreRedirect(
	w http.ResponseWriter, r *http.Request,
	seq uint64, hash [32]byte, logTime time.Time, ttl time.Duration,
) {
	if deps.Presigner == nil {
		deps.Logger.Error("raw entry: shipped entry but no Presigner configured",
			"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]))
		writeTypedError(r.Context(), w, apitypes.ErrorClassFetcherFailed,
			http.StatusInternalServerError,
			"byte store redirect not configured")
		return
	}
	url, err := deps.Presigner.PresignGet(r.Context(), seq, hash, ttl)
	if err != nil {
		deps.Logger.Error("raw entry: PresignGet",
			"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]), "error", err)
		writeTypedError(r.Context(), w, apitypes.ErrorClassFetcherFailed,
			http.StatusInternalServerError, "presign failed")
		return
	}
	w.Header().Set("Location", url)
	setRawHeaders(w, seq, logTime)
	w.Header().Set("X-Source", "bytestore")
	// Cache-Control: private,max-age=<ttl-30s> would let the
	// consumer's HTTP cache hold the URL for almost its lifetime
	// without re-asking us. Skipped for now; commit 13 adds it
	// alongside operational telemetry.
	w.WriteHeader(http.StatusFound)
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time pins
// ─────────────────────────────────────────────────────────────────────

// SeqHashLookup is satisfied by api.EntryStore (see ports.go);
// the EntryStore interface declares FetchHashBySeq so any
// implementation that implements it satisfies SeqHashLookup
// transitively. The wire-time pin lives at cmd/operator/main.go
// where *store.EntryStore is assigned into the api EntryStore
// interface field — drift in either side surfaces there.
var _ SeqHashLookup = EntryStore(nil)
