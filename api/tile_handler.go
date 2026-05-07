/*
FILE PATH:
    api/tile_handler.go

DESCRIPTION:
    Static-CT tile-serving handlers. Mounts three routes that
    follow c2sp.org/tlog-tiles exactly:

        GET /checkpoint
        GET /tile/{level}/{rest...}             (hash tiles)
        GET /tile/entries/{rest...}             (entry-bundle tiles)

    External auditors fetch these to reconstruct inclusion +
    consistency proofs offline using the SDK's
    log/tessera_fetcher primitive — no per-entry round-trip to
    the ledger required, no ledger CPU consumed past one
    os.ReadFile per tile.

KEY ARCHITECTURAL DECISIONS:
    - Path-traversal defense in depth. The TileBackend already
      defends against ".." escape via filepath.Clean +
      prefix-check; this handler ALSO refuses path segments
      containing "..", absolute paths, and non-printable bytes
      BEFORE calling the backend. A malicious URL never reaches
      the filesystem layer.
    - Cache-Control matched to c2sp.org / Sigsum / Sigstore
      Rekor convention so a generic CDN (CloudFront, Cloud CDN,
      Fastly) fronts these routes without bespoke config:
          full tiles       Cache-Control: public, max-age=86400, immutable
          partial tiles    Cache-Control: public, max-age=2
          checkpoint       Cache-Control: max-age=2
      Full-tile immutability is a structural property of the
      c2sp spec — once written, a full tile never changes.
    - Range header support via stdlib http.ServeContent. Lets
      auditors resume large entry-bundle downloads without re-
      fetching from byte 0.
    - Single dispatcher for /tile/{level}/{rest...} routes by
      LITERAL path-segment match: level=="entries" → entry
      bundles, otherwise hash tiles. Stdlib's mux pattern
      coverage stays unambiguous (no specificity collision
      with /tile/entries/...).
    - LEDGER_TILE_SERVE_DISABLE escape hatch in cmd/ledger
      composes by passing nil handlers to api.NewServer; this
      file's helpers are pure constructors and impose no
      requirement.
    - Bounded I/O. The TileBackend's underlying os.ReadFile is
      bounded by the file size on disk; we don't add an in-handler
      cap because tile sizes are mathematically bounded by the
      c2sp spec (256 entries × MaxBundleEntrySize). The SDK's
      log/tessera_fetcher.MaxTileBytes (~16 MiB) is the matching
      ceiling on the fetch side.

OVERVIEW:
    Each handler:
        1. Validates the path segment(s) for traversal /
           printable-ASCII discipline.
        2. Calls TileBackend.ReadTileByPath (or ReadCheckpoint)
           with the request context.
        3. On os.ErrNotExist → 404. On other errors → 500.
        4. On success → ServeContent with the appropriate
           Cache-Control header. ServeContent handles If-Modified-
           Since, If-None-Match, Range, and HEAD verbs natively.

KEY DEPENDENCIES:
    - tessera/posix_tile_backend.go: TileBackend impl backing
      ReadTileByPath / ReadCheckpoint.
    - net/http: ServeContent for Range + ETag handling.
    - apitypes.ErrorClass: typed error_class taxonomy for the
      structured-error responses.
*/
package api

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clearcompass-ai/ledger/apitypes"
	"github.com/clearcompass-ai/ledger/bytestore"
)

// -------------------------------------------------------------------------------------------------
// 1) Backend contract (re-exported from bytestore)
// -------------------------------------------------------------------------------------------------

// TileBackend is an alias for bytestore.TileBackend — the
// read-only storage contract behind the /checkpoint and /tile
// HTTP routes. Re-exported here so the api package's public
// surface stays self-contained for callers that import api
// alone, while the canonical definition + compile-time guards
// for concrete implementations (POSIX, GCS) live in bytestore.
type TileBackend = bytestore.TileBackend

// -------------------------------------------------------------------------------------------------
// 2) Cache-Control constants
// -------------------------------------------------------------------------------------------------

// CacheControlFullTile applies to fully-integrated tiles. Once
// a tile is fully populated (256 entries at the leaf level, or
// 256 children at intermediate levels), it never changes —
// "immutable" tells CDNs to skip re-validation entirely.
const CacheControlFullTile = "public, max-age=86400, immutable"

// CacheControlPartialTile applies to partial tiles (leading
// frontier of the tree). Partial tiles are mutable until the
// full tile bound is reached; short max-age forces edge re-
// validation but still off-loads steady-state queries.
const CacheControlPartialTile = "public, max-age=2"

// CacheControlCheckpoint applies to /checkpoint. Updates every
// integration cycle (typically seconds-to-minutes). Short
// max-age so auditors see the latest signed root within bounded
// staleness; ETag-driven re-validation handled by ServeContent.
const CacheControlCheckpoint = "max-age=2"

// -------------------------------------------------------------------------------------------------
// 3) Constructors — handler factories
// -------------------------------------------------------------------------------------------------

// NewCheckpointHandler returns the GET /checkpoint handler.
//
// Returns the c2sp.org/tlog-tiles signed checkpoint Tessera
// writes after each integration cycle. Auditors fetch this to
// anchor inclusion proofs.
func NewCheckpointHandler(backend TileBackend, logger *slog.Logger) http.HandlerFunc {
	if backend == nil {
		// Defensive — if cmd/ledger wired Checkpoint without a
		// backend, return 503 rather than panic. The route is
		// nil-guarded in api/server.go so this branch should
		// never fire in a correctly-wired deployment.
		return func(w http.ResponseWriter, r *http.Request) {
			writeTypedError(r.Context(), w, apitypes.ErrorClassNotFound,
				http.StatusServiceUnavailable, "tile backend not configured")
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := backend.ReadCheckpoint(r.Context())
		if errors.Is(err, os.ErrNotExist) {
			// Fresh boot before first integration cycle.
			writeTypedError(r.Context(), w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "checkpoint not yet available")
			return
		}
		if err != nil {
			logger.ErrorContext(r.Context(), "checkpoint read failed", "error", err)
			writeTypedError(r.Context(), w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, fmt.Sprintf("checkpoint read failed: %s", err))
			return
		}
		w.Header().Set("Cache-Control", CacheControlCheckpoint)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeContent(w, r, "checkpoint", time.Time{}, bytes.NewReader(data))
	}
}

// NewTileHandler returns the GET /tile/{level}/{rest...} handler.
//
// Dispatches internally:
//
//   - {level} == "entries" → entry-bundle tile served from
//     <root>/tile/entries/{rest...}.
//   - {level} parses as a small integer → hash tile served from
//     <root>/tile/{level}/{rest...}.
//
// The single-handler dispatcher keeps the stdlib mux pattern
// coverage unambiguous — no specificity collision between
// /tile/entries/... and /tile/{level}/...
func NewTileHandler(backend TileBackend, logger *slog.Logger) http.HandlerFunc {
	if backend == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			writeTypedError(r.Context(), w, apitypes.ErrorClassNotFound,
				http.StatusServiceUnavailable, "tile backend not configured")
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		level := r.PathValue("level")
		rest := r.PathValue("rest")

		// Path-traversal defense in depth (the TileBackend also
		// defends, but stopping the request at the handler edge
		// keeps the os.ReadFile call site free of hostile input).
		if !validPathSegment(level) || !validRestPath(rest) {
			writeTypedError(r.Context(), w, apitypes.ErrorClassBadHexEncoding,
				http.StatusBadRequest, "invalid tile path")
			return
		}

		// Compose the c2sp path. The TileBackend expects the
		// path WITHOUT a leading slash and INCLUDING the leading
		// "tile/" component.
		fullPath := "tile/" + level + "/" + rest

		data, err := backend.ReadTileByPath(r.Context(), fullPath)
		if errors.Is(err, os.ErrNotExist) {
			// Standard c2sp "not yet integrated" signal — 404
			// matches the partial-then-full fallback flow the
			// SDK's log/tessera_fetcher implements.
			writeTypedError(r.Context(), w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "tile not found")
			return
		}
		if err != nil {
			logger.ErrorContext(r.Context(), "tile read failed",
				"path", fullPath, "error", err)
			writeTypedError(r.Context(), w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, fmt.Sprintf("tile read failed: %s", err))
			return
		}

		// Cache-Control: full tiles are immutable (256-entry
		// boundary); partial tiles re-validate at the edge. The
		// ".p/" segment in the path is the c2sp marker for
		// partial tiles.
		if isPartialTilePath(rest) {
			w.Header().Set("Cache-Control", CacheControlPartialTile)
		} else {
			w.Header().Set("Cache-Control", CacheControlFullTile)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, fullPath, time.Time{}, bytes.NewReader(data))
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Path validation
// -------------------------------------------------------------------------------------------------

// validPathSegment guards a single path segment. Rejects empty,
// path-traversal markers, absolute-path bytes, and any non-
// printable / non-ASCII content. Tile path segments are tightly
// bounded by the c2sp spec (digits or the literal "entries"),
// so even small extra characters are signal of malformed input.
func validPathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.ContainsAny(s, "/\\") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// validRestPath guards the multi-segment {rest...} captured by
// the stdlib mux wildcard. Each segment is validated; the joined
// path must not contain "..".
func validRestPath(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	if strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Allow path separator + dot (for ".p/" partial markers)
		// + alphanumeric + nothing else.
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '/' || c == '.':
		default:
			return false
		}
	}
	// Reject any path that has a "." or empty path component (i.e.,
	// "tile/0/.", "tile//067", "."). Surfaced by the J1 fuzzer as a
	// shape that producers never emit but storage backends would
	// resolve inconsistently. Defense-in-depth on the path-traversal
	// rejection above.
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." {
			return false
		}
	}
	return true
}

// isPartialTilePath reports whether the rest-path segment
// indicates a partial tile (per c2sp.org spec, partial tiles
// carry a ".p/{partial_size}" suffix).
func isPartialTilePath(rest string) bool {
	return strings.Contains(rest, ".p/")
}

// -------------------------------------------------------------------------------------------------
// 5) Helpers
// -------------------------------------------------------------------------------------------------

// fmtBackendErr is a small helper used in tests + callers that
// want a single-line backend-error string without leaking the
// raw filesystem path of the error chain.
func fmtBackendErr(err error) string {
	return fmt.Sprintf("backend: %s", err.Error())
}

var _ = fmtBackendErr // silence unused-symbol warnings; available for tests
