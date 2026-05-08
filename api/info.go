/*
FILE PATH:

	api/info.go

DESCRIPTION:

	Public introspection endpoints. The ledger is zero-trust by
	design: there is no privileged "admin" surface. Build
	provenance and deployment posture are AUDITOR-FACING surfaces
	that pair with /checkpoint and the witness bootstrap document
	as the public-truth artifacts of this log.

	    GET /version       — build provenance (cacheable 1h)
	    GET /v1/log-info   — public deployment posture (cacheable 60s)

KEY ARCHITECTURAL DECISIONS:
  - PUBLIC, no auth. The trust model (L-1 dumb ledger, T-6
    zero-trust dual verification, T-11 pull-based gossip)
    mandates that anything an SRE needs to debug is also
    something an auditor needs to verify. If a piece of info
    was sensitive enough to require auth, it doesn't belong on
    a runtime endpoint at all — operational tunables (pool
    sizes, timeouts, internal paths) are surfaced via the boot
    banner log + pprof private listener instead.
  - Two endpoints, two cache windows:
    /version → 1 hour (build is immutable)
    /v1/log-info → 60 seconds (witness rotation + topology
    changes propagate within a minute)
  - LogInfo is the SCOPED payload — only fields auditors need
    to verify the log's posture (LogDID, NetworkID, witness
    set, byte-store backend, tile backend, gossip enabled).
    Operational tunables (PG pool sizes, statement timeout,
    WAL path) are deliberately absent; the boot banner G7 is
    the authoritative source for those.
  - JSON output. Auditors compose with jq; downstream tooling
    (monitors, witness coordinators) parses programmatically.
  - cmd/ledger constructs both payloads at boot and hands them
    in. api/ stays pgx + ledger-shape-free (L-8 pure CQRS).

OVERVIEW:

	/version     — deterministic per-build, no ledger state.
	/v1/log-info — captures the deployment posture cmd/ledger
	               loaded; matches what the boot banner logs
	               minus the operational-only fields.

KEY DEPENDENCIES:
  - encoding/json: payload encoding.
  - net/http: handler shape.
*/
package api

import (
	"encoding/json"
	"net/http"
	"sort"
)

// -------------------------------------------------------------------------------------------------
// 1) Types
// -------------------------------------------------------------------------------------------------

// LogInfo is the public deployment-posture payload returned by
// GET /v1/log-info. cmd/ledger builds it from its loaded Config;
// api/ stays pgx + ledger-shape-free.
//
// SCOPE: only fields an external auditor needs to verify the
// log's trust posture. Operational tunables (pool sizes,
// statement timeout, internal file paths) are NOT included here
// — they live in the boot banner log (G7) for administrators to read
// from their log shipper.
type LogInfo map[string]any

// VersionInfo is the build-provenance payload returned by GET
// /version. Fields populated at build time via -ldflags except
// SDKVersion which comes from go.mod.
type VersionInfo struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	BuildTime  string `json:"build_time"`
	SDKVersion string `json:"sdk_version"`
}

// -------------------------------------------------------------------------------------------------
// 2) Handlers
// -------------------------------------------------------------------------------------------------

// NewLogInfoHandler returns the GET /v1/log-info handler. The
// payload is captured by reference; cmd/ledger may mutate
// individual entries at runtime (none does today).
//
// Cache-Control: public, max-age=60. Witness rotation can change
// witness_quorum_k and witness_set_hash; a minute is the
// staleness floor we accept on the public surface.
func NewLogInfoHandler(info LogInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Sort keys for stable diff-friendly output. JSON
		// marshaling preserves map order in Go 1.12+, but
		// stability across versions is worth the explicit sort.
		keys := make([]string, 0, len(info))
		for k := range info {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		ordered := make(map[string]any, len(info))
		for _, k := range keys {
			ordered[k] = info[k]
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ordered)
	}
}

// NewVersionHandler returns the GET /version handler. info is
// captured at boot; mutating package-level version vars after
// construction does NOT propagate (Go's closure capture).
//
// Cache-Control: public, max-age=3600. Build is immutable per
// pod; the only way a /version response can change is via a
// rolling redeploy, in which case auditors' cached responses
// will already be stale by the next probe cycle.
func NewVersionHandler(info VersionInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(info)
	}
}
