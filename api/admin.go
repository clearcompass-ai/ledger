/*
FILE PATH:
    api/admin.go

DESCRIPTION:
    Admin endpoints (G5/G6 from the production-hardening plan):

        GET /v1/admin/config   — effective runtime config redacted
        GET /v1/admin/version  — version, commit, build time, SDK

    These are operator-debug surfaces. They let the on-call
    engineer prove from a single curl what the running pod
    actually loaded (vs. what the deployment manifest said it
    should load) and which build artifact this pod was made from.

KEY ARCHITECTURAL DECISIONS:
    - JSON output. Operators grep with jq; structured output
      composes cleanly into automation.
    - Redaction taxonomy: every secret-shaped field name (DSN,
      KEY_FILE, ACCESS_KEY, SECRET_KEY, SIGNER, CREDENTIALS) is
      redacted to "<redacted>" or "<set>"/"<unset>" depending on
      whether the operator wants to confirm presence vs. content.
      Public identifiers (LogDID, NetworkID, addrs, intervals) are
      surfaced verbatim.
    - No coupling to cmd/ledger config struct shape — the
      ConfigSnapshot type is a flat map[string]any built by
      cmd/ledger and handed in. Keeps api/ pgx-free + ledger-
      shape-agnostic.
    - Version handler reads from a VersionInfo value supplied at
      construction. cmd/ledger populates it from -ldflags-injected
      package vars (Version/Commit/BuildTime/SDKVersion).
    - UNAUTHENTICATED in this commit. The route registration
      comment in api/server.go documents that production
      deployments should mount these on a private pprof listener
      OR put auth in front. Future work: token-gated middleware.

OVERVIEW:
    cmd/ledger constructs a ConfigSnapshot at boot from its loaded
    Config (calling RedactSecrets) and a VersionInfo from the
    package-level vars, then wires both handlers into the
    Handlers struct.
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

// ConfigSnapshot is the redacted-effective-config payload returned
// by GET /v1/admin/config. cmd/ledger builds it from its loaded
// Config; api/ stays pgx + ledger-shape-free.
type ConfigSnapshot map[string]any

// VersionInfo is the payload returned by GET /v1/admin/version.
// All fields populated at build time via -ldflags except
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

// NewAdminConfigHandler returns the GET /v1/admin/config handler.
// snapshot is captured by reference so cmd/ledger can update
// individual entries at runtime if needed (none does today).
func NewAdminConfigHandler(snapshot ConfigSnapshot) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Sort keys for stable diff-friendly output. JSON
		// marshaling preserves map order in Go 1.12+, but
		// stability across versions is worth the explicit sort.
		keys := make([]string, 0, len(snapshot))
		for k := range snapshot {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		ordered := make(map[string]any, len(snapshot))
		for _, k := range keys {
			ordered[k] = snapshot[k]
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ordered)
	}
}

// NewAdminVersionHandler returns the GET /v1/admin/version
// handler. info is captured at boot; mutating package-level
// version vars after construction does NOT propagate (Go's
// closure capture semantics).
func NewAdminVersionHandler(info VersionInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(info)
	}
}
