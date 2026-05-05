/*
FILE PATH: api/mmd.go

GET /v1/admission/mmd — the ledger's published Maximum Merge Delay.
This is the SLA on the Sequencer's drain latency: the ledger
asserts that any entry it issues an SCT for will be merged into the
log within MMD seconds.

RFC 6962-aligned. Consumers verify the ledger's promised
redemption window programmatically before trusting any SCT, so the
SCT semantics are auditable end-to-end without out-of-band
configuration agreements.
*/
package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// NewMMDHandler returns a handler that publishes the ledger's
// Maximum Merge Delay as both seconds (for programmatic checks)
// and a human-readable form (for ops dashboards).
func NewMMDHandler(mmd time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"mmd_seconds": mmd.Seconds(),
			"mmd_human":   mmd.String(),
		})
	}
}
