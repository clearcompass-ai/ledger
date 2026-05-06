/*
FILE PATH: api/middleware/evidence_cap.go

Early guard that rejects entries with Evidence_Pointers exceeding
the cap (10) unless the entry is an Authority Snapshot.

KEY ARCHITECTURAL DECISIONS:
  - Early rejection at HTTP layer before builder queue.
  - Snapshot heuristic: AuthorityPath==ScopeAuthority AND TargetRoot set
    AND PriorAuthority set → exempt from cap.
  - Duplicates the check in sdk NewEntry; defense in depth.
*/
package middleware

import (
	"github.com/clearcompass-ai/attesta/core/envelope"
)

// MaxEvidencePointers caps Evidence_Pointers per entry.
const MaxEvidencePointers = 10

// CheckEvidenceCap validates the evidence pointer cap for a deserialized entry.
// Returns true if the entry is within cap or is an exempt snapshot.
func CheckEvidenceCap(entry *envelope.Entry) bool {
	h := &entry.Header
	if len(h.EvidencePointers) <= MaxEvidencePointers {
		return true
	}
	// Authority Snapshot exemption: AuthorityPath=ScopeAuthority + TargetRoot + PriorAuthority.
	if h.AuthorityPath != nil &&
		*h.AuthorityPath == envelope.AuthorityScopeAuthority &&
		h.TargetRoot != nil &&
		h.PriorAuthority != nil {
		return true
	}
	return false
}
