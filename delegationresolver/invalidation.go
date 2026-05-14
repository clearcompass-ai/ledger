/*
FILE PATH:

	delegationresolver/invalidation.go

DESCRIPTION:

	Rotation-aware invalidation API for the delegation cache.

	The cache (cache.go) carries an LRU snapshot of "what is the
	current delegation for DID X?" That snapshot is correct until
	the on-log delegation for X changes — typically when a new
	delegation entry for X is admitted (rotation, revocation,
	scope-set update). Without invalidation, post-rotation
	admissions would see stale delegations from the cache for
	the rotation's TTL window and accept entries that should
	now be rejected.

WHAT INVALIDATES:

  - Direct: Cached.Invalidate(delegateDID) on demand. Operator
    tooling or test code calls this directly.
  - InvalidateOnEntry: passed an envelope.Entry, the helper
    inspects the header for the rotation signal (a non-nil
    DelegateDID indicating the entry IS a delegation update for
    that DID) and clears the cache row.

WHERE THE HOOK FIRES:

	The conventional integration point is the post-admission
	dispatch in api/submission.go AFTER the entry is durably in
	the WAL and the sequence number has been issued. A future
	wiring PR (E or F) drops a single line:

	    cache.InvalidateOnEntry(entry)

	directly there. Plumbing the cache through SubmissionDeps is
	deferred until that consumer lands so this PR stays substrate-
	only with no production-path changes.

DEFENSIVE DESIGN:

	A nil *Cached makes both invalidation helpers no-ops. Tests
	and degraded modes that don't wire a cache still survive the
	invalidation call site without nil-panic.
*/
package delegationresolver

import (
	"github.com/clearcompass-ai/attesta/core/envelope"
)

// InvalidateOnEntry inspects entry's header for delegation-update
// signals and clears any matching cache row. Returns true if a
// row was actually evicted; false on no-op (entry not a
// delegation, or cache didn't have the key).
//
// The signal: entry.Header.DelegateDID is non-nil. Per envelope's
// ControlHeader contract, that field is set ONLY on entries that
// are themselves delegation events. The two cases (rotation /
// revocation) both invalidate equally — the cache simply re-asks
// the underlying source on next lookup and gets the new answer.
//
// nil cache or nil entry are silent no-ops.
func InvalidateOnEntry(c *Cached, entry *envelope.Entry) bool {
	if c == nil || entry == nil {
		return false
	}
	if entry.Header.DelegateDID == nil {
		return false
	}
	did := *entry.Header.DelegateDID
	if did == "" {
		return false
	}
	return c.Invalidate(did)
}

// InvalidateOnEntries fans the invalidator across a slice. Used
// by batch admission paths or by replay tooling that wants to
// re-warm a fresh cache against a span of recent entries.
//
// Returns the count of entries that produced an actual eviction.
func InvalidateOnEntries(c *Cached, entries []*envelope.Entry) int {
	if c == nil || len(entries) == 0 {
		return 0
	}
	n := 0
	for _, e := range entries {
		if InvalidateOnEntry(c, e) {
			n++
		}
	}
	return n
}
