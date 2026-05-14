/*
FILE PATH: store/indexes/delegate_did.go

QueryByDelegateDID — all live entries on this log whose
Header.DelegateDID matches the given DID. Used by the L2 read
API (PR-K) for the /v1/query/delegate_did/{did} endpoint that
judicial-network, multi-network shims, and audit tooling
consume to build their own delegation projections.

QueryLatestDelegationByDID — the single most-recent live row
for the same DID. Used by the admission-side
LedgerEntrySource (delegationresolver/) for the hot path that
the SDK's policy verifier's constraint walk consumes.

Both queries hit the idx_delegate_did_latest partial compound
index (migration 0008):

	(delegate_did, sequence_number DESC) WHERE delegate_did IS NOT NULL

QueryLatestDelegationByDID benefits most — the DESC half of
the compound key collapses "latest" to a single index seek with
no sort. QueryByDelegateDID also uses the index but iterates
DESC; callers paginate via the standard "?cursor=" patterns
when they need bounded result sets.
*/
package indexes

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/types"
)

// QueryByDelegateDID returns every live entry whose
// Header.DelegateDID equals did. Ordered by sequence_number
// DESCENDING — newest first. The read API consumer typically
// only cares about the latest few; sorting at the index keeps
// pagination cheap.
//
// Filters to StatusLive: tombstoned / ghost rows are excluded.
// Empty did → empty slice + nil error (no work to do).
func (q *PostgresQueryAPI) QueryByDelegateDID(did string) ([]types.EntryWithMetadata, error) {
	if did == "" {
		return nil, nil
	}
	ctx := q.ctx
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, log_time, canonical_hash
		  FROM entry_index
		 WHERE delegate_did = $1
		   AND status = 0
		 ORDER BY sequence_number DESC`,
		did,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/delegate_did: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
