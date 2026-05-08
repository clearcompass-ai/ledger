/*
FILE PATH: store/indexes/scan.go

ScanFromPosition — sequential iteration using the entry_index primary key.
For monitoring, load accounting, mirror consistency, delta buffer reconstruction.

KEY ARCHITECTURAL DECISIONS:
  - Uses sequence_number PK directly: no secondary index needed.
  - Strict ascending order: deterministic pagination.
  - Hard cap at MaxScanCount: prevents unbounded result sets.
  - Bytes hydrated from EntryReader, not stored in Postgres.
*/
package indexes

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/types"
)

// ScanFromPosition returns entries starting at startPos in sequence order.
// Count is clamped to MaxScanCount. Returns empty slice (never nil) if no results.
func (q *PostgresQueryAPI) ScanFromPosition(startPos uint64, count int) ([]types.EntryWithMetadata, error) {
	ctx := q.ctx
	if count <= 0 {
		count = DefaultScanCount
	}
	if count > MaxScanCount {
		count = MaxScanCount
	}
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, log_time, canonical_hash
		FROM entry_index WHERE sequence_number >= $1 ORDER BY sequence_number ASC LIMIT $2`,
		startPos, count,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/scan: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
