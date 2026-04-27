/*
FILE PATH: store/indexes/target_root.go

QueryByTargetRoot — all entries targeting a specific root entity.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// QueryByTargetRoot returns entries whose Target_Root matches pos.
func (q *PostgresQueryAPI) QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	ctx := context.TODO()
	posBytes := store.SerializeLogPosition(pos)
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, log_time
		FROM entry_index WHERE target_root = $1 ORDER BY sequence_number ASC`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/target_root: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
