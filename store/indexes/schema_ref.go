/*
FILE PATH: store/indexes/schema_ref.go

QueryBySchemaRef — all entries governed by a specific schema.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// QueryBySchemaRef returns entries referencing the given schema position.
func (q *PostgresQueryAPI) QueryBySchemaRef(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	ctx := context.TODO()
	posBytes := store.SerializeLogPosition(pos)
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, log_time, canonical_hash
		FROM entry_index WHERE schema_ref = $1 ORDER BY sequence_number ASC`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/schema_ref: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
