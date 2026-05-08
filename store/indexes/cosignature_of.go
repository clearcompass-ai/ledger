/*
FILE PATH: store/indexes/cosignature_of.go

QueryByCosignatureOf — certification-required per governance spec.
Returns all entries whose Cosignature_Of field matches the given position.
*/
package indexes

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// QueryByCosignatureOf returns entries whose Cosignature_Of matches pos.
func (q *PostgresQueryAPI) QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	ctx := q.ctx
	posBytes := store.SerializeLogPosition(pos)
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, log_time, canonical_hash
		FROM entry_index WHERE cosignature_of = $1 ORDER BY sequence_number ASC`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/cosignature_of: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
