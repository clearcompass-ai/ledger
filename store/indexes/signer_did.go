/*
FILE PATH: store/indexes/signer_did.go

QueryBySignerDID — all entries signed by a specific DID.
Postgres provides sequence numbers + metadata. EntryReader provides bytes.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// QueryBySignerDID returns entries signed by the given DID.
func (q *PostgresQueryAPI) QueryBySignerDID(did string) ([]types.EntryWithMetadata, error) {
	ctx := context.TODO()
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, log_time, canonical_hash
		FROM entry_index WHERE signer_did = $1 ORDER BY sequence_number ASC`,
		did,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/signer_did: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
