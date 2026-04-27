/*
FILE PATH: store/indexes/query_api.go

PostgresQueryAPI satisfies sdk log.OperatorQueryAPI. Methods are spread
across the package files — each file provides one method's SQL query.

DESIGN RULE: Postgres is an index. Tessera is the source of truth for
entry bytes. Always.

  - Queries hit entry_index for sequence numbers + metadata.
  - Entry bytes hydrated via EntryReader (bytestore.Reader).
  - scanAndHydrate: query rows → collect seqs + metadata → batch hydrate.
  - ReadEntryBatch is tile-aware: entries in the same tile = 1 read.

EntryWithMetadata field set: under v6 the SDK type carries only
CanonicalBytes, LogTime, Position. Signatures live inside
CanonicalBytes (in the v6 multi-sig section) and are extracted via
envelope.Deserialize when callers need them. No sidecar sig
fields exist on the type or in the entry_index schema.
*/
package indexes

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/bytestore"
)

// MaxScanCount is the hard upper limit per scan request.
const MaxScanCount = 10000

// DefaultScanCount is the default page size when count is not specified.
const DefaultScanCount = 100

// PostgresQueryAPI implements sdk log.OperatorQueryAPI.
// Metadata from entry_index (Postgres). Bytes from EntryReader (Tessera).
type PostgresQueryAPI struct {
	db     *pgxpool.Pool
	reader bytestore.Reader
	logDID string
}

// NewPostgresQueryAPI creates the query API for a log.
func NewPostgresQueryAPI(db *pgxpool.Pool, reader bytestore.Reader, logDID string) *PostgresQueryAPI {
	return &PostgresQueryAPI{db: db, reader: reader, logDID: logDID}
}

// indexMeta holds the metadata columns scanned from entry_index.
// Aligned with the v6 EntryWithMetadata field set: only sequence
// number and log time are needed to populate the response.
type indexMeta struct {
	Seq  uint64
	Time time.Time
}

// scanAndHydrate queries entry_index for metadata, then batch-hydrates
// bytes from EntryReader. Shared path for all 5 query methods.
//
// SQL projection contract: per-method queries that call this helper
// MUST select exactly (sequence_number, log_time) in that order.
func (q *PostgresQueryAPI) scanAndHydrate(ctx context.Context, rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}) ([]types.EntryWithMetadata, error) {
	defer rows.Close()

	// (1) Collect sequence numbers + metadata from Postgres.
	var metas []indexMeta
	for rows.Next() {
		var (
			seq uint64
			lt  time.Time
		)
		if err := rows.Scan(&seq, &lt); err != nil {
			return nil, fmt.Errorf("store/indexes: scan: %w", err)
		}
		metas = append(metas, indexMeta{Seq: seq, Time: lt})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/indexes: rows: %w", err)
	}

	if len(metas) == 0 {
		return []types.EntryWithMetadata{}, nil
	}

	// (2) Batch-hydrate wire bytes from EntryReader.
	seqs := make([]uint64, len(metas))
	for i, m := range metas {
		seqs[i] = m.Seq
	}
	wires, err := q.reader.ReadEntryBatch(seqs)
	if err != nil {
		return nil, fmt.Errorf("store/indexes: hydrate: %w", err)
	}

	// (3) Assemble []EntryWithMetadata. Three-field type per the v6
	// SDK; signatures live inside CanonicalBytes (wire bytes ARE the
	// canonical bytes) and surface via envelope.Deserialize.
	results := make([]types.EntryWithMetadata, len(metas))
	for i, m := range metas {
		results[i] = types.EntryWithMetadata{
			CanonicalBytes: wires[i],
			LogTime:        m.Time,
			Position:       types.LogPosition{LogDID: q.logDID, Sequence: m.Seq},
		}
	}
	return results, nil
}
