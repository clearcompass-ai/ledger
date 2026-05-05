/*
FILE PATH: store/indexes/query_api.go

PostgresQueryAPI satisfies sdk log.LedgerQueryAPI. Methods are spread
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

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/bytestore"
)

// MaxScanCount is the hard upper limit per scan request.
const MaxScanCount = 10000

// DefaultScanCount is the default page size when count is not specified.
const DefaultScanCount = 100

// PostgresQueryAPI implements sdk log.LedgerQueryAPI.
// Metadata from entry_index (Postgres). Bytes from EntryReader (Tessera).
type PostgresQueryAPI struct {
	db *pgxpool.Pool
	reader bytestore.Reader
	logDID string
}

// NewPostgresQueryAPI creates the query API for a log.
func NewPostgresQueryAPI(db *pgxpool.Pool, reader bytestore.Reader, logDID string) *PostgresQueryAPI {
	return &PostgresQueryAPI{db: db, reader: reader, logDID: logDID}
}

// indexMeta holds the metadata columns scanned from entry_index.
// canonical_hash is required to construct the bytestore object key
// for the read-side hydrate; log_time and seq populate the response.
type indexMeta struct {
	Seq uint64
	Time time.Time
	Hash [32]byte
}

// scanAndHydrate queries entry_index for metadata, then batch-hydrates
// bytes from EntryReader. Shared path for all 5 query methods.
//
// SQL projection contract: per-method queries that call this helper
// MUST select exactly (sequence_number, log_time, canonical_hash)
// in that order.
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
			lt time.Time
			hashCol []byte
		)
		if err := rows.Scan(&seq, &lt, &hashCol); err != nil {
			return nil, fmt.Errorf("store/indexes: scan: %w", err)
		}
		if len(hashCol) != 32 {
			return nil, fmt.Errorf("store/indexes: corrupt canonical_hash seq=%d (len=%d, want 32)", seq, len(hashCol))
		}
		var meta indexMeta
		meta.Seq = seq
		meta.Time = lt
		copy(meta.Hash[:], hashCol)
		metas = append(metas, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/indexes: rows: %w", err)
	}

	if len(metas) == 0 {
		return []types.EntryWithMetadata{}, nil
	}

	// (2) Batch-hydrate wire bytes from EntryReader.
	refs := make([]bytestore.EntryRef, len(metas))
	for i, m := range metas {
		refs[i] = bytestore.EntryRef{Seq: m.Seq, Hash: m.Hash}
	}
	wires, err := q.reader.ReadEntryBatch(ctx, refs)
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
