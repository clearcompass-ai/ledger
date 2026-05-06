/*
FILE PATH: store/commitment_fetcher.go

PostgresCommitmentFetcher — implements the SDK's
types.CommitmentFetcher interface for cryptographic commitment
lookup. The SDK primitives FetchPREGrantCommitment and
FetchEscrowSplitCommitment depend on this fetcher to resolve a
SplitID to its on-log entries.

Contract:

	FindCommitmentEntries(schemaID string, splitID [32]byte)
	    ([]*types.EntryWithMetadata, error)

	- Returns ALL matching rows (length 1 normal case, length 2+ on
	  dealer equivocation). Multi-row preservation is the load-bearing
	  invariant; the SDK's *CommitmentEquivocationError construction
	  depends on it.
	- Joins commitment_split_id (the secondary index) → entry_index
	  (metadata) → bytestore.Reader (canonical bytes) so the
	  EntryWithMetadata struct returned matches what
	  PostgresEntryFetcher.Fetch produces — same canonical bytes,
	  same log_time, same position.

EntryWithMetadata field set: the SDK type carries CanonicalBytes,
LogTime, Position. Signatures live inside CanonicalBytes (extracted
via envelope.Deserialize when needed); this fetcher reads only what
the type carries.

DESIGN RULE (mirrors store/entries.go): Postgres is an index;
Tessera is the source of truth for entry bytes. The fetcher reads
sequence numbers + metadata from Postgres and bytes from
bytestore.Reader; the two sources stay separated.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/bytestore"
)

// PostgresCommitmentFetcher resolves a (schemaID, splitID) tuple to
// every matching entry on the ledger's log. Implements the SDK's
// types.CommitmentFetcher interface.
//
// Distinct from PostgresEntryFetcher: the latter is keyed by
// LogPosition (uniquely one row), this one is keyed by SplitID
// (potentially multiple rows under equivocation).
type PostgresCommitmentFetcher struct {
	db *pgxpool.Pool
	reader bytestore.Reader
	logDID string
}

// NewPostgresCommitmentFetcher returns a fetcher backed by db and
// reader, scoped to the supplied logDID. The logDID populates the
// Position.LogDID field of every returned EntryWithMetadata so SDK
// callers see a fully-qualified position even though the underlying
// commitment_split_id row carries only the sequence number.
func NewPostgresCommitmentFetcher(
	db *pgxpool.Pool, reader bytestore.Reader, logDID string,
) *PostgresCommitmentFetcher {
	return &PostgresCommitmentFetcher{db: db, reader: reader, logDID: logDID}
}

// FindCommitmentEntries returns every entry in the ledger's log
// whose (schema_id, split_id) tuple matches the supplied arguments.
//
// Multi-row contract: the slice is length 1 in the normal case,
// length 2+ when the dealer has equivocated. The
// SDK's FetchPREGrantCommitment and FetchEscrowSplitCommitment
// primitives interpret length > 1 as cryptographic equivocation
// evidence and construct *artifact.CommitmentEquivocationError
// carrying every entry the fetcher returned.
//
// Returns:
//
//   - (slice, nil) on a successful lookup. Slice may be empty (no
//     match — a normal recovery / history-replay outcome) or have
//     one or more elements.
//   - (nil, error) on database / Tessera transport failure.
//
// Each EntryWithMetadata is populated to the v6 type's three fields:
//
//   - Position: {LogDID: f.logDID, Sequence: <row>}
//   - CanonicalBytes: from the Tessera reader
//   - LogTime: from the entry_index row
//
// Stable ordering by sequence number guarantees that callers
// observing equivocation see the entries in admission order.
func (f *PostgresCommitmentFetcher) FindCommitmentEntries(
	schemaID string, splitID [32]byte,
) ([]*types.EntryWithMetadata, error) {
	if f == nil {
		return nil, errors.New("store/commitment_fetcher: nil receiver")
	}
	if f.reader == nil {
		return nil, errors.New("store/commitment_fetcher: nil tessera reader")
	}
	if schemaID == "" {
		return nil, errors.New("store/commitment_fetcher: empty schemaID")
	}

	// Use TODO() because the SDK CommitmentFetcher interface does
	// not propagate a context. The query is bounded by the database
	// pool's per-connection timeout configuration; long-running
	// scans are not expected because the (schema_id, split_id)
	// index makes the lookup an O(rows-matching) operation.
	ctx := context.TODO()

	// Join: commitment_split_id provides the candidate sequence
	// numbers under (schema_id, split_id); entry_index supplies the
	// matching log_time and canonical_hash (the latter is required
	// to construct the bytestore object key). Stable ASC sort by
	// sequence so equivocation evidence has deterministic order.
	rows, err := f.db.Query(ctx, `
		SELECT csi.sequence_number, ei.log_time, ei.canonical_hash
		FROM commitment_split_id AS csi
		JOIN entry_index AS ei USING (sequence_number)
		WHERE csi.schema_id = $1 AND csi.split_id = $2
		ORDER BY csi.sequence_number ASC`,
		schemaID, splitID[:],
	)
	if err != nil {
		return nil, fmt.Errorf(
			"store/commitment_fetcher: query schema=%q: %w",
			schemaID, err,
		)
	}
	defer rows.Close()

	type rowMeta struct {
		seq uint64
		logTime time.Time
		hash [32]byte
	}
	var rowMetas []rowMeta
	for rows.Next() {
		var rm rowMeta
		var hashCol []byte
		if scanErr := rows.Scan(&rm.seq, &rm.logTime, &hashCol); scanErr != nil {
			return nil, fmt.Errorf(
				"store/commitment_fetcher: scan: %w", scanErr,
			)
		}
		if len(hashCol) != 32 {
			return nil, fmt.Errorf(
				"store/commitment_fetcher: corrupt canonical_hash seq=%d (len=%d, want 32)",
				rm.seq, len(hashCol),
			)
		}
		copy(rm.hash[:], hashCol)
		rowMetas = append(rowMetas, rm)
	}
	if iterErr := rows.Err(); iterErr != nil {
		// pgx.Rows.Err treats some errors (e.g., no rows) as nil;
		// only genuine transport / scan errors surface here.
		if !errors.Is(iterErr, pgx.ErrNoRows) {
			return nil, fmt.Errorf(
				"store/commitment_fetcher: iterate: %w", iterErr,
			)
		}
	}
	if len(rowMetas) == 0 {
		return nil, nil
	}

	// Read canonical bytes from Tessera one row at a time. The
	// signatures live inside the canonical bytes (v6 multi-sig
	// section), so the EntryWithMetadata's CanonicalBytes field
	// is the complete view a caller needs — they call
	// envelope.Deserialize on it when they need the parsed Entry.
	out := make([]*types.EntryWithMetadata, 0, len(rowMetas))
	for _, rm := range rowMetas {
		wire, readErr := f.reader.ReadEntry(ctx, rm.seq, rm.hash)
		if readErr != nil {
			return nil, fmt.Errorf(
				"store/commitment_fetcher: tessera read seq=%d: %w",
				rm.seq, readErr,
			)
		}
		out = append(out, &types.EntryWithMetadata{
			Position: types.LogPosition{
				LogDID:   f.logDID,
				Sequence: rm.seq,
			},
			CanonicalBytes: wire,
			LogTime:        rm.logTime,
		})
	}
	return out, nil
}

// Compile-time check: PostgresCommitmentFetcher must satisfy the
// SDK's types.CommitmentFetcher interface. A drift in either side's
// signature surfaces here at build time rather than as a runtime
// "method not found" on first lookup.
var _ types.CommitmentFetcher = (*PostgresCommitmentFetcher)(nil)
