/*
FILE PATH: store/entries.go

Entry index and the PostgresEntryFetcher — the concrete implementation
of sdk builder.EntryFetcher.

DESIGN RULE: Postgres is an index. Tessera is the source of truth for
entry bytes. Always.

  - entry_index stores ~40 bytes/row: sequence, hash, log_time,
    signer_did, target_root, cosignature_of, schema_ref.
  - canonical_bytes and sig_bytes are NEVER in Postgres.
  - EntryReader (bytestore.Reader) is the ONLY source of entry bytes.
  - PostgresEntryFetcher combines: metadata from entry_index + bytes from EntryReader.
  - SDK EntryFetcher interface unchanged: Fetch(pos) → *EntryWithMetadata.

EntryWithMetadata field set: under v6 the SDK type carries only
CanonicalBytes, LogTime, Position. Signatures live inside
CanonicalBytes (extracted via envelope.Deserialize when needed);
no sidecar fields exist.

INVARIANTS:
  - SDK-D5: all returned entries have verified signatures.
  - Decision 47: Fetch returns nil for foreign log DIDs.
  - Duplicate canonical_hash → ErrDuplicateEntry (mapped to HTTP 409).
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/bytestore"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Entry Index Storage (Postgres — metadata only, no bytes)
// ─────────────────────────────────────────────────────────────────────────────

// EntryStore handles entry index persistence.
type EntryStore struct {
	db *pgxpool.Pool
}

// NewEntryStore creates an entry store.
func NewEntryStore(db *pgxpool.Pool) *EntryStore {
	return &EntryStore{db: db}
}

// EntryRow is the index record for insertion. No canonical_bytes, no sig_bytes.
type EntryRow struct {
	SequenceNumber uint64
	CanonicalHash  [32]byte
	LogTime        time.Time
	SignerDID      string
	TargetRoot     []byte // nil if null
	CosignatureOf  []byte // nil if null
	SchemaRef      []byte // nil if null
}

// Insert persists an entry's index columns. Called within the admission transaction.
// Entry bytes go to EntryWriter (Tessera), NOT here.
// Returns ErrDuplicateEntry on hash collision (UNIQUE constraint).
func (s *EntryStore) Insert(ctx context.Context, tx pgx.Tx, row EntryRow) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO entry_index (
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		row.SequenceNumber, row.CanonicalHash[:],
		row.LogTime, row.SignerDID,
		row.TargetRoot, row.CosignatureOf, row.SchemaRef,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return ErrDuplicateEntry
		}
		return fmt.Errorf("store/entries: insert seq=%d: %w", row.SequenceNumber, err)
	}
	return nil
}

// FetchHashBySeq returns the canonical_hash for a given sequence number.
// Returns (hash, true, nil) on hit, ([32]byte{}, false, nil) when no
// row at that seq, ([32]byte{}, false, err) on transport failure.
//
// Used by the /v1/entries/{seq}/raw byte-fetch handler to decide
// between inline (WAL) serve and 302 redirect (bytestore) — both
// require the (seq, hash) tuple as the key into the byte source.
func (s *EntryStore) FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, bool, error) {
	var hashCol []byte
	err := s.db.QueryRow(ctx,
		"SELECT canonical_hash FROM entry_index WHERE sequence_number = $1", seq,
	).Scan(&hashCol)

	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, false, nil
	}
	if err != nil {
		return [32]byte{}, false, fmt.Errorf("store/entries: fetch by seq: %w", err)
	}
	if len(hashCol) != 32 {
		return [32]byte{}, false, fmt.Errorf(
			"store/entries: corrupt canonical_hash seq=%d (len=%d, want 32)", seq, len(hashCol))
	}
	var hash [32]byte
	copy(hash[:], hashCol)
	return hash, true, nil
}

// FetchByHash checks if an entry with the given canonical hash exists.
func (s *EntryStore) FetchByHash(ctx context.Context, hash [32]byte) (uint64, bool, error) {
	var seq uint64
	err := s.db.QueryRow(ctx,
		"SELECT sequence_number FROM entry_index WHERE canonical_hash = $1", hash[:],
	).Scan(&seq)

	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store/entries: fetch by hash: %w", err)
	}
	return seq, true, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) PostgresEntryFetcher — implements sdk builder.EntryFetcher
// ─────────────────────────────────────────────────────────────────────────────

// PostgresEntryFetcher implements builder.EntryFetcher.
// Metadata from entry_index (Postgres). Bytes from EntryReader (Tessera).
//
// CONTRACT (SDK-D5): all returned entries have verified signatures.
// CONTRACT (Decision 47): returns nil for foreign log DIDs.
type PostgresEntryFetcher struct {
	db     *pgxpool.Pool
	reader bytestore.Reader
	logDID string
}

// NewPostgresEntryFetcher creates a fetcher for the given log.
func NewPostgresEntryFetcher(db *pgxpool.Pool, reader bytestore.Reader, logDID string) *PostgresEntryFetcher {
	return &PostgresEntryFetcher{db: db, reader: reader, logDID: logDID}
}

// Fetch retrieves an entry by LogPosition.
// Metadata from Postgres. Bytes from Tessera. Returns nil if not found.
func (f *PostgresEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if pos.LogDID != f.logDID {
		return nil, nil // Foreign log — not found locally (Decision 47).
	}

	ctx := context.TODO()

	// (1) Metadata from entry_index. canonical_hash is required to
	// construct the bytestore object key; log_time populates the
	// EntryWithMetadata response.
	var (
		logTime  time.Time
		hashCol  []byte
	)
	err := f.db.QueryRow(ctx, `
		SELECT log_time, canonical_hash
		FROM entry_index WHERE sequence_number = $1`,
		pos.Sequence,
	).Scan(&logTime, &hashCol)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/entries: fetch index seq=%d: %w", pos.Sequence, err)
	}
	if len(hashCol) != 32 {
		return nil, fmt.Errorf("store/entries: corrupt canonical_hash seq=%d (len=%d, want 32)", pos.Sequence, len(hashCol))
	}
	var hash [32]byte
	copy(hash[:], hashCol)

	// (2) Wire bytes from EntryReader.
	wire, err := f.reader.ReadEntry(ctx, pos.Sequence, hash)
	if err != nil {
		return nil, fmt.Errorf("store/entries: read bytes seq=%d: %w", pos.Sequence, err)
	}

	// (3) Assemble — three-field EntryWithMetadata per the v6 SDK
	// type. Wire bytes ARE the canonical bytes under v7.75 (signatures
	// section embedded). Callers that need the primary signature's
	// algoID call envelope.Deserialize and read entry.Signatures[0].
	return &types.EntryWithMetadata{
		CanonicalBytes: wire,
		LogTime:        logTime,
		Position:       pos,
	}, nil
}
