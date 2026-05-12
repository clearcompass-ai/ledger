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
  - All returned entries have verified signatures.
  - Fetch returns nil for foreign log DIDs (this ledger's local
    store only ever holds entries whose Destination matches its
    own LogDID).
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

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/bytestore"
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

// EntryStatus enumerates the entry_index.status column values. The
// schema CHECK constraint (entry_index_status_check) pins this to
// {StatusLive, StatusTombstone}; any third value is rejected at
// insert time.
//
// Tombstone semantics: Tessera.AppendLeaf is irrevocable — once it
// returns seq=N for a hash, N exists in the log permanently. If the
// entry at seq=N cannot be projected normally (e.g., a future
// post-AppendLeaf failure or a persistent batch-commit error), the
// committer inserts a tombstone row to preserve sequence-number
// contiguity. Without this, the committer's heap would stall waiting
// for seq=N to arrive at the head of the contiguous prefix and the
// entire pipeline would deadlock. See migrations/0005 for the
// full rationale.
type EntryStatus uint8

const (
	// StatusLive — normal entry. Builder will fetch wire bytes,
	// deserialize, and project to SMT state. Default for all rows
	// inserted without an explicit Status field.
	StatusLive EntryStatus = 0
	// StatusTombstone — Tessera assigned this seq, but the entry
	// couldn't be projected. canonical_hash is the real hash;
	// log_time is wall-clock at tombstone time; signer_did is
	// the literal "system:tombstone"; target_root / cosignature_of /
	// schema_ref are NULL. Builder.BeginBatch skips these but
	// advances the cursor past them.
	StatusTombstone EntryStatus = 1
)

// TombstoneSignerDID is the sentinel signer for tombstone rows. The
// schema's CHECK (signer_did <> '') requires non-empty, so we use a
// reserved namespace identifier that can never collide with a real
// signer.
const TombstoneSignerDID = "system:tombstone"

// EntryRow is the index record for insertion. No canonical_bytes, no sig_bytes.
//
// For tombstones, set Status = StatusTombstone, leave TargetRoot /
// CosignatureOf / SchemaRef as nil, and set SignerDID =
// TombstoneSignerDID. LogTime should be the wall-clock at tombstone
// time. CanonicalHash is the real (Tessera-bound) hash.
type EntryRow struct {
	SequenceNumber uint64
	CanonicalHash  [32]byte
	LogTime        time.Time
	SignerDID      string
	TargetRoot     []byte // nil if null
	CosignatureOf  []byte // nil if null
	SchemaRef      []byte // nil if null
	Status         EntryStatus
}

// Insert persists an entry's index columns. Called within the admission transaction.
// Entry bytes go to EntryWriter (Tessera), NOT here.
// Returns ErrDuplicateEntry on hash collision (UNIQUE constraint).
//
// Prefer InsertBatch for the hot sequencer path — the per-row Insert
// pays one synchronous PG round-trip per call and is the N+1 pattern
// the SetBatchTx / PutBatchTx refactor eliminated for smt_leaves /
// jellyfish_nodes. Insert remains for the rebuild tool and unit
// tests that legitimately write a single row.
func (s *EntryStore) Insert(ctx context.Context, tx pgx.Tx, row EntryRow) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO entry_index (
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		row.SequenceNumber, row.CanonicalHash[:],
		row.LogTime, row.SignerDID,
		row.TargetRoot, row.CosignatureOf, row.SchemaRef,
		int16(row.Status),
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return ErrDuplicateEntry
		}
		return fmt.Errorf("store/entries: insert seq=%d: %w", row.SequenceNumber, err)
	}
	return nil
}

// InsertBatch persists N entry_index rows in a single transactional
// round-trip using PostgreSQL's parallel `unnest()` form. This is the
// hot sequencer-committer write path; the gap-free commit invariant
// the new architecture enforces requires that all rows in a batch
// become visible to readers atomically (so a partial-visibility
// snapshot cannot let the builder's cursor reader leapfrog past
// uncommitted seqs).
//
// Mixed live + tombstone rows are supported in the same call.
//
// Returns the rows-affected count from PG (== len(rows) under normal
// operation — ON CONFLICT DO NOTHING means the count drops if a seq
// happens to already exist from a crash-recovery re-run, which is
// the desired idempotent behavior).
//
// Empty input is a no-op — callers don't need to guard.
func (s *EntryStore) InsertBatch(ctx context.Context, tx pgx.Tx, rows []EntryRow) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	// Build the parallel-array shape pgx expects for unnest. Each
	// nullable column (target_root, cosignature_of, schema_ref) is
	// represented as `[][]byte` where nil entries land as SQL NULL.
	seqs := make([]int64, len(rows))
	hashes := make([][]byte, len(rows))
	logTimes := make([]time.Time, len(rows))
	signers := make([]string, len(rows))
	targets := make([][]byte, len(rows))
	cosigs := make([][]byte, len(rows))
	schemas := make([][]byte, len(rows))
	statuses := make([]int16, len(rows))
	for i := range rows {
		seqs[i] = int64(rows[i].SequenceNumber)
		h := rows[i].CanonicalHash
		hashes[i] = h[:]
		logTimes[i] = rows[i].LogTime
		signers[i] = rows[i].SignerDID
		targets[i] = rows[i].TargetRoot
		cosigs[i] = rows[i].CosignatureOf
		schemas[i] = rows[i].SchemaRef
		statuses[i] = int16(rows[i].Status)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO entry_index (
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref, status
		)
		SELECT
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref, status
		FROM unnest(
			$1::bigint[], $2::bytea[], $3::timestamptz[],
			$4::text[], $5::bytea[], $6::bytea[], $7::bytea[],
			$8::smallint[]
		) AS t(
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref, status
		)
		ON CONFLICT (sequence_number) DO NOTHING`,
		seqs, hashes, logTimes, signers,
		targets, cosigs, schemas, statuses,
	)
	if err != nil {
		return 0, fmt.Errorf("store/entries: insert batch (n=%d): %w", len(rows), err)
	}
	return tag.RowsAffected(), nil
}

// FetchHashBySeq returns the canonical_hash and admission log_time
// for a given sequence number. Returns (hash, logTime, true, nil) on
// hit, ([32]byte{}, zero-time, false, nil) when no row at that seq,
// (..., false, err) on transport failure.
//
// Used by the /v1/entries/{seq}/raw byte-fetch handler to:
//   - decide between inline (WAL) serve and 302 redirect (bytestore)
//   - stamp X-Sequence + X-Log-Time response headers per the SDK
//     fetcher's contract (Tier-2 alignment).
func (s *EntryStore) FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, time.Time, bool, error) {
	var (
		hashCol []byte
		logTime time.Time
	)
	err := s.db.QueryRow(ctx,
		"SELECT canonical_hash, log_time FROM entry_index WHERE sequence_number = $1", seq,
	).Scan(&hashCol, &logTime)

	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, time.Time{}, false, nil
	}
	if err != nil {
		return [32]byte{}, time.Time{}, false, fmt.Errorf("store/entries: fetch by seq: %w", err)
	}
	if len(hashCol) != 32 {
		return [32]byte{}, time.Time{}, false, fmt.Errorf(
			"store/entries: corrupt canonical_hash seq=%d (len=%d, want 32)", seq, len(hashCol))
	}
	var hash [32]byte
	copy(hash[:], hashCol)
	return hash, logTime, true, nil
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
// CONTRACTS:
//   - All returned entries have verified signatures.
//   - Returns nil for foreign log DIDs (this fetcher only resolves
//     entries written into this ledger's own log).
type PostgresEntryFetcher struct {
	db     *pgxpool.Pool
	reader bytestore.Reader
	logDID string
}

// NewPostgresEntryFetcher creates a fetcher for the given log.
// Per-call ctx is supplied via the SDK's types.EntryFetcher.Fetch
// signature; nothing is bound on the struct.
func NewPostgresEntryFetcher(db *pgxpool.Pool, reader bytestore.Reader, logDID string) *PostgresEntryFetcher {
	return &PostgresEntryFetcher{db: db, reader: reader, logDID: logDID}
}

// Fetch retrieves an entry by LogPosition.
// Metadata from Postgres. Bytes from Tessera. Returns nil if not found.
func (f *PostgresEntryFetcher) Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if pos.LogDID != f.logDID {
		return nil, nil // Foreign log — not found locally.
	}

	// (1) Metadata from entry_index. canonical_hash is required to
	// construct the bytestore object key; log_time populates the
	// EntryWithMetadata response.
	var (
		logTime time.Time
		hashCol []byte
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
	// type. Wire bytes ARE the canonical bytes under (signatures
	// section embedded). Callers that need the primary signature's
	// algoID call envelope.Deserialize and read entry.Signatures[0].
	return &types.EntryWithMetadata{
		CanonicalBytes: wire,
		LogTime:        logTime,
		Position:       pos,
	}, nil
}
