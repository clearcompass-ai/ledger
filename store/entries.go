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
	// StatusGhostLeaf — Tessera assigned this seq to a hash that
	// already has a PRIMARY row (Live or Tombstone) at a different
	// seq. The pre_commit_post_pg crash window can produce a
	// duplicate Tessera leaf when antispam loses its in-memory
	// cache; the ghost row at this seq preserves the routable
	// projection so the API can serve bytes for the Tessera leaf
	// via redirect to the primary seq. canonical_hash matches the
	// primary's; the unique constraint is a PARTIAL UNIQUE INDEX
	// scoped to status <> 2 (migration 0006). Builder.BeginBatch
	// skips ghost rows.
	//
	// CRYPTOGRAPHIC INVARIANT: every Tessera-assigned seq has an
	// entry_index row. Ghosts preserve that invariant under
	// crash-recovery edges where Tessera dedup gaps would otherwise
	// produce gaps in the projection.
	StatusGhostLeaf EntryStatus = 2
)

// TombstoneSignerDID is the sentinel signer for tombstone rows. The
// schema's CHECK (signer_did <> ”) requires non-empty, so we use a
// reserved namespace identifier that can never collide with a real
// signer.
const TombstoneSignerDID = "system:tombstone"

// GhostSignerDID is the sentinel signer for StatusGhostLeaf rows.
// Distinct from TombstoneSignerDID so audit-trail queries can
// distinguish a tombstone (admission-time rejection) from a ghost
// leaf (crash-recovery duplicate Tessera leaf) by signer_did
// alone, without joining on status. Both are reserved "system:"
// namespace identifiers that can never collide with a real signer
// DID.
const GhostSignerDID = "system:ghost"

// EntryRow is the index record for insertion. No canonical_bytes, no sig_bytes.
//
// For tombstones, set Status = StatusTombstone, leave TargetRoot /
// CosignatureOf / SchemaRef / DelegateDID as nil-or-empty, and set
// SignerDID = TombstoneSignerDID. LogTime should be the wall-clock
// at tombstone time. CanonicalHash is the real (Tessera-bound) hash.
type EntryRow struct {
	SequenceNumber uint64
	CanonicalHash  [32]byte
	LogTime        time.Time
	SignerDID      string
	TargetRoot     []byte // nil if null
	CosignatureOf  []byte // nil if null
	SchemaRef      []byte // nil if null
	// DelegateDID is the on-log delegate DID this entry
	// establishes a delegation for. Empty when the entry is not
	// a delegation. Projected by the sequencer from
	// envelope.ControlHeader.DelegateDID. Indexed via
	// idx_delegate_did_latest (migration 0008) so the
	// attestation policy verifier's delegation-chain walk can
	// resolve the latest delegation for a DID in one index seek.
	DelegateDID string
	Status      EntryStatus
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
	// delegate_did is stored as nullable TEXT (NULL when empty);
	// the partial index idx_delegate_did_latest is only populated
	// for non-NULL values.
	var delegateDID any
	if row.DelegateDID != "" {
		delegateDID = row.DelegateDID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO entry_index (
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref,
			delegate_did, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		row.SequenceNumber, row.CanonicalHash[:],
		row.LogTime, row.SignerDID,
		row.TargetRoot, row.CosignatureOf, row.SchemaRef,
		delegateDID,
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

// HashCollision describes a row whose INSERT into the primary
// partition (status <> 2) was silently skipped because the
// canonical_hash matched an existing primary row at a DIFFERENT
// sequence_number. This is the structural signature of a Tessera
// antispam dedup gap across a crash boundary: Tessera assigned
// AttemptedSeq to a hash that already had an entry_index row at
// ExistingSeq from a pre-crash commit.
//
// On every HashCollision the InsertBatch path follows up with a
// second INSERT that writes a GHOST ROW at AttemptedSeq with
// status=StatusGhostLeaf, preserving the routable-projection
// invariant: every Tessera-assigned seq has an entry_index row
// (ghosts redirect to primaries; the partial unique index admits
// the duplicate canonical_hash at status=2).
//
// The committer additionally routes each HashCollision through
// committerStaleRecover with ExistingSeq so the WAL state for the
// hash advances under the canonical seq — the shipper uploads
// bytes to the canonical-seq bytestore path exactly once.
//
// AttemptedSeq is what Tessera tried to give us (now stored as the
// ghost row's seq). ExistingSeq is the canonical seq that the
// shipper / API / WAL state should reference.
type HashCollision struct {
	AttemptedSeq  uint64
	CanonicalHash [32]byte
	ExistingSeq   uint64
}

// InsertBatchResult is the disposition of an InsertBatch call.
//
// Inserted is the number of rows that became durable on this call
// as primary rows (status <> 2).
//
// SeqReplays counts rows skipped because a row with the same
// (sequence_number, canonical_hash) tuple was already present —
// benign idempotent retry of a prior batch. Not a collision; not
// actionable.
//
// HashCollisions enumerates rows whose canonical_hash matched an
// existing PRIMARY row at a DIFFERENT seq. For each collision, the
// InsertBatch call ALSO wrote a ghost row at AttemptedSeq with
// status=StatusGhostLeaf so the projection has no gaps. The caller
// must additionally route each through committerStaleRecover with
// ExistingSeq to advance WAL state under the canonical seq.
// Empty in steady state; non-empty only on crash-recovery edges
// where Tessera's in-memory antispam cache lost a mapping.
//
// Inserted + SeqReplays + len(HashCollisions) == len(input rows)
// is the invariant. Caller may assert it as a sanity check.
type InsertBatchResult struct {
	Inserted       int
	SeqReplays     int
	HashCollisions []HashCollision
}

// InsertBatch persists N entry_index rows in a single transactional
// round-trip using PostgreSQL's parallel `unnest()` form. This is the
// hot sequencer-committer write path; the gap-free commit invariant
// the new architecture enforces requires that all rows in a batch
// become visible to readers atomically (so a partial-visibility
// snapshot cannot let the builder's cursor reader leapfrog past
// uncommitted seqs).
//
// CONFLICT HANDLING — ON CONFLICT (canonical_hash) DO NOTHING RETURNING
//
// The targeted `ON CONFLICT (canonical_hash)` form catches the case
// the architecture has to tolerate: a Tessera antispam dedup gap
// across a crash, where Tessera assigned a fresh seq to a hash
// that already had an entry_index row at a different seq. The
// RETURNING clause yields the (sequence_number, canonical_hash)
// pairs that actually landed; the set-difference identifies
// skipped rows; a single follow-up SELECT classifies each as:
//
//	seq-replay     — existing_seq == attempted_seq (benign
//	                 idempotent retry; same row already present).
//	hash-collision — existing_seq != attempted_seq (the ghost-
//	                 leaf pattern; caller routes via stale-recover
//	                 with ExistingSeq).
//
// The targeted form (vs bare `ON CONFLICT DO NOTHING`) is
// deliberate: a UNIQUE(sequence_number) violation indicates a
// genuine bug (two different hashes assigned the same seq, which
// Tessera's contract forbids). We WANT that to surface as a hard
// PG error, not be silently swallowed.
//
// Cost discipline:
//
//   - Fast path (no skips): one INSERT roundtrip. Same as before.
//   - Skip path: one INSERT + one SELECT roundtrip. Only fires
//     when PG actually skipped at least one row, which is rare
//     (crash-recovery only) AND already-anomalous.
//
// Mixed live + tombstone rows are supported. Empty input is a no-op.
func (s *EntryStore) InsertBatch(ctx context.Context, tx pgx.Tx, rows []EntryRow) (InsertBatchResult, error) {
	if len(rows) == 0 {
		return InsertBatchResult{}, nil
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
	// delegate_did is parallel-arrayed as TEXT[] using "" for
	// "this entry is not a delegation" — NOT a NULL marker.
	// unnest()'s text[] preserves the empty-string distinction;
	// the INSERT NULLIFs the empty string back to SQL NULL so the
	// partial idx_delegate_did_latest index excludes non-delegation
	// rows.
	delegateDIDs := make([]string, len(rows))
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
		delegateDIDs[i] = rows[i].DelegateDID
		statuses[i] = int16(rows[i].Status)
	}
	insertRows, err := tx.Query(ctx, `
		INSERT INTO entry_index (
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref,
			delegate_did, status
		)
		SELECT
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref,
			NULLIF(delegate_did, ''), status
		FROM unnest(
			$1::bigint[], $2::bytea[], $3::timestamptz[],
			$4::text[], $5::bytea[], $6::bytea[], $7::bytea[],
			$8::text[], $9::smallint[]
		) AS t(
			sequence_number, canonical_hash, log_time,
			signer_did, target_root, cosignature_of, schema_ref,
			delegate_did, status
		)
		ON CONFLICT (canonical_hash) WHERE status <> 2 DO NOTHING
		RETURNING sequence_number, canonical_hash`,
		seqs, hashes, logTimes, signers,
		targets, cosigs, schemas, delegateDIDs, statuses,
	)
	if err != nil {
		return InsertBatchResult{}, fmt.Errorf("store/entries: insert batch (n=%d): %w", len(rows), err)
	}

	// Collect the (seq, hash) pairs actually inserted. The keyed-by-
	// hash set is what we set-difference against the input.
	insertedByHash := make(map[[32]byte]uint64, len(rows))
	for insertRows.Next() {
		var insSeq int64
		var insHash []byte
		if scanErr := insertRows.Scan(&insSeq, &insHash); scanErr != nil {
			insertRows.Close()
			return InsertBatchResult{}, fmt.Errorf("store/entries: scan returning (n=%d): %w", len(rows), scanErr)
		}
		var h [32]byte
		copy(h[:], insHash)
		insertedByHash[h] = uint64(insSeq)
	}
	insertRows.Close()
	if err := insertRows.Err(); err != nil {
		return InsertBatchResult{}, fmt.Errorf("store/entries: insert batch iterate (n=%d): %w", len(rows), err)
	}

	result := InsertBatchResult{Inserted: len(insertedByHash)}
	if result.Inserted == len(rows) {
		// Fast path: every row landed. No skips, no follow-up query.
		return result, nil
	}

	// Skip path: at least one row was skipped. Identify which input
	// hashes were NOT in the returned set; query for their existing
	// (seq, canonical_hash) tuples in one roundtrip.
	//
	// The follow-up SELECT explicitly filters status <> 2 because
	// the partial unique index only constrains PRIMARY rows. A row
	// with status=2 (ghost) coexisting with the same canonical_hash
	// at status<2 is not a conflict — it's a prior ghost-leaf
	// recovery. We want the PRIMARY row's seq for each skipped hash.
	skippedHashBytes := make([][]byte, 0, len(rows)-result.Inserted)
	skippedAttemptedRow := make(map[[32]byte]EntryRow, len(rows)-result.Inserted)
	for i := range rows {
		h := rows[i].CanonicalHash
		if _, ok := insertedByHash[h]; ok {
			continue
		}
		skippedHashBytes = append(skippedHashBytes, h[:])
		skippedAttemptedRow[h] = rows[i]
	}

	existingRows, err := tx.Query(ctx, `
		SELECT sequence_number, canonical_hash FROM entry_index
		WHERE canonical_hash = ANY($1::bytea[]) AND status <> 2`,
		skippedHashBytes,
	)
	if err != nil {
		return InsertBatchResult{}, fmt.Errorf("store/entries: skip-lookup (n=%d skipped): %w",
			len(skippedHashBytes), err)
	}
	for existingRows.Next() {
		var existSeq int64
		var existHash []byte
		if scanErr := existingRows.Scan(&existSeq, &existHash); scanErr != nil {
			existingRows.Close()
			return InsertBatchResult{}, fmt.Errorf("store/entries: scan skip-lookup: %w", scanErr)
		}
		var h [32]byte
		copy(h[:], existHash)
		attemptedRow, ok := skippedAttemptedRow[h]
		if !ok {
			continue
		}
		if uint64(existSeq) == attemptedRow.SequenceNumber {
			result.SeqReplays++
		} else {
			result.HashCollisions = append(result.HashCollisions, HashCollision{
				AttemptedSeq:  attemptedRow.SequenceNumber,
				CanonicalHash: h,
				ExistingSeq:   uint64(existSeq),
			})
		}
	}
	existingRows.Close()
	if err := existingRows.Err(); err != nil {
		return InsertBatchResult{}, fmt.Errorf("store/entries: skip-lookup iterate: %w", err)
	}

	// Second pass: for each HashCollision, INSERT a ghost row at the
	// ATTEMPTED seq (the Tessera-assigned duplicate seq) with
	// status=StatusGhostLeaf. The partial unique index admits this
	// row: status=2 is outside the canonical_hash uniqueness
	// partition. Each ghost row carries the SAME canonical_hash as
	// the primary, so the API's ghost-resolution path can find the
	// primary by canonical_hash lookup.
	//
	// Cryptographic invariant: every Tessera-assigned seq now has an
	// entry_index row, either primary (status<2) or ghost (status=2).
	// External auditors querying GET /v1/entries/{seq}/raw never get
	// a 404 for a seq Tessera published.
	if len(result.HashCollisions) > 0 {
		gSeqs := make([]int64, len(result.HashCollisions))
		gHashes := make([][]byte, len(result.HashCollisions))
		gLogTimes := make([]time.Time, len(result.HashCollisions))
		gSigners := make([]string, len(result.HashCollisions))
		gStatuses := make([]int16, len(result.HashCollisions))
		now := time.Now().UTC()
		for i, c := range result.HashCollisions {
			gSeqs[i] = int64(c.AttemptedSeq)
			h := c.CanonicalHash
			gHashes[i] = h[:]
			gLogTimes[i] = now
			gSigners[i] = GhostSignerDID // distinct from TombstoneSignerDID
			gStatuses[i] = int16(StatusGhostLeaf)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO entry_index (
				sequence_number, canonical_hash, log_time,
				signer_did, target_root, cosignature_of, schema_ref,
				delegate_did, status
			)
			SELECT
				sequence_number, canonical_hash, log_time,
				signer_did, NULL, NULL, NULL, NULL, status
			FROM unnest(
				$1::bigint[], $2::bytea[], $3::timestamptz[],
				$4::text[], $5::smallint[]
			) AS t(
				sequence_number, canonical_hash, log_time,
				signer_did, status
			)
			ON CONFLICT (sequence_number) DO NOTHING`,
			gSeqs, gHashes, gLogTimes, gSigners, gStatuses,
		)
		if err != nil {
			return InsertBatchResult{}, fmt.Errorf("store/entries: ghost-leaf insert (n=%d): %w",
				len(result.HashCollisions), err)
		}
	}

	return result, nil
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
func (s *EntryStore) FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, time.Time, bool, bool, error) {
	var (
		hashCol []byte
		logTime time.Time
		status  int16
	)
	err := s.db.QueryRow(ctx,
		"SELECT canonical_hash, log_time, status FROM entry_index WHERE sequence_number = $1", seq,
	).Scan(&hashCol, &logTime, &status)

	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, time.Time{}, false, false, nil
	}
	if err != nil {
		return [32]byte{}, time.Time{}, false, false, fmt.Errorf("store/entries: fetch by seq: %w", err)
	}
	if len(hashCol) != 32 {
		return [32]byte{}, time.Time{}, false, false, fmt.Errorf(
			"store/entries: corrupt canonical_hash seq=%d (len=%d, want 32)", seq, len(hashCol))
	}
	var hash [32]byte
	copy(hash[:], hashCol)
	isGhost := EntryStatus(status) == StatusGhostLeaf
	return hash, logTime, isGhost, true, nil
}

// FetchPrimarySeqByHash returns the canonical (primary) sequence
// number for a given canonical_hash — the row with status <> 2.
// Used by the API's ghost-redirect path: when a client requests
// GET /v1/entries/{ghost_seq}/raw, the handler resolves the
// underlying canonical_hash and routes to the primary seq's
// bytestore path so the bytes are served (302 or proxied)
// regardless of which Tessera seq the auditor asked for.
//
// Returns (primarySeq, true, nil) on hit, (0, false, nil) when no
// non-ghost row exists for the hash, (0, false, err) on transport
// failure. The partial unique index
// entry_index_canonical_hash_primary_idx guarantees AT MOST one
// non-ghost row per hash, so the query is single-row-bounded.
func (s *EntryStore) FetchPrimarySeqByHash(ctx context.Context, hash [32]byte) (uint64, bool, error) {
	var seq int64
	err := s.db.QueryRow(ctx,
		"SELECT sequence_number FROM entry_index WHERE canonical_hash = $1 AND status <> 2",
		hash[:],
	).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store/entries: fetch primary seq by hash: %w", err)
	}
	return uint64(seq), true, nil
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

// FetchLatestDelegationByDID returns the MOST RECENT live entry
// on this log whose Header.DelegateDID equals delegateDID. Used
// by the delegation.EntrySource adapter (delegationresolver/) so
// the SDK's attestation policy verifier's constraint walk
// (DelegationOriginDID / RequiredScopes) can resolve delegations
// from the on-log projection.
//
// CONTRACTS:
//
//   - Returns (nil, nil) when no live delegation exists for the
//     DID. The delegation.EntrySource adapter converts this to
//     attestation.ErrUnknownDelegate per the SDK's interface
//     contract.
//   - Filters to StatusLive: revoked / tombstoned delegations
//     are NOT returned as the current delegation. A successor
//     delegation entry (rotation, revocation) supersedes earlier
//     ones by virtue of having a higher sequence_number — the
//     ORDER BY sequence_number DESC LIMIT 1 query returns the
//     newest live row.
//   - Empty delegateDID → (nil, nil). The SDK interface guards
//     against empty DIDs upstream; we belt-and-braces here.
//
// COST PROFILE:
//
// The partial compound index idx_delegate_did_latest
// (delegate_did, sequence_number DESC) WHERE delegate_did IS NOT
// NULL turns this into a single-row index seek in O(log N).
func (f *PostgresEntryFetcher) FetchLatestDelegationByDID(
	ctx context.Context,
	delegateDID string,
) (*types.EntryWithMetadata, error) {
	if delegateDID == "" {
		return nil, nil
	}

	var (
		seq     int64
		hashCol []byte
		logTime time.Time
	)
	err := f.db.QueryRow(ctx, `
		SELECT sequence_number, canonical_hash, log_time
		  FROM entry_index
		 WHERE delegate_did = $1
		   AND status = $2
		 ORDER BY sequence_number DESC
		 LIMIT 1`,
		delegateDID, int16(StatusLive),
	).Scan(&seq, &hashCol, &logTime)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf(
			"store/entries: FetchLatestDelegationByDID query: %w", err)
	}
	if len(hashCol) != 32 {
		return nil, fmt.Errorf(
			"store/entries: FetchLatestDelegationByDID corrupt canonical_hash seq=%d (len=%d, want 32)",
			seq, len(hashCol))
	}
	var hash [32]byte
	copy(hash[:], hashCol)

	wire, err := f.reader.ReadEntry(ctx, uint64(seq), hash)
	if err != nil {
		return nil, fmt.Errorf(
			"store/entries: FetchLatestDelegationByDID read seq=%d: %w", seq, err)
	}
	return &types.EntryWithMetadata{
		CanonicalBytes: wire,
		LogTime:        logTime,
		Position:       types.LogPosition{LogDID: f.logDID, Sequence: uint64(seq)},
	}, nil
}

// FetchByCosignatureOf returns every live entry on THIS log whose
// Header.CosignatureOf points at the given primary position.
// Materialises the candidate set the SDK's
// attestation.VerifyCollection / VerifyEntryAttestationPolicy /
// VerifyComplete Stage 6 consume.
//
// CONTRACTS:
//
//   - Returns [] (not nil) and nil error when no candidates exist.
//   - Returns nil and nil when primaryPos points at a foreign log
//     (this fetcher only knows about its own log's entries).
//   - Filters to StatusLive: tombstones and ghost leaves are NEVER
//     returned as candidates. An attestation entry that got
//     tombstoned has the same meaning as never having been admitted.
//   - Ordered by sequence_number ascending — deterministic for
//     downstream verifiers that may want a stable iteration order
//     for window-evaluation traceability.
//   - Each candidate's bytes come from the EntryReader (same path
//     Fetch uses). Metadata is from entry_index.
//
// COST PROFILE:
//
//   - One indexed query (idx_cosignature_of, partial WHERE
//     cosignature_of IS NOT NULL since 0001_initial.sql) returning
//     N rows.
//   - N follow-up byte reads from EntryReader (parallelisable, but
//     this implementation is sequential — typical N is small for
//     atomic-submission policies; if a primary accumulates
//     thousands of candidates, callers SHOULD paginate via a
//     ranged seq filter in a follow-up).
//
// CONSUMERS:
//
//   - PR-I LedgerPolicyResolver (admission gate 3 for
//     AdmissionEnforced policies — the narrow exception path).
//   - PR-K HTTP /v1/attestations-of (read-time, served to JN and
//     multi-network shims).
//
// Per the matrix-of-consumers design, this function is the
// authoritative SHARED PRIMITIVE; each consumer layers its own
// cache strategy on top.
func (f *PostgresEntryFetcher) FetchByCosignatureOf(
	ctx context.Context,
	primaryPos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	if primaryPos.LogDID != f.logDID {
		// Foreign log: we cannot resolve. Surface as "no
		// candidates found" rather than an error — callers
		// (admission, read API) treat zero as "policy unmet
		// from THIS log's perspective" and decide how to
		// surface that.
		return nil, nil
	}
	cosigBytes := SerializeLogPosition(primaryPos)

	rows, err := f.db.Query(ctx, `
		SELECT sequence_number, canonical_hash, log_time
		  FROM entry_index
		 WHERE cosignature_of = $1
		   AND status = $2
		 ORDER BY sequence_number ASC`,
		cosigBytes, int16(StatusLive),
	)
	if err != nil {
		return nil, fmt.Errorf("store/entries: FetchByCosignatureOf query: %w", err)
	}
	defer rows.Close()

	type pending struct {
		seq     uint64
		hash    [32]byte
		logTime time.Time
	}
	var queue []pending
	for rows.Next() {
		var (
			seq     int64
			hashCol []byte
			logTime time.Time
		)
		if err := rows.Scan(&seq, &hashCol, &logTime); err != nil {
			return nil, fmt.Errorf("store/entries: FetchByCosignatureOf scan: %w", err)
		}
		if len(hashCol) != 32 {
			return nil, fmt.Errorf(
				"store/entries: FetchByCosignatureOf corrupt canonical_hash seq=%d (len=%d, want 32)",
				seq, len(hashCol))
		}
		var hash [32]byte
		copy(hash[:], hashCol)
		queue = append(queue, pending{seq: uint64(seq), hash: hash, logTime: logTime})
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("store/entries: FetchByCosignatureOf rows: %w", rows.Err())
	}
	rows.Close()

	// Materialise bytes per candidate. Sequential is fine for
	// the expected size of an admission-time candidate set
	// (~K-of-N where K is small). Pagination concerns belong on
	// the HTTP read API (PR-K), not here.
	out := make([]types.EntryWithMetadata, 0, len(queue))
	for _, p := range queue {
		wire, err := f.reader.ReadEntry(ctx, p.seq, p.hash)
		if err != nil {
			return nil, fmt.Errorf(
				"store/entries: FetchByCosignatureOf read seq=%d: %w", p.seq, err)
		}
		out = append(out, types.EntryWithMetadata{
			CanonicalBytes: wire,
			LogTime:        p.logTime,
			Position:       types.LogPosition{LogDID: f.logDID, Sequence: p.seq},
		})
	}
	return out, nil
}
