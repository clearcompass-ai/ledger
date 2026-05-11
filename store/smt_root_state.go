/*
FILE PATH: store/smt_root_state.go

SMTRootStateStore — Postgres-backed singleton holding the
authoritative current SMT root + the highest sequence number it
reflects. Updated by the builder loop in the same atomic commit
transaction that writes leaves (store/smt_state.go) and advances the
builder cursor (store/sequence_cursor.go).

WHY THIS EXISTS:

	The SDK's Jellyfish/Patricia tree (attesta v0.3.0 smt.Tree) reads
	and writes nodes through a content-addressed NodeStore. The tree's
	root is the hash of the topmost node, or the canonical empty-tree
	hash for an empty tree. This row holds that root so /v1/smt/root
	reads in O(1) and the builder's atomic commit can advance leaves +
	nodes + root + cursor in a single transaction.

INVARIANTS:

  - Exactly one row, id = 1. Enforced by PRIMARY KEY + CHECK
    constraint (see migrations/0002_smt_root_state.sql).
  - current_root is always 32 bytes (CHECK constraint).
  - On a fresh database, current_root = the Jellyfish empty-tree
    hash sha256("") = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b
    934ca495991b7852b855`. Migration 0003 sets this; migration 0002
    seeds a placeholder that 0003 overwrites. Read always returns a
    usable root after migrations complete.
  - committed_through_seq is monotonically non-decreasing. The
    builder MUST NOT advance it past the largest seq it observed
    in the corresponding batch.

CONCURRENCY:

	Single writer (the builder loop). Read concurrency is unbounded.
	Writes happen inside the builder's existing serializable
	transaction; reads are at the default isolation level (read
	committed) — readers see only committed updates, never partial
	batches, because the row update is atomic with the leaf + cursor
	writes.

	A row-level UPDATE under serializable isolation will conflict
	with another concurrent serializable transaction touching the
	same row; the builder is the sole writer so this never happens in
	practice. Documented for any future contributor wondering whether
	the singleton pattern is a contention hazard.
*/
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SMTRootStateStore reads + writes the singleton smt_root_state row.
type SMTRootStateStore struct {
	db *pgxpool.Pool
}

// NewSMTRootStateStore constructs a store rooted at the supplied pool.
// The migration creates the singleton row with the empty-tree root, so
// the first Read after migration succeeds without any explicit init.
func NewSMTRootStateStore(db *pgxpool.Pool) *SMTRootStateStore {
	return &SMTRootStateStore{db: db}
}

// SMTRootState is the in-memory shape of the singleton row.
type SMTRootState struct {
	CurrentRoot         [32]byte
	CommittedThroughSeq uint64
}

// ReadRoot satisfies api.SMTRootReader so handlers can resolve the
// current root without depending on the SMTRootState wrapper.
func (s *SMTRootStateStore) ReadRoot(ctx context.Context) ([32]byte, error) {
	st, err := s.Read(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	return st.CurrentRoot, nil
}

// Read returns the current SMT root + committed-through seq. Returns
// an error if the singleton row is missing (which would indicate the
// migration didn't run, NOT a normal first-boot case).
func (s *SMTRootStateStore) Read(ctx context.Context) (SMTRootState, error) {
	var rootBytes []byte
	var seq int64
	err := s.db.QueryRow(ctx,
		`SELECT current_root, committed_through_seq
		 FROM smt_root_state WHERE id = 1`,
	).Scan(&rootBytes, &seq)
	if err != nil {
		return SMTRootState{}, fmt.Errorf("store/smt-root: read: %w", err)
	}
	if len(rootBytes) != 32 {
		return SMTRootState{}, fmt.Errorf("store/smt-root: bad root length %d (want 32)", len(rootBytes))
	}
	var out SMTRootState
	copy(out.CurrentRoot[:], rootBytes)
	out.CommittedThroughSeq = uint64(seq)
	return out, nil
}

// SetTx writes the new root + advances committed_through_seq inside
// the caller's transaction. Caller (the builder loop) commits this
// alongside the leaf SetTx + cursor AdvanceTx + buffer SaveTx calls
// so all four state writes succeed or none do.
//
// Strict monotonicity on committed_through_seq: a regression would
// indicate a builder bug (cursor went backwards). We don't enforce
// it here — the builder's CursorReader.CommitBatch already enforces
// it on the cursor; the root advances in lockstep with the cursor.
func (s *SMTRootStateStore) SetTx(ctx context.Context, tx pgx.Tx, root [32]byte, committedThroughSeq uint64) error {
	_, err := tx.Exec(ctx,
		`UPDATE smt_root_state
		 SET current_root = $1,
		     committed_through_seq = $2,
		     updated_at = NOW()
		 WHERE id = 1`,
		root[:], int64(committedThroughSeq),
	)
	if err != nil {
		return fmt.Errorf("store/smt-root: set: %w", err)
	}
	return nil
}
