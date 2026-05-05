/*
FILE PATH: store/derivation_commitments.go

SMT batch DERIVATION commitment persistence — fast-lookup index for
fraud proof verification: "give me the commitment covering tree_size=N."

This file is NOT about cryptographic Pedersen commitments
(escrow_split_commitments.go and pre_grant_commitments.go cover those).
The word "commitment" is overloaded across two distinct concepts:

  - DERIVATION commitments (this file): ledger-published commentary
    that pins the (range_start, range_end, prior_smt_root, post_smt_root,
    mutations_json) tuple for a builder batch. Used by fraud-proof
    verifiers to attest that a specific run of the builder against
    a specific entry range produced a specific SMT mutation set.

  - CRYPTOGRAPHIC commitments: Pedersen commitments published
    on-log alongside escrow shares and PRE grants per ADR-005 §4.
    Verifier-side equivocation detection and cross-share consistency
    rely on these.

CRASH RECOVERY: Commitments are persisted POST-COMMIT (loop.go step 7).
A crash between atomic commit and commitment persistence loses the row.
This is acceptable — the table is a LOOKUP INDEX, not consensus-critical
state. Commitments are reconstructable by replaying entries through the
SDK builder. If the table diverges, replay from entries to rebuild.

commentary_seq is nullable — populated only when the commentary entry
is actually submitted to the log via submitFn.
*/
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// CommitmentRow lives in apitypes/ so api/ can consume it without
// importing store/ (PT-7 — Pure CQRS). Re-exported as a type alias
// for builder/ + integration tests already using *store.CommitmentRow.
type CommitmentRow = apitypes.CommitmentRow

// CommitmentStore persists derivation commitments.
type CommitmentStore struct {
	db *pgxpool.Pool
}

// NewCommitmentStore creates a derivation-commitment store.
func NewCommitmentStore(db *pgxpool.Pool) *CommitmentStore {
	return &CommitmentStore{db: db}
}

// Insert persists a derivation commitment. Best-effort — called post-commit.
func (s *CommitmentStore) Insert(ctx context.Context, row CommitmentRow) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO derivation_commitments
			(range_start_seq, range_end_seq, prior_smt_root, post_smt_root,
			 mutations_json, commentary_seq)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		row.RangeStartSeq, row.RangeEndSeq,
		row.PriorSMTRoot[:], row.PostSMTRoot[:],
		row.MutationsJSON, row.CommentarySeq,
	)
	if err != nil {
		return fmt.Errorf("store/derivation_commitments: insert: %w", err)
	}
	return nil
}

// QueryBySequence finds the commitment whose range covers the given sequence.
// Returns nil if no commitment covers that range.
func (s *CommitmentStore) QueryBySequence(ctx context.Context, seq uint64) (*CommitmentRow, error) {
	var row CommitmentRow
	var priorRoot, postRoot []byte
	err := s.db.QueryRow(ctx, `
		SELECT id, range_start_seq, range_end_seq, prior_smt_root, post_smt_root,
		       mutations_json, commentary_seq, created_at
		FROM derivation_commitments
		WHERE range_start_seq <= $1 AND range_end_seq >= $1
		ORDER BY created_at DESC LIMIT 1`, seq,
	).Scan(&row.ID, &row.RangeStartSeq, &row.RangeEndSeq,
		&priorRoot, &postRoot,
		&row.MutationsJSON, &row.CommentarySeq, &row.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/derivation_commitments: query seq=%d: %w", seq, err)
	}
	if len(priorRoot) == 32 {
		copy(row.PriorSMTRoot[:], priorRoot)
	}
	if len(postRoot) == 32 {
		copy(row.PostSMTRoot[:], postRoot)
	}
	return &row, nil
}
