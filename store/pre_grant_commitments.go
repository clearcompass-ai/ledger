/*
FILE PATH: store/pre_grant_commitments.go

Typed insert + lookup helpers for pre-grant-commitment-v1 entries
(ADR-005 §4 cryptographic-commitment surface).

Two responsibilities:

 1. InsertSplitID populates commitment_split_id at admission time so
    the SDK lookup primitive FetchPREGrantCommitment can resolve a
    (grantorDID, recipientDID, artifactCID) tuple to its on-log
    commitment entry. Called from api/submission.go after schema
    dispatch parses the payload and exposes the SplitID.

 2. LookupBySplitID returns every entry sequence number indexed under
    the supplied (PREGrantCommitmentSchemaID, splitID) tuple. Returns
    a slice — length 1 in the normal case, length 2+ when the dealer
    has equivocated. Decision 3 of Wave 1 v3 mandates that both rows
    persist; this lookup surfaces them all.

Domain disambiguation: this file is about CRYPTOGRAPHIC commitments
(Pedersen on the secp256k1 curve, used to bind every escrow share
and PRE KFrag to a polynomial the dealer published). It is NOT
about SMT batch derivation commitments — those live in
store/derivation_commitments.go and follow a separate lookup contract
(by sequence range, not by SplitID).
*/
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/crypto/artifact"
)

// PREGrantCommitmentStore wraps SplitID-keyed access to the
// commitment_split_id table for pre-grant-commitment-v1 entries.
//
// Construction is cheap; the caller may instantiate one per request
// or share a single instance across the handler. The struct holds no
// state beyond the connection pool.
type PREGrantCommitmentStore struct {
	db *pgxpool.Pool
}

// NewPREGrantCommitmentStore returns a store backed by db.
func NewPREGrantCommitmentStore(db *pgxpool.Pool) *PREGrantCommitmentStore {
	return &PREGrantCommitmentStore{db: db}
}

// InsertSplitID records a (sequence_number, schema_id, split_id) row
// in commitment_split_id. Called from the admission pipeline after
// the C2 schema-payload dispatch has parsed the entry and exposed
// the SplitID. Intended to run inside the same Postgres transaction
// as the entry_index insert so the SplitID index never references
// a non-existent sequence number.
//
// Errors: returns the underlying pgx error wrapped with this store's
// path. The PRIMARY KEY on sequence_number means a duplicate insert
// for the same sequence is a programmer error (the admission pipeline
// only invokes this once per entry); callers should treat any error
// as fatal for the surrounding transaction.
//
// The (schema_id, split_id) tuple is intentionally NOT unique — see
// store/postgres.go schemaDDL commentary on commitment_split_id and
// Wave 1 v3 Decision 3.
func (s *PREGrantCommitmentStore) InsertSplitID(
	ctx context.Context, tx pgx.Tx, sequenceNumber uint64, splitID [32]byte,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
		VALUES ($1, $2, $3)`,
		sequenceNumber, artifact.PREGrantCommitmentSchemaID, splitID[:],
	)
	if err != nil {
		return fmt.Errorf(
			"store/pre_grant_commitments: insert split_id seq=%d: %w",
			sequenceNumber, err,
		)
	}
	return nil
}

// LookupBySplitID returns every sequence number indexed under the
// supplied splitID for the pre-grant-commitment-v1 schema.
//
// Multi-row contract (Wave 1 v3 Decision 3): the slice is length 1
// in the normal case, length 2+ when the dealer has equivocated.
// Callers MUST NOT collapse the result to a single row; the SDK's
// FetchPREGrantCommitment uses the multi-row signal to construct
// *artifact.CommitmentEquivocationError.
//
// Returns an empty slice when the SplitID is unknown — distinct
// from a database error. The SDK treats nil/empty as "no commitment
// on log" (a normal recovery / history-replay outcome).
func (s *PREGrantCommitmentStore) LookupBySplitID(
	ctx context.Context, splitID [32]byte,
) ([]uint64, error) {
	rows, err := s.db.Query(ctx, `
		SELECT sequence_number
		FROM commitment_split_id
		WHERE schema_id = $1 AND split_id = $2
		ORDER BY sequence_number ASC`,
		artifact.PREGrantCommitmentSchemaID, splitID[:],
	)
	if err != nil {
		return nil, fmt.Errorf(
			"store/pre_grant_commitments: lookup split_id: %w", err,
		)
	}
	defer rows.Close()

	var seqs []uint64
	for rows.Next() {
		var seq uint64
		if scanErr := rows.Scan(&seq); scanErr != nil {
			return nil, fmt.Errorf(
				"store/pre_grant_commitments: scan: %w", scanErr,
			)
		}
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"store/pre_grant_commitments: iterate: %w", err,
		)
	}
	return seqs, nil
}
