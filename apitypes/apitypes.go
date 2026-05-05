/*
Package apitypes is a leaf package shared by api/ + store/ that
holds the value types and error sentinels exchanged across the
api ↔ store boundary. It has zero dependencies on github.com/jackc/pgx
or github.com/clearcompass-ai/ortholog-operator/store.

# WHY THIS PACKAGE EXISTS

PT-7 closes the api/ pgx-purge: api/ depends on interfaces (defined
at the api/ side, in api/ports.go) instead of concrete *store.X
types. Some payloads exchanged across that boundary are PURE DATA —
they carry no behavior and don't need an interface. Examples:

  - *CosignedTreeHead returned by TreeHeadFetcher.Latest /
    GetBySize
  - *CommitmentRow returned by DerivationCommitmentFetcher.QueryBySequence
  - ErrInsufficientCredits — the sentinel that maps to HTTP 402

These value types live HERE so:

  1. api/ can use them without importing store/ (which transitively
     pulls pgx).
  2. store/ implementations return *apitypes.X verbatim — no
     translation layer between the database query and the api
     handler.

Compliance verified by `go list -deps ./apitypes/` containing zero
pgx packages.

# DESIGN

This package contains ONLY:

  - Value types (struct definitions).
  - Error sentinels.

It MUST NOT contain:

  - Database access (no pgx, no sql).
  - HTTP code (no net/http).
  - Business logic (no schema validation, signature checks, etc.).

The test for membership: a type belongs here if BOTH api/ and
store/ refer to it AND it has no method bodies that would pull
in extra imports.
*/
package apitypes

import (
	"errors"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Tree head value types
// ─────────────────────────────────────────────────────────────────────

// CosignedTreeHead is a tree head with all its attestation
// signatures. Returned by TreeHeadFetcher.Latest / GetBySize.
//
// The value-only shape (no methods) keeps this package free of
// dependencies on cosign primitives. Callers that need to
// validate signatures use the SDK's cosign verifier on the
// Signatures slice.
type CosignedTreeHead struct {
	TreeSize   uint64
	RootHash   [32]byte
	HashAlgo   uint16
	Signatures []TreeHeadSignature
	CreatedAt  time.Time
}

// TreeHeadSignature is a single attestation: "signer vouches for
// this root."
type TreeHeadSignature struct {
	Signer    string
	SigAlgo   uint16
	Signature []byte
	CreatedAt time.Time
}

// ─────────────────────────────────────────────────────────────────────
// Derivation-commitment value types
// ─────────────────────────────────────────────────────────────────────

// CommitmentRow represents a derivation commitment in the database.
// Returned by DerivationCommitmentFetcher.QueryBySequence.
type CommitmentRow struct {
	ID            int64
	RangeStartSeq uint64
	RangeEndSeq   uint64
	PriorSMTRoot  [32]byte
	PostSMTRoot   [32]byte
	MutationsJSON []byte
	CommentarySeq *uint64 // nullable — set when commentary entry submitted
	CreatedAt     time.Time
}

// ─────────────────────────────────────────────────────────────────────
// Escrow-override flow result
// ─────────────────────────────────────────────────────────────────────

// EscrowOverrideResult is the return shape of
// EscrowOverrideProcessor.ProcessOverride. Lives here so api/'s
// escrow-override handler doesn't need to import gossipnet (which
// transitively imports sequencer + pgx via PT-4).
type EscrowOverrideResult struct {
	EventID    [32]byte
	Signatures int
	Lamport    uint64
}

// ─────────────────────────────────────────────────────────────────────
// Error sentinels
// ─────────────────────────────────────────────────────────────────────

// ErrInsufficientCredits is returned by CreditDeducter.Deduct when
// the exchange's balance is zero or no row exists. The api handler
// surfaces this as HTTP 402 (Payment Required).
//
// Lives in apitypes/ so api/batch.go + api/submission.go can
// `errors.Is` against it without importing store/.
var ErrInsufficientCredits = errors.New("apitypes: insufficient credits")
