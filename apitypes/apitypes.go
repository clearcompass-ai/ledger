/*
Package apitypes is a leaf package shared by api/ + store/ that
holds the value types and error sentinels exchanged across the
api ↔ store boundary. It has zero dependencies on github.com/jackc/pgx
or github.com/clearcompass-ai/ledger/store.

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

// ─────────────────────────────────────────────────────────────────────
// Error dimensionality (PT-6 — A10 + P10)
// ─────────────────────────────────────────────────────────────────────

// ErrorClass is the typed, bounded-cardinality taxonomy of
// error categories surfaced from api/ HTTP handlers. Each
// writeError site MUST carry exactly one ErrorClass value; the
// api/ ErrorCounter increments an OpenTelemetry counter with
// `error_class` set to the String() of this value.
//
// # WHY BOUNDED CARDINALITY
//
// At 10B+ entries SREs cannot troubleshoot generic HTTP-status
// counters. The dimensions distinguish ACTIVE attacks
// (ErrorClassSignatureInvalid) from network noise
// (ErrorClassWALBackpressure) so alerts fire on the dangerous
// classes only and on-call engineers don't drown in 4xx
// chatter.
//
// CARDINALITY BUDGET: every ErrorClass value listed below is a
// constant defined in this file. New values are explicit
// additions; the taxonomy never grows from caller-controlled
// strings (which would melt Prometheus's index). Per Prometheus
// best practices, total label cardinality (status × error_class
// × route) stays under O(few hundred).
//
// # MAPPING TO HTTP STATUS
//
// One-to-many: a single HTTP status (e.g., 400 Bad Request) can
// fan out into multiple ErrorClass values
// (ErrorClassMalformedJSON, ErrorClassBadHexEncoding,
// ErrorClassUnsupportedSchema, ...). The status alone is the
// client-facing wire shape; ErrorClass is the operator-side
// telemetry shape.
type ErrorClass uint16

// String returns the kebab-case attribute value emitted as the
// `error_class` OpenTelemetry attribute. Fixed strings, never
// derived from runtime input.
func (c ErrorClass) String() string {
	switch c {
	case ErrorClassUnknown:
		return "unknown"

	// 4xx — caller-supplied bytes
	case ErrorClassMalformedBody:
		return "malformed_body"
	case ErrorClassMalformedJSON:
		return "malformed_json"
	case ErrorClassBodyTooLarge:
		return "body_too_large"
	case ErrorClassBadHexEncoding:
		return "bad_hex_encoding"
	case ErrorClassBadHexLength:
		return "bad_hex_length"
	case ErrorClassMissingPathParam:
		return "missing_path_param"
	case ErrorClassMissingQueryParam:
		return "missing_query_param"
	case ErrorClassInvalidQueryParam:
		return "invalid_query_param"
	case ErrorClassUnsupportedSchema:
		return "unsupported_schema"
	case ErrorClassBatchTooLarge:
		return "batch_too_large"
	case ErrorClassEmptyBatch:
		return "empty_batch"

	// 4xx — semantic
	case ErrorClassInsufficientCredits:
		return "insufficient_credits"
	case ErrorClassDuplicateEntry:
		return "duplicate_entry"
	case ErrorClassInvalidSession:
		return "invalid_session"
	case ErrorClassExpiredSession:
		return "expired_session"

	// 4xx — cryptographic / authoritative rejection (HOSTILE-FLAVOR)
	case ErrorClassSignatureInvalid:
		return "signature_invalid"
	case ErrorClassEnvelopeRejected:
		return "envelope_rejected"
	case ErrorClassFreshnessExpired:
		return "freshness_expired"
	case ErrorClassDestinationMismatch:
		return "destination_mismatch"
	case ErrorClassAdmissionProofInvalid:
		return "admission_proof_invalid"
	case ErrorClassDifficultyTooLow:
		return "difficulty_too_low"

	// 404
	case ErrorClassNotFound:
		return "not_found"

	// 5xx — operator infrastructure
	case ErrorClassWALBackpressure:
		return "wal_backpressure"
	case ErrorClassWALPersistFailed:
		return "wal_persist_failed"
	case ErrorClassSCTSigningFailed:
		return "sct_signing_failed"
	case ErrorClassDBQueryFailed:
		return "db_query_failed"
	case ErrorClassReadProjectionFailed:
		return "read_projection_failed"
	case ErrorClassFetcherFailed:
		return "fetcher_failed"
	case ErrorClassProofGenFailed:
		return "proof_gen_failed"
	case ErrorClassCreditDeductFailed:
		return "credit_deduct_failed"
	case ErrorClassEscrowOverrideFailed:
		return "escrow_override_failed"
	}
	return "unknown"
}

const (
	// ErrorClassUnknown is the zero value — a writeError site
	// that didn't pass an explicit class. Surfacing this in
	// metrics flags the call site as needing classification.
	ErrorClassUnknown ErrorClass = iota

	// 4xx — caller-supplied bytes (NETWORK NOISE)
	ErrorClassMalformedBody
	ErrorClassMalformedJSON
	ErrorClassBodyTooLarge
	ErrorClassBadHexEncoding
	ErrorClassBadHexLength
	ErrorClassMissingPathParam
	ErrorClassMissingQueryParam
	ErrorClassInvalidQueryParam
	ErrorClassUnsupportedSchema
	ErrorClassBatchTooLarge
	ErrorClassEmptyBatch

	// 4xx — semantic (TENANT STATE)
	ErrorClassInsufficientCredits
	ErrorClassDuplicateEntry
	ErrorClassInvalidSession
	ErrorClassExpiredSession

	// 4xx — cryptographic / authoritative rejection
	// (HOSTILE-FLAVOR — alerts should fire on sustained rates)
	ErrorClassSignatureInvalid
	ErrorClassEnvelopeRejected
	ErrorClassFreshnessExpired
	ErrorClassDestinationMismatch
	ErrorClassAdmissionProofInvalid
	ErrorClassDifficultyTooLow

	// 404
	ErrorClassNotFound

	// 5xx — operator infrastructure (PAGE THE OPERATOR)
	ErrorClassWALBackpressure
	ErrorClassWALPersistFailed
	ErrorClassSCTSigningFailed
	ErrorClassDBQueryFailed
	ErrorClassReadProjectionFailed
	ErrorClassFetcherFailed
	ErrorClassProofGenFailed
	ErrorClassCreditDeductFailed
	ErrorClassEscrowOverrideFailed
)
