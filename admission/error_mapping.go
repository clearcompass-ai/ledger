/*
FILE PATH:

	admission/error_mapping.go

DESCRIPTION:

	Single source of truth mapping every SDK admission-time sentinel
	to (HTTP status, OTel error_class). The mapping replaces the
	scattered errors.Is switches that grew in api/submission.go as
	the legacy single-sig path was wired in (lines 372-381, 391-399,
	417-422); each new gate added in PR-C through PR-F adds rows
	here instead of forking another switch in the handler.

WHY ONE TABLE:

  - **Auditable**: a security review can read this file and know
    every cryptographic / structural rejection mode the ledger
    surfaces, with its observable dimension and HTTP shape, in
    one ~100-line table.
  - **Greppable**: a single grep for a sentinel name finds its
    handling here. Forgetting to enroll a new sentinel surfaces
    as ErrorClassUnknown in the dashboard — visible.
  - **Observable**: dashboards alert on (status, error_class)
    pairs. Adding a row here is the only change required to
    light up a new metric dimension.

PER-SENTINEL MAPPING SHAPE:

	Each Mapping declares:
	  - Sentinel: the SDK-level error.New value to match via errors.Is
	  - HTTPStatus: the wire-shape the client sees (429/422/500/...)
	  - Class: the apitypes.ErrorClass dimension for OTel telemetry

	MapSDKError walks the table in order and returns the first match.
	A non-match returns (false, _, _) so callers fall back to their
	existing default branch (typically 500 + ErrorClassDBQueryFailed
	for unrecognized infrastructure faults).

NON-GOAL — domain-payload errors:

	Schema, NFC, freshness, and admission-proof rejections continue
	to use their own handling because they predate this table and
	are not SDK-uniform-verify gates. The table covers exactly the
	sentinels that PR-C through PR-F will surface plus the existing
	gate-1-precursors (ErrSignerDIDResolution, ErrSignatureInvalid)
	enrolled here as the proof-of-wiring acceptance criterion in #76.
*/
package admission

import (
	"errors"
	"net/http"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// Mapping is a single row in the SDK-sentinel mapping table.
type Mapping struct {
	// Sentinel is matched via errors.Is. Wrapped errors (fmt.Errorf
	// "%w" chains) match correctly.
	Sentinel error
	// HTTPStatus is the wire shape returned to the client. Stable
	// across SDK versions because the table is the contract, not
	// the underlying SDK error vocabulary.
	HTTPStatus int
	// Class is the OTel dimension for the error_counter. Lets
	// dashboards alert on (status, error_class) pairs even when
	// the sentinel itself evolves.
	Class apitypes.ErrorClass
}

// sdkErrorTable is the canonical mapping. Order is significant
// only in the sense that the FIRST match wins; sentinels are
// disjoint in practice (each errors.New constructs a distinct
// error value), so the order is just review-friendly grouping.
//
// EVERY new gate MUST add its sentinels here. A regression that
// surfaces an unmapped sentinel will show as ErrorClassUnknown +
// HTTP 500 in MapSDKError's fallback path — visible in CI tests
// (TestSDKErrorTable_NoUnmappedGateSentinel) and in production
// dashboards.
var sdkErrorTable = []Mapping{
	// ── Gate 1: multi-sig at admission (PR-C) ─────────────────────
	// attestation.VerifyEntrySignatures rejections. Auth-shaped:
	// the entry's signature(s) didn't verify, so 401.
	{Sentinel: attestation.ErrNilEntry, HTTPStatus: http.StatusBadRequest, Class: apitypes.ErrorClassEnvelopeRejected},
	{Sentinel: attestation.ErrNilSignatureVerifier, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassDBQueryFailed},
	{Sentinel: attestation.ErrEmptySignatures, HTTPStatus: http.StatusUnauthorized, Class: apitypes.ErrorClassSignatureInvalid},
	{Sentinel: attestation.ErrPrimaryDIDMismatch, HTTPStatus: http.StatusUnauthorized, Class: apitypes.ErrorClassSignatureInvalid},

	// ── Gate 2: CosignatureOf binding (PR-D) ──────────────────────
	// attestation.IsAttestation false → ErrBindingMismatch. The
	// entry asserts it cosigns target X, but the wire bytes don't
	// actually point at X. Structural — not a crypto failure — so
	// 422 with its own dimension.
	{Sentinel: attestation.ErrBindingMismatch, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassCosignatureBindingMismatch},

	// ── Gate 3: schema-declared policy enforcement (PR-E) ─────────
	// attestation.VerifyEntryAttestationPolicy rejections. Policy-
	// not-met is an authoritative rejection (the entry is well-
	// formed but doesn't meet the schema's declared K-of-N /
	// constraints). 422 + own dimension so dashboards distinguish
	// "policy didn't pass" from "primary signature didn't verify".
	{Sentinel: attestation.ErrAttestationPolicyNotMet, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrPolicyMinAttestorsNegative, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassDBQueryFailed},
	{Sentinel: attestation.ErrNegativeThreshold, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassDBQueryFailed},
	{Sentinel: attestation.ErrConstraintDenied, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrConstraintAllowlistMiss, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrConstraintOriginMismatch, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrConstraintScopeMissing, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrConstraintChainRevoked, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrWindowExpired, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassFreshnessExpired},
	{Sentinel: attestation.ErrMissingLogTime, HTTPStatus: http.StatusBadRequest, Class: apitypes.ErrorClassEnvelopeRejected},
	{Sentinel: attestation.ErrNilDelegationResolver, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassDBQueryFailed},
	{Sentinel: attestation.ErrUnknownDelegate, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},
	{Sentinel: attestation.ErrChainBroken, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassAttestationPolicyNotMet},

	// ── Gate 4: surgical evidence-chain walk (PR-F) ───────────────
	// verifier.VerifyEvidenceChain rejections. Structural failures
	// (cycle, max-depth, deserialization) → 422; fetcher failures
	// (root not found, hop fetch) → 500 because they're IO faults,
	// not authoritative rejections. The two-class split lets ops
	// distinguish "the entry's chain is malformed" from "we couldn't
	// reach the byte store to walk it".
	{Sentinel: verifier.ErrNilFetcher, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassEvidenceChainUnavailable},
	{Sentinel: verifier.ErrRootFetchFailed, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassEvidenceChainUnavailable},
	{Sentinel: verifier.ErrHopFetchFailed, HTTPStatus: http.StatusInternalServerError, Class: apitypes.ErrorClassEvidenceChainUnavailable},
	{Sentinel: verifier.ErrChainCycle, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassEvidenceChainBroken},
	{Sentinel: verifier.ErrMaxDepthExceeded, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassEvidenceChainBroken},
	{Sentinel: verifier.ErrHopDeserialize, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassEvidenceChainBroken},

	// ── Existing single-sig admission gate (proof-of-wiring) ──────
	// Enrolled here so api/submission.go's signature-verify branch
	// can call MapSDKError instead of duplicating the switch. The
	// behavior shape is unchanged: 401 + ErrorClassSignatureInvalid.
	{Sentinel: ErrSignerDIDResolution, HTTPStatus: http.StatusUnauthorized, Class: apitypes.ErrorClassSignatureInvalid},
	{Sentinel: ErrSignatureInvalid, HTTPStatus: http.StatusUnauthorized, Class: apitypes.ErrorClassSignatureInvalid},

	// ── PR-C / PR-D ledger-side sentinels ─────────────────────────
	// Multi-sig path's "unsupported algorithm" + cosig-binding gate's
	// "target missing" / "binding mismatch". Routed to the SDK-
	// equivalent dimensions so dashboards don't have to learn new
	// classes for ledger-side wrappers.
	{Sentinel: ErrUnsupportedSignatureAlgo, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassEnvelopeRejected},
	{Sentinel: ErrCosignatureTargetNotFound, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassCosignatureBindingMismatch},
	{Sentinel: ErrCosignatureBindingMismatch, HTTPStatus: http.StatusUnprocessableEntity, Class: apitypes.ErrorClassCosignatureBindingMismatch},
}

// MapSDKError walks the sdkErrorTable looking for a match against
// err via errors.Is, returning (true, status, class) on hit and
// (false, 0, 0) on miss. Callers should fall back to their default
// branch on miss (typically 500 + DBQueryFailed for infrastructure
// faults; the miss is not the table's responsibility to interpret).
//
// Wrapped errors (fmt.Errorf with "%w") match correctly because
// errors.Is unwraps the chain.
//
// Returns immediately on the first match. The table is small (~24
// rows today) and per-request lookups happen at most a handful of
// times per admission, so a linear scan is the right shape; a map
// would prevent matching on wrapped errors.
func MapSDKError(err error) (matched bool, status int, class apitypes.ErrorClass) {
	if err == nil {
		return false, 0, 0
	}
	for _, m := range sdkErrorTable {
		if errors.Is(err, m.Sentinel) {
			return true, m.HTTPStatus, m.Class
		}
	}
	return false, 0, 0
}

// SDKErrorTable returns a defensive copy of the mapping for tests
// and tooling that need to enumerate registered sentinels (e.g.,
// the "no-unmapped-gate-sentinel" CI check). Production code calls
// MapSDKError, never this.
func SDKErrorTable() []Mapping {
	out := make([]Mapping, len(sdkErrorTable))
	copy(out, sdkErrorTable)
	return out
}
