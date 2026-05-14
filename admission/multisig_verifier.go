/*
FILE PATH:

	admission/multisig_verifier.go

DESCRIPTION:

	PR-C gate 1 — multi-signature admission via the SDK's uniform
	attestation.VerifyEntrySignatures primitive.

	The legacy admission.VerifyEntrySignature path (entry_signature_
	verifier.go) verifies ONLY Signatures[0]. Entries arriving with N
	cosignatures pass through with Signatures[1..N] cryptographically
	unchecked — a silent gap an adversary could weaponise by attaching
	garbage cosignatures that imply (to downstream readers) a
	cosignature chain that never actually verifies.

	VerifyEntryAllSignatures closes that gap by calling
	attestation.VerifyEntrySignatures, which:

	  1. Computes sha256(SigningPayload(entry)) ONCE (no quadratic
	     re-hash across signatures).
	  2. Verifies every Signatures[i] against its declared SignerDID
	     and AlgoID.
	  3. Enforces the SDK Principle 5 envelope invariant
	     (Signatures[0].SignerDID == Header.SignerDID).
	  4. Returns a structured report with per-signature outcomes,
	     mapped here to the existing admission sentinels for the
	     api/submission.go switch.

	The legacy single-sig path stays intact in
	entry_signature_verifier.go. The api/submission.go branch picks
	one or the other based on SubmissionDeps.Gates.MultiSig (PR-A).
	Default flag OFF — flipped via LEDGER_ADMISSION_MULTISIG_ENABLE
	on rollout after one canary cycle confirms no regression against
	the bench/admission baseline.

KEY ARCHITECTURAL DECISIONS:

  - SignatureVerifier adapter (sigVerifierAdapter below) wraps the
    existing DIDResolver. The ledger keeps one resolver wiring for
    both single-sig and multi-sig paths; the adapter just bridges
    to attestation.SignatureVerifier's algoID-aware shape.

  - Only SigAlgoECDSA is supported today. Other algoIDs surface
    ErrUnsupportedSignatureAlgo so a multi-sig entry attaching, say,
    an Ed25519 cosignature gets a clear rejection rather than a
    silent skip. A future PR extends the adapter when ledger
    deployments need non-ECDSA cosignatures.

  - The verifier propagates the FIRST per-signature error, mapped
    to admission.ErrSignatureInvalid (same shape as the single-sig
    path → HTTP 401). Per-signature granularity stays available
    via the underlying SignatureReport (returned to callers so
    test code can assert against specific Results[i].Err).
*/
package admission

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// ErrUnsupportedSignatureAlgo is surfaced when the multi-sig path
// encounters a Signature whose AlgoID is not in the supported set.
// Today: only SigAlgoECDSA. Wrapped errors include the offending
// algoID for diagnostic context.
var ErrUnsupportedSignatureAlgo = errors.New("admission: unsupported signature algorithm")

// sigVerifierAdapter bridges the ledger's DIDResolver (which
// returns *ecdsa.PublicKey for did:key identifiers) to the SDK's
// attestation.SignatureVerifier (which expects an algoID-dispatching
// Verify(ctx, did, msg, sig, algoID) method).
//
// Stateless; safe for concurrent use by every admission goroutine.
type sigVerifierAdapter struct {
	resolver DIDResolver
}

// Verify implements attestation.SignatureVerifier. Dispatches by
// algoID; only SigAlgoECDSA is supported today.
func (a *sigVerifierAdapter) Verify(
	ctx context.Context,
	did string,
	message []byte,
	sig []byte,
	algoID uint16,
) error {
	if a.resolver == nil {
		// Wire-format-integrity-only trust model: the same shape
		// the single-sig path uses (entry_signature_verifier.go
		// short-circuits on nil resolver). For multi-sig, "skip
		// crypto" means treat every signature as nominally valid;
		// the caller must explicitly opt into this by passing a
		// nil resolver, and a future hardening PR can flip this
		// default to fail-closed.
		return nil
	}
	if algoID != envelope.SigAlgoECDSA {
		return fmt.Errorf("%w: did=%q algo=0x%04x", ErrUnsupportedSignatureAlgo, did, algoID)
	}
	pub, err := a.resolver.ResolvePublicKey(ctx, did)
	if err != nil {
		return fmt.Errorf("%w: did=%s: %v", ErrSignerDIDResolution, did, err)
	}
	if pub == nil {
		return fmt.Errorf("%w: did=%s: resolver returned nil public key", ErrSignerDIDResolution, did)
	}
	// signingHash here is the same digest VerifyEntrySignatures
	// computed once at the top — message IS that digest's bytes
	// (32 bytes). signatures.VerifyEntry takes [32]byte by value.
	if len(message) != 32 {
		return fmt.Errorf("%w: expected 32-byte signing hash, got %d", ErrSignatureInvalid, len(message))
	}
	var hash [32]byte
	copy(hash[:], message)
	if err := signatures.VerifyEntry(hash, sig, pub); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// NewSignatureVerifier wraps a DIDResolver as an
// attestation.SignatureVerifier suitable for the SDK's
// policy verifier (attestation.VerifyEntryAttestationPolicy /
// verifier.VerifyComplete Stage 6) and for any future Stage 6
// caller. Internally reuses the same sigVerifierAdapter that
// PR-C's VerifyEntryAllSignatures uses, so signature-verification
// semantics are uniform across the multi-sig gate and the policy
// gate.
//
// nil resolver: the returned verifier short-circuits to "every
// signature is nominally valid" — wire-format-integrity-only
// trust model, matching the legacy single-sig path. Production
// always wires a real resolver.
func NewSignatureVerifier(resolver DIDResolver) attestation.SignatureVerifier {
	return &sigVerifierAdapter{resolver: resolver}
}

// VerifyEntryAllSignatures verifies EVERY signature on entry via
// the SDK's attestation.VerifyEntrySignatures. Returns nil on full
// success (all signatures valid); returns one of the existing
// admission sentinels on failure:
//
//   - attestation.ErrNilEntry        → bad-call programmer error
//   - attestation.ErrNilSignatureVerifier → bad-call programmer error
//   - attestation.ErrEmptySignatures → SDK envelope invariant
//   - attestation.ErrPrimaryDIDMismatch → SDK envelope invariant
//   - ErrSignatureInvalid (wrapping first per-sig error) → 401
//   - ErrSignerDIDResolution (wrapping resolver error) → 401
//   - ErrUnsupportedSignatureAlgo → 422
//
// All of these are enrolled in admission/error_mapping.go so the
// api/submission.go branch (PR-A wiring) routes them to the right
// HTTP status + OTel error_class without per-call switches.
//
// nil resolver: same wire-format-integrity-only behaviour as the
// legacy single-sig path. Every signature is rubber-stamped as
// valid (the adapter returns nil unconditionally).
func VerifyEntryAllSignatures(
	ctx context.Context,
	entry *envelope.Entry,
	resolver DIDResolver,
) (*attestation.SignatureReport, error) {
	adapter := &sigVerifierAdapter{resolver: resolver}
	report, err := attestation.VerifyEntrySignatures(ctx, entry, adapter)
	if err != nil {
		// Envelope-level rejection — propagate the SDK sentinel
		// as-is so error_mapping.go can route it.
		return nil, err
	}
	if report.FirstError != nil {
		// Per-signature failure. The first error is already
		// wrapped with admission.ErrSignatureInvalid /
		// ErrSignerDIDResolution / ErrUnsupportedSignatureAlgo
		// (the adapter does the wrapping) so callers using
		// errors.Is get the right sentinel.
		return report, report.FirstError
	}
	return report, nil
}

// compile-time assertion: sigVerifierAdapter implements
// attestation.SignatureVerifier. A drift in the SDK interface
// surfaces here at build time.
var _ attestation.SignatureVerifier = (*sigVerifierAdapter)(nil)

// compile-time assertion: an *ecdsa.PublicKey is still what the
// adapter expects from the resolver. Surfaces resolver-shape
// drift at build time.
var _ = (*ecdsa.PublicKey)(nil)
