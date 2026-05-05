/*
FILE PATH:

	admission/entry_signature_verifier.go

DESCRIPTION:

	Entry-signature verification at the ledger's trust boundary.
	Thin wrapper around the SDK's signatures.VerifyEntry primitive
	with ledger-side error mapping.

	The SDK owns the cryptographic gate logic (muEnableEntrySignatureVerify,
	muEnablePubKeyOnCurve, muEnableSignatureLength); the ledger's
	job is to invoke the primitive on every inbound entry, resolve
	the signer DID to a public key via the configured DIDResolver,
	and map any failure to ErrSignatureInvalid for HTTP 401 dispatch.

KEY ARCHITECTURAL DECISIONS:

  - DIDResolver is an interface, not a concrete type. Phase 4 wires
    a real did.VerifierRegistry; tests wire stubs. The Phase 2 trust
    model (nil resolver = wire-format integrity only) is preserved
    via the explicit nil check — the ledger can run without DID
    resolution during the v0.3.0-tessera → v7.75 cutover.
  - Error mapping is the only ledger-side logic. The SDK's
    signatures.VerifyEntry already enforces the cryptographic
    invariants (length, on-curve, ecdsa.Verify) gated by the
    mutation-audit constants; this file does not duplicate any of
    those checks.
  - Canonical hash comes from envelope.EntryIdentity, the SDK's
    single Tessera-aligned entry-hash primitive. Computing the hash
    inside this function (rather than accepting it as a parameter)
    keeps the verifier API impossible to misuse with a hash that
    doesn't match the entry's canonical bytes.

KEY DEPENDENCIES:

  - github.com/clearcompass-ai/attesta/core/envelope: Entry,
    EntryIdentity.
  - github.com/clearcompass-ai/attesta/crypto/signatures:
    VerifyEntry primitive (gated by SDK mutation switches).
*/
package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// ErrSignatureInvalid is returned by VerifyEntrySignature when an
// entry's signature fails cryptographic verification. Wraps the
// underlying SDK error for diagnostic context but is the sentinel
// callers match against for HTTP 401 dispatch.
var ErrSignatureInvalid = errors.New("admission: entry signature invalid")

// ErrSignerDIDResolution is returned when the configured DIDResolver
// fails to resolve the entry's SignerDID to a public key. Distinct
// from ErrSignatureInvalid because the failure mode is identity
// rather than cryptographic — the caller may want to surface a
// different HTTP status (typically 401, but conceivably 503 if the
// resolver is transiently unreachable).
var ErrSignerDIDResolution = errors.New("admission: signer DID resolution failed")

// DIDResolver resolves a signer DID to its current secp256k1 public
// key. Phase 4 wires a real did.VerifierRegistry that dispatches
// across DID methods (web/key/pkh); tests wire stubs.
//
// A nil DIDResolver is permitted at the call site of
// VerifyEntrySignature and triggers the Phase 2 trust model
// (verification skipped, wire-format integrity only). This is a
// transitional accommodation for the v0.3.0-tessera → v7.75 cutover
// and will be tightened in a later commit once the DID resolver is
// wired in production.
type DIDResolver interface {
	ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error)
}

// VerifyEntrySignature verifies the entry's signature against the
// public key the resolver returns for entry.Header.SignerDID.
//
// Returns:
//   - nil when verification succeeds.
//   - nil when resolver is nil (Phase 2 trust model — the caller
//     has explicitly opted out of DID resolution and is operating
//     under wire-format integrity only).
//   - ErrSignerDIDResolution wrapped with the resolver error when
//     resolution fails.
//   - ErrSignatureInvalid wrapped with the SDK error when the SDK
//     primitive rejects the signature.
//
// The hash bound to the verifier is sha256(envelope.SigningPayload(entry)),
// matching the SDK's documented signing contract at
// envelope/serialize.go:218-225:
//
//  1. signingHash := sha256.Sum256(envelope.SigningPayload(entry))
//  2. signatures.SignEntry(signingHash, priv)
//
// SigningPayload covers preamble + header_body + payload but NOT the
// signatures section. Hashing envelope.EntryIdentity (= sha256(Serialize)
// which embeds the signatures section) here would (a) panic on entries
// whose Signatures slice is the one being verified into, and (b)
// disagree with what every legitimate signer actually signed over —
// rejecting every well-formed entry.
func VerifyEntrySignature(
	ctx context.Context,
	entry *envelope.Entry,
	sigBytes []byte,
	resolver DIDResolver,
) error {
	if entry == nil {
		return fmt.Errorf("admission: VerifyEntrySignature called with nil entry")
	}
	if resolver == nil {
		// Phase 2 trust model: caller has opted out of DID
		// resolution. The signature is still on the wire and was
		// length-validated during envelope deserialize; we just
		// don't crypto-verify it here.
		return nil
	}

	pub, err := resolver.ResolvePublicKey(ctx, entry.Header.SignerDID)
	if err != nil {
		return fmt.Errorf("%w: did=%s: %v", ErrSignerDIDResolution, entry.Header.SignerDID, err)
	}
	if pub == nil {
		return fmt.Errorf("%w: did=%s: resolver returned nil public key",
			ErrSignerDIDResolution, entry.Header.SignerDID)
	}

	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	if err := signatures.VerifyEntry(signingHash, sigBytes, pub); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}
