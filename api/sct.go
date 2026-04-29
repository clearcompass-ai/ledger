/*
FILE PATH: api/sct.go

SignedCertificateTimestamp (SCT) — the operator's cryptographic
promise on admission. Returned by POST /v1/entries instead of a
sequence number; signed with the operator's secp256k1 ECDSA key
(the same OPERATOR_SIGNER_KEY_FILE that signs anchor and
commitment commentary entries).

ALIGNMENT WITH SDK (Tier 1):

	The SCT wire layout, the SignedCertificateTimestamp JSON shape,
	the canonical signing-payload packer, and the verification
	function are all owned by ortholog-sdk/crypto/sct. The operator
	consumes the SDK directly so the byte layouts cannot drift —
	if the SDK's packer changes, every consumer's signatures stop
	verifying simultaneously, including the operator's own
	VerifySCT.

	This file ships ONE operator-only piece: SignSCT. The SDK is
	verifier-side and does not (and should not) hold a signing
	function — the operator's private secp256k1 identity key is
	never exported. SignSCT delegates to sct.SigningPayload for
	the wire bytes and to signatures.SignEntry for the ECDSA
	signature, so the only operator-resident logic is key
	handling and JSON construction.

WHAT THE SCT GUARANTEES:

  - The operator has the canonical bytes durably persisted (WAL
    fsync) and will sequence them into the Merkle tree within
    Maximum Merge Delay (OPERATOR_MMD, default 24h).
  - The signature binds the (LogDID, canonical_hash, log_time)
    triple. Replaying with a different LogDID or hash invalidates
    the signature; mutating the timestamp invalidates the
    signature.

WHAT THE SCT DOES NOT GUARANTEE:

  - Visibility in /v1/entries/{seq} or /v1/entries-hash/{hash}
    metadata. That happens when the background Sequencer drains
    StatePending and writes the row to entry_index.
  - Bytestore migration. That's the Shipper's job; surfaces as
    302 redirects on /v1/entries/{seq}/raw post-migration.

CANONICAL SIGNING PAYLOAD:

	The byte layout lives in ortholog-sdk/crypto/sct/sct.go's
	package godoc. Pinned-byte tests in api/sct_test.go and the
	SDK's own crypto/sct/sct_test.go both exercise the same
	packer and continue to verify after this delegation.

VERIFICATION (consumer side):

	Use sct.Verify(pub, sct) directly from the SDK. VerifySCT in
	this file is preserved as a thin compatibility wrapper for
	any in-tree callers that still reference api.VerifySCT — it
	is a single-line forward to sct.Verify.

The operator's public key is reachable via cfg.OperatorDID, which
is always a did:key:z... — pure parse, no network. See
admission/didkey_resolver.go for the resolution path.
*/
package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	sdksct "github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// ─────────────────────────────────────────────────────────────────────
// Re-exports — preserve api.{SCTVersion, SCTDomainSep, ...} for
// existing call sites while the SDK owns the canonical values.
// ─────────────────────────────────────────────────────────────────────

// SCTVersion is the wire-format version of the SCT signing payload.
// Re-export of sdksct.Version. Kept so api.SCTVersion stays a valid
// reference at every existing call site without a sweep.
const SCTVersion = sdksct.Version

// SCTDomainSep is the cross-protocol domain separator. Re-export of
// sdksct.DomainSep.
const SCTDomainSep = sdksct.DomainSep

// SCTSigAlgoECDSASecp256k1SHA256 is the only signature algorithm
// the v1 SCT format supports. Re-export of
// sdksct.SigAlgoECDSASecp256k1SHA256.
const SCTSigAlgoECDSASecp256k1SHA256 = sdksct.SigAlgoECDSASecp256k1SHA256

// SignedCertificateTimestamp is the JSON shape returned by
// POST /v1/entries. Type-aliased to sdksct.SignedCertificateTimestamp
// so JSON serialization is byte-for-byte stable — any future
// json-tag change happens in one place (the SDK) rather than two.
type SignedCertificateTimestamp = sdksct.SignedCertificateTimestamp

// ─────────────────────────────────────────────────────────────────────
// SCTSigningPayload — thin wrapper around the SDK packer.
// ─────────────────────────────────────────────────────────────────────

// SCTSigningPayload builds the deterministic byte sequence that the
// SCT signature is computed over. Delegates to sdksct.SigningPayload
// so operator and SDK packers cannot drift. Inherits the SDK's
// negative-LogTimeMicros guard (BUG #5).
func SCTSigningPayload(
	signerDID string,
	sigAlgoID string,
	logDID string,
	canonicalHash [32]byte,
	logTimeMicros int64,
) ([]byte, error) {
	return sdksct.SigningPayload(signerDID, sigAlgoID, logDID, canonicalHash, logTimeMicros)
}

// ─────────────────────────────────────────────────────────────────────
// SignSCT — operator-only signing path.
// ─────────────────────────────────────────────────────────────────────

// SignSCT builds and signs an SCT for (LogDID, canonical_hash,
// log_time). The signing key MUST be the operator's secp256k1
// ECDSA identity key (OPERATOR_SIGNER_KEY_FILE); a single key
// covers entry signing and SCT signing so consumers verify both
// against the operator's published public key without ambiguity.
//
// SDK does not (and should not) ship this function — the
// operator's private key never leaves the operator process.
func SignSCT(
	priv *ecdsa.PrivateKey,
	signerDID string,
	logDID string,
	canonicalHash [32]byte,
	logTime time.Time,
) (*SignedCertificateTimestamp, error) {
	if priv == nil {
		return nil, fmt.Errorf("api/sct: SignSCT requires non-nil priv")
	}
	if signerDID == "" {
		return nil, fmt.Errorf("api/sct: SignSCT requires non-empty signerDID")
	}
	logTimeMicros := logTime.UTC().UnixMicro()
	payload, err := SCTSigningPayload(signerDID, SCTSigAlgoECDSASecp256k1SHA256, logDID, canonicalHash, logTimeMicros)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	// signatures.SignEntry's only documented error mode is
	// privkey == nil, which the function-entry guard above already
	// rules out. The unreachable-but-explicit err return is preserved
	// (rather than dropped) so a future SignEntry contract change
	// surfaces here instead of silently producing an empty sig.
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		return nil, err //nolint:nilerr // SDK error already typed
	}
	return &SignedCertificateTimestamp{
		Version:       SCTVersion,
		SignerDID:     signerDID,
		SigAlgoID:     SCTSigAlgoECDSASecp256k1SHA256,
		LogDID:        logDID,
		CanonicalHash: hex.EncodeToString(canonicalHash[:]),
		LogTimeMicros: logTimeMicros,
		// LogTime is derived from LogTimeMicros (the signed-over
		// value) so VerifySCT's reconstruction matches byte-for-byte.
		// Sourcing it from the original logTime would leak
		// sub-microsecond precision and break the round-trip.
		LogTime:   time.UnixMicro(logTimeMicros).UTC().Format(time.RFC3339Nano),
		Signature: hex.EncodeToString(sig),
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// VerifySCT — thin wrapper around the SDK Verify.
// ─────────────────────────────────────────────────────────────────────

// VerifySCT recomputes the canonical signing payload from the
// SCT's JSON fields and verifies the signature against pub.
// Delegates to sdksct.Verify so the verification logic is owned
// by the SDK; this wrapper exists only for in-tree callers that
// still reference api.VerifySCT.
//
// Errors are SDK sentinels (sct.ErrNilPubKey, sct.ErrUnsupportedVer,
// sct.ErrLogTimeMismatch, sct.ErrNegativeLogTime, etc.) — callers
// can errors.Is against either the SDK names or the legacy api.*
// references kept for compatibility.
func VerifySCT(pub *ecdsa.PublicKey, sct *SignedCertificateTimestamp) error {
	return sdksct.Verify(pub, sct)
}
