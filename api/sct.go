/*
FILE PATH: api/sct.go

SignedCertificateTimestamp (SCT) — the operator's cryptographic
promise on admission. Returned by POST /v1/entries instead of a
sequence number; signed with the operator's secp256k1 ECDSA key
(the same OPERATOR_SIGNER_KEY_FILE that signs anchor and
commitment commentary entries).

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

CANONICAL SIGNING PAYLOAD (RFC-6962-style binary packing):

	domain_sep       (16 bytes; "ORTHOLOG_SCT_V1\x00")
	version          (u8)
	signerDID_len    (u16, big-endian)
	signerDID_bytes  (variable; 0..65535)
	sigAlgoID_len    (u16, big-endian)
	sigAlgoID_bytes  (variable; 0..65535)
	logDID_len       (u16, big-endian)
	logDID_bytes     (variable; 0..65535)
	canonical_hash   (32 bytes)
	log_time_micros  (i64, big-endian; microseconds since Unix epoch)

	Total size: 65 + len(signerDID) + len(sigAlgoID) + len(logDID) bytes.

Length-prefixed encoding makes the parse unambiguous — concatenated
fields cannot drift across boundaries (the classic
"alice"+"/"+"bob" vs "ali"+"ce/b"+"ob" footgun with naive string
concatenation). The version byte at the front lets future formats
dispatch on the leading byte.

VERIFICATION (consumer side):

 1. Reconstruct the signing payload from the SCT's JSON fields
    via SCTSigningPayload(...).
 2. SHA-256 it.
 3. signatures.VerifyEntry(hash, sct.Signature, operatorPubKey).

The operator's public key is reachable via cfg.OperatorDID, which
is always a did:key:z... — pure parse, no network. See
admission/didkey_resolver.go for the resolution path that the
operator's own admission step 4 uses.
*/
package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// SCTVersion is the wire-format version of the SCT signing
// payload. Bumping this is a breaking change for every consumer;
// the version byte at the front of the signing payload makes it
// dispatchable.
const SCTVersion uint8 = 1

const (
	// SCTDomainSep is a strong domain separator that prevents cross-protocol
	// signature confusion between SCT payloads and any other signed blobs.
	SCTDomainSep = "ORTHOLOG_SCT_V1\x00"
	// SCTSigAlgoECDSASecp256k1SHA256 identifies the algorithm used for SCT
	// signatures in v1.
	SCTSigAlgoECDSASecp256k1SHA256 = "ecdsa-secp256k1-sha256"
)

// SignedCertificateTimestamp is the JSON shape returned by
// POST /v1/entries on successful admission. Consumers verify the
// signature against the operator's public key (reachable via
// cfg.OperatorDID) before treating the SCT as a binding promise.
//
// LogTimeMicros is signed-over; LogTime is a derived RFC-3339
// rendering for human consumption only — never trust it for
// signature reconstruction.
type SignedCertificateTimestamp struct {
	Version       uint8  `json:"version"`
	SignerDID     string `json:"signer_did"`  // DID/key identifier for verification across key rotation windows
	SigAlgoID     string `json:"sig_algo_id"` // signature algorithm identifier (crypto agility)
	LogDID        string `json:"log_did"`
	CanonicalHash string `json:"canonical_hash"`  // hex-encoded sha256 of canonical bytes
	LogTimeMicros int64  `json:"log_time_micros"` // microseconds since Unix epoch (signed-over)
	LogTime       string `json:"log_time"`        // RFC-3339 nano (derived; not signed-over)
	Signature     string `json:"signature"`       // hex-encoded ECDSA signature
}

// SCTSigningPayload builds the deterministic byte sequence that
// the SCT signature is computed over. Same packing on both sides:
// the operator builds it during SignSCT, the consumer rebuilds
// it during VerifySCT, and the two must match byte-for-byte.
func SCTSigningPayload(
	signerDID string,
	sigAlgoID string,
	logDID string,
	canonicalHash [32]byte,
	logTimeMicros int64,
) ([]byte, error) {
	if len(signerDID) > 0xFFFF {
		return nil, fmt.Errorf("api/sct: signerDID too long (%d bytes, max %d)", len(signerDID), 0xFFFF)
	}
	if len(sigAlgoID) > 0xFFFF {
		return nil, fmt.Errorf("api/sct: sigAlgoID too long (%d bytes, max %d)", len(sigAlgoID), 0xFFFF)
	}
	if len(logDID) > 0xFFFF {
		return nil, fmt.Errorf("api/sct: logDID too long (%d bytes, max %d)", len(logDID), 0xFFFF)
	}
	buf := make([]byte, 0, len(SCTDomainSep)+1+2+len(signerDID)+2+len(sigAlgoID)+2+len(logDID)+32+8)
	buf = append(buf, SCTDomainSep...)
	buf = append(buf, SCTVersion)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(signerDID)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, signerDID...)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sigAlgoID)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, sigAlgoID...)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(logDID)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, logDID...)
	buf = append(buf, canonicalHash[:]...)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(logTimeMicros))
	buf = append(buf, tsBuf[:]...)
	return buf, nil
}

// SignSCT builds and signs an SCT for (LogDID, canonical_hash,
// log_time). The signing key MUST be the operator's secp256k1
// ECDSA identity key (OPERATOR_SIGNER_KEY_FILE); a single key
// covers entry signing and SCT signing so consumers verify both
// against the operator's published public key without ambiguity.
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
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		return nil, fmt.Errorf("api/sct: SignEntry: %w", err)
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

// VerifySCT recomputes the canonical signing payload from the
// SCT's JSON fields and verifies the signature against pub.
// Returns nil on success or a wrapped verification error.
//
// Tampering with any of (Version, LogDID, CanonicalHash,
// LogTimeMicros) invalidates the signature. LogTime (the
// human-readable rendering) is not part of the signed payload —
// consumers MUST rebuild from LogTimeMicros.
func VerifySCT(pub *ecdsa.PublicKey, sct *SignedCertificateTimestamp) error {
	if pub == nil {
		return fmt.Errorf("api/sct: VerifySCT requires non-nil pub")
	}
	if sct == nil {
		return fmt.Errorf("api/sct: VerifySCT requires non-nil sct")
	}
	if sct.Version != SCTVersion {
		return fmt.Errorf("api/sct: unsupported SCT version %d (want %d)", sct.Version, SCTVersion)
	}
	if sct.SignerDID == "" {
		return fmt.Errorf("api/sct: missing signer_did")
	}
	if sct.SigAlgoID != SCTSigAlgoECDSASecp256k1SHA256 {
		return fmt.Errorf("api/sct: unsupported sig_algo_id %q", sct.SigAlgoID)
	}
	expectedLogTime := time.UnixMicro(sct.LogTimeMicros).UTC().Format(time.RFC3339Nano)
	if sct.LogTime != expectedLogTime {
		return fmt.Errorf("api/sct: log_time mismatch (got %q want %q)", sct.LogTime, expectedLogTime)
	}
	canonicalHashBytes, err := hex.DecodeString(sct.CanonicalHash)
	if err != nil {
		return fmt.Errorf("api/sct: canonical_hash decode: %w", err)
	}
	if len(canonicalHashBytes) != 32 {
		return fmt.Errorf("api/sct: canonical_hash length %d (want 32)", len(canonicalHashBytes))
	}
	var canonicalHash [32]byte
	copy(canonicalHash[:], canonicalHashBytes)

	sigBytes, err := hex.DecodeString(sct.Signature)
	if err != nil {
		return fmt.Errorf("api/sct: signature decode: %w", err)
	}

	payload, err := SCTSigningPayload(sct.SignerDID, sct.SigAlgoID, sct.LogDID, canonicalHash, sct.LogTimeMicros)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	if err := signatures.VerifyEntry(hash, sigBytes, pub); err != nil {
		return fmt.Errorf("api/sct: VerifyEntry: %w", err)
	}
	return nil
}
