/*
FILE PATH: api/sct.go

SignedCertificateTimestamp (SCT) — the ledger's cryptographic
promise on admission. Returned by POST /v1/entries instead of a
sequence number; signed with the ledger's secp256k1 ECDSA key
(the same LEDGER_SIGNER_KEY_FILE that signs anchor and
commitment commentary entries).

# SCOPE OF THIS FILE

The SCT wire layout, the SignedCertificateTimestamp JSON shape,
the canonical signing-payload packer, and the verification
function ALL live in attesta/crypto/sct. This ledger-side
file ships ONE function: SignSCT — the signing path that holds
the ledger's private key. The SDK is verifier-side and does
not (and should not) hold a signing function.

Callers consume the SDK directly:

  - sdksct.Version, sdksct.DomainSep, sdksct.SigAlgoECDSASecp256k1SHA256
  - sdksct.SignedCertificateTimestamp (JSON shape)
  - sdksct.SigningPayload (canonical bytes packer)
  - sdksct.Verify (verification path)

# WHAT THE SCT GUARANTEES

  - The ledger has the canonical bytes durably persisted (WAL
    fsync) and will sequence them into the Merkle tree within
    Maximum Merge Delay (LEDGER_MMD, default 24h).
  - The signature binds the (LogDID, canonical_hash, log_time)
    triple. Replaying with a different LogDID or hash invalidates
    the signature; mutating the timestamp invalidates the
    signature.

# WHAT THE SCT DOES NOT GUARANTEE

  - Visibility in /v1/entries/{seq} or /v1/entries-hash/{hash}
    metadata. That happens when the background Sequencer drains
    StatePending and writes the row to entry_index.
  - Bytestore migration. That's the Shipper's job; surfaces as
    302 redirects on /v1/entries/{seq}/raw post-migration.
*/
package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	sdksct "github.com/clearcompass-ai/attesta/crypto/sct"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// SignSCT builds and signs an SCT for (LogDID, canonical_hash,
// log_time). The signing key MUST be the ledger's secp256k1
// ECDSA identity key (LEDGER_SIGNER_KEY_FILE); a single key
// covers entry signing and SCT signing so consumers verify both
// against the ledger's published public key without ambiguity.
//
// SDK does not (and should not) ship this function — the
// ledger's private key never leaves the ledger process.
func SignSCT(
	priv *ecdsa.PrivateKey,
	signerDID string,
	logDID string,
	canonicalHash [32]byte,
	logTime time.Time,
) (*sdksct.SignedCertificateTimestamp, error) {
	if priv == nil {
		return nil, fmt.Errorf("api/sct: SignSCT requires non-nil priv")
	}
	if signerDID == "" {
		return nil, fmt.Errorf("api/sct: SignSCT requires non-empty signerDID")
	}
	logTimeMicros := logTime.UTC().UnixMicro()
	payload, err := sdksct.SigningPayload(
		signerDID,
		sdksct.SigAlgoECDSASecp256k1SHA256,
		logDID, canonicalHash, logTimeMicros,
	)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		return nil, err //nolint:nilerr // SDK error already typed
	}
	return &sdksct.SignedCertificateTimestamp{
		Version:       sdksct.Version,
		SignerDID:     signerDID,
		SigAlgoID:     sdksct.SigAlgoECDSASecp256k1SHA256,
		LogDID:        logDID,
		CanonicalHash: hex.EncodeToString(canonicalHash[:]),
		LogTimeMicros: logTimeMicros,
		// LogTime is derived from LogTimeMicros (the signed-over
		// value) so consumer-side reconstruction matches
		// byte-for-byte. Sourcing it from the original logTime
		// would leak sub-microsecond precision and break the
		// round-trip.
		LogTime:   time.UnixMicro(logTimeMicros).UTC().Format(time.RFC3339Nano),
		Signature: hex.EncodeToString(sig),
	}, nil
}
