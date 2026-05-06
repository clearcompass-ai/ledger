/*
FILE PATH: tests/signing_helper_test.go

The signed-entry test helper. Canonical signing path:

 1. envelope.NewUnsignedEntry(hdr, payload)
    structural validation; Signatures left nil per the builder
    contract.
 2. hash := sha256.Sum256(envelope.SigningPayload(entry))
    SigningPayload is the canonical bytes WITHOUT the signatures
    section (using envelope.EntryIdentity here would panic — that
    function calls Serialize on an unsigned entry).
 3. signatures.SignEntry(hash, priv)
    SDK ECDSA primitive over secp256k1.
 4. entry.Signatures = []envelope.Signature{{...}}
    Caller-side append, mirroring builder/entry_builders.go's
    documented "produce → sign → append" sequence.
 5. entry.Validate()
    Enforces the full invariant set: Signatures[0].SignerDID ==
    Header.SignerDID, signature length / algoID, primary-cosigner
    ordering, etc.

After (5), entry.Serialize is total — passing the entry to
envelope.Serialize, envelope.EntryIdentity, or any tile-leaf
computation no longer risks the Serialize panic documented at
envelope/serialize.go:443.

WHY A DEDICATED HELPER:
  - envelope.Serialize PANICS on entries that bypass the
    validated paths. Tests that build entries via NewUnsignedEntry
    alone and call Serialize will crash the test runner.
  - This helper mirrors production-code signing flow so test
    fixtures and production code agree on what a "valid signed
    entry" is.
  - github.com/clearcompass-ai/attesta/internal/testkeys is not
    importable from this module (Go's internal/ rule), so the
    ledger's test tree carries its own thin wrapper.

OUT OF SCOPE FOR THIS HELPER:
  - Tests that DELIBERATELY forge malformed entries (bypass
    NewUnsignedEntry's gate, hand-construct via &envelope.Entry{...}
    struct literal) keep their bypass pattern. Those tests are
    asserting the rejection-path invariants, not the success path.
  - Tests that exercise SignerDID-vs-key mismatch build the
    Signature[0] manually with a divergent SignerDID. This helper
    sets Signatures[0].SignerDID == Header.SignerDID by construction
    so the happy path stays clean.
*/
package tests

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
)

// testKeypair returns a freshly-generated secp256k1 keypair plus its
// did:key identifier. Suitable as the SignerDID for any test entry.
//
// did:key resolution is purely parse-based (no network IO, no
// registry), so this helper works against any test server config.
func testKeypair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	return kp.PrivateKey, kp.DID
}

// makeSignedEntry constructs a canonical signed *envelope.Entry
// that is safe to feed to envelope.Serialize, envelope.EntryIdentity,
// or any caller that consumes a fully-validated entry.
//
// hdr.Destination defaults to testLogDID when empty (matches the
// makeUnsignedEntry contract so existing tests keep working).
//
// hdr.SignerDID is overwritten with signerDID — this closes the most
// common test-fixture bug (priv and Header.SignerDID out of sync,
// which Validate would catch later with a confusing error). Tests
// that deliberately exercise the SignerDID-vs-key mismatch path
// build the Signature[0] manually and bypass this helper.
func makeSignedEntry(
	t *testing.T,
	hdr envelope.ControlHeader,
	payload []byte,
	priv *ecdsa.PrivateKey,
	signerDID string,
) *envelope.Entry {
	t.Helper()
	if hdr.Destination == "" {
		hdr.Destination = testLogDID
	}
	hdr.SignerDID = signerDID

	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	return entry
}

// signedWire is the byte-stream form of makeSignedEntry. Returns the
// wire bytes produced by envelope.Serialize on the validated entry —
// suitable as a request body for POST /v1/entries.
//
// Under the wire bytes ARE the canonical bytes (signatures
// section is appended INSIDE Serialize), so callers no longer need
// the old "canonical || sig" concatenation step.
func signedWire(
	t *testing.T,
	hdr envelope.ControlHeader,
	payload []byte,
	priv *ecdsa.PrivateKey,
	signerDID string,
) []byte {
	t.Helper()
	return mustSerialize(makeSignedEntry(t, hdr, payload, priv, signerDID))
}
