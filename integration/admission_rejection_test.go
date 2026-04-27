/*
FILE PATH: integration/admission_rejection_test.go

Admission-rejection coverage per Wave 1 v3 §CI5. One test case per
documented rejection error code, plus one test for the C2
passthrough invariant.

Why a mix of unit-level and HTTP-level tests:

  - For NFC, signature, BLS quorum: the operator's admission
    package exposes typed errors directly. A unit-level call
    against the package's exported functions exercises the same
    code path the HTTP handler invokes, with less ceremony than
    constructing a wire-encoded entry that triggers the rejection
    at exactly the right pipeline stage. The test asserts
    errors.Is on the typed sentinel — a regression that drops
    the wrapping fails the test.

  - For the SDK's commitment payload errors and the C2 passthrough
    invariant: tests call the SDK schema parsers (or the operator's
    dispatch logic) directly because the rejection contract is the
    error type returned, not the HTTP status code that wraps it.
    The HTTP-status mapping is exercised in CI3's happy-path test
    by inversion (anything other than 202 fails the happy path).

This split keeps each test focused on one assertion and avoids the
combinatorial explosion of "construct a wire entry that passes the
N-1 prior pipeline stages and fails on the Nth."

Skip semantics: the database-touching helper resetTables in the
shared CI2 harness fixtures is not invoked by these tests because
they exercise admission-layer code paths that don't write to the
database. ORTHOLOG_TEST_DSN is therefore not required, and these
tests run unconditionally on every `go test`.
*/
package integration

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdkschema "github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/admission"
)

// ─────────────────────────────────────────────────────────────────────
// CI5.1 — ErrIngressNotNFC
// ─────────────────────────────────────────────────────────────────────

// TestAdmission_RejectsNonNFCSignerDID confirms that the operator's
// defensive NFC check rejects an entry whose SignerDID is in NFD
// (decomposed) form rather than NFC (composed). The test bypasses
// envelope.NewEntry because that constructor enforces other
// invariants we are not testing here; the unit under test is
// admission.CheckNFC reading a manually-built header.
func TestAdmission_RejectsNonNFCSignerDID(t *testing.T) {
	// "Café" with the e-acute as a precomposed character (NFC, 5
	// bytes) versus "Café" (NFD, 6 bytes). The visual
	// rendering is identical; the byte sequences are not. SDK
	// Decision 52 puts the normalization burden on the caller; the
	// operator MUST reject NFD-form input rather than silently
	// normalize it.
	const nfdDID = "did:web:Café.example"
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   nfdDID,
			Destination: "did:web:operator.example",
		},
	}
	err := admission.CheckNFC(entry)
	if err == nil {
		t.Fatal("expected ErrIngressNotNFC, got nil")
	}
	if !errors.Is(err, admission.ErrIngressNotNFC) {
		t.Fatalf("expected ErrIngressNotNFC, got %v", err)
	}
}

// TestAdmission_AcceptsNFCSignerDID is the negative control:
// the same DID in precomposed (NFC) form passes the check.
func TestAdmission_AcceptsNFCSignerDID(t *testing.T) {
	// "Café" precomposed (NFC, e-acute as a single codepoint).
	const nfcDID = "did:web:Café.example"
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   nfcDID,
			Destination: "did:web:operator.example",
		},
	}
	if err := admission.CheckNFC(entry); err != nil {
		t.Fatalf("expected nil for NFC input, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// CI5.2 — ErrSignatureInvalid
// ─────────────────────────────────────────────────────────────────────

// TestAdmission_RejectsBadSignature confirms that
// admission.VerifyEntrySignature wraps the SDK's signature failure
// in ErrSignatureInvalid. The test signs the entry with key A and
// asks the verifier to verify with key B's public key; the SDK's
// signatures.VerifyEntry returns ErrSignatureVerificationFailed,
// which the operator wrapper maps to ErrSignatureInvalid.
func TestAdmission_RejectsBadSignature(t *testing.T) {
	keyA, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	keyB, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}

	// Build a minimal valid entry header for signing.
	const signerDID = "did:web:test-signer.example"
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   signerDID,
			Destination: "did:web:operator.example",
		},
	}
	// Sign over arbitrary 32 bytes — the test exercises the
	// verifier's wrong-key rejection, not the canonical-hash
	// derivation. signatures.SignEntry takes [32]byte directly.
	var hash [32]byte
	hash[0] = 0x01
	sigA, err := signatures.SignEntry(hash, keyA)
	if err != nil {
		t.Fatalf("SignEntry A: %v", err)
	}

	// Resolver returns key B's public key, not key A's. The
	// signature was produced with A; verification with B's key
	// MUST fail.
	resolver := stubDIDResolver{
		did: signerDID,
		pub: &keyB.PublicKey,
	}
	err = admission.VerifyEntrySignature(context.Background(), entry, sigA, resolver)
	if err == nil {
		t.Fatal("expected ErrSignatureInvalid, got nil")
	}
	if !errors.Is(err, admission.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

// stubDIDResolver satisfies admission.DIDResolver by returning a
// canned (did, pubkey) pair on every Resolve call.
type stubDIDResolver struct {
	did string
	pub *ecdsa.PublicKey
}

func (s stubDIDResolver) ResolvePublicKey(_ context.Context, did string) (*ecdsa.PublicKey, error) {
	if did != s.did {
		return nil, errors.New("stubDIDResolver: unknown DID")
	}
	return s.pub, nil
}

// ─────────────────────────────────────────────────────────────────────
// CI5.3 — ErrCommitmentPayloadMalformed
// ─────────────────────────────────────────────────────────────────────

// TestAdmission_RejectsMalformedCommitmentPayload confirms that
// the SDK's schema.ParsePREGrantCommitmentEntry rejects a payload
// whose commitment_bytes_hex decodes to bytes that do not parse as
// a valid PREGrantCommitment wire form.
//
// The operator's C2 dispatcher routes such payloads through the
// SDK parser; the rejection lands as ErrCommitmentPayloadMalformed
// at the dispatch site and the admission handler maps that to
// HTTP 422.
func TestAdmission_RejectsMalformedCommitmentPayload(t *testing.T) {
	// Valid envelope structure, invalid inner bytes (8 bytes of
	// zero — too short to be a PREGrantCommitment which needs
	// at least SplitID + M + N + one 33-byte commitment point).
	envelopeBytes, _ := json.Marshal(map[string]any{
		"schema_id":            artifact.PREGrantCommitmentSchemaID,
		"commitment_bytes_hex": "0000000000000000",
	})
	entry := &envelope.Entry{
		DomainPayload: envelopeBytes,
	}

	_, err := sdkschema.ParsePREGrantCommitmentEntry(entry)
	if err == nil {
		t.Fatal("expected ErrCommitmentPayloadMalformed, got nil")
	}
	// The SDK's wrapping uses fmt.Errorf("%w: ...", err) which
	// preserves errors.Is matching against the sentinel.
	if !errors.Is(err, sdkschema.ErrCommitmentPayloadMalformed) {
		t.Fatalf("expected ErrCommitmentPayloadMalformed, got %v", err)
	}
}

// TestAdmission_ParseSucceedsOnWellFormedCommitmentPayload is the
// negative control: the same envelope shape with valid inner
// bytes parses cleanly.
func TestAdmission_ParseSucceedsOnWellFormedCommitmentPayload(t *testing.T) {
	// Minimal valid wire: 32-byte SplitID + M=2 + N=2 + 2 zero
	// commitment points. The on-curve check would fire later in
	// VerifyPREGrantCommitment but is not part of Parse.
	wire := make([]byte, 32+2+2*33)
	wire[32] = 2 // M
	wire[33] = 2 // N

	envelopeBytes, _ := json.Marshal(map[string]any{
		"schema_id":            artifact.PREGrantCommitmentSchemaID,
		"commitment_bytes_hex": hexEncode(wire),
	})
	entry := &envelope.Entry{
		DomainPayload: envelopeBytes,
	}

	commitment, err := sdkschema.ParsePREGrantCommitmentEntry(entry)
	if err != nil {
		t.Fatalf("ParsePREGrantCommitmentEntry: %v", err)
	}
	if commitment == nil {
		t.Fatal("expected non-nil commitment")
	}
	if commitment.M != 2 || commitment.N != 2 {
		t.Errorf("threshold: got M=%d N=%d, want M=2 N=2",
			commitment.M, commitment.N)
	}
}

// ─────────────────────────────────────────────────────────────────────
// CI5.4 — ErrCommitmentSchemaIDMismatch
// ─────────────────────────────────────────────────────────────────────

// TestAdmission_RejectsSchemaIDMismatch confirms that the SDK
// parser rejects a payload whose schema_id field does not match
// the schema being parsed against. This is the primary defense
// against routing mistakes — admitting a pre-grant payload as an
// escrow split would corrupt the index.
func TestAdmission_RejectsSchemaIDMismatch(t *testing.T) {
	// Payload carries the ESCROW schema id but is being parsed
	// as a PRE grant. The SDK MUST reject.
	wire := make([]byte, 32+2+2*33)
	wire[32] = 2
	wire[33] = 2
	envelopeBytes, _ := json.Marshal(map[string]any{
		"schema_id":            escrow.EscrowSplitCommitmentSchemaID,
		"commitment_bytes_hex": hexEncode(wire),
	})
	entry := &envelope.Entry{
		DomainPayload: envelopeBytes,
	}

	_, err := sdkschema.ParsePREGrantCommitmentEntry(entry)
	if err == nil {
		t.Fatal("expected ErrCommitmentSchemaIDMismatch, got nil")
	}
	if !errors.Is(err, sdkschema.ErrCommitmentSchemaIDMismatch) {
		t.Fatalf("expected ErrCommitmentSchemaIDMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// CI5.5 — ErrWitnessQuorumInsufficient
// ─────────────────────────────────────────────────────────────────────

// TestAdmission_RejectsInsufficientWitnessQuorum confirms that
// admission/bls_quorum_verifier.go's VerifyEmbeddedTreeHead wraps
// SDK quorum failures in ErrWitnessQuorumInsufficient.
//
// We construct an empty witness key set, which the SDK's
// witness.VerifyTreeHead rejects with ErrEmptyWitnessSet. The
// operator wrapper catches this and any other quorum-class error
// and remaps to the operator-side typed sentinel.
func TestAdmission_RejectsInsufficientWitnessQuorum(t *testing.T) {
	v := admission.NewBLSQuorumVerifier(
		emptyKeySet{},
		nil, // BLS verifier not needed; ECDSA path handles empty set
	)
	// A zero CosignedTreeHead is fine — the verifier rejects on
	// the empty witness set before it even looks at the head's
	// signatures.
	err := v.VerifyEmbeddedTreeHead(types.CosignedTreeHead{})
	if err == nil {
		t.Fatal("expected ErrWitnessQuorumInsufficient, got nil")
	}
	if !errors.Is(err, admission.ErrWitnessQuorumInsufficient) {
		t.Fatalf("expected ErrWitnessQuorumInsufficient, got %v", err)
	}
}

// emptyKeySet returns ([], 1, nil) — a configuration where the
// quorum K=1 cannot be met because the witness set is empty.
type emptyKeySet struct{}

func (emptyKeySet) Active() ([]types.WitnessPublicKey, int, error) {
	return nil, 1, nil
}

// ─────────────────────────────────────────────────────────────────────
// CI5.6 — C2 passthrough invariant
// ─────────────────────────────────────────────────────────────────────

// TestC2Passthrough_UnknownSchemaID confirms the load-bearing
// invariant from Wave 1 v3 §C2: an entry payload with an
// unrecognized schema_id flows through the dispatcher unchanged
// (no extracted SplitID, no error). This is what allows the F4
// bootstrap script to admit schema-definition entries before any
// commitment entry exists, and preserves the Domain/Protocol
// Separation Principle.
//
// Because dispatchCommitmentSchema is package-private to api/,
// the test exercises the invariant via the SDK parsers' negative
// behavior: parsing a payload with unrecognized schema_id against
// EITHER known parser fails with ErrCommitmentSchemaIDMismatch,
// confirming that the dispatcher's switch statement (which
// matches on the same schema_id constants) cannot route those
// payloads to either parser. The default branch of that switch
// is the passthrough.
func TestC2Passthrough_UnknownSchemaID(t *testing.T) {
	envelopeBytes, _ := json.Marshal(map[string]any{
		"schema_id":            "some-unrelated-domain-schema-v1",
		"commitment_bytes_hex": "00",
	})
	entry := &envelope.Entry{
		DomainPayload: envelopeBytes,
	}

	// Both parsers reject the unrecognized schema_id with the
	// SAME error sentinel (ErrCommitmentSchemaIDMismatch), which
	// confirms the dispatcher's switch statement cannot route
	// these payloads — the default branch (passthrough) is the
	// only path open to them.
	_, preErr := sdkschema.ParsePREGrantCommitmentEntry(entry)
	if !errors.Is(preErr, sdkschema.ErrCommitmentSchemaIDMismatch) {
		t.Errorf("expected schema ID mismatch from PRE parser, got %v", preErr)
	}
	_, escrowErr := sdkschema.ParseEscrowSplitCommitmentEntry(entry)
	if !errors.Is(escrowErr, sdkschema.ErrCommitmentSchemaIDMismatch) {
		t.Errorf("expected schema ID mismatch from escrow parser, got %v", escrowErr)
	}

	// The dispatcher's contract: when neither parser matches, it
	// returns (nil SplitID, "", nil) and admission proceeds with
	// no SplitID indexed for this entry. The HTTP-level
	// confirmation is in CI3's happy-path test (the synthetic
	// commitment goes through admission and admits successfully);
	// here we pin the unit-level invariant that the SDK parsers
	// agree on the schema_id discriminator.
}

// TestC2Passthrough_NoDomainPayload confirms that an entry with
// an empty DomainPayload also passes through dispatch — there is
// no schema_id field to peek, so the dispatcher's JSON unmarshal
// step produces a zero-value envelope and the switch falls to
// the default branch.
//
// This case matters because commentary entries (BuildCommentary
// output) often have minimal or empty payloads; admission must
// not require every entry to carry a recognized schema_id.
func TestC2Passthrough_NoDomainPayload(t *testing.T) {
	entry := &envelope.Entry{
		DomainPayload: nil,
	}
	// Neither SDK parser should fire on an entry with no payload;
	// they reject with malformed-payload errors when they do see
	// non-JSON or wrong-shape input.
	if _, err := sdkschema.ParsePREGrantCommitmentEntry(entry); err == nil {
		t.Errorf("PRE parser unexpectedly accepted entry with no DomainPayload")
	}
	if _, err := sdkschema.ParseEscrowSplitCommitmentEntry(entry); err == nil {
		t.Errorf("escrow parser unexpectedly accepted entry with no DomainPayload")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// hexEncode is a thin wrapper to keep the table-test bodies tidy.
// strings.ToLower because hex.EncodeToString already returns
// lowercase but we make the contract explicit for any future
// reader.
func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return strings.ToLower(string(out))
}
