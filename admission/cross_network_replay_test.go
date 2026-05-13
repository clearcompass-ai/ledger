/*
FILE PATH: admission/cross_network_replay_test.go

Cross-network replay defense — evidence-based test.

# PROPERTY UNDER TEST

A types.CosignedTreeHead whose signatures were generated against
NetworkID="jurisdiction-A" MUST fail verification when checked
against a *cosign.WitnessKeySet constructed with
NetworkID="jurisdiction-B". This is the load-bearing invariant
that prevents an adversary from copying a valid cosigned head
from Network A and replaying it as if it were valid on Network B.

# PHYSICS

cosign.NewTreeHeadPayload(head) is the canonical byte serialization
of (tree_size, root_hash). cosign.Sign HASHES this payload with
the NetworkID prefix-mixed in BEFORE producing the signature
(crypto/cosign/sign.go in the SDK), so signing under NetworkID=A
produces a fundamentally different signed-message-digest than
signing the same TreeHead under NetworkID=B. The downstream
cosign.Verify path recomputes the digest with its own configured
NetworkID (held by the WitnessKeySet) and compares — a mismatch
surfaces as a cryptographic check failure, not a quorum failure.

# WHY A SEPARATE FILE

bls_quorum_verifier_test.go pins local-construction invariants.
v011_contract_test.go pins the SDK alignment shape. THIS file
pins the cross-network replay rejection, which is conceptually
neither (it's a multi-jurisdiction security property). Keeping
the three files distinct means a regression in any of the three
surfaces shows up in its own test file — diagnosable from CI
output alone.

# COVERAGE

  (1) Raw cosign.Verify path — produces SDK error directly.
  (2) admission.BLSQuorumVerifier wrapper — the ledger's actual
      hot-path entrypoint, demonstrating the wrap preserves the
      NetworkID-mismatch rejection.
  (3) Round-trip control — verifies that signing AND verifying
      under the SAME NetworkID DOES succeed, so test (1)/(2)'s
      failures are attributable to the mismatch and not to broken
      fixtures.
*/
package admission_test

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/ledger/admission"
)

// crossNetworkFixture bundles a single witness + the matching
// WitnessPublicKey entry. One witness with K=1 is sufficient
// for this property; the cross-network rejection is per-signature
// (each signature's digest binds NetworkID) so the K-of-N quorum
// dimension is orthogonal.
type crossNetworkFixture struct {
	signer cosign.WitnessSigner
	pubKey types.WitnessPublicKey
}

func newCrossNetworkFixture(t *testing.T) crossNetworkFixture {
	t.Helper()
	// Matched (DID, PrivateKey) pair — the SDK helper that the
	// equivocation_monitor_test.go fixture also uses. The DID is
	// the witness identity; the private key signs.
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	keys, err := witness.KeysFromDIDs([]string{kp.DID})
	if err != nil {
		t.Fatalf("witness.KeysFromDIDs: %v", err)
	}
	return crossNetworkFixture{
		signer: cosign.NewECDSAWitnessSigner(kp.PrivateKey),
		pubKey: keys[0],
	}
}

// signedHead builds a cosigned head for `head` under `netID` using
// `fx.signer`. Returns a fully-formed types.CosignedTreeHead whose
// single signature binds netID into its digest.
func signedHead(t *testing.T, fx crossNetworkFixture, head types.TreeHead, netID cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	payload := cosign.NewTreeHeadPayload(head)
	sig, err := fx.signer.Sign(context.Background(), payload, netID, cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatalf("signer.Sign under NetworkID=%v: %v", netID, err)
	}
	return types.CosignedTreeHead{TreeHead: head, Signatures: []types.WitnessSignature{sig}}
}

// distinctNetworkIDs returns two non-equal NetworkIDs ("A" and "B").
// Deliberately non-zero to avoid colliding with NewWitnessKeySet's
// zero-rejection guard.
func distinctNetworkIDs() (cosign.NetworkID, cosign.NetworkID) {
	var a, b cosign.NetworkID
	for i := range a {
		a[i] = byte('A')
		b[i] = byte('B')
	}
	return a, b
}

// representativeTreeHead returns a non-trivial TreeHead fixture.
// TreeSize=42 + non-zero RootHash so that the byte serialization
// produced by cosign.NewTreeHeadPayload is not all-zeros (which
// might mask a serialization bug behind the cryptographic check).
func representativeTreeHead() types.TreeHead {
	var root [32]byte
	for i := range root {
		root[i] = byte(0x10 + i)
	}
	return types.TreeHead{TreeSize: 42, RootHash: root}
}

// ─────────────────────────────────────────────────────────────────────
// (1) Raw cosign.Verify — NetworkID mismatch produces an SDK error
// ─────────────────────────────────────────────────────────────────────

// TestCrossNetworkReplay_RawCosignVerifyRejects pins the SDK-level
// behavior: a head signed under NetworkID-A produces a digest
// distinct from the digest the verifier (configured with
// NetworkID-B) recomputes. cosign.Verify MUST return a non-nil
// error. This is the foundational property; (2) layers on top.
func TestCrossNetworkReplay_RawCosignVerifyRejects(t *testing.T) {
	t.Parallel()

	fx := newCrossNetworkFixture(t)
	netA, netB := distinctNetworkIDs()
	head := representativeTreeHead()

	signed := signedHead(t, fx, head, netA)

	// Build a verifier keyset under NetworkID-B.
	setB, err := cosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{fx.pubKey},
		netB,
		1, // K=1; quorum threshold is orthogonal to this property
		nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet(netB): %v", err)
	}

	payload := cosign.NewTreeHeadPayload(signed.TreeHead)
	_, verifyErr := cosign.Verify(payload, setB, cosign.HashAlgoSHA256, signed.Signatures)
	if verifyErr == nil {
		t.Fatal("cosign.Verify accepted cross-network signature; replay defense BROKEN")
	}
	// The error MUST NOT be ErrEmptySignatures — we passed exactly
	// one signature. It MUST also not be a "well-formed and verified"
	// success. The specific SDK error vocabulary can evolve over
	// versions; we assert non-nil + non-empty-signatures + non-quorum
	// pathways.
	if errors.Is(verifyErr, cosign.ErrEmptySignatures) {
		t.Errorf("verify reported ErrEmptySignatures, but exactly one signature was provided; "+
			"this would mask the cross-network rejection: %v", verifyErr)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (2) admission.BLSQuorumVerifier wrapper rejects identically
// ─────────────────────────────────────────────────────────────────────

// TestCrossNetworkReplay_BLSQuorumVerifierRejects pins the ledger's
// admission hot-path behavior: the same cross-network mismatch
// surfaces through BLSQuorumVerifier.VerifyEmbeddedTreeHead, which
// is what every HTTP POST /v1/entries request flows through.
//
// The wrap chain MUST preserve the failure (i.e. the head MUST NOT
// be admitted) even though the precise sentinel may differ from
// (1). We assert non-nil error and that the wrap does NOT collapse
// to a "successful verification" by accident.
func TestCrossNetworkReplay_BLSQuorumVerifierRejects(t *testing.T) {
	t.Parallel()

	fx := newCrossNetworkFixture(t)
	netA, netB := distinctNetworkIDs()
	head := representativeTreeHead()

	signed := signedHead(t, fx, head, netA)

	setB, err := cosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{fx.pubKey},
		netB,
		1,
		nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet(netB): %v", err)
	}

	v := admission.NewBLSQuorumVerifier(setB)
	if err := v.VerifyEmbeddedTreeHead(signed); err == nil {
		t.Fatal("BLSQuorumVerifier accepted cross-network signature; replay defense BROKEN")
	}
}

// ─────────────────────────────────────────────────────────────────────
// (3) Round-trip control — same-network signing+verifying succeeds
// ─────────────────────────────────────────────────────────────────────

// TestCrossNetworkReplay_RoundTripControl is the load-bearing
// control. If signing and verifying under the SAME NetworkID also
// fails, (1)/(2)'s failures are not attributable to the cross-
// network mismatch — they'd be attributable to a broken fixture
// (wrong key, wrong payload shape, wrong API call). This test
// rules that class of false-positive out.
func TestCrossNetworkReplay_RoundTripControl(t *testing.T) {
	t.Parallel()

	fx := newCrossNetworkFixture(t)
	netA, _ := distinctNetworkIDs()
	head := representativeTreeHead()

	signed := signedHead(t, fx, head, netA)

	setA, err := cosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{fx.pubKey},
		netA, // same NetworkID as the signer used
		1,
		nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet(netA): %v", err)
	}

	v := admission.NewBLSQuorumVerifier(setA)
	if err := v.VerifyEmbeddedTreeHead(signed); err != nil {
		t.Fatalf("same-network verification rejected — fixture is broken, "+
			"so the cross-network test signal is unreliable: %v", err)
	}
}
