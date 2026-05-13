/*
FILE PATH: witnessclient/rotation_cross_network_test.go

Cross-network replay defense for witness rotations at the
RotationHandler boundary.

# PROPERTY UNDER TEST

A types.WitnessRotation signed under NetworkID="jurisdiction-A"
MUST be rejected by a RotationHandler whose current witness set
is bound to NetworkID="jurisdiction-B". The audit-flagged Trust
Alignment #11 invariant (Cryptographic Domain Separation)
applied at the rotation path — the most security-critical
operation on the network: a forged rotation that admits a
peer-network's quorum as our own would let auditors verify
signatures from witnesses we never authorized.

# WHY HERE, NOT ONLY IN THE SDK

The SDK's tests/witness_rotation_finding_verify_test.go pins the
property at the FINDING surface. This test pins it at the LEDGER
boundary — RotationHandler.ProcessRotation, which is the
function we'll call from admin paths + inbound gossip handlers.
A regression that drops Verify from ProcessRotation's path (e.g.,
a future refactor that "optimizes" the verify step away) fails
loudly here, distinguishable in CI output from a SDK-side
regression.

The test deliberately uses a nil *pgxpool.Pool: Verify runs
BEFORE the DB write in ProcessRotation's load-bearing ordering.
A rotation that fails verification must never reach the database;
if a regression reorders the steps and tries the DB first, the
nil-pool nil-pointer dereference surfaces as a panic.
*/
package witnessclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/ledger/witnessclient"
)

// ─────────────────────────────────────────────────────────────────────
// Helpers — mirror the SDK's tests/witness_rotation_helpers_test.go
// shape. Replicated here because the SDK's tests/ helpers are
// internal-test-package and not importable.
// ─────────────────────────────────────────────────────────────────────

// netID returns a non-zero NetworkID with every byte set to b.
// Two distinct values produce two distinct NetworkIDs.
func netID(b byte) cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = b
	}
	return n
}

// freshKeys generates n witness keys + matching private keys.
func freshKeys(t *testing.T, n int) ([]types.WitnessPublicKey, []*ecdsa.PrivateKey) {
	t.Helper()
	keys := make([]types.WitnessPublicKey, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("freshKeys[%d]: %v", i, err)
		}
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		id := sha256.Sum256(pubBytes)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}
		privs[i] = priv
	}
	return keys, privs
}

// buildValidRotation creates a rotation signed under the OLD set's
// private keys, against the supplied NetworkID. Mirrors the SDK's
// tests/witness_rotation_helpers_test.go::buildValidRotation. The
// rotation is dual-sign-clean (SchemeTagOld == SchemeTagNew == ECDSA),
// so the SDK Verify's Step 5 dual-sign branch is skipped — placeholder
// NewSignatures satisfy Validate's non-empty check without contributing
// to the cryptographic verdict.
func buildValidRotation(
	t *testing.T,
	setSize, sigCount, newSetSize int,
	signedUnderNetwork cosign.NetworkID,
) (currentKeys []types.WitnessPublicKey, rotation types.WitnessRotation) {
	t.Helper()
	currentKeys, currentPrivs := freshKeys(t, setSize)
	newKeys, _ := freshKeys(t, newSetSize)
	setHash := witness.ComputeSetHash(currentKeys)
	newSetHash := witness.ComputeSetHash(newKeys)

	payload := cosign.NewRotationPayloadSHA256(newSetHash)
	sigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sigBytes, err := cosign.SignECDSA(payload, signedUnderNetwork, cosign.HashAlgoSHA256, currentPrivs[i])
		if err != nil {
			t.Fatalf("SignECDSA rotation[%d]: %v", i, err)
		}
		sigs[i] = types.WitnessSignature{
			PubKeyID:  currentKeys[i].ID,
			SchemeTag: signatures.SchemeECDSA,
			SigBytes:  sigBytes,
		}
	}

	// Placeholder NewSignatures — same-scheme rotation skips Step 5
	// dual-sign verification, but the finding's Validate requires
	// non-empty NewSignatures.
	var placeholderID [32]byte
	for i := range placeholderID {
		placeholderID[i] = 0xEE
	}
	newSigs := []types.WitnessSignature{
		{PubKeyID: placeholderID, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xAA}},
	}

	rotation = types.WitnessRotation{
		CurrentSetHash:    setHash,
		NewSet:            newKeys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: sigs,
		SchemeTagNew:      signatures.SchemeECDSA,
		NewSignatures:     newSigs,
	}
	return currentKeys, rotation
}

// ─────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────

// TestRotationHandler_CrossNetworkReplay_Rejects pins the load-
// bearing property: a rotation signed under Network-A's NetworkID
// MUST fail RotationHandler.ProcessRotation when the handler's
// current witness set is bound to Network-B's NetworkID. The
// rejection happens in the SDK Verify step (no DB write, no
// emit), so we can run the test with a nil *pgxpool.Pool — if a
// regression reorders the verify-before-persist invariant and
// tries the DB first, the test surfaces as a nil-pointer panic.
func TestRotationHandler_CrossNetworkReplay_Rejects(t *testing.T) {
	t.Parallel()

	const K, N = 2, 3
	netA := netID('A')
	netB := netID('B')

	// Build a valid rotation signed under Network-A's NetworkID.
	currentKeys, rotation := buildValidRotation(t, N, K, N, netA)

	// Handler holds a WitnessKeySet bound to Network-B's NetworkID
	// — the keys match the rotation's OLD set, but the NetworkID
	// is the wrong jurisdiction. The cryptographic domain-
	// separation invariant should refuse the rotation.
	setB, err := cosign.NewWitnessKeySet(currentKeys, netB, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet[netB]: %v", err)
	}
	rh := witnessclient.NewRotationHandler(
		nil, // *pgxpool.Pool — load-bearing nil; the test asserts
		// the verify rejection short-circuits before any DB write.
		setB,
		signatures.SchemeECDSA,
		"https://ledger.example/", // LedgerEndpoint
		nil,                       // logger → default
	)

	// Capture emit attempts so we can assert the emitter is NEVER
	// invoked on a rotation that fails Verify.
	cap := &countingEmitter{}
	rh.WithEmitter(cap)

	newSet, err := rh.ProcessRotation(context.Background(), rotation)
	if err == nil {
		t.Fatal("ProcessRotation accepted cross-network rotation — domain separation BROKEN")
	}
	if newSet != nil {
		t.Errorf("expected nil newSet on verify failure, got %v", newSet)
	}
	// The error MUST come from the verify step. The wrap shape is
	// "witness/rotation: verify: ...". A regression that catches
	// the error after DB-write would surface as a different wrap.
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("err = %v, want substring 'verify' (failure must surface from the Verify step)", err)
	}
	// Emitter MUST NOT fire on verify failure. The handler's
	// step ordering pin: verify-before-emit.
	if cap.calls != 0 {
		t.Errorf("emitter fired %d times on verify-failed rotation; want 0 (verify-before-emit invariant)", cap.calls)
	}
}

// TestRotationHandler_SameNetwork_AcceptControl is the load-
// bearing control: if signing AND verifying under the SAME
// NetworkID also fails, the cross-network test's failure isn't
// attributable to the network mismatch — it would be a broken
// fixture. This test rules that class of false-positive out by
// exercising the SDK finding's Verify directly (which is the
// step ProcessRotation calls internally). We don't drive the
// handler's full hot path here because the downstream DB step
// would deref the unit-test environment's nil *pgxpool.Pool.
func TestRotationHandler_SameNetwork_AcceptControl(t *testing.T) {
	t.Parallel()

	const K, N = 2, 3
	netA := netID('A')

	currentKeys, rotation := buildValidRotation(t, N, K, N, netA)

	setA, err := cosign.NewWitnessKeySet(currentKeys, netA, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet[netA]: %v", err)
	}

	// Drive Verify directly — the exact call ProcessRotation makes
	// at rotation_handler.go::Step 2. If THIS rejects the fixture,
	// the cross-network test's "verify rejected" signal isn't
	// attributable to the network mismatch.
	finding, err := findings.NewWitnessRotationFinding(rotation, "https://ledger.example/")
	if err != nil {
		t.Fatalf("NewWitnessRotationFinding: %v", err)
	}
	if err := finding.Verify(setA); err != nil {
		t.Fatalf("same-network Verify rejected the fixture — "+
			"cross-network test signal is unreliable: %v", err)
	}
}

// countingEmitter records every Emit call. Used to assert the
// emit-after-verify-after-persist invariant in
// TestRotationHandler_CrossNetworkReplay_Rejects.
type countingEmitter struct {
	calls int
}

func (c *countingEmitter) Emit(_ context.Context, _ *findings.WitnessRotationFinding) {
	c.calls++
}

var _ witnessclient.WitnessRotationEmitter = (*countingEmitter)(nil)
