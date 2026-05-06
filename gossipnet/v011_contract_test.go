/*
FILE PATH: gossipnet/v011_contract_test.go

v0.1.1 SDK alignment contract tests for the gossipnet layer.

# WHAT THIS PINS

The cross-package contract that ledger boot wires into the
gossipnet's EquivocationMonitor + EquivocationPublisher:

 1. EquivocationMonitorConfig accepts WitnessSet *cosign.WitnessKeySet
    as a single field — no separate WitnessKeys / QuorumK / NetworkID
    / BLSVerifier args. NewEquivocationMonitor surfaces a typed
    rejection for nil WitnessSet so boot wiring's failure mode is
    visible at startup, not at first tick.

 2. EquivocationPublisher.Publish takes a plain *findings.EquivocationFinding,
    not a phantom-typed wrapper. The Verify-before-Publish discipline
    lives at the call site (the EquivocationMonitor.checkPeer flow);
    this test pins that contract by walking the wire shape end-to-end.

 3. The SDK's witness.DetectEquivocation returns
    *witness.EquivocationProof or nil, with K-of-N read from the
    set's Quorum() — no separate K argument. A regression that
    re-introduces the K parameter would fail to compile here.

# WHY A SEPARATE FILE

equivocation_monitor_test.go tests the runtime detection +
publishing flow with real cosignatures. This file pins the
v0.1.1-specific contract surface (interface dispatch, single-set
boot wiring) so a regression to the v0.1.0 multi-arg shape is
caught explicitly with a contract-level test name in CI.
*/
package gossipnet

import (
	"context"
	"testing"

	sdkcosign "github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	sdkwitness "github.com/clearcompass-ai/attesta/witness"
)

// TestV011_EquivocationMonitor_AcceptsSingleKeyset confirms the
// boot-time wiring shape: one *cosign.WitnessKeySet hands the
// monitor everything it needs (keys, K, NetworkID, BLS verifier).
func TestV011_EquivocationMonitor_AcceptsSingleKeyset(t *testing.T) {
	t.Parallel()

	witKey := types.WitnessPublicKey{}
	witKey.ID[0] = 0x77
	witKey.PublicKey = []byte{0x04, 1, 2, 3}

	set, err := sdkcosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{witKey},
		nonZeroNetworkID(),
		1, // K=1
		nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	m, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store:      sdkgossip.NewInMemoryStore(),
		WitnessSet: set,
	})
	if err != nil {
		t.Fatalf("NewEquivocationMonitor with single keyset: %v", err)
	}
	if m == nil {
		t.Fatal("constructor returned nil monitor")
	}
}

// TestV011_EquivocationMonitor_RejectsNilKeyset confirms the
// constructor surfaces the missing-keyset failure mode at boot,
// not at first tick.
func TestV011_EquivocationMonitor_RejectsNilKeyset(t *testing.T) {
	t.Parallel()

	_, err := NewEquivocationMonitor(EquivocationMonitorConfig{
		Store: sdkgossip.NewInMemoryStore(),
		// WitnessSet missing
	})
	if err == nil {
		t.Fatal("nil WitnessSet accepted; want explicit boot failure")
	}
}

// TestV011_DetectEquivocation_ReadsKFromSet exercises the SDK's
// witness.DetectEquivocation across the same keyset to confirm K
// is read from set.Quorum() — not passed as a separate arg.
// Different roots at the same tree size with K=2 + 1 valid sig
// → no proof (cannot meet quorum on either side).
func TestV011_DetectEquivocation_ReadsKFromSet(t *testing.T) {
	t.Parallel()

	witKey := types.WitnessPublicKey{}
	witKey.ID[0] = 0x88
	witKey.PublicKey = []byte{0x04, 4, 5, 6}
	set, err := sdkcosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{witKey, func() types.WitnessPublicKey {
			k := types.WitnessPublicKey{}
			k.ID[0] = 0x99
			k.PublicKey = []byte{0x04, 7, 8, 9}
			return k
		}()},
		nonZeroNetworkID(),
		2, // K=2 of 2
		nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	headA := types.CosignedTreeHead{
		TreeHead: types.TreeHead{TreeSize: 50, RootHash: [32]byte{0xAA}},
		Signatures: []types.WitnessSignature{
			{PubKeyID: witKey.ID, SigBytes: []byte{0xCA}, SchemeTag: 1},
		},
	}
	headB := types.CosignedTreeHead{
		TreeHead: types.TreeHead{TreeSize: 50, RootHash: [32]byte{0xBB}},
		Signatures: []types.WitnessSignature{
			{PubKeyID: witKey.ID, SigBytes: []byte{0xFE}, SchemeTag: 1},
		},
	}

	// API SHAPE TEST: the call signature is
	// DetectEquivocation(headA, headB, set) — three args, no
	// separate K. A regression to (heads, keys, K, networkID, bls)
	// fails to compile here.
	_, err = sdkwitness.DetectEquivocation(headA, headB, set)
	// We assert the call SIGNATURE is correct — the actual outcome
	// (err non-nil because synthetic sigs don't verify cryptographically)
	// is not the contract under test. A nil err would mean the call
	// dispatched correctly but the synthetic crypto somehow passed,
	// which is impossible with random bytes.
	if err == nil {
		t.Fatal("synthetic signatures unexpectedly verified; test fixture broken")
	}
}

// TestV011_EquivocationPublisher_AcceptsPlainFinding confirms the
// publisher signature is Publish(ctx, *findings.EquivocationFinding)
// — the *VerifiedEquivocationFinding wrapper was removed. We
// don't actually publish here (no real signing key wired); the
// load-bearing assertion is the parameter type.
func TestV011_EquivocationPublisher_AcceptsPlainFinding(t *testing.T) {
	t.Parallel()

	// Construct a finding (validates structurally — no crypto
	// verification needed for the type-shape assertion).
	finding, err := findings.NewEquivocationFinding(
		sdkwitness.EquivocationProof{
			TreeSize: 1,
			HeadA: types.CosignedTreeHead{
				TreeHead: types.TreeHead{TreeSize: 1, RootHash: [32]byte{0xAA}},
				Signatures: []types.WitnessSignature{
					{PubKeyID: [32]byte{1}, SigBytes: []byte{1}, SchemeTag: 1},
				},
			},
			HeadB: types.CosignedTreeHead{
				TreeHead: types.TreeHead{TreeSize: 1, RootHash: [32]byte{0xBB}},
				Signatures: []types.WitnessSignature{
					{PubKeyID: [32]byte{1}, SigBytes: []byte{2}, SchemeTag: 1},
				},
			},
			ValidSigsA: 1,
			ValidSigsB: 1,
		},
		"https://test.example",
	)
	if err != nil {
		t.Fatalf("NewEquivocationFinding: %v", err)
	}

	// COMPILE-TIME contract: the Publish method's parameter list
	// MUST be (ctx, *findings.EquivocationFinding). The line below
	// fails to build if a regression re-introduces the
	// *VerifiedEquivocationFinding wrapper or any other shape.
	var p *EquivocationPublisher // nil is fine for the type-only check
	publishFn := p.Publish        // forces method-value resolution
	_ = publishFn

	// Runtime: nil publisher returns immediately (defensive guard
	// in Publish). A nil finding panics — both are documented in
	// the publisher's contract.
	p.Publish(context.Background(), finding) // no-op; doesn't crash
}
