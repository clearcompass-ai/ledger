/*
FILE PATH: admission/v011_contract_test.go

v0.1.1 SDK alignment contract tests for the admission layer.

# WHAT THIS PINS

Three load-bearing properties of the v0.1.1 break:

 1. *cosign.WitnessKeySet is the single boot-time topology object —
    keys, NetworkID, K-of-N quorum, BLS verifier all live inside it.
    The admission BLSQuorumVerifier accepts ONE such object; the
    previous (keys, K, networkID, blsVerifier) parameter group + the
    StaticWitnessKeySet wrapper are gone.

 2. The SDK's findings.WitnessAttested interface requires
    Verify(set *cosign.WitnessKeySet) error. Any finding satisfying
    WitnessAttested can be verified against the same keyset the
    BLSQuorumVerifier holds — i.e., the ledger and the SDK agree on
    the topology object passed across the boundary.

 3. The wrap chain preserves both ErrWitnessQuorumInsufficient
    (ledger sentinel for HTTP 401 dispatch) AND the underlying SDK
    cause (cosign.ErrEmptySignatures, cosign.ErrQuorumNotReached,
    etc.) so callers can errors.Is on either.

# WHY A SEPARATE FILE

bls_quorum_verifier_test.go pins the local construction contract;
this file pins the cross-package alignment with the SDK's v0.1.1
interfaces. Keeping them separate means a regression in the
admission shape (renaming a field, dropping the wrap) shows up as
THIS file failing — distinguishable in CI from a regression in the
local-only behavior tested by the sibling file.
*/
package admission_test

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/ledger/admission"
)

// TestV011_KeysetIsSingleBootObject confirms the boot-time
// keyset that the ledger constructs and hands to BOTH admission
// and gossipnet is a single *cosign.WitnessKeySet — not two
// duplicates with possibly-divergent topology. This is the
// load-bearing property that makes the v0.1.1 break valuable:
// one source of truth for K, N, NetworkID, BLS verifier.
func TestV011_KeysetIsSingleBootObject(t *testing.T) {
	t.Parallel()

	witKey := types.WitnessPublicKey{}
	witKey.ID[0] = 0x42
	witKey.PublicKey = []byte{0x04, 1, 2, 3}

	var nid cosign.NetworkID
	nid[0] = 0xCC

	set, err := cosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{witKey},
		nid,
		1, // K=1
		nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	// Same set is consumable by the admission verifier and (in
	// the gossipnet package) by EquivocationMonitor. Here we
	// just confirm the admission side accepts it.
	v := admission.NewBLSQuorumVerifier(set)
	if v == nil {
		t.Fatal("BLSQuorumVerifier rejected the keyset")
	}

	// Topology readouts MUST match what the ledger configured.
	if got := set.Quorum(); got != 1 {
		t.Errorf("set.Quorum() = %d, want 1", got)
	}
	if got := set.Size(); got != 1 {
		t.Errorf("set.Size() = %d, want 1", got)
	}
	if got := set.NetworkID(); got != nid {
		t.Errorf("set.NetworkID() = %x, want %x", got, nid)
	}
}

// TestV011_FindingSatisfiesWitnessAttested is a compile-time +
// runtime check that the SDK's *findings.EquivocationFinding
// satisfies findings.WitnessAttested. If the SDK ever drops or
// renames the interface, this file fails to compile — surfacing
// the break at the right place (the cross-package contract) in
// a way that the ledger maintainer can act on before code that
// dispatches over the interface reaches the cluster.
func TestV011_FindingSatisfiesWitnessAttested(t *testing.T) {
	t.Parallel()

	// Compile-time: the assignment below fails to build if
	// *EquivocationFinding does not satisfy WitnessAttested.
	var _ findings.WitnessAttested = (*findings.EquivocationFinding)(nil)

	// Runtime: construct a structurally-valid finding and observe
	// that its Verify(set) method exists and is callable through
	// the interface (not just through the concrete type). A nil
	// keyset is supplied — Verify rejects with a typed error
	// rather than running real crypto. The point is to exercise
	// the interface dispatch path.
	finding, err := findings.NewEquivocationFinding(
		witness.EquivocationProof{
			TreeSize: 1,
			HeadA: types.CosignedTreeHead{
				TreeHead: types.TreeHead{TreeSize: 1, RootHash: [32]byte{0xAA}},
				Signatures: []types.WitnessSignature{
					{PubKeyID: [32]byte{1}, SigBytes: []byte{0xCA, 0xFE}, SchemeTag: 1},
				},
			},
			HeadB: types.CosignedTreeHead{
				TreeHead: types.TreeHead{TreeSize: 1, RootHash: [32]byte{0xBB}},
				Signatures: []types.WitnessSignature{
					{PubKeyID: [32]byte{1}, SigBytes: []byte{0xDE, 0xAD}, SchemeTag: 1},
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

	var iface findings.WitnessAttested = finding
	if err := iface.Verify(nil); err == nil {
		t.Error("interface dispatch on Verify(nil) returned nil; want typed rejection")
	}
}

// TestV011_WrapChainPreservesBothSentinels confirms the
// admission wrapper preserves both errors in the unwrap chain.
// HTTP dispatch lives on ErrWitnessQuorumInsufficient; cause
// diagnostics live on the underlying cosign sentinel. A
// regression to single-%w (or %v on the cause) silently breaks
// the diagnostic path.
func TestV011_WrapChainPreservesBothSentinels(t *testing.T) {
	t.Parallel()

	witKey := types.WitnessPublicKey{}
	witKey.ID[0] = 1
	witKey.PublicKey = []byte{0x04, 1, 2, 3}

	set, err := cosign.NewWitnessKeySet(
		[]types.WitnessPublicKey{witKey},
		cosign.NetworkID{1}, 1, nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	v := admission.NewBLSQuorumVerifier(set)

	// Empty signatures → ErrEmptySignatures inside cosign.Verify
	// → wrapped by the admission layer with ErrWitnessQuorumInsufficient.
	err = v.VerifyEmbeddedTreeHead(types.CosignedTreeHead{})
	if err == nil {
		t.Fatal("Verify on empty sigs returned nil; want quorum rejection")
	}
	if !errors.Is(err, admission.ErrWitnessQuorumInsufficient) {
		t.Errorf("err = %v; missing ErrWitnessQuorumInsufficient", err)
	}
	if !errors.Is(err, cosign.ErrEmptySignatures) {
		t.Errorf("err = %v; missing cosign.ErrEmptySignatures cause through wrap chain", err)
	}
}
