/*
Tests for StaticWitnessKeySet + BLSQuorumVerifier wiring contract.

# WHAT THIS PINS

The R1 audit revealed BLSQuorumVerifier was constructed in code
but unwired — defined in admission/bls_quorum_verifier.go,
referenced only from a test. The cmd/operator/main.go wiring
was missing.

These tests pin the construction contract end-to-end:

  1. StaticWitnessKeySet rejects empty keys / bad K.
  2. StaticWitnessKeySet's Active() returns a defensive copy
     (caller can't mutate authoritative state).
  3. BLSQuorumVerifier.VerifyEntry on a non-embedding entry is a
     no-op — confirms the verifier accepts the v7.75 entry surface
     without spurious rejections.

# WHAT THIS DOES NOT PIN

Running cosign.Verify against real K-of-N witness signatures
on a synthetic CosignedTreeHead would duplicate the SDK's
cosign tests. The wiring contract is what's operator-side; the
crypto path is the SDK's responsibility.
*/
package admission_test

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/admission"
)

func TestStaticWitnessKeySet_RejectsEmptyKeys(t *testing.T) {
	_, err := admission.NewStaticWitnessKeySet(nil, 1)
	if err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Errorf("err = %v, want non-empty rejection", err)
	}
}

func TestStaticWitnessKeySet_RejectsBadQuorum(t *testing.T) {
	keys := []types.WitnessPublicKey{{ID: [32]byte{1}}}
	if _, err := admission.NewStaticWitnessKeySet(keys, 0); err == nil {
		t.Error("err = nil for K=0; want rejection")
	}
	if _, err := admission.NewStaticWitnessKeySet(keys, 2); err == nil {
		t.Error("err = nil for K=2 with len(keys)=1; want impossible-quorum rejection")
	}
}

func TestStaticWitnessKeySet_ActiveReturnsCopy(t *testing.T) {
	original := []types.WitnessPublicKey{
		{ID: [32]byte{1}}, {ID: [32]byte{2}},
	}
	set, err := admission.NewStaticWitnessKeySet(original, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, k, err := set.Active()
	if err != nil {
		t.Fatal(err)
	}
	if k != 1 {
		t.Errorf("quorumK = %d, want 1", k)
	}
	if len(got) != 2 {
		t.Errorf("len(active) = %d, want 2", len(got))
	}
	// Defensive copy: mutating the returned slice doesn't affect
	// subsequent Active() calls.
	got[0].ID[0] = 0xFF
	got2, _, _ := set.Active()
	if got2[0].ID[0] != 1 {
		t.Errorf("Active() returned aliased slice — caller mutation visible: got2[0]=%v",
			got2[0])
	}
}

func TestBLSQuorumVerifier_NoOpOnNonEmbeddingEntry(t *testing.T) {
	// EntryEmbedsTreeHead returns false for every v7.75 schema
	// today. Construct a verifier and an entry, confirm
	// VerifyEntry returns nil — the chain check is a no-op
	// without an embedded tree head.
	keys := []types.WitnessPublicKey{{ID: [32]byte{1}}}
	keySet, err := admission.NewStaticWitnessKeySet(keys, 1)
	if err != nil {
		t.Fatal(err)
	}
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	v := admission.NewBLSQuorumVerifier(
		keySet,
		cosign.NewProductionBLSVerifier(),
		nid,
	)

	// Entry with no commitment-tree-head embedding (the v7.75
	// commitment-entry surface). EntryEmbedsTreeHead → false →
	// VerifyEntry no-op.
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID: "did:web:test.example",
		},
		DomainPayload: []byte(`{"schema_id":"pre-grant-commitment-v1"}`),
	}
	if err := v.VerifyEntry(entry); err != nil {
		t.Errorf("VerifyEntry on non-embedding entry returned err = %v, want nil", err)
	}
}

func TestBLSQuorumVerifier_NilEntryNoOp(t *testing.T) {
	keys := []types.WitnessPublicKey{{ID: [32]byte{1}}}
	keySet, _ := admission.NewStaticWitnessKeySet(keys, 1)
	var nid cosign.NetworkID
	nid[0] = 1
	v := admission.NewBLSQuorumVerifier(keySet, cosign.NewProductionBLSVerifier(), nid)
	if err := v.VerifyEntry(nil); err != nil {
		t.Errorf("VerifyEntry(nil) = %v, want nil", err)
	}
}
