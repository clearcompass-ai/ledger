/*
FILE PATH: admission/bls_quorum_verifier_test.go

Tests for the BLSQuorumVerifier wiring contract.

# WHAT THIS PINS

The cmd/ledger/main.go wiring + LEDGER_WITNESS_QUORUM_K env-var
injection is mandatory; these tests pin the contract:

 1. NewBLSQuorumVerifier with a valid *cosign.WitnessKeySet
    constructs cleanly.
 2. VerifyEntry on a non-embedding entry is a no-op — confirms
    the verifier accepts the entry surface (commitment-entry
    schemas) without spurious rejections.
 3. VerifyEntry(nil) is a no-op — admission may dispatch over a
    pool of entries some of which are filtered upstream.
 4. VerifyEmbeddedTreeHead with no signatures rejects with
    ErrWitnessQuorumInsufficient (wraps cosign.ErrEmptySignatures).
 5. A nil verifier value rejects rather than panicking — defends
    against accidental construction-without-wiring.
 6. A verifier with a nil set rejects with
    ErrWitnessKeySetUnavailable — the construction-time invariant
    leaks correctly to the call site if it's violated.

# WHAT THIS DOES NOT PIN

Running cosign.Verify against real K-of-N witness signatures on
a synthetic CosignedTreeHead would duplicate the SDK's cosign
tests (TestVerify_QuorumReached, TestVerify_QuorumFailure_*).
The wiring contract is what's ledger-side; the crypto path is
the SDK's responsibility.

# SDK ALIGNMENT

The SDK's *cosign.WitnessKeySet encapsulates keys + NetworkID +
quorum + BLS verifier. Tests construct the keyset directly via
cosign.NewWitnessKeySet — the same path cmd/ledger/main.go uses.
*/
package admission_test

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/admission"
)

// testNetworkID returns a non-zero NetworkID so cosign.NewWitnessKeySet
// accepts the construction. The exact bytes don't matter — these
// tests don't exercise the crypto path.
func testNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	return nid
}

// testWitnessKey returns a synthetic WitnessPublicKey with a
// distinguishable ID. The PublicKey bytes are non-zero but
// otherwise meaningless — these tests don't run cosign.Verify
// against real signatures.
func testWitnessKey(id byte) types.WitnessPublicKey {
	var k types.WitnessPublicKey
	k.ID[0] = id
	k.PublicKey = []byte{0x04, id, id, id} // 0x04 prefix matches uncompressed form
	return k
}

func TestNewBLSQuorumVerifier_ConstructsWithValidKeySet(t *testing.T) {
	t.Parallel()
	keys := []types.WitnessPublicKey{testWitnessKey(1)}
	set, err := cosign.NewWitnessKeySet(keys, testNetworkID(), 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	v := admission.NewBLSQuorumVerifier(set)
	if v == nil {
		t.Fatal("NewBLSQuorumVerifier returned nil")
	}
}

func TestVerifyEntry_NoOpOnNonEmbeddingEntry(t *testing.T) {
	t.Parallel()
	// EntryEmbedsTreeHead returns false for every schema today.
	// Construct a verifier and a commitment-shape entry, confirm
	// VerifyEntry returns nil — the chain check is a no-op
	// without an embedded tree head.
	keys := []types.WitnessPublicKey{testWitnessKey(1)}
	set, err := cosign.NewWitnessKeySet(keys, testNetworkID(), 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	v := admission.NewBLSQuorumVerifier(set)

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

func TestVerifyEntry_NilEntryNoOp(t *testing.T) {
	t.Parallel()
	keys := []types.WitnessPublicKey{testWitnessKey(1)}
	set, _ := cosign.NewWitnessKeySet(keys, testNetworkID(), 1, nil)
	v := admission.NewBLSQuorumVerifier(set)
	if err := v.VerifyEntry(nil); err != nil {
		t.Errorf("VerifyEntry(nil) = %v, want nil", err)
	}
}

func TestVerifyEmbeddedTreeHead_EmptySigsRejected(t *testing.T) {
	t.Parallel()
	keys := []types.WitnessPublicKey{testWitnessKey(1)}
	set, err := cosign.NewWitnessKeySet(keys, testNetworkID(), 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	v := admission.NewBLSQuorumVerifier(set)

	// Zero CosignedTreeHead → zero signatures. cosign.Verify
	// surfaces this as ErrEmptySignatures, which the verifier
	// maps to ErrWitnessQuorumInsufficient. We assert on the
	// LEDGER-side sentinel because that's what the HTTP layer
	// dispatches on.
	err = v.VerifyEmbeddedTreeHead(types.CosignedTreeHead{})
	if err == nil {
		t.Fatal("VerifyEmbeddedTreeHead(zero) returned nil; want quorum-insufficient")
	}
	if !errors.Is(err, admission.ErrWitnessQuorumInsufficient) {
		t.Errorf("err = %v; want errors.Is(.., ErrWitnessQuorumInsufficient)", err)
	}
	// And the SDK cause is preserved through the wrap chain.
	if !errors.Is(err, cosign.ErrEmptySignatures) {
		t.Errorf("err = %v; want errors.Is(.., cosign.ErrEmptySignatures) preserved through wrap",
			err)
	}
}

func TestVerifyEmbeddedTreeHead_NilVerifierRejected(t *testing.T) {
	t.Parallel()
	var v *admission.BLSQuorumVerifier // nil
	err := v.VerifyEmbeddedTreeHead(types.CosignedTreeHead{})
	if err == nil {
		t.Fatal("nil verifier accepted call; want defensive rejection")
	}
}

func TestVerifyEmbeddedTreeHead_NilSetRejected(t *testing.T) {
	t.Parallel()
	// A verifier constructed with a nil keyset is caller error
	// (cmd/ledger/main.go wiring is supposed to fail at boot if
	// the keyset can't be built). This test pins that the
	// runtime check still surfaces a clean error rather than
	// panicking inside cosign.Verify.
	v := admission.NewBLSQuorumVerifier(nil)
	err := v.VerifyEmbeddedTreeHead(types.CosignedTreeHead{})
	if err == nil {
		t.Fatal("verifier with nil set accepted call; want unavailable rejection")
	}
	if !errors.Is(err, admission.ErrWitnessKeySetUnavailable) {
		t.Errorf("err = %v; want errors.Is(.., ErrWitnessKeySetUnavailable)", err)
	}
}
