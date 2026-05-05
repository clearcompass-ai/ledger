/*
FILE PATH: gossipnet/witness_keys_test.go

Round-trip tests for WitnessKeysFromDIDs. Confirms the resolved
PubKeyID matches what cosign.NewECDSAWitnessSigner derives — the
critical property: a signature produced under one path verifies
under the other.
*/
package gossipnet

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

func TestWitnessKeysFromDIDs_RoundTrip(t *testing.T) {
	// Generate a fresh did:key + signer pair. The SDK's
	// signer-side PubKeyID is the canonical reference; our
	// resolved PubKeyID must equal it.
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	signer := cosign.NewECDSAWitnessSigner(kp.PrivateKey)
	signerID := signer.PubKeyID()

	keys, err := WitnessKeysFromDIDs([]string{kp.DID})
	if err != nil {
		t.Fatalf("WitnessKeysFromDIDs: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
	if keys[0].ID != signerID {
		t.Errorf("resolved PubKeyID = %x, signer PubKeyID = %x (mismatch breaks verification)",
			keys[0].ID, signerID)
	}
	if len(keys[0].PublicKey) != 65 {
		t.Errorf("PublicKey length = %d, want 65 (uncompressed secp256k1)", len(keys[0].PublicKey))
	}
}

func TestWitnessKeysFromDIDs_MultipleDIDs(t *testing.T) {
	dids := make([]string, 0, 3)
	wantIDs := make([][32]byte, 0, 3)
	for i := 0; i < 3; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatal(err)
		}
		dids = append(dids, kp.DID)
		wantIDs = append(wantIDs,
			cosign.NewECDSAWitnessSigner(kp.PrivateKey).PubKeyID())
	}
	keys, err := WitnessKeysFromDIDs(dids)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("len(keys) = %d, want 3", len(keys))
	}
	for i, k := range keys {
		if k.ID != wantIDs[i] {
			t.Errorf("keys[%d].ID mismatch", i)
		}
	}
}

func TestWitnessKeysFromDIDs_RejectsDuplicate(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	_, err := WitnessKeysFromDIDs([]string{kp.DID, kp.DID})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("err = %v, want duplicate-rejection", err)
	}
}

func TestWitnessKeysFromDIDs_RejectsEmpty(t *testing.T) {
	if _, err := WitnessKeysFromDIDs(nil); err == nil {
		t.Error("err = nil; want empty-list rejection")
	}
	if _, err := WitnessKeysFromDIDs([]string{""}); err == nil {
		t.Error("err = nil; want empty-DID rejection")
	}
}

func TestWitnessKeysFromDIDs_RejectsBadDID(t *testing.T) {
	_, err := WitnessKeysFromDIDs([]string{"did:web:example.com"})
	if err == nil || !strings.Contains(err.Error(), "ParseDIDKey") {
		t.Errorf("err = %v, want ParseDIDKey rejection (did:web not supported)", err)
	}
}
