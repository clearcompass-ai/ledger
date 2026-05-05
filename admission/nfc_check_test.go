package admission

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// nfdEAcute is the precomposed NFC form of "é" expressed as the NFD
// decomposition: "e" (U+0065) followed by combining acute accent
// (U+0301). Visually identical to the NFC form "é" but byte-
// distinct, which is exactly the case CheckNFC must reject.
const nfdEAcute = "é"

func nfcEntry() *envelope.Entry {
	return &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   "did:web:alice.example",
			Destination: "did:web:log.example",
		},
	}
}

func TestCheckNFC_HappyPath(t *testing.T) {
	if err := CheckNFC(nfcEntry()); err != nil {
		t.Fatalf("NFC entry rejected: %v", err)
	}
}

func TestCheckNFC_RejectsNFDSignerDID(t *testing.T) {
	e := nfcEntry()
	e.Header.SignerDID = "did:web:caf" + nfdEAcute + ".example"
	if err := CheckNFC(e); !errors.Is(err, ErrIngressNotNFC) {
		t.Fatalf("NFD SignerDID accepted: %v", err)
	}
}

func TestCheckNFC_RejectsNFDDestination(t *testing.T) {
	e := nfcEntry()
	e.Header.Destination = "did:web:log-caf" + nfdEAcute + ".example"
	if err := CheckNFC(e); !errors.Is(err, ErrIngressNotNFC) {
		t.Fatalf("NFD Destination accepted: %v", err)
	}
}

func TestCheckNFC_RejectsNFDDelegateDID(t *testing.T) {
	e := nfcEntry()
	delegate := "did:web:bob-caf" + nfdEAcute + ".example"
	e.Header.DelegateDID = &delegate
	if err := CheckNFC(e); !errors.Is(err, ErrIngressNotNFC) {
		t.Fatalf("NFD DelegateDID accepted: %v", err)
	}
}

func TestCheckNFC_RejectsNFDAuthoritySetKey(t *testing.T) {
	e := nfcEntry()
	e.Header.AuthoritySet = map[string]struct{}{
		"did:web:alice.example":                  {},
		"did:web:bob-caf" + nfdEAcute + ".example": {},
	}
	if err := CheckNFC(e); !errors.Is(err, ErrIngressNotNFC) {
		t.Fatalf("NFD AuthoritySet key accepted: %v", err)
	}
}

func TestCheckNFC_NilDelegateSkipped(t *testing.T) {
	e := nfcEntry()
	e.Header.DelegateDID = nil
	if err := CheckNFC(e); err != nil {
		t.Fatalf("nil DelegateDID rejected: %v", err)
	}
}

func TestCheckNFC_EmptyAuthoritySetSkipped(t *testing.T) {
	e := nfcEntry()
	e.Header.AuthoritySet = nil
	if err := CheckNFC(e); err != nil {
		t.Fatalf("nil AuthoritySet rejected: %v", err)
	}
}

func TestCheckNFC_NilEntryError(t *testing.T) {
	if err := CheckNFC(nil); err == nil {
		t.Fatal("nil entry should error")
	}
}
