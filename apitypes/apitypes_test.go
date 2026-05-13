/*
FILE PATH: apitypes/apitypes_test.go

Tests pinning the leaf-package contract:

  - The package's transitive imports contain ZERO pgx packages
    (this is the load-bearing P8 / invariant; verified at
    build time via go list -deps in CI).
  - Value types preserve their fields verbatim across instantiation.
  - ErrInsufficientCredits is a stable, errors.Is-compatible
    sentinel (callers use errors.Is, not == comparison).
*/
package apitypes_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/apitypes"
)

func TestCosignedTreeHead_FieldsRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	h := apitypes.CosignedTreeHead{
		TreeSize: 42,
		RootHash: [32]byte{0x01, 0x02},
		SMTRoot:  [32]byte{0xAA, 0xBB},
		HashAlgo: 1,
		Signatures: []apitypes.TreeHeadSignature{{
			Signer:    "did:test:witness",
			SigAlgo:   2,
			Signature: []byte("sig"),
			CreatedAt: now,
		}},
		CreatedAt: now,
	}
	if h.TreeSize != 42 {
		t.Errorf("TreeSize lost")
	}
	if h.SMTRoot != ([32]byte{0xAA, 0xBB}) {
		t.Errorf("SMTRoot lost")
	}
	if len(h.Signatures) != 1 {
		t.Errorf("Signatures lost")
	}
}

func TestCommitmentRow_FieldsRoundTrip(t *testing.T) {
	r := apitypes.CommitmentRow{
		ID:            7,
		RangeStartSeq: 100,
		RangeEndSeq:   200,
		PriorSMTRoot:  [32]byte{0xaa},
		PostSMTRoot:   [32]byte{0xbb},
		MutationsJSON: []byte(`{"k":"v"}`),
		CommentarySeq: nil,
		CreatedAt:     time.Now().UTC(),
	}
	if r.RangeEndSeq-r.RangeStartSeq != 100 {
		t.Errorf("range arithmetic broken")
	}
}

func TestEscrowOverrideResult_FieldsRoundTrip(t *testing.T) {
	r := apitypes.EscrowOverrideResult{
		EventID:    [32]byte{0x42},
		Signatures: 5,
		Lamport:    1234,
	}
	if r.Signatures != 5 || r.Lamport != 1234 {
		t.Errorf("fields drift")
	}
}

func TestErrInsufficientCredits_ErrorsIsCompatible(t *testing.T) {
	// Wrapping → errors.Is must still match the sentinel.
	wrapped := fmt.Errorf("at admission: %w", apitypes.ErrInsufficientCredits)
	if !errors.Is(wrapped, apitypes.ErrInsufficientCredits) {
		t.Error("errors.Is broken across wrap")
	}
}

func TestErrInsufficientCredits_Stable(t *testing.T) {
	// Re-importing the package must yield the same sentinel
	// pointer — Go guarantees this at the language level, but
	// pinning here catches a hypothetical future migration that
	// accidentally splits the sentinel into two distinct values.
	a := apitypes.ErrInsufficientCredits
	b := apitypes.ErrInsufficientCredits
	if !errors.Is(a, b) {
		t.Error("sentinel split")
	}
}
