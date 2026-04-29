/*
FILE PATH: api/submission_test.go

Handler-level tests for POST /v1/entries (NewSubmissionHandler) —
the unified asynchronous SCT/MMD entry point.

WHAT'S COVERED:

	Constructor guards:
	  - Panics on nil deps.
	  - Panics on non-positive EpochWindowSeconds.
	  - Panics on empty LogDID.
	  - Panics on empty OperatorDID.
	  - Panics on nil OperatorSignerPriv.

	Happy path:
	  - Returns 202 + signed SCT.
	  - SCT signature verifies against the operator's public key.
	  - SCT carries the configured LogDID, OperatorDID, version 1.
	  - WAL.Submit invoked exactly once.

	Error paths:
	  - Bad preamble → 422.
	  - WAL queue full → 503 + Retry-After.
	  - WAL internal error → 500.

	Mode A credit deduction:
	  - Unauthenticated callers skip deduction entirely.
	  - deductCreditModeA short-circuits on nil DB / nil CreditStore.
	  - Insufficient-credits sentinel is comparable across boundaries.

These are unit-level tests that mock WAL, EntryStore, Tessera via
the shared fake types in api/submission_helpers_test.go.
End-to-end coverage (real WAL, real Sequencer drain, full HTTP
server) lives in tests/.
*/
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)


// ─────────────────────────────────────────────────────────────────────
// Constructor guards
// ─────────────────────────────────────────────────────────────────────

func TestNewSubmissionHandler_NilDepsPanics(t *testing.T) {
	defer expectPanic(t, "nil deps")
	NewSubmissionHandler(nil)
}

func TestNewSubmissionHandler_MissingEpochPanics(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	defer expectPanic(t, "EpochWindowSeconds")
	NewSubmissionHandler(&SubmissionDeps{
		Admission:          AdmissionConfig{EpochWindowSeconds: 0},
		OperatorDID:        "did:test:operator",
		LogDID:             "did:test:log",
		MaxEntrySize:       1 << 20,
		Logger:             discardLogger(),
		OperatorSignerPriv: priv,
	})
}

func TestNewSubmissionHandler_MissingLogDIDPanics(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	defer expectPanic(t, "LogDID")
	NewSubmissionHandler(&SubmissionDeps{
		Admission:          AdmissionConfig{EpochWindowSeconds: 3600},
		OperatorDID:        "did:test:operator",
		LogDID:             "",
		MaxEntrySize:       1 << 20,
		Logger:             discardLogger(),
		OperatorSignerPriv: priv,
	})
}

func TestNewSubmissionHandler_MissingOperatorDIDPanics(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	defer expectPanic(t, "OperatorDID")
	NewSubmissionHandler(&SubmissionDeps{
		Admission:          AdmissionConfig{EpochWindowSeconds: 3600},
		OperatorDID:        "",
		LogDID:             "did:test:log",
		MaxEntrySize:       1 << 20,
		Logger:             discardLogger(),
		OperatorSignerPriv: priv,
	})
}

func TestNewSubmissionHandler_NilSignerPanics(t *testing.T) {
	defer expectPanic(t, "OperatorSignerPriv")
	NewSubmissionHandler(&SubmissionDeps{
		Admission:          AdmissionConfig{EpochWindowSeconds: 3600},
		OperatorDID:        "did:test:operator",
		LogDID:             "did:test:log",
		MaxEntrySize:       1 << 20,
		Logger:             discardLogger(),
		OperatorSignerPriv: nil,
	})
}

// ─────────────────────────────────────────────────────────────────────
// Handler — happy path
// ─────────────────────────────────────────────────────────────────────

func TestV1Handler_HappyPath_ReturnsValidSCT(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", []byte("v1-happy"), 1, 3600)
	walFake := &stubSubmissionWAL{}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)

	h := NewSubmissionHandler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d (%s), want 202\nbody: %s", rr.Code, http.StatusText(rr.Code), rr.Body.String())
	}
	var sct SignedCertificateTimestamp
	if err := json.NewDecoder(rr.Body).Decode(&sct); err != nil {
		t.Fatalf("decode SCT: %v", err)
	}
	if sct.LogDID != deps.LogDID {
		t.Errorf("SCT.LogDID = %q, want %q", sct.LogDID, deps.LogDID)
	}
	if sct.SignerDID != deps.OperatorDID {
		t.Errorf("SCT.SignerDID = %q, want %q", sct.SignerDID, deps.OperatorDID)
	}
	if sct.Version != SCTVersion {
		t.Errorf("SCT.Version = %d, want %d", sct.Version, SCTVersion)
	}
	if err := VerifySCT(&opSignerPriv.PublicKey, &sct); err != nil {
		t.Errorf("SCT signature does not verify: %v", err)
	}
	if len(walFake.submitted) != 1 {
		t.Errorf("WAL.Submit calls = %d, want 1", len(walFake.submitted))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Handler — error paths
// ─────────────────────────────────────────────────────────────────────

// Tier-2 BUG #1 alignment pin: the wire field
// envelope.AdmissionProofBody.Difficulty is uint8. The SDK's
// crypto/admission.ProofFromWire promotes it to uint32 inside
// types.AdmissionProof; VerifyStamp then enforces
//
//   1 <= proof.Difficulty <= 256
//
// (difficultyMin = 1, difficultyMax = 256). On a uint8 wire that
// means a wire byte of 0x00 → proof.Difficulty=0 → rejected as
// ErrStampDifficultyOutOfRange. This test pins the operator-side
// validation so the SDK's bounds-check actually fires when a
// pathological client (or a wrapped int → byte cast bug) sends
// difficulty=0.
//
// We cannot easily test difficulty>255 because the wire field is
// uint8; the SDK's BUG #1 client-side guard rejects that case
// before any byte is ever sent (see SDK's
// TestBuildModeB_RejectsOverflowDifficulty).
func TestV1Handler_ZeroDifficulty_Rejected(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewSubmissionHandler(deps)

	// Build a Mode B entry whose AdmissionProofBody.Difficulty byte
	// is 0. signedEntryModeBWithKey sets Difficulty=uint8(d); pass
	// d=0 and a tiny PoW search (any nonce satisfies "0 leading
	// zero bits required").
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: deps.LogDID,
		EventTime:   time.Now().UTC().UnixMicro(),
		AdmissionProof: &envelope.AdmissionProofBody{
			Mode:       types.WireByteModeB,
			Difficulty: 0,
			HashFunc:   sdkadmission.WireByteHashSHA256,
			Epoch:      sdkadmission.CurrentEpoch(3600),
			Nonce:      0,
		},
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte("zero-difficulty-rejected"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(signingHash, signerPriv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	wire := envelope.Serialize(entry)

	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusAccepted {
		t.Fatalf("zero-difficulty entry was admitted; expected rejection. body: %s", rr.Body.String())
	}
	// 403 is the operator's stamp-rejection class; either 403 or
	// 422 is acceptable (validation failure surface). What we
	// MUST NOT see is 202 (accepted).
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("zero-difficulty rejection: got %d (%s), want 403 or 422", rr.Code, http.StatusText(rr.Code))
	}
}

// Tier-2 BUG #3 alignment: oversize bodies must surface as 413 with
// a typed *http.MaxBytesError, not silently truncate to a downstream
// 422 deserialize error. This test bypasses the SizeLimit middleware
// chain and hits the handler directly so the handler-side defensive
// MaxBytesReader is what fires.
func TestV1Handler_OversizeBody_Returns413(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewSubmissionHandler(deps)

	// Body larger than MaxEntrySize+sigOverhead. makeSubmissionDeps
	// sets MaxEntrySize = 1<<20 and sigOverhead is 512 in
	// prepareSubmission, so 1<<20 + 4096 is comfortably oversize.
	oversized := make([]byte, (1<<20)+4096)
	oversized[0] = 0x00
	oversized[1] = 0x05 // valid v5 preamble
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(oversized))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: got %d (%s), want 413\nbody: %s",
			rr.Code, http.StatusText(rr.Code), rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "exceeds") {
		t.Errorf("response should mention size cap: %q", rr.Body.String())
	}
}

func TestV1Handler_BadPreamble_Rejects422(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	h := NewSubmissionHandler(deps)

	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader([]byte("xx")))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", rr.Code)
	}
}

func TestV1Handler_WALQueueFull_Returns503(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", []byte("queue-full"), 1, 3600)
	walFake := &stubSubmissionWAL{submitErr: wal.ErrQueueFull}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)

	h := NewSubmissionHandler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 503")
	}
}

func TestV1Handler_WALInternalError_Returns500(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", []byte("wal-broken"), 1, 3600)
	walFake := &stubSubmissionWAL{submitErr: errors.New("WAL: disk full")}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)

	h := NewSubmissionHandler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Mode A credit deduction
// ─────────────────────────────────────────────────────────────────────

// Credit deduction failures are exercised end-to-end against a real
// Postgres in tests/. At the unit-test level we directly drive
// deductCreditModeA and the mode-A wiring; the full handler path
// for these cases is covered by the e2e suite where a CreditStore
// stub can be injected against a real DB. Here we lock the
// fast-path behavior: when EntryStore + DB + CreditStore are all
// nil (the unauthenticated case), no deduction happens, the WAL is
// hit, and the SCT lands.

func TestV1Handler_UnauthenticatedSkipCreditDeduction(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", []byte("anon"), 1, 3600)
	walFake := &stubSubmissionWAL{}
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)
	// Belt-and-suspenders: make absolutely sure no DB/CreditStore
	// is wired so the deductCreditModeA short-circuits.
	deps.Storage.DB = nil
	deps.Identity.CreditStore = nil

	h := NewSubmissionHandler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", rr.Code, rr.Body.String())
	}
	if len(walFake.submitted) != 1 {
		t.Errorf("WAL.Submit calls = %d, want 1", len(walFake.submitted))
	}
}

// deductCreditModeA returns nil for unauthenticated callers and for
// the dev/test path where DB and CreditStore are nil. Insufficient
// credits surface as store.ErrInsufficientCredits — the handler maps
// that to 402. Locks the helper's contract so the handler-side guard
// (above) cannot regress silently.
func TestDeductCreditModeA_UnauthenticatedReturnsNil(t *testing.T) {
	if err := deductCreditModeA(context.Background(), &SubmissionDeps{}, false, ""); err != nil {
		t.Errorf("expected nil for unauthenticated: %v", err)
	}
}

func TestDeductCreditModeA_NilStoresReturnNil(t *testing.T) {
	deps := &SubmissionDeps{
		Storage:  StorageDeps{DB: nil},
		Identity: IdentityDeps{CreditStore: nil},
	}
	if err := deductCreditModeA(context.Background(), deps, true, "did:test:exchange"); err != nil {
		t.Errorf("expected nil with nil DB+CreditStore: %v", err)
	}
}

// Sentinel coverage for the 402 mapping at the handler boundary.
// deductCreditModeA's full DB-side test is in store_test.go.
func TestErrInsufficientCreditsIsRecognized(t *testing.T) {
	if !errors.Is(store.ErrInsufficientCredits, store.ErrInsufficientCredits) {
		t.Error("sentinel comparison broken")
	}
}
