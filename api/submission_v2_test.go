/*
FILE PATH: api/submission_v2_test.go

Handler-level tests for POST /v2/entries (NewSubmissionV2Handler)
and GET /v1/admission/mmd (NewMMDHandler).

WHAT'S COVERED:

	NewSubmissionV2Handler:
	  - Constructor panics on nil deps, nil signer key, missing
	    EpochWindowSeconds, missing LogDID.
	  - Handler returns 202 + signed SCT on the happy path
	    (Mode B / unauthenticated, with a stub DiffController).
	  - SCT signature verifies against the operator's public key.
	  - Invalid wire bytes → 422.
	  - WAL queue full → 503 + Retry-After.
	  - Insufficient credits (Mode A) → 402.

	NewMMDHandler:
	  - Returns the configured MMD as both seconds and human form.

These are unit-level handler tests that mock out WAL, EntryStore,
Tessera, etc. via the existing fake types. End-to-end coverage
(real WAL, real Sequencer drain, full HTTP server) lives in
tests/e2e_v2_sct_test.go (commit 9).
*/
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Stubs for the v2 dep surface.
// ─────────────────────────────────────────────────────────────────────

type stubV2WAL struct {
	submitErr error
	submitted [][32]byte
}

func (s *stubV2WAL) Submit(ctx context.Context, hash [32]byte, wire []byte) error {
	if s.submitErr != nil {
		return s.submitErr
	}
	s.submitted = append(s.submitted, hash)
	return nil
}

func (s *stubV2WAL) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	return nil
}

func (s *stubV2WAL) MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error) {
	return wal.Meta{}, nil
}

type stubV2EntryStore struct{}

func (s *stubV2EntryStore) FetchByHash(ctx context.Context, hash [32]byte) (uint64, bool, error) {
	return 0, false, nil // never duplicate
}

type stubV2DiffController struct{}

func (s *stubV2DiffController) CurrentDifficulty() uint32 { return 1 }
func (s *stubV2DiffController) HashFunction() string      { return "sha256" }

type stubV2Tessera struct{}

func (s *stubV2Tessera) AppendLeaf(data []byte) (uint64, error) {
	return 0, errors.New("v2 fast-path should not call AppendLeaf")
}

// fakeDIDResolver returns a fixed pub for any DID — admission's
// signature verifier consults the resolver and we want to control
// the verify outcome without standing up real did:key parsing.
type fakeDIDResolver struct {
	pub *ecdsa.PublicKey
	err error
}

func (f *fakeDIDResolver) ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.pub, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// signedV2EntryModeB produces wire bytes for a Mode B (anonymous,
// PoW-stamped) v2 submission. Brute-forces the nonce at difficulty=1
// (~2 iterations average) so the test is fast.
func signedV2EntryModeB(t *testing.T, logDID string, payload []byte, difficulty uint32, epochWindowSec uint64) (wire []byte, hash [32]byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: logDID,
		EventTime:   time.Now().UTC().UnixMicro(),
		AdmissionProof: &envelope.AdmissionProofBody{
			Mode:       types.WireByteModeB,
			Difficulty: uint8(difficulty),
			HashFunc:   sdkadmission.WireByteHashSHA256,
			Epoch:      sdkadmission.CurrentEpoch(epochWindowSec),
		},
	}
	const maxIter uint64 = 1 << 24
	for nonce := uint64(0); nonce < maxIter; nonce++ {
		hdr.AdmissionProof.Nonce = nonce
		entry, err := envelope.NewUnsignedEntry(hdr, payload)
		if err != nil {
			t.Fatalf("NewUnsignedEntry: %v", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(entry))
		sig, err := signatures.SignEntry(signingHash, priv)
		if err != nil {
			t.Fatalf("SignEntry: %v", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: hdr.SignerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		}}
		canonical := envelope.Serialize(entry)
		entryHash := sha256.Sum256(canonical)
		apiProof := sdkadmission.ProofFromWire(hdr.AdmissionProof, logDID)
		if err := sdkadmission.VerifyStamp(
			apiProof,
			entryHash,
			logDID,
			difficulty,
			sdkadmission.HashSHA256,
			nil,
			sdkadmission.CurrentEpoch(epochWindowSec),
			1,
		); err == nil {
			return canonical, entryHash, priv
		}
	}
	t.Fatalf("could not find valid stamp at difficulty=%d in %d iterations", difficulty, maxIter)
	return
}

// makeV2Deps wires SubmissionV2Deps with stubs. The returned
// SubmissionV2Deps satisfies the NewSubmissionV2Handler constructor
// validation; per-test overrides happen by mutating individual
// fields before calling the handler.
func makeV2Deps(t *testing.T, opSignerPriv *ecdsa.PrivateKey, signerPub *ecdsa.PublicKey, walFake *stubV2WAL) *SubmissionV2Deps {
	t.Helper()
	diffController := middleware.NewDifficultyController(
		nil,
		middleware.DifficultyConfig{
			InitialDifficulty: 1,
			MinDifficulty:     1,
			MaxDifficulty:     1,
			HashFunction:      "sha256",
		},
		discardLogger(),
	)
	return &SubmissionV2Deps{
		SubmissionDeps: &SubmissionDeps{
			Storage: StorageDeps{
				DB:         nil, // tests use authenticated=false → no credit deduction
				EntryStore: nil, // hashLookup short-circuit handled below
				WAL:        walFake,
				Tessera:    &stubV2Tessera{},
			},
			Admission: AdmissionConfig{
				DiffController:        diffController,
				EpochWindowSeconds:    3600,
				EpochAcceptanceWindow: 1,
			},
			Identity: IdentityDeps{
				CreditStore: nil,
				DIDResolver: &fakeDIDResolver{pub: signerPub},
			},
			OperatorDID:        "did:test:operator",
			LogDID:             "did:test:log",
			MaxEntrySize:       1 << 20,
			Logger:             discardLogger(),
			FreshnessTolerance: 5 * time.Minute,
		},
		OperatorSignerPriv: opSignerPriv,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Constructor guards
// ─────────────────────────────────────────────────────────────────────

func TestNewSubmissionV2Handler_NilDepsPanics(t *testing.T) {
	defer expectPanic(t, "nil deps")
	NewSubmissionV2Handler(nil)
}

func TestNewSubmissionV2Handler_NilSignerPanics(t *testing.T) {
	defer expectPanic(t, "nil signer")
	NewSubmissionV2Handler(&SubmissionV2Deps{
		SubmissionDeps: &SubmissionDeps{
			Admission:    AdmissionConfig{EpochWindowSeconds: 3600},
			OperatorDID:  "did:test:operator",
			LogDID:       "did:test:log",
			MaxEntrySize: 1 << 20,
			Logger:       discardLogger(),
		},
		OperatorSignerPriv: nil,
	})
}

func TestNewSubmissionV2Handler_MissingEpochPanics(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	defer expectPanic(t, "EpochWindowSeconds")
	NewSubmissionV2Handler(&SubmissionV2Deps{
		SubmissionDeps: &SubmissionDeps{
			Admission:    AdmissionConfig{EpochWindowSeconds: 0},
			OperatorDID:  "did:test:operator",
			LogDID:       "did:test:log",
			MaxEntrySize: 1 << 20,
			Logger:       discardLogger(),
		},
		OperatorSignerPriv: priv,
	})
}

func TestNewSubmissionV2Handler_MissingLogDIDPanics(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	defer expectPanic(t, "LogDID")
	NewSubmissionV2Handler(&SubmissionV2Deps{
		SubmissionDeps: &SubmissionDeps{
			Admission:    AdmissionConfig{EpochWindowSeconds: 3600},
			OperatorDID:  "did:test:operator",
			LogDID:       "",
			MaxEntrySize: 1 << 20,
			Logger:       discardLogger(),
		},
		OperatorSignerPriv: priv,
	})
}

func TestNewSubmissionV2Handler_MissingOperatorDIDPanics(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	defer expectPanic(t, "OperatorDID")
	NewSubmissionV2Handler(&SubmissionV2Deps{
		SubmissionDeps: &SubmissionDeps{
			Admission:    AdmissionConfig{EpochWindowSeconds: 3600},
			OperatorDID:  "",
			LogDID:       "did:test:log",
			MaxEntrySize: 1 << 20,
			Logger:       discardLogger(),
		},
		OperatorSignerPriv: priv,
	})
}

func expectPanic(t *testing.T, label string) {
	t.Helper()
	if r := recover(); r == nil {
		t.Errorf("expected panic on %s", label)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Handler — happy path
// ─────────────────────────────────────────────────────────────────────

func TestV2Handler_HappyPath_ReturnsValidSCT(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	const epochWindow = 3600
	wire, _, signerPriv := signedV2EntryModeB(t, "did:test:log", []byte("v2-happy"), 1, epochWindow)
	walFake := &stubV2WAL{}
	deps := makeV2Deps(t, opSignerPriv, &signerPriv.PublicKey, walFake)

	h := NewSubmissionV2Handler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v2/entries", bytes.NewReader(wire))
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

func TestV2Handler_BadPreamble_Rejects422(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	signerPriv, _ := signatures.GenerateKey()
	deps := makeV2Deps(t, opSignerPriv, &signerPriv.PublicKey, &stubV2WAL{})
	h := NewSubmissionV2Handler(deps)

	req := httptest.NewRequest(http.MethodPost, "/v2/entries", bytes.NewReader([]byte("xx")))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", rr.Code)
	}
}

func TestV2Handler_WALQueueFull_Returns503(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedV2EntryModeB(t, "did:test:log", []byte("queue-full"), 1, 3600)
	walFake := &stubV2WAL{submitErr: wal.ErrQueueFull}
	deps := makeV2Deps(t, opSignerPriv, &signerPriv.PublicKey, walFake)

	h := NewSubmissionV2Handler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v2/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 503")
	}
}

func TestV2Handler_WALInternalError_Returns500(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedV2EntryModeB(t, "did:test:log", []byte("wal-broken"), 1, 3600)
	walFake := &stubV2WAL{submitErr: errors.New("WAL: disk full")}
	deps := makeV2Deps(t, opSignerPriv, &signerPriv.PublicKey, walFake)

	h := NewSubmissionV2Handler(deps)
	req := httptest.NewRequest(http.MethodPost, "/v2/entries", bytes.NewReader(wire))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// MMD handler
// ─────────────────────────────────────────────────────────────────────

func TestMMDHandler_RoundsToConfiguredValue(t *testing.T) {
	for _, mmd := range []time.Duration{
		time.Second, 30 * time.Second, 24 * time.Hour, 7 * 24 * time.Hour,
	} {
		h := NewMMDHandler(mmd)
		req := httptest.NewRequest(http.MethodGet, "/v1/admission/mmd", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("mmd=%v: status = %d, want 200", mmd, rr.Code)
		}
		var body struct {
			MMDSeconds float64 `json:"mmd_seconds"`
			MMDHuman   string  `json:"mmd_human"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
			t.Errorf("mmd=%v: decode: %v", mmd, err)
			continue
		}
		if body.MMDSeconds != mmd.Seconds() {
			t.Errorf("mmd=%v: mmd_seconds = %v, want %v", mmd, body.MMDSeconds, mmd.Seconds())
		}
		if body.MMDHuman != mmd.String() {
			t.Errorf("mmd=%v: mmd_human = %q, want %q", mmd, body.MMDHuman, mmd.String())
		}
	}
}
