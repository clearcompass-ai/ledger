/*
FILE PATH: api/submission_helpers_test.go

Shared fakes + builders for handler tests in this package.
Lives independently of any specific handler so deletion of one
handler file (e.g. the historical submission_v2.go) does not
strand the helpers other tests depend on.
*/
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
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
// Fakes
// ─────────────────────────────────────────────────────────────────────

// stubSubmissionWAL records hash-of-each-Submit and can inject a
// configurable error.
type stubSubmissionWAL struct {
	submitErr error
	submitted [][32]byte
}

func (s *stubSubmissionWAL) Submit(ctx context.Context, hash [32]byte, wire []byte) error {
	if s.submitErr != nil {
		return s.submitErr
	}
	s.submitted = append(s.submitted, hash)
	return nil
}

func (s *stubSubmissionWAL) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	return nil
}

func (s *stubSubmissionWAL) MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error) {
	return wal.Meta{}, nil
}

// stubSubmissionDiffController returns difficulty=1 + sha256.
type stubSubmissionDiffController struct{}

func (s *stubSubmissionDiffController) CurrentDifficulty() uint32 { return 1 }
func (s *stubSubmissionDiffController) HashFunction() string      { return "sha256" }

// stubSubmissionTessera should never be called from the unified
// /v1 fast path — Tessera lives behind the Sequencer now.
type stubSubmissionTessera struct{}

func (s *stubSubmissionTessera) AppendLeaf(data []byte) (uint64, error) {
	return 0, errors.New("submission fast path should not call AppendLeaf")
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
// Builders
// ─────────────────────────────────────────────────────────────────────

// signedEntryModeB produces wire bytes for a Mode B (anonymous,
// PoW-stamped) submission. Brute-forces the nonce at difficulty=1
// (~2 iterations average) so the test is fast. Generates a fresh
// signing key per call.
func signedEntryModeB(t *testing.T, logDID string, payload []byte, difficulty uint32, epochWindowSec uint64) (wire []byte, hash [32]byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wire, hash = signedEntryModeBWithKey(t, priv, logDID, payload, difficulty, epochWindowSec)
	return wire, hash, priv
}

// signedEntryModeBWithKey is like signedEntryModeB but uses the
// caller-supplied signing key. Lets a test build N entries that
// all verify against the same fakeDIDResolver pubkey.
func signedEntryModeBWithKey(t *testing.T, priv *ecdsa.PrivateKey, logDID string, payload []byte, difficulty uint32, epochWindowSec uint64) (wire []byte, hash [32]byte) {
	t.Helper()
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
			return canonical, entryHash
		}
	}
	t.Fatalf("could not find valid stamp at difficulty=%d in %d iterations", difficulty, maxIter)
	return
}

// makeSubmissionDeps wires a SubmissionDeps suitable for the
// unified /v1/entries handler. Per-test overrides happen by
// mutating individual fields on the returned pointer.
func makeSubmissionDeps(t *testing.T, opSignerPriv *ecdsa.PrivateKey, signerPub *ecdsa.PublicKey, walFake *stubSubmissionWAL) *SubmissionDeps {
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
	return &SubmissionDeps{
		Storage: StorageDeps{
			DB:         nil, // tests use authenticated=false → no credit deduction
			EntryStore: nil,
			WAL:        walFake,
			Tessera:    &stubSubmissionTessera{},
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
		OperatorSignerPriv: opSignerPriv,
	}
}

// expectPanic is a defer'd helper for constructor-guard tests.
func expectPanic(t *testing.T, label string) {
	t.Helper()
	if r := recover(); r == nil {
		t.Errorf("expected panic on %s", label)
	}
}
