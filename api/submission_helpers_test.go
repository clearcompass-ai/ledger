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

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkadmission "github.com/clearcompass-ai/attesta/crypto/admission"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// stubSubmissionWAL records hash-of-each-Submit, persists Meta
// (so the P5 idempotency probe via MetaState observes the
// persisted log_time on resubmission), and can inject a
// configurable Submit error.
type stubSubmissionWAL struct {
	submitErr error
	submitted [][32]byte
	metas     map[[32]byte]wal.Meta
}

func (s *stubSubmissionWAL) Submit(ctx context.Context, hash [32]byte, wire []byte, logTimeMicros int64) error {
	if s.submitErr != nil {
		return s.submitErr
	}
	s.submitted = append(s.submitted, hash)
	if s.metas == nil {
		s.metas = make(map[[32]byte]wal.Meta)
	}
	// Mirror the real Committer's preserve-on-existing semantics:
	// a re-Submit does NOT overwrite the persisted log_time.
	if _, exists := s.metas[hash]; !exists {
		s.metas[hash] = wal.Meta{
			State:         wal.StatePending,
			LogTimeMicros: logTimeMicros,
		}
	}
	return nil
}

func (s *stubSubmissionWAL) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	return nil
}

func (s *stubSubmissionWAL) MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error) {
	if s.metas == nil {
		return wal.Meta{}, nil
	}
	if m, ok := s.metas[hash]; ok {
		return m, nil
	}
	return wal.Meta{}, nil
}

// stubSubmissionTessera should never be called from the unified
// /v1 fast path — Tessera lives behind the Sequencer now.
type stubSubmissionTessera struct{}

func (s *stubSubmissionTessera) AppendLeaf(_ context.Context, data []byte) (uint64, error) {
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
		canonical, sErr := envelope.Serialize(entry)
		if sErr != nil {
			t.Fatalf("envelope.Serialize: %v", sErr)
		}
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
			Credits:     nil, // tests use authenticated=false → no credit deduction
			DIDResolver: &fakeDIDResolver{pub: signerPub},
		},
		LedgerDID:          "did:test:ledger",
		LogDID:             "did:test:log",
		MaxEntrySize:       1 << 20,
		Logger:             discardLogger(),
		FreshnessTolerance: 5 * time.Minute,
		LedgerSignerPriv:   opSignerPriv,
	}
}

// expectPanic is a defer'd helper for constructor-guard tests.
func expectPanic(t *testing.T, label string) {
	t.Helper()
	if r := recover(); r == nil {
		t.Errorf("expected panic on %s", label)
	}
}
