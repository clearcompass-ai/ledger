package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

type stubResolver struct {
	pub *ecdsa.PublicKey
	err error
}

func (s *stubResolver) ResolvePublicKey(_ context.Context, _ string) (*ecdsa.PublicKey, error) {
	return s.pub, s.err
}

func signedEntryFixture(t *testing.T) (*envelope.Entry, []byte, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   "did:web:alice.example",
			Destination: "did:web:log.example",
		},
	}
	// v7.75 signing contract (envelope/serialize.go:218-225): sign over
	// sha256(SigningPayload(entry)), NOT EntryIdentity. SigningPayload
	// is computed without the signatures section, so it is safe to call
	// on a struct-literal entry that has no Signatures yet.
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return entry, sig, &priv.PublicKey
}

func TestVerifyEntrySignature_HappyPath(t *testing.T) {
	entry, sig, pub := signedEntryFixture(t)
	res := &stubResolver{pub: pub}
	if err := VerifyEntrySignature(context.Background(), entry, sig, res); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyEntrySignature_NilResolverPhase2Skip(t *testing.T) {
	entry, sig, _ := signedEntryFixture(t)
	if err := VerifyEntrySignature(context.Background(), entry, sig, nil); err != nil {
		t.Fatalf("nil resolver should skip, got: %v", err)
	}
}

func TestVerifyEntrySignature_ResolverError(t *testing.T) {
	entry, sig, _ := signedEntryFixture(t)
	res := &stubResolver{err: errors.New("transient")}
	err := VerifyEntrySignature(context.Background(), entry, sig, res)
	if !errors.Is(err, ErrSignerDIDResolution) {
		t.Fatalf("resolver error not wrapped: %v", err)
	}
}

func TestVerifyEntrySignature_NilPubKey(t *testing.T) {
	entry, sig, _ := signedEntryFixture(t)
	res := &stubResolver{pub: nil}
	err := VerifyEntrySignature(context.Background(), entry, sig, res)
	if !errors.Is(err, ErrSignerDIDResolution) {
		t.Fatalf("nil pubkey not classified as resolution failure: %v", err)
	}
}

func TestVerifyEntrySignature_WrongKey(t *testing.T) {
	entry, sig, _ := signedEntryFixture(t)
	other, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	res := &stubResolver{pub: &other.PublicKey}
	err = VerifyEntrySignature(context.Background(), entry, sig, res)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong key not classified as signature invalid: %v", err)
	}
}

func TestVerifyEntrySignature_TamperedHash(t *testing.T) {
	entry, _, pub := signedEntryFixture(t)
	// Construct a 64-byte signature over a different hash.
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongHash := sha256.Sum256([]byte("different bytes"))
	sig, err := signatures.SignEntry(wrongHash, priv)
	if err != nil {
		t.Fatalf("sign wrong hash: %v", err)
	}
	res := &stubResolver{pub: pub}
	err = VerifyEntrySignature(context.Background(), entry, sig, res)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered hash not rejected as signature invalid: %v", err)
	}
}

func TestVerifyEntrySignature_NilEntry(t *testing.T) {
	if err := VerifyEntrySignature(context.Background(), nil, nil, &stubResolver{}); err == nil {
		t.Fatal("nil entry should error")
	}
}
