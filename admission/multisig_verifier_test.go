/*
FILE PATH:

	admission/multisig_verifier_test.go

DESCRIPTION:

	Binding tests for PR-C gate 1 — admission.VerifyEntryAllSignatures.

	Pins the load-bearing property: every Signatures[i] is verified,
	not only Signatures[0]. The legacy single-sig path skips
	Signatures[1..N], so an entry attaching a garbage cosignature
	would pass admission today; under the multi-sig path it MUST
	NOT.

	Test discipline (carried from PR-A): real ECDSA keys, real
	envelope.SigningPayload, real signatures.SignEntry. No
	did:web:a/b/c placeholders.
*/
package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// multiSigKey bundles one signer's identity for fixture
// construction. SignerDID is "did:web:N" rotation across the
// fixture so the resolver stub can find each one.
type multiSigKey struct {
	DID  string
	Priv *ecdsa.PrivateKey
	Pub  *ecdsa.PublicKey
}

// multiSigFixture builds N signers + a multiResolver that answers
// for all of them.
func multiSigFixture(t *testing.T, n int) ([]multiSigKey, *multiResolver) {
	t.Helper()
	keys := make([]multiSigKey, 0, n)
	resolver := &multiResolver{m: make(map[string]*ecdsa.PublicKey, n)}
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey %d: %v", i, err)
		}
		did := didForIndex(i)
		keys = append(keys, multiSigKey{DID: did, Priv: priv, Pub: &priv.PublicKey})
		resolver.m[did] = &priv.PublicKey
	}
	return keys, resolver
}

func didForIndex(i int) string {
	return testDIDPrefix() + indexSuffix(i)
}

func testDIDPrefix() string { return "did:web:multisig-test." }

func indexSuffix(i int) string {
	// Stable distinct suffixes; not derived from the int so tests
	// don't have to care about formatting.
	const tab = "0123456789abcdef"
	return string(tab[i%len(tab)])
}

// multiResolver answers ResolvePublicKey from an in-memory map.
type multiResolver struct {
	m   map[string]*ecdsa.PublicKey
	err error // optional; when non-nil ALWAYS returned
}

func (r *multiResolver) ResolvePublicKey(_ context.Context, did string) (*ecdsa.PublicKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	pub, ok := r.m[did]
	if !ok {
		return nil, errors.New("multiResolver: unknown DID")
	}
	return pub, nil
}

// signMultiSigEntry constructs an *envelope.Entry whose primary
// signer is keys[0] and which carries cosignatures from keys[1..].
// All signatures are valid by construction. Tests then mutate
// individual signatures to negative cases.
func signMultiSigEntry(t *testing.T, keys []multiSigKey) *envelope.Entry {
	t.Helper()
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   keys[0].DID,
			Destination: "did:web:bench.log",
		},
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	entry.Signatures = make([]envelope.Signature, 0, len(keys))
	for _, k := range keys {
		sig, err := signatures.SignEntry(hash, k.Priv)
		if err != nil {
			t.Fatalf("SignEntry %s: %v", k.DID, err)
		}
		entry.Signatures = append(entry.Signatures, envelope.Signature{
			SignerDID: k.DID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		})
	}
	return entry
}

func TestVerifyEntryAllSignatures_SingleSigHappyPath(t *testing.T) {
	t.Parallel()

	keys, resolver := multiSigFixture(t, 1)
	entry := signMultiSigEntry(t, keys)
	report, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if err != nil {
		t.Fatalf("VerifyEntryAllSignatures: %v", err)
	}
	if report.ValidCount != 1 || report.Total != 1 {
		t.Errorf("report ValidCount=%d Total=%d, want 1/1", report.ValidCount, report.Total)
	}
}

func TestVerifyEntryAllSignatures_MultiSigHappyPath(t *testing.T) {
	t.Parallel()

	keys, resolver := multiSigFixture(t, 3)
	entry := signMultiSigEntry(t, keys)
	report, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if err != nil {
		t.Fatalf("VerifyEntryAllSignatures: %v", err)
	}
	if report.ValidCount != 3 || report.Total != 3 {
		t.Errorf("report ValidCount=%d Total=%d, want 3/3", report.ValidCount, report.Total)
	}
}

func TestVerifyEntryAllSignatures_RejectsBadCosignature(t *testing.T) {
	t.Parallel()

	// The load-bearing property: an entry with one bad Signatures[i]
	// (i > 0) MUST be rejected. The legacy single-sig path would
	// accept this entry because it only checks Signatures[0].
	keys, resolver := multiSigFixture(t, 3)
	entry := signMultiSigEntry(t, keys)
	// Corrupt the SECOND cosignature byte to make verification fail.
	entry.Signatures[2].Bytes[0] ^= 0xFF
	report, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if err == nil {
		t.Fatal("VerifyEntryAllSignatures accepted entry with corrupted cosignature")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("err=%v, want ErrSignatureInvalid", err)
	}
	if report == nil {
		t.Fatal("report nil on per-sig failure; expected populated report")
	}
	if report.Results[0].Err != nil || report.Results[1].Err != nil {
		t.Errorf("non-failing signatures reported errors: %v / %v",
			report.Results[0].Err, report.Results[1].Err)
	}
	if report.Results[2].Err == nil {
		t.Error("corrupted cosignature did not surface as Results[2].Err")
	}
}

func TestVerifyEntryAllSignatures_RejectsPrimaryDIDMismatch(t *testing.T) {
	t.Parallel()

	// SDK Principle 5: Signatures[0].SignerDID MUST equal
	// Header.SignerDID. Mismatch is an envelope-level invariant
	// violation, distinct from a per-signature crypto failure.
	keys, resolver := multiSigFixture(t, 2)
	entry := signMultiSigEntry(t, keys)
	entry.Header.SignerDID = keys[1].DID // mismatch with Signatures[0]
	_, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if !errors.Is(err, attestation.ErrPrimaryDIDMismatch) {
		t.Errorf("err=%v, want ErrPrimaryDIDMismatch", err)
	}
}

func TestVerifyEntryAllSignatures_RejectsEmptySignatures(t *testing.T) {
	t.Parallel()

	keys, resolver := multiSigFixture(t, 1)
	entry := signMultiSigEntry(t, keys)
	entry.Signatures = nil
	_, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if !errors.Is(err, attestation.ErrEmptySignatures) {
		t.Errorf("err=%v, want ErrEmptySignatures", err)
	}
}

func TestVerifyEntryAllSignatures_RejectsNilEntry(t *testing.T) {
	t.Parallel()

	_, resolver := multiSigFixture(t, 1)
	_, err := VerifyEntryAllSignatures(context.Background(), nil, resolver)
	if !errors.Is(err, attestation.ErrNilEntry) {
		t.Errorf("err=%v, want ErrNilEntry", err)
	}
}

func TestVerifyEntryAllSignatures_UnsupportedAlgoIDRejects(t *testing.T) {
	t.Parallel()

	// Multi-sig path supports only SigAlgoECDSA today. An entry
	// attaching a non-ECDSA cosignature MUST surface
	// ErrUnsupportedSignatureAlgo so it can't pass silently.
	keys, resolver := multiSigFixture(t, 2)
	entry := signMultiSigEntry(t, keys)
	entry.Signatures[1].AlgoID = envelope.SigAlgoEd25519
	_, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if !errors.Is(err, ErrUnsupportedSignatureAlgo) {
		t.Errorf("err=%v, want ErrUnsupportedSignatureAlgo", err)
	}
}

func TestVerifyEntryAllSignatures_ResolverErrorSurfaces(t *testing.T) {
	t.Parallel()

	keys, _ := multiSigFixture(t, 1)
	entry := signMultiSigEntry(t, keys)
	resolver := &multiResolver{m: nil, err: errors.New("transient transport")}
	_, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if !errors.Is(err, ErrSignerDIDResolution) {
		t.Errorf("err=%v, want ErrSignerDIDResolution", err)
	}
}

func TestVerifyEntryAllSignatures_NilResolverWireFormatTrust(t *testing.T) {
	t.Parallel()

	// Wire-format-integrity-only trust model: nil resolver skips
	// cryptographic verification. Matches the single-sig path's
	// behaviour for back-compat.
	keys, _ := multiSigFixture(t, 2)
	entry := signMultiSigEntry(t, keys)
	report, err := VerifyEntryAllSignatures(context.Background(), entry, nil)
	if err != nil {
		t.Errorf("nil resolver returned err=%v; want nil (skip)", err)
	}
	if report.ValidCount != 2 {
		t.Errorf("nil resolver did not skip-as-valid: ValidCount=%d", report.ValidCount)
	}
}

func TestVerifyEntryAllSignatures_RejectionsRouteThroughErrorMapping(t *testing.T) {
	t.Parallel()

	// PR-A acceptance: every gate's sentinels MUST round-trip
	// through MapSDKError. The multi-sig path's specific
	// rejections are enrolled.
	keys, resolver := multiSigFixture(t, 1)
	entry := signMultiSigEntry(t, keys)
	entry.Signatures = nil
	_, err := VerifyEntryAllSignatures(context.Background(), entry, resolver)
	if err == nil {
		t.Fatal("expected ErrEmptySignatures, got nil")
	}
	matched, status, _ := MapSDKError(err)
	if !matched {
		t.Error("MapSDKError did not match ErrEmptySignatures; PR-A wiring violated")
	}
	if status != 401 {
		t.Errorf("ErrEmptySignatures status=%d, want 401", status)
	}
}
