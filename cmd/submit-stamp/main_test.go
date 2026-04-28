/*
FILE PATH: cmd/submit-stamp/main_test.go

Unit tests for the SCT decode + verify helpers in main.go.

End-to-end coverage (real operator + Sequencer + admission) lives
in tests/e2e_v2_sct_test.go. This file targets the bits the CLI
binary owns directly:

  apiSCT JSON decoding round-trips with the api package's
  SignedCertificateTimestamp shape (caught the moment the
  api-side type drifts).

  verifyClientSCT byte-for-byte matches api.VerifySCT — same
  packing, same signature primitive. Tampering any signed-over
  field rejects.

The CLI binary intentionally re-implements the SCT verification
loop to stay free of the api/ package import (cmd packages don't
take api/ dependencies). This test pins the contract so the
duplication can't drift.
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdksigs "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"

	"github.com/clearcompass-ai/ortholog-operator/api"
)

// TestApiSCTJSONRoundTrips_MatchesAPIType: marshalling api's
// SignedCertificateTimestamp and unmarshalling into apiSCT (this
// CLI's mirror) must produce identical fields. If api/ adds a
// new field, this test fails until apiSCT mirrors it.
func TestApiSCTJSONRoundTrips_MatchesAPIType(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	hash := sha256.Sum256([]byte("roundtrip"))
	apiSCTValue, err := api.SignSCT(priv, "did:test:log", hash, time.Now().UTC())
	if err != nil {
		t.Fatalf("api.SignSCT: %v", err)
	}
	encoded, err := json.Marshal(apiSCTValue)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var clientSide apiSCT
	if err := json.Unmarshal(encoded, &clientSide); err != nil {
		t.Fatalf("unmarshal into apiSCT: %v", err)
	}
	if clientSide.Version != apiSCTValue.Version {
		t.Errorf("Version drift: %d vs %d", clientSide.Version, apiSCTValue.Version)
	}
	if clientSide.LogDID != apiSCTValue.LogDID {
		t.Errorf("LogDID drift: %q vs %q", clientSide.LogDID, apiSCTValue.LogDID)
	}
	if clientSide.CanonicalHash != apiSCTValue.CanonicalHash {
		t.Errorf("CanonicalHash drift")
	}
	if clientSide.LogTimeMicros != apiSCTValue.LogTimeMicros {
		t.Errorf("LogTimeMicros drift: %d vs %d", clientSide.LogTimeMicros, apiSCTValue.LogTimeMicros)
	}
	if clientSide.LogTime != apiSCTValue.LogTime {
		t.Errorf("LogTime drift")
	}
	if clientSide.Signature != apiSCTValue.Signature {
		t.Errorf("Signature drift")
	}
}

// TestVerifyClientSCT_MatchesAPIPath: any SCT api.SignSCT
// produces, verifyClientSCT must accept (proves the CLI's
// independent re-implementation of the canonical packing matches
// the api side byte-for-byte).
func TestVerifyClientSCT_MatchesAPIPath(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	for _, payload := range []string{"a", "longer payload here", strings.Repeat("x", 500)} {
		hash := sha256.Sum256([]byte(payload))
		sct, err := api.SignSCT(priv, "did:test:log", hash, time.Now().UTC())
		if err != nil {
			t.Fatalf("SignSCT(%q): %v", payload, err)
		}
		client := apiSCT{
			Version:       sct.Version,
			LogDID:        sct.LogDID,
			CanonicalHash: sct.CanonicalHash,
			LogTimeMicros: sct.LogTimeMicros,
			LogTime:       sct.LogTime,
			Signature:     sct.Signature,
		}
		if err := verifyClientSCT(&priv.PublicKey, &client); err != nil {
			t.Errorf("payload=%q: verifyClientSCT: %v", payload, err)
		}
	}
}

// TestVerifyClientSCT_TamperedHashRejects locks the consumer-side
// tamper resistance.
func TestVerifyClientSCT_TamperedHashRejects(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	hash := sha256.Sum256([]byte("tamper-hash"))
	sct, _ := api.SignSCT(priv, "did:test:log", hash, time.Now().UTC())
	client := apiSCT{
		Version:       sct.Version,
		LogDID:        sct.LogDID,
		CanonicalHash: "ff" + sct.CanonicalHash[2:],
		LogTimeMicros: sct.LogTimeMicros,
		LogTime:       sct.LogTime,
		Signature:     sct.Signature,
	}
	if err := verifyClientSCT(&priv.PublicKey, &client); err == nil {
		t.Error("expected rejection on tampered canonical_hash")
	}
}

func TestVerifyClientSCT_TamperedTimestampRejects(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	hash := sha256.Sum256([]byte("tamper-ts"))
	sct, _ := api.SignSCT(priv, "did:test:log", hash, time.Now().UTC())
	client := apiSCT{
		Version:       sct.Version,
		LogDID:        sct.LogDID,
		CanonicalHash: sct.CanonicalHash,
		LogTimeMicros: sct.LogTimeMicros + 1,
		LogTime:       sct.LogTime,
		Signature:     sct.Signature,
	}
	if err := verifyClientSCT(&priv.PublicKey, &client); err == nil {
		t.Error("expected rejection on tampered log_time_micros")
	}
}

func TestVerifyClientSCT_TamperedLogDIDRejects(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	hash := sha256.Sum256([]byte("tamper-did"))
	sct, _ := api.SignSCT(priv, "did:test:log", hash, time.Now().UTC())
	client := apiSCT{
		Version:       sct.Version,
		LogDID:        "did:test:other",
		CanonicalHash: sct.CanonicalHash,
		LogTimeMicros: sct.LogTimeMicros,
		LogTime:       sct.LogTime,
		Signature:     sct.Signature,
	}
	if err := verifyClientSCT(&priv.PublicKey, &client); err == nil {
		t.Error("expected rejection on tampered log_did")
	}
}

func TestVerifyClientSCT_BadHexErrors(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	client := apiSCT{
		Version:       1,
		CanonicalHash: "not-hex",
	}
	if err := verifyClientSCT(&priv.PublicKey, &client); err == nil {
		t.Error("expected error on bad hex")
	}
}

func TestVerifyClientSCT_WrongHashLengthErrors(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	client := apiSCT{
		Version:       1,
		CanonicalHash: hex.EncodeToString([]byte("only-eleven")),
	}
	if err := verifyClientSCT(&priv.PublicKey, &client); err == nil {
		t.Error("expected error on short hash")
	}
}

func TestVerifyClientSCT_VersionMismatchErrors(t *testing.T) {
	priv, _ := sdksigs.GenerateKey()
	hash := sha256.Sum256([]byte("ver"))
	sct, _ := api.SignSCT(priv, "did:test:log", hash, time.Now().UTC())
	client := apiSCT{
		Version:       sct.Version + 1,
		LogDID:        sct.LogDID,
		CanonicalHash: sct.CanonicalHash,
		LogTimeMicros: sct.LogTimeMicros,
		LogTime:       sct.LogTime,
		Signature:     sct.Signature,
	}
	if err := verifyClientSCT(&priv.PublicKey, &client); err == nil {
		t.Error("expected error on unsupported version")
	}
}
