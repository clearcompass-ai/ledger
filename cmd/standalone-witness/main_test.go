// FILE PATH: cmd/standalone-witness/main_test.go
//
// Unit tests for the witness daemon's two file-loaders. Both run
// against on-disk fixtures under t.TempDir(); no network, no
// running daemon.
//
// The main() function itself isn't unit-tested directly because
// it owns flag.Parse + signal.NotifyContext + ListenAndServe —
// pure I/O composition. cmd/standalone-witness/tests/daemon_e2e_test.go
// covers the full flag-to-listen path via os/exec + http.Client.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/attesta/network"
)

// writePEMKey writes a fresh P-256 EC private key in
// x509.MarshalECPrivateKey-encoded PEM form to path. Mirrors
// what cmd/init-network produces.
func writePEMKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return priv
}

// ─────────────────────────────────────────────────────────────────
// loadECPrivateKey
// ─────────────────────────────────────────────────────────────────

func TestLoadECPrivateKey_HappyPath(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "witness.pem")
	want := writePEMKey(t, keyPath)

	got, err := loadECPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadECPrivateKey: %v", err)
	}
	if got.D.Cmp(want.D) != 0 {
		t.Errorf("loaded key D differs from written key — round-trip broken")
	}
}

func TestLoadECPrivateKey_FileNotExist(t *testing.T) {
	_, err := loadECPrivateKey(filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadECPrivateKey_EmptyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(keyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	_, err := loadECPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error on empty PEM file")
	}
}

func TestLoadECPrivateKey_BadPEM(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(keyPath, []byte("not a pem block"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, err := loadECPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error on malformed PEM")
	}
}

func TestLoadECPrivateKey_RejectsNonECPEM(t *testing.T) {
	// Valid PEM block but wrong type.
	keyPath := filepath.Join(t.TempDir(), "wrong-type.pem")
	body := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte{0x30, 0x82, 0x01, 0x00},
	})
	if err := os.WriteFile(keyPath, body, 0o600); err != nil {
		t.Fatalf("write wrong-type: %v", err)
	}
	_, err := loadECPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error on non-EC PEM")
	}
}

// ─────────────────────────────────────────────────────────────────
// loadBootstrap
// ─────────────────────────────────────────────────────────────────

// validBootstrapJSON returns a minimal valid network bootstrap
// document body. The DID list is intentionally non-empty — empty
// genesis_witness_set is rejected by the SDK's IDs() validator,
// which the standalone-witness daemon calls at boot.
func validBootstrapJSON(t *testing.T) []byte {
	t.Helper()
	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:test-ledger.example",
		NetworkName:       "unit-test",
		GenesisWitnessSet: []string{"did:key:z6MkUnitTestWitness"},
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal valid bootstrap: %v", err)
	}
	return body
}

func TestLoadBootstrap_HappyPath(t *testing.T) {
	bsPath := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(bsPath, validBootstrapJSON(t), 0o644); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}

	doc, err := loadBootstrap(bsPath)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	if doc.NetworkName != "unit-test" {
		t.Errorf("doc.NetworkName = %q, want unit-test", doc.NetworkName)
	}
	if len(doc.GenesisWitnessSet) != 1 {
		t.Errorf("doc.GenesisWitnessSet len = %d, want 1", len(doc.GenesisWitnessSet))
	}
}

func TestLoadBootstrap_FileNotExist(t *testing.T) {
	_, err := loadBootstrap(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadBootstrap_BadJSON(t *testing.T) {
	bsPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bsPath, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, err := loadBootstrap(bsPath)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestLoadBootstrap_DerivesNonZeroNetworkID(t *testing.T) {
	bsPath := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(bsPath, validBootstrapJSON(t), 0o644); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}
	doc, err := loadBootstrap(bsPath)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	identity, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs(): %v", err)
	}
	var zero [32]byte
	if identity.NetworkID == zero {
		t.Fatal("derived NetworkID is zero — SDK contract broken")
	}
}
