/*
FILE PATH: tests/chaos/harness/bootstrap.go

Bootstrap document + ledger signer key generation for chaos
tests. The ledger binary requires:

  LEDGER_NETWORK_BOOTSTRAP_FILE — JSON file path containing the
    network.BootstrapDocument (defines NetworkID + witness DIDs).
  LEDGER_SIGNER_KEY_FILE — PEM-encoded secp256k1 private key
    that becomes the ledger's signing identity.

This file builds both, writes them to disk, and returns metadata
the rest of the harness needs (NetworkID for witness validation,
ledger DID for log identity claims, file paths to point env vars
at).
*/
package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkcryptosigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/network"

	// secp256k1 curve registration so x509 / ecdsa.GenerateKey
	// can find it. Same dependency cmd/ledger/signers.go pulls in.
	_ "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BootstrapBundle is everything needed to wire up a ledger
// subprocess that talks to the witness fixture: paths to the
// JSON + PEM files (for env vars), the computed NetworkID (which
// the witness fixture also needs so it accepts incoming
// requests), and the ledger's derived did:key (for log-identity
// assertions).
type BootstrapBundle struct {
	// BootstrapPath is the absolute path to the bootstrap.json
	// file. Set LEDGER_NETWORK_BOOTSTRAP_FILE to this.
	BootstrapPath string

	// SignerKeyPath is the absolute path to the ledger signer's
	// PEM-encoded secp256k1 private key. Set
	// LEDGER_SIGNER_KEY_FILE to this.
	SignerKeyPath string

	// NetworkID is the SHA-256 of the canonical bootstrap doc.
	// The witness fixture must be constructed with this NetworkID
	// in its AllowedNetworks set, otherwise cosign requests will
	// be rejected with a network-mismatch error.
	NetworkID cosign.NetworkID

	// LedgerDID is the did:key derived from the signer key. The
	// ledger overrides LEDGER_DID to this at boot regardless of
	// what's in the env, but capturing it here lets tests assert
	// the ledger-signed entries carry the expected signer
	// identity.
	LedgerDID string
}

// BuildBootstrap writes a fresh bootstrap.json + signer-key PEM
// into dir and returns the bundle metadata. n witnessDIDs must
// be supplied (typically Witnesses.DIDs()) so the bootstrap doc's
// genesis_witness_set field matches what the witness fixture
// will sign as. ExchangeDID + NetworkName are caller-controlled
// so different test cases can produce different NetworkIDs.
//
// On any failure, t.Fatalf is called — chaos tests want
// fail-loud, not error propagation.
func BuildBootstrap(t *testing.T, dir string, exchangeDID, networkName string, witnessDIDs []string) BootstrapBundle {
	t.Helper()
	if exchangeDID == "" {
		t.Fatal("BuildBootstrap: empty exchangeDID")
	}
	if networkName == "" {
		t.Fatal("BuildBootstrap: empty networkName")
	}
	if len(witnessDIDs) == 0 {
		t.Fatal("BuildBootstrap: empty witnessDIDs")
	}

	// Generate the ledger signer's private key (secp256k1).
	signerPriv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		t.Fatalf("BuildBootstrap: GenerateKey: %v", err)
	}
	signerDID, err := didKeyFromPriv(signerPriv)
	if err != nil {
		t.Fatalf("BuildBootstrap: derive ledger did:key: %v", err)
	}

	// PEM-encode the signer key in the format cmd/ledger/signers.go
	// reads at boot (x509 EC private key).
	signerPath := filepath.Join(dir, "ledger-signer.pem")
	if err := writeECPrivateKey(signerPath, signerPriv); err != nil {
		t.Fatalf("BuildBootstrap: write signer key: %v", err)
	}

	// Construct the bootstrap document.
	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       exchangeDID,
		NetworkName:       networkName,
		GenesisWitnessSet: append([]string(nil), witnessDIDs...),
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
	}
	// Validate by computing IDs — this surfaces malformed inputs
	// at construction time rather than at subprocess boot.
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("BuildBootstrap: bootstrap.IDs (validation): %v", err)
	}

	// Marshal + write.
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("BuildBootstrap: marshal bootstrap doc: %v", err)
	}
	bootstrapPath := filepath.Join(dir, "bootstrap.json")
	if err := os.WriteFile(bootstrapPath, body, 0o644); err != nil {
		t.Fatalf("BuildBootstrap: write bootstrap.json: %v", err)
	}

	return BootstrapBundle{
		BootstrapPath: bootstrapPath,
		SignerKeyPath: signerPath,
		NetworkID:     ids.NetworkID,
		LedgerDID:     signerDID,
	}
}

// writeECPrivateKey marshals an ECDSA private key to PEM in the
// format cmd/ledger/signers.go reads. Matches the SDK's
// signatures.EncodePEM convention: PKCS#8 wrapped, EC PRIVATE
// KEY block label.
func writeECPrivateKey(path string, priv *ecdsa.PrivateKey) error {
	// MarshalECPrivateKey serializes to SEC1 form. PEM block type
	// "EC PRIVATE KEY" is what x509.ParseECPrivateKey expects.
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	encoded := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// generateP256Key is a fallback for cases where the secp256k1
// curve registration is unavailable. Unused in production code
// paths; kept for tests that don't need protocol-grade curves.
func generateP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
