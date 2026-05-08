// Signer-key loading + DID derivation helpers.
//
// FILE PATH:
//
//	cmd/ledger/signers.go
//
// DESCRIPTION:
//
//	Three loaders, one DID-derivation helper. Each loader follows the
//	same shape: keyFile non-empty → load from disk; keyFile empty →
//	generate ephemeral + warn. Production deployments MUST use the
//	on-disk path so cryptographic identity is stable across restarts.
//
// CONTENTS:
//
//	loadOrGenerateTesseraSigner — checkpoint signer (Ed25519 via note.Signer).
//	loadOrGenerateLedgerSigner   — entry signer (secp256k1 ECDSA + did:key).
//	loadOrGenerateWitnessSigner  — witness cosign-server signer (ECDSA).
//	didKeyFromSecp256k1Priv      — composes did:key:z... from a private key.
//
// Extracted verbatim from cmd/ledger/main.go as part of the
// lifecycle-phase decomposition (P3). No behavioural change.
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/mod/sumdb/note"

	sdkcryptosigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	sdkdid "github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/ledger/tessera"
)

// loadOrGenerateTesseraSigner resolves the checkpoint signer.
// Priority:
//   - keyFile non-empty: load note.Signer from disk; fail if
//     unreadable. Production deployments MUST use this.
//   - keyFile empty: generate an ephemeral Ed25519 signer with a
//     loud warning log. Local-dev only — the verifier key is
//     printed once and lost on next restart.
//
// origin / logDID are used to derive the signer name when
// generating ephemerally (Tessera's signer name appears in every
// checkpoint and identifies the log).
func loadOrGenerateTesseraSigner(keyFile, origin, logDID string, logger *slog.Logger) (note.Signer, string, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read tessera signer key %q: %w", keyFile, err)
		}
		signer, err := note.NewSigner(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("parse tessera signer key %q: %w", keyFile, err)
		}
		logger.Info("tessera signer loaded from file", "key_file", keyFile, "name", signer.Name())
		return signer, "", nil
	}
	// Ephemeral fallback for local dev.
	name := origin
	if name == "" {
		name = logDID
	}
	signer, vkey, err := tessera.GenerateEphemeralSigner(name)
	if err != nil {
		return nil, "", err
	}
	logger.Warn("tessera signer is ephemeral — NOT for production",
		"name", signer.Name(),
		"verifier_key", vkey,
	)
	return signer, vkey, nil
}

// loadOrGenerateLedgerSigner resolves the ledger's entry signing key.
// The ledger signs its own entries (anchor commentary, commitment
// commentary) before submitting them to admission, which then
// verifies the signature via did.NewECDSAKeyResolver (SDK). Returns
// the private key plus the computed did:key:z... identifier — that
// string becomes cfg.LedgerDID at the composition root.
//
// Priority:
//   - keyFile non-empty: PEM-decode + x509.ParseECPrivateKey.
//     Production deployments MUST use this so the ledger's DID
//     is stable across restarts.
//   - keyFile empty: generate an ephemeral secp256k1 key and log a
//     warning. Local-dev only — entry consumers that pin the
//     ledger's DID will see a different DID on every restart.
func loadOrGenerateLedgerSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, string, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read ledger signer key %q: %w", keyFile, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, "", fmt.Errorf("ledger signer key %q: PEM decode failed", keyFile)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse ledger signer key %q: %w", keyFile, err)
		}
		didKey, err := didKeyFromSecp256k1Priv(priv)
		if err != nil {
			return nil, "", fmt.Errorf("encode did:key from %q: %w", keyFile, err)
		}
		logger.Info("ledger signer loaded from file", "key_file", keyFile, "did", didKey)
		return priv, didKey, nil
	}
	// Ephemeral fallback for local dev.
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		return nil, "", fmt.Errorf("generate ledger signer: %w", err)
	}
	didKey, err := didKeyFromSecp256k1Priv(priv)
	if err != nil {
		return nil, "", fmt.Errorf("encode did:key for ephemeral signer: %w", err)
	}
	logger.Warn("ledger signer is ephemeral — NOT for production",
		"did", didKey,
	)
	return priv, didKey, nil
}

// didKeyFromSecp256k1Priv composes a did:key:z... identifier from a
// secp256k1 private key. Same multibase + multicodec encoding the
// SDK's did.GenerateDIDKeySecp256k1 produces internally; this helper
// exists because the ledger threads in keys loaded from disk rather
// than generating them via the SDK constructor.
func didKeyFromSecp256k1Priv(priv *ecdsa.PrivateKey) (string, error) {
	uncompressed := sdkcryptosigs.PubKeyBytes(&priv.PublicKey)
	compressed, err := sdkcryptosigs.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return "", err
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}

// loadOrGenerateWitnessSigner resolves the witness cosign-server
// signing key. Distinct from the ledger's entry signer — this key
// signs cosign responses (witness/serve.go), and its public key
// fingerprint is what peer ledgers pin in their
// HeadSync.WitnessEndpoints set.
//
// Priority:
//   - keyFile non-empty: PEM-decode + x509.ParseECPrivateKey.
//     Production deployments MUST use this so the witness's identity
//     is stable across restarts.
//   - keyFile empty: generate ephemeral. Local-dev only; peers will
//     see a different witness fingerprint on each restart.
func loadOrGenerateWitnessSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read witness signer key %q: %w", keyFile, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("witness signer key %q: PEM decode failed", keyFile)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse witness signer key %q: %w", keyFile, err)
		}
		logger.Info("witness signer loaded from file", "key_file", keyFile)
		return priv, nil
	}
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate witness signer: %w", err)
	}
	logger.Warn("witness signer is ephemeral — NOT for production")
	return priv, nil
}
