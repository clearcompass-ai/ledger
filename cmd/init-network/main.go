/*
FILE PATH:

	cmd/init-network/main.go

DESCRIPTION:

	One-shot bootstrap-doc + witness-key generator for local
	dev. Produces a self-witness K=1 topology that
	scripts/run-local.sh consumes:

	    ./bin/init-network \
	        -out-witness-key=.run/witness.pem \
	        -out-bootstrap=.run/network-bootstrap.json \
	        -log-did=did:attesta:ledger:local

	Idempotent on the witness key: re-runs preserve the
	existing key file, derive the SAME did:key from it, and
	rewrite the bootstrap doc (which depends on the DID).

KEY ARCHITECTURAL DECISIONS:
  - Mirrors loadOrGenerateWitnessSigner in cmd/ledger/main.go:
    same secp256k1 key shape (PEM-encoded EC private key) so
    the ledger consumes whatever this tool produces without
    a translation layer.
  - DID derivation reuses didKeyFromSecp256k1Priv-equivalent
    logic via the SDK's did.EncodeDIDKey + multicodec.
  - Bootstrap doc is the minimum-viable shape: protocol_version
  - exchange_did + network_name + genesis_witness_set
    (single-element) + zero-tree-head. Sufficient for
    single-node K=1 dev; production deployments use a real
    Exchange-issued bootstrap.

OVERVIEW:

	Output:
	  .run/witness.pem            — secp256k1 EC private key (PEM)
	  .run/network-bootstrap.json — BootstrapDocument with the
	                                derived did:key in genesis_witness_set
*/
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	sdkdid "github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/network"
)

func main() {
	outWitnessKey := flag.String("out-witness-key", ".run/witness.pem",
		"path to write (or load) the witness EC private key in PEM form")
	outBootstrap := flag.String("out-bootstrap", ".run/network-bootstrap.json",
		"path to write the network BootstrapDocument JSON")
	logDID := flag.String("log-did", "did:attesta:ledger:local",
		"LogDID — used as exchange_did stand-in for local dev")
	networkName := flag.String("network-name", "local-dev",
		"network_name field of the BootstrapDocument")
	flag.Parse()

	priv, generated, err := loadOrGenerateWitnessKey(*outWitnessKey)
	if err != nil {
		log.Fatalf("init-network: witness key: %v", err)
	}

	// did:key P-256 encoding: 33-byte compressed point.
	// crypto/ecdh.PublicKey.Bytes() returns the uncompressed
	// SEC1 form; we compress it via elliptic.MarshalCompressed.
	pubX, pubY := priv.PublicKey.X, priv.PublicKey.Y
	compressed := elliptic.MarshalCompressed(elliptic.P256(), pubX, pubY)
	witnessDID := sdkdid.EncodeDIDKey(sdkdid.MulticodecP256, compressed)
	_ = ecdh.P256() // silence unused-import in case we later switch APIs

	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       *logDID,
		NetworkName:       *networkName,
		GenesisWitnessSet: []string{witnessDID},
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
	}
	// IDs() validates the document internally + returns the
	// derived (NetworkID, NetworkUUID, NetworkDID) — we discard
	// the IDs and use the validation as our gate.
	if _, err := doc.IDs(); err != nil {
		log.Fatalf("init-network: validate doc: %v", err)
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatalf("init-network: marshal: %v", err)
	}
	if err := os.WriteFile(*outBootstrap, append(body, '\n'), 0o644); err != nil {
		log.Fatalf("init-network: write bootstrap: %v", err)
	}

	keyAction := "loaded"
	if generated {
		keyAction = "generated"
	}
	fmt.Printf("init-network: witness key %s (%s)\n", keyAction, *outWitnessKey)
	fmt.Printf("init-network: witness did  = %s\n", witnessDID)
	fmt.Printf("init-network: bootstrap    = %s\n", *outBootstrap)
}

// loadOrGenerateWitnessKey loads a PEM-encoded EC private key
// from path, OR generates a fresh one and writes it. Returns
// the key + a flag indicating whether it was newly generated.
func loadOrGenerateWitnessKey(path string) (*ecdsa.PrivateKey, bool, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, false, fmt.Errorf("decode PEM %q: nil block", path)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("parse EC key %q: %w", path, err)
		}
		return priv, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read %q: %w", path, err)
	}

	// Generate fresh — NIST P-256 (compatible with x509.Marshal/
	// ParseECPrivateKey which is what cmd/ledger's
	// loadOrGenerateWitnessSigner uses for the file-load path).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, false, fmt.Errorf("marshal EC key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, false, fmt.Errorf("write %q: %w", path, err)
	}
	return priv, true, nil
}
