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
	outDir := flag.String("out-dir", ".run",
		"directory to write witness keys + bootstrap doc into")
	outBootstrap := flag.String("out-bootstrap", "",
		"path to write the network BootstrapDocument JSON "+
			"(default: <out-dir>/network-bootstrap.json)")
	logDID := flag.String("log-did", "did:attesta:ledger:local",
		"LogDID — used as exchange_did stand-in for local dev")
	networkName := flag.String("network-name", "local-dev",
		"network_name field of the BootstrapDocument")
	witnessCount := flag.Int("witnesses", 1,
		"number of witness keys to generate. Each key is written to "+
			"<out-dir>/witnesses/witness-<i>.pem and its DID is added "+
			"to GenesisWitnessSet. The Ledger writer is NEVER in the "+
			"witness set — that's a network role, not a Ledger role.")
	flag.Parse()

	if *witnessCount < 1 {
		log.Fatalf("init-network: -witnesses must be >= 1 (a network without witnesses cannot finalise heads)")
	}

	bootstrapPath := *outBootstrap
	if bootstrapPath == "" {
		bootstrapPath = *outDir + "/network-bootstrap.json"
	}

	// Generate N witness keys and collect their DIDs. Every key is
	// genuinely network witness material: a standalone-witness daemon
	// will load the PEM file and serve /v1/cosign for the
	// corresponding DID. The Ledger writer holds NONE of these keys.
	_ = ecdh.P256() // silence unused-import in case we later switch APIs
	genesisDIDs := make([]string, 0, *witnessCount)
	keyPaths := make([]string, 0, *witnessCount)
	for i := 1; i <= *witnessCount; i++ {
		path := fmt.Sprintf("%s/witnesses/witness-%d.pem", *outDir, i)
		priv, generated, kerr := loadOrGenerateWitnessKey(path)
		if kerr != nil {
			log.Fatalf("init-network: witness #%d (%s): %v", i, path, kerr)
		}
		compressed := elliptic.MarshalCompressed(
			elliptic.P256(), priv.X, priv.Y)
		did := sdkdid.EncodeDIDKey(sdkdid.MulticodecP256, compressed)
		genesisDIDs = append(genesisDIDs, did)
		keyPaths = append(keyPaths, path)
		fmt.Printf("init-network: witness #%d %s = %s -> %s\n",
			i, ifGenerated(generated), path, did)
	}

	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       *logDID,
		NetworkName:       *networkName,
		GenesisWitnessSet: genesisDIDs,
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
	}
	// IDs() validates the document internally + returns the
	// derived (NetworkID, NetworkUUID, NetworkDID) — we discard
	// the IDs and use the validation as our gate.
	if _, vErr := doc.IDs(); vErr != nil {
		log.Fatalf("init-network: validate doc: %v", vErr)
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatalf("init-network: marshal: %v", err)
	}
	if err := os.MkdirAll(dirOf(bootstrapPath), 0o755); err != nil {
		log.Fatalf("init-network: mkdir bootstrap dir: %v", err)
	}
	if err := os.WriteFile(bootstrapPath, append(body, '\n'), 0o644); err != nil {
		log.Fatalf("init-network: write bootstrap: %v", err)
	}

	fmt.Printf("init-network: witnesses     = %d (key paths: %v)\n",
		*witnessCount, keyPaths)
	fmt.Printf("init-network: bootstrap     = %s\n", bootstrapPath)
}

// dirOf returns the directory portion of path. For
// ".run/witness.pem" it returns ".run".
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// ifGenerated returns "generated" or "loaded" — used in human
// log lines to make first-vs-subsequent runs distinguishable.
func ifGenerated(generated bool) string {
	if generated {
		return "generated"
	}
	return "loaded"
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
		priv, pErr := x509.ParseECPrivateKey(block.Bytes)
		if pErr != nil {
			return nil, false, fmt.Errorf("parse EC key %q: %w", path, pErr)
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
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, false, fmt.Errorf("mkdir %q: %w", dirOf(path), err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, false, fmt.Errorf("write %q: %w", path, err)
	}
	return priv, true, nil
}
