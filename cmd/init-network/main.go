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
		"path to write (or load) the writer's witness EC private key in PEM form")
	outBootstrap := flag.String("out-bootstrap", ".run/network-bootstrap.json",
		"path to write the network BootstrapDocument JSON")
	logDID := flag.String("log-did", "did:attesta:ledger:local",
		"LogDID — used as exchange_did stand-in for local dev")
	networkName := flag.String("network-name", "local-dev",
		"network_name field of the BootstrapDocument")
	extraWitnesses := flag.Int("extra-witnesses", 0,
		"number of ADDITIONAL witness keys to generate (0 = single self-witness; "+
			"N = writer + N standalone witnesses). Keys are written to "+
			"<dir>/witness-<i>.pem under the directory of -out-witness-key.")
	flag.Parse()

	priv, generated, err := loadOrGenerateWitnessKey(*outWitnessKey)
	if err != nil {
		log.Fatalf("init-network: witness key: %v", err)
	}

	// did:key P-256 encoding: 33-byte compressed point.
	// crypto/ecdh.PublicKey.Bytes() returns the uncompressed
	// SEC1 form; we compress it via elliptic.MarshalCompressed.
	pubX, pubY := priv.X, priv.Y
	compressed := elliptic.MarshalCompressed(elliptic.P256(), pubX, pubY)
	writerWitnessDID := sdkdid.EncodeDIDKey(sdkdid.MulticodecP256, compressed)
	_ = ecdh.P256() // silence unused-import in case we later switch APIs

	// genesis_witness_set defines the NETWORK's witness fleet.
	// Two distinct topologies:
	//
	//   1. Single-instance dev (extra=0): the writer ledger ALSO
	//      serves /v1/cosign as its own witness (K=1 self-loop).
	//      The writer's DID is the single entry in the network's
	//      genesis witness set — i.e., the writer is the network's
	//      sole witness in this dev shortcut.
	//
	//   2. Multi-instance dev (extra=N>0): N standalone-witness
	//      processes hold the network's witness keys. The writer
	//      ledger is NOT a witness — it's purely a writer. Genesis
	//      set is the N standalone-witness DIDs only. Writer's
	//      own witness key (still generated above for code-path
	//      parity with single-instance mode) is NOT in the
	//      network's witness set.
	//
	// This is the SDK's network/ledger separation, made explicit:
	// the genesis witness set describes the network, not the
	// ledger.
	var genesisDIDs []string
	if *extraWitnesses == 0 {
		genesisDIDs = []string{writerWitnessDID}
	} else {
		genesisDIDs = make([]string, 0, *extraWitnesses)
	}

	extraKeyPaths := make([]string, 0, *extraWitnesses)
	for i := 1; i <= *extraWitnesses; i++ {
		path := extraWitnessKeyPath(*outWitnessKey, i)
		extraPriv, extraGen, kerr := loadOrGenerateWitnessKey(path)
		if kerr != nil {
			log.Fatalf("init-network: extra witness #%d (%s): %v", i, path, kerr)
		}
		extraCompressed := elliptic.MarshalCompressed(
			elliptic.P256(), extraPriv.X, extraPriv.Y)
		extraDID := sdkdid.EncodeDIDKey(sdkdid.MulticodecP256, extraCompressed)
		genesisDIDs = append(genesisDIDs, extraDID)
		extraKeyPaths = append(extraKeyPaths, path)
		fmt.Printf("init-network: network witness #%d %s = %s -> %s\n",
			i, ifGenerated(extraGen), path, extraDID)
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
	if err := os.WriteFile(*outBootstrap, append(body, '\n'), 0o644); err != nil {
		log.Fatalf("init-network: write bootstrap: %v", err)
	}

	fmt.Printf("init-network: writer key file    %s (%s)\n",
		ifGenerated(generated), *outWitnessKey)
	if *extraWitnesses == 0 {
		fmt.Printf("init-network: topology           = K=1 self-loop (writer is the network's sole witness)\n")
		fmt.Printf("init-network: writer witness did = %s\n", writerWitnessDID)
	} else {
		fmt.Printf("init-network: topology           = K=%d external witnesses (writer is NOT a witness)\n",
			*extraWitnesses)
		fmt.Printf("init-network: network witnesses  = %d standalone (key paths: %v)\n",
			*extraWitnesses, extraKeyPaths)
	}
	fmt.Printf("init-network: bootstrap          = %s\n", *outBootstrap)
}

// extraWitnessKeyPath derives "<dir>/witness-<i>.pem" relative to
// the writer's witness key path. Mirrors the convention
// scripts/run-local.sh consumes when --witnesses N is passed.
func extraWitnessKeyPath(writerKey string, i int) string {
	return fmt.Sprintf("%s/witnesses/witness-%d.pem",
		dirOf(writerKey), i)
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
