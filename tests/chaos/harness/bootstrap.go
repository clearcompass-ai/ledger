/*
FILE PATH: tests/chaos/harness/bootstrap.go

Bootstrap document generation for chaos tests. The ledger
binary requires:

  LEDGER_NETWORK_BOOTSTRAP_FILE — JSON file path containing the
    network.BootstrapDocument (defines NetworkID + witness DIDs).

This file builds the bootstrap, writes it to disk, and returns
metadata the rest of the harness needs (NetworkID for witness
validation, file path to point the env var at).

LEDGER SIGNER KEY — INTENTIONALLY EPHEMERAL

We do NOT write a LEDGER_SIGNER_KEY_FILE. The ledger generates
an ephemeral secp256k1 key in-process when the env var is empty
(cmd/ledger/signers.go:117). For chaos tests this is the
correct trade-off:

  - Go's stdlib x509.MarshalECPrivateKey does not support
    secp256k1; only NIST P-curves. The SDK uses secp256k1, so
    there is no portable way to write a secp256k1 PEM the
    ledger's x509.ParseECPrivateKey path can read.

  - Chaos tests don't assert on the ledger's signer DID. The
    submitter's signing identity (Submitter.signerPriv) is
    constructed in-test and is stable; that's the DID that
    matters for kill-restart correctness.

  - The cost: across a kill-restart cycle, the ledger's own
    DID changes. If a chaos test scenario ever included a
    ledger-published anchor or commitment, the post-restart
    anchor would have a different SignerDID than pre-restart.
    No current chaos test exercises that path within its
    timeout window (anchor publisher runs on a periodic
    interval far longer than test wall-time).

If a future chaos test needs stable LEDGER_DID across restart,
the right fix is to write a secp256k1 PEM via a custom SEC1
ASN.1 marshaler — but that also requires the ledger's signer
loader to support the secp256k1 OID, which currently it does
not (it relies on Go stdlib x509.ParseECPrivateKey).
*/
package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/network"
)

// BootstrapBundle is everything needed to wire up a ledger
// subprocess: path to the JSON file (for env var) and the
// computed NetworkID (which the witness fixture also needs so
// it accepts incoming requests).
type BootstrapBundle struct {
	// BootstrapPath is the absolute path to the bootstrap.json
	// file. Set LEDGER_NETWORK_BOOTSTRAP_FILE to this.
	BootstrapPath string

	// NetworkID is the SHA-256 of the canonical bootstrap doc.
	// The witness fixture must be constructed with this NetworkID
	// in its AllowedNetworks set, otherwise cosign requests will
	// be rejected with a network-mismatch error.
	NetworkID cosign.NetworkID
}

// BuildBootstrap writes a fresh bootstrap.json into dir and
// returns the bundle metadata. n witnessDIDs must be supplied
// (typically Witnesses.DIDs()) so the bootstrap doc's
// genesis_witness_set field matches what the witness fixture
// will sign as. ExchangeDID + NetworkName are caller-controlled
// so different test cases can produce different NetworkIDs.
//
// On any failure, t.Fatalf is called.
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
	// Validate by computing IDs — surfaces malformed inputs at
	// construction time rather than at subprocess boot.
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("BuildBootstrap: bootstrap.IDs (validation): %v", err)
	}

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
		NetworkID:     ids.NetworkID,
	}
}

// _ ensures the fmt import is used when this file is otherwise
// trivially refactored; remove if unused after subsequent edits.
var _ = fmt.Sprintf

