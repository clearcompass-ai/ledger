/*
FILE PATH: gossipnet/equivocation_binding_pin_test.go

Drift-pin tests for the 0x0B equivocation-projection key: every
producer (the EquivocationScanner) and every consumer (the SDK's
findings.FetchEquivocationByBinding, the ledger's
GetEquivProjection callers) MUST compute the binding identically.

Before PT-3 the ledger re-implemented findings.EntryCommitmentBinding
locally as sha256SchemaSplit, "to avoid an import cycle." That
duplication is exactly the kind of silent drift this file pins —
if the SDK ever adds a domain separator to gossip.BindingHash,
this test fails loudly and the ledger follows.

The tests do not exercise the network path; they pin the wire
contract at the byte level.
*/
package gossipnet_test

import (
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// TestEquivocationBinding_LedgerMatchesSDK pins the byte-level
// equivalence between the SDK helper and the raw SHA-256 of
// (schemaID || splitID) the ledger previously open-coded. If the
// SDK changes BindingHash to add a domain separator, this test
// fails — and the ledger's projection key needs the same
// migration.
func TestEquivocationBinding_LedgerMatchesSDK(t *testing.T) {
	cases := []struct {
		name string
		schemaID string
		splitID [32]byte
	}{
		{"empty-split", "schema-x", [32]byte{}},
		{"common", "attesta.network/schema/pre-grant-commitment/v1",
			[32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"all-ones", "schema-y",
			[32]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			}},
		{"empty-schema", "", [32]byte{0xab, 0xcd}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Ledger-side construction (was sha256SchemaSplit
			// pre-PT-3): raw SHA-256(schemaID || splitID).
			var input []byte
			input = append(input, []byte(tc.schemaID)...)
			input = append(input, tc.splitID[:]...)
			ledgerWay := sha256.Sum256(input)

			// SDK-side construction.
			sdkWay := findings.EntryCommitmentBinding(tc.schemaID, tc.splitID)

			if ledgerWay != sdkWay {
				t.Errorf(
					"binding drift: ledger-bytes=%x sdk-bytes=%x — "+
						"the SDK helper now adds a domain separator or "+
						"changed its hash; the 0x0B projection key MUST "+
						"track the SDK to keep peer-published findings "+
						"and locally-detected findings sharing one key",
					ledgerWay, sdkWay)
			}
		})
	}
}

// TestEquivocationBinding_StableAcrossInvocations pins the
// determinism of the SDK helper itself — re-invoking with the
// same (schemaID, splitID) MUST produce the same bytes. Without
// this, a future BindingHash that introduced a salt would silently
// break detection.
func TestEquivocationBinding_StableAcrossInvocations(t *testing.T) {
	schemaID := "schema-stability"
	splitID := [32]byte{0x42}
	first := findings.EntryCommitmentBinding(schemaID, splitID)
	for i := 0; i < 10; i++ {
		got := findings.EntryCommitmentBinding(schemaID, splitID)
		if got != first {
			t.Fatalf("iter=%d: binding not stable: %x vs %x", i, got, first)
		}
	}
}

// TestEquivocationBinding_DistinctInputsDistinctOutputs sanity-
// checks that distinct (schema, split_id) tuples produce distinct
// bindings — the projection's keying assumption.
func TestEquivocationBinding_DistinctInputsDistinctOutputs(t *testing.T) {
	a := findings.EntryCommitmentBinding("schema-A", [32]byte{0x01})
	b := findings.EntryCommitmentBinding("schema-B", [32]byte{0x01})
	c := findings.EntryCommitmentBinding("schema-A", [32]byte{0x02})
	if a == b {
		t.Error("distinct schemaIDs collided")
	}
	if a == c {
		t.Error("distinct splitIDs collided")
	}
	if b == c {
		t.Error("schema+split swap collided")
	}
}
