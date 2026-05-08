/*
FILE PATH:

	cmd/ledger/fuzz_test.go

DESCRIPTION:

	J1 — Fuzz the network bootstrap document JSON parser. The
	bootstrap document is the administrator-supplied trust anchor
	(witness keys, NetworkID, K-of-N quorum); a parser bug here
	would let a hostile config file crash the boot path or
	silently corrupt the witness set.

	Run via:
	    go test -run=^$ -fuzz=^FuzzNetworkBootstrapJSON$ \
	        -fuzztime=30s ./cmd/ledger/

	Property: parser NEVER PANICS on arbitrary JSON-shaped input.
	A nil-deref or bounds violation in the deserializer is a
	bug; rejection (return err) is the desired outcome for
	invalid input.
*/
package main

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/attesta/network"
)

func FuzzNetworkBootstrapJSON(f *testing.F) {
	// Production-shaped seeds (minimal valid + minimal empty).
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"genesis_witness_set":[]}`))
	f.Add([]byte(`{"genesis_witness_set":["did:web:w1","did:web:w2"]}`))
	// Hostile seeds.
	f.Add([]byte(``))     // empty
	f.Add([]byte(`null`)) // null root
	f.Add([]byte(`[]`))   // wrong shape
	f.Add([]byte(`{`))    // truncated
	f.Add([]byte(`{"genesis_witness_set":null}`))
	f.Add([]byte(`{"genesis_witness_set":["",""]}`)) // empty DIDs
	// Deeply-nested JSON would otherwise blow the stack; use this
	// to confirm the parser respects encoding/json's depth cap.
	f.Add([]byte(`{"x":` + repeatBracket("{\"x\":", 100) + `null` + repeatBracket("}", 100) + `}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Cap input length so a 10-MiB fuzz blob doesn't OOM
		// the runner. Production-realistic bootstrap files are
		// well under 64 KiB.
		if len(raw) > 64*1024 {
			raw = raw[:64*1024]
		}
		var doc network.BootstrapDocument
		// We tolerate any error; the property is "no panic".
		// A failed parse returning err is a clean rejection.
		_ = json.Unmarshal(raw, &doc)
		// Property: even on success, the IDs() call must not
		// panic. This catches cases where parsing succeeds but
		// downstream derivation crashes on malformed-but-syntactically-valid
		// inputs (e.g., empty DID strings).
		_, _ = doc.IDs()
	})
}

func repeatBracket(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
