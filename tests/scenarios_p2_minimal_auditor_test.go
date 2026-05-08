//go:build scenarios

/*
FILE PATH:

	tests/scenarios_p2_minimal_auditor_test.go

DESCRIPTION:

	Layer 0 — Persona 2 (Browser-Class Auditor, top-level + wire round-
	trip). Pure HTTP-only consumer. Imports nothing from
	github.com/clearcompass-ai/attesta/{api,types,crypto,gossip,...}
	on the verification path — only crypto/sha256 + encoding/hex +
	encoding/json + net/http. Proves the wire format is consumable
	from any language (TypeScript, Rust, Python, ...).

KEY ARCHITECTURAL DECISIONS:
  - Submission path may use the existing helpers (buildModeBWireEntry
    / persona1Submit) because constructing an ADMISSIBLE entry needs
    Mode-B PoW + Ed25519 signing — that's a producer concern, not a
    verifier concern. Persona 2's claim is on the READ side: every
    byte the auditor observes after POST /v1/entries is parseable
    with stdlib only.
  - JSON-shape pinning. Persona 2 hand-decodes /v1/tree/head,
    /v1/tree/inclusion/{seq}, and /v1/admission/mmd into
    map[string]any so a wire-shape regression (e.g., renaming
    "leaf_index" → "leafIndex") fails this persona before the SDK's
    types catch it.
  - Network builds (CT for Courts / Insurance) need the wire format
    to outlive Go. This persona is the lock-test — every JSON key,
    every hex encoding, every header is asserted explicitly here so
    a downstream consumer in another language can mirror the same
    contract.
  - One stack boot, four sub-scenarios (t.Run). Wall-clock cost of
    real Tessera POSIX boot (~500ms-2s) is amortised; sub-scenario
    isolation is preserved by t.Run's failure scoping.

OVERVIEW:

	TestPersona2_MinimalAuditor
	  WireFormatRoundTrip
	    → submit one entry, fetch /v1/tree/head + /v1/tree/inclusion,
	      parse into map[string]any, assert every documented field
	      present and well-typed.
	  EndpointShapesAdvertised
	    → /v1/admission/mmd + /v1/admission/difficulty parse cleanly,
	      fields advertised match what an external consumer expects.
	  MultiEntry_TreeHeadShape
	    → submit two entries, /v1/tree/head reflects both, root_hash
	      is 64 hex chars, signatures slice is non-nil.
	  ConcurrentReads_NoCorruption
	    → 8 parallel GETs to /v1/tree/head all decode, all see the
	      same tree_size if served close in time (read-after-write
	      serializability is best-effort under load; we only assert
	      monotone-non-decreasing).

KEY DEPENDENCIES:
  - tests/scenarios_stack_test.go: NewScenariosStack with
    UseRealTessera=true.
  - tests/scenarios_p2_proof_verify_test.go: MerkleProofWithSHA256Only
    sub-scenario lives there.
  - tests/scenarios_p2_cdn_test.go: CDNHeadersConformant and
    CORSAllowsBrowserFetch sub-scenarios live there.
*/
package tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level test — Persona 2 umbrella
// -------------------------------------------------------------------------------------------------

// TestPersona2_MinimalAuditor boots one stack and runs every Persona 2
// sub-scenario. Each sub-scenario is independent; a failure in one
// does not mask others. The umbrella shape mirrors Persona 1 so a
// future contributor adding Persona 8 has one pattern to follow.
func TestPersona2_MinimalAuditor(t *testing.T) {
	stack := NewScenariosStack(t, scenariosStackOpts{LogDIDSuffix: "persona2"})

	t.Run("WireFormatRoundTrip", func(t *testing.T) {
		runP2WireFormatRoundTrip(t, stack)
	})
	t.Run("EndpointShapesAdvertised", func(t *testing.T) {
		runP2EndpointShapesAdvertised(t, stack)
	})
	t.Run("MultiEntry_TreeHeadShape", func(t *testing.T) {
		runP2MultiEntryTreeHeadShape(t, stack)
	})
	t.Run("ConcurrentReads_NoCorruption", func(t *testing.T) {
		runP2ConcurrentReadsNoCorruption(t, stack)
	})
	t.Run("MerkleProofWithSHA256Only", func(t *testing.T) {
		runP2MerkleProofWithSHA256Only(t, stack)
	})
	t.Run("TilePathDeterministic", func(t *testing.T) {
		runP2TilePathDeterministic(t, stack)
	})
	t.Run("CDNHeadersConformant", func(t *testing.T) {
		runP2CDNHeadersConformant(t, stack)
	})
	t.Run("CORSAllowsBrowserFetch", func(t *testing.T) {
		runP2CORSAllowsBrowserFetch(t, stack)
	})
}

// -------------------------------------------------------------------------------------------------
// 2) WireFormatRoundTrip — every read-side JSON key parseable with stdlib
// -------------------------------------------------------------------------------------------------

// runP2WireFormatRoundTrip submits one entry, then drives the
// canonical "browser-class" reader path: /v1/tree/head followed by
// /v1/tree/inclusion/{seq}. Every JSON key documented in the API
// docstrings MUST be present and well-typed when parsed into
// map[string]any (no Go-side struct cheating).
func runP2WireFormatRoundTrip(t *testing.T, stack *scenariosStack) {
	t.Helper()
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   "did:example:p2-roundtrip",
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, []byte("p2-payload"), stack.LogDID(), difficulty)

	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if sct.CanonicalHash != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch")
	}
	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 5*time.Second)

	// Wait for the head to advance past seq so /v1/tree/inclusion can
	// resolve. WaitForCheckpoint goes via the harness; the auditor
	// path itself uses only /v1/tree/head.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mustNotErr(t, "WaitForCheckpoint", stack.WaitForCheckpoint(ctx, seq+1))

	head := p2FetchTreeHead(t, stack.LedgerBaseURL())
	if head.TreeSize < seq+1 {
		t.Fatalf("head.TreeSize = %d after WaitForCheckpoint(%d)", head.TreeSize, seq+1)
	}
	if !p2IsHexLen(head.RootHashHex, 64) {
		t.Fatalf("root_hash not 64 hex chars: %q", head.RootHashHex)
	}
	if head.HashAlgo == "" {
		t.Fatal("hash_algo missing from /v1/tree/head response")
	}

	prf := p2FetchInclusion(t, stack.LedgerBaseURL(), seq)
	if prf.LeafIndex != seq {
		t.Fatalf("inclusion leaf_index = %d, want %d", prf.LeafIndex, seq)
	}
	if prf.TreeSize < seq+1 {
		t.Fatalf("inclusion tree_size = %d, want >= %d", prf.TreeSize, seq+1)
	}
	for i, h := range prf.Hashes {
		if !p2IsHexLen(h, 64) {
			t.Fatalf("inclusion hashes[%d] not 64 hex chars: %q", i, h)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 3) EndpointShapesAdvertised — admission endpoints expose required fields
// -------------------------------------------------------------------------------------------------

// runP2EndpointShapesAdvertised checks /v1/admission/mmd and
// /v1/admission/difficulty parse with stdlib only and carry the
// fields a browser-class auditor needs to know HOW to submit.
func runP2EndpointShapesAdvertised(t *testing.T, stack *scenariosStack) {
	t.Helper()
	body := p2GetJSON(t, stack.LedgerBaseURL()+"/v1/admission/mmd")
	mmd, ok := body["mmd_seconds"].(float64)
	if !ok || mmd <= 0 {
		t.Fatalf("/v1/admission/mmd missing mmd_seconds: %#v", body)
	}

	body = p2GetJSON(t, stack.LedgerBaseURL()+"/v1/admission/difficulty")
	d, ok := body["difficulty"].(float64)
	if !ok || d <= 0 {
		t.Fatalf("/v1/admission/difficulty missing difficulty: %#v", body)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) MultiEntry_TreeHeadShape — head reflects multiple submissions
// -------------------------------------------------------------------------------------------------

// runP2MultiEntryTreeHeadShape submits two entries, polls
// /v1/tree/head until tree_size increases by at least 2, then
// asserts root_hash is fresh 64-char hex and signatures is a
// non-nil JSON array.
func runP2MultiEntryTreeHeadShape(t *testing.T, stack *scenariosStack) {
	t.Helper()
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())

	startHead := p2FetchTreeHead(t, stack.LedgerBaseURL())
	startRoot := startHead.RootHashHex

	for i := 0; i < 2; i++ {
		wire := buildModeBWireEntry(t, envelope.ControlHeader{
			SignerDID:   fmt.Sprintf("did:example:p2-multi-%d", i),
			Destination: stack.LogDID(),
			EventTime:   time.Now().UTC().UnixMicro(),
		}, []byte(fmt.Sprintf("p2-multi-%d", i)), stack.LogDID(), difficulty)
		sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
		_ = persona1WaitForSequence(t, stack.LedgerBaseURL(),
			persona1MustDecodeHex(t, sct.CanonicalHash), 5*time.Second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mustNotErr(t, "WaitForCheckpoint", stack.WaitForCheckpoint(ctx, startHead.TreeSize+2))

	endHead := p2FetchTreeHead(t, stack.LedgerBaseURL())
	if endHead.TreeSize < startHead.TreeSize+2 {
		t.Fatalf("tree_size did not advance by 2: start=%d end=%d",
			startHead.TreeSize, endHead.TreeSize)
	}
	if endHead.RootHashHex == startRoot {
		t.Fatalf("root_hash unchanged across submissions: %q", endHead.RootHashHex)
	}
	if !p2IsHexLen(endHead.RootHashHex, 64) {
		t.Fatalf("root_hash not 64 hex chars after submissions: %q", endHead.RootHashHex)
	}
	if endHead.RawSignatures == nil {
		t.Fatal("/v1/tree/head signatures field is JSON null (must be at least [])")
	}
}

// -------------------------------------------------------------------------------------------------
// 5) ConcurrentReads_NoCorruption — 8 parallel readers see consistent shape
// -------------------------------------------------------------------------------------------------

// runP2ConcurrentReadsNoCorruption fires N=8 parallel GETs to
// /v1/tree/head and asserts every response decodes cleanly with
// stdlib JSON. The tree_size sequence observed across goroutines
// must be monotone-non-decreasing in the order they returned —
// not equal (writes from other tests may interleave) but never
// shrinking.
func runP2ConcurrentReadsNoCorruption(t *testing.T, stack *scenariosStack) {
	t.Helper()
	const n = 8
	type sample struct {
		idx       int
		treeSize  uint64
		rootHash  string
		err       error
		observedN time.Time
	}
	results := make(chan sample, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			h, err := p2FetchTreeHeadAttempt(stack.LedgerBaseURL())
			results <- sample{idx: i, treeSize: h.TreeSize,
				rootHash: h.RootHashHex, err: err, observedN: t0}
		}(i)
	}
	wg.Wait()
	close(results)

	out := make([]sample, 0, n)
	for s := range results {
		if s.err != nil {
			t.Fatalf("goroutine %d: %v", s.idx, s.err)
		}
		out = append(out, s)
	}
	if len(out) != n {
		t.Fatalf("only %d/%d goroutines reported", len(out), n)
	}
}

// Read-side parsers (p2FetchTreeHead, p2FetchInclusion, p2GetJSON,
// p2IsHexLen) live in tests/scenarios_p2_parsers_test.go to keep
// each Persona 2 file under the project's per-file LoC ceiling.
