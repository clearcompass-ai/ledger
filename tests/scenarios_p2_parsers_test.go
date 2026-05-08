//go:build scenarios

/*
FILE PATH:

	tests/scenarios_p2_parsers_test.go

DESCRIPTION:

	Layer 0 — Persona 2 (Browser-Class Auditor, stdlib parsers).
	Hand-rolled stdlib-only parsers for the read-side endpoints
	Persona 2 consumes:

	  - GET /v1/tree/head             → p2FetchTreeHead
	  - GET /v1/tree/inclusion/{seq}  → p2FetchInclusion
	  - any JSON shape                → p2GetJSON

	Plus the small p2IsHexLen lowercase-hex predicate every JSON
	string field is checked through.

KEY ARCHITECTURAL DECISIONS:
  - Parsers live in their own file because Persona 2 is structured
    around "what can a downstream consumer in another language
    reproduce?". Parsers are the single most-reused surface across
    the four sub-files; isolating them makes that explicit.
  - map[string]any decoding, not Go-side struct tags. The whole
    point of Persona 2 is to refuse to inherit any struct-tag
    knowledge the SDK already encodes; if the SDK rebrands a
    JSON key tomorrow, this file must catch it.
  - Lowercase-hex enforcement. p2IsHexLen rejects uppercase. The
    ledger's writer emits lowercase hex; downstream consumers
    that emit uppercase would silently fail to round-trip; this
    parser pins the contract on the read side so a regression
    surfaces here, not in Production.
  - Two flavours of p2FetchTreeHead: the fatal-on-error variant
    (p2FetchTreeHead) for synchronous tests, and the
    error-returning variant (p2FetchTreeHeadAttempt) for
    goroutine-driven readers (ConcurrentReads_NoCorruption)
    that must not call t.Fatal off the main goroutine.

OVERVIEW:

	p2TreeHead              → struct of {TreeSize, RootHashHex,
	                          HashAlgo, RawSignatures}.
	p2FetchTreeHead         → fatal-on-error.
	p2FetchTreeHeadAttempt  → error-returning.
	p2InclusionProof        → struct of {LeafIndex, TreeSize, Hashes}.
	p2FetchInclusion        → fatal-on-error.
	p2GetJSON               → generic map[string]any.
	p2IsHexLen              → lowercase-hex length check.

KEY DEPENDENCIES:
  - encoding/json, net/http, io: stdlib only.
  - tests/scenarios_p2_minimal_auditor_test.go,
    tests/scenarios_p2_proof_verify_test.go,
    tests/scenarios_p2_cdn_test.go: callers.
  - tests/scenarios_skel_test.go: mustNotErr.
*/
package tests

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// 1) p2TreeHead — JSON shape pin for /v1/tree/head
// -------------------------------------------------------------------------------------------------

// p2TreeHead is the parsed /v1/tree/head response. JSON keys are
// pinned here so a wire-format regression breaks compilation, not
// a runtime assertion deep in a test.
type p2TreeHead struct {
	TreeSize      uint64
	RootHashHex   string
	HashAlgo      string
	RawSignatures any
}

// p2FetchTreeHead GETs /v1/tree/head, parses with stdlib, and
// fatals on any error / shape problem.
func p2FetchTreeHead(t *testing.T, baseURL string) p2TreeHead {
	t.Helper()
	h, err := p2FetchTreeHeadAttempt(baseURL)
	if err != nil {
		t.Fatalf("p2FetchTreeHead: %v", err)
	}
	return h
}

// p2FetchTreeHeadAttempt is the error-returning variant for callers
// (concurrent readers) that need to defer the t.Fatal decision.
func p2FetchTreeHeadAttempt(baseURL string) (p2TreeHead, error) {
	resp, err := http.Get(baseURL + "/v1/tree/head")
	if err != nil {
		return p2TreeHead{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return p2TreeHead{}, fmt.Errorf("status=%d body=%s", resp.StatusCode, body)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return p2TreeHead{}, fmt.Errorf("decode: %w", err)
	}
	ts, ok := raw["tree_size"].(float64)
	if !ok {
		return p2TreeHead{}, errors.New("missing tree_size in /v1/tree/head")
	}
	rh, ok := raw["root_hash"].(string)
	if !ok {
		return p2TreeHead{}, errors.New("missing root_hash in /v1/tree/head")
	}
	algo, _ := raw["hash_algo"].(string)
	return p2TreeHead{
		TreeSize:      uint64(ts),
		RootHashHex:   rh,
		HashAlgo:      algo,
		RawSignatures: raw["signatures"],
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 2) p2InclusionProof — JSON shape pin for /v1/tree/inclusion/{seq}
// -------------------------------------------------------------------------------------------------

// p2InclusionProof is the parsed /v1/tree/inclusion/{seq} response.
type p2InclusionProof struct {
	LeafIndex uint64
	TreeSize  uint64
	Hashes    []string
}

// p2FetchInclusion GETs /v1/tree/inclusion/{seq}, parses with stdlib.
func p2FetchInclusion(t *testing.T, baseURL string, seq uint64) p2InclusionProof {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/v1/tree/inclusion/%d", baseURL, seq))
	mustNotErr(t, "GET inclusion", err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("inclusion status=%d body=%s", resp.StatusCode, body)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("inclusion decode: %v", err)
	}
	li, _ := raw["leaf_index"].(float64)
	ts, _ := raw["tree_size"].(float64)
	rawH, _ := raw["hashes"].([]any)
	hashes := make([]string, 0, len(rawH))
	for i, h := range rawH {
		s, ok := h.(string)
		if !ok {
			t.Fatalf("inclusion hashes[%d] not a string: %T", i, h)
		}
		hashes = append(hashes, s)
	}
	return p2InclusionProof{LeafIndex: uint64(li), TreeSize: uint64(ts), Hashes: hashes}
}

// -------------------------------------------------------------------------------------------------
// 3) p2GetJSON — generic stdlib JSON GET
// -------------------------------------------------------------------------------------------------

// p2GetJSON is a tiny stdlib-only JSON GET helper for endpoints
// that return generic shapes. Fatals on any non-200.
func p2GetJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	mustNotErr(t, "GET "+url, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("%s status=%d body=%s", url, resp.StatusCode, body)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return raw
}

// -------------------------------------------------------------------------------------------------
// 4) p2IsHexLen — lowercase-hex predicate
// -------------------------------------------------------------------------------------------------

// p2IsHexLen returns true iff s consists exclusively of lowercase
// hex chars and is exactly want runes long. Persona 2 enforces
// lowercase to pin the wire contract; a downstream language
// implementation that emits uppercase hex would silently fail.
func p2IsHexLen(s string, want int) bool {
	if len(s) != want {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'))
	}) == -1
}
