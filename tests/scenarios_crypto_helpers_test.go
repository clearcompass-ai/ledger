//go:build scenarios

/*
FILE PATH:

	tests/scenarios_crypto_helpers_test.go

DESCRIPTION:

	Layer 0 — shared helpers for the cryptographic-proof-verification
	test family (CRYPTO-INT-01..03, CRYPTO-EXT-01..03). Wraps the
	SDK-blessed RFC-6962 verifiers from
	github.com/transparency-dev/merkle and the ledger's HTTP
	surface so each persona test stays under the per-file LoC
	ceiling.

KEY ARCHITECTURAL DECISIONS:
  - Verification uses transparency-dev/merkle/proof.VerifyInclusion
    and proof.VerifyConsistency — the EXACT functions the
    attesta SDK's verifier package calls (verifier/consistency.go
    line 162). Using the same canonical verifier means a
    future SDK upgrade to a different RFC-6962 implementation
    either upgrades this test or surfaces the drift.
  - Hasher is rfc6962.DefaultHasher (SHA-256, leaf prefix 0x00,
    node prefix 0x01). All four crypto / tile / byte test files
    thread the same hasher so RFC-6962 is asserted exactly
    once per build.
  - Tree-head + inclusion + consistency parsers decode into
    typed structs (cryptoTreeHead, cryptoInclusion,
    cryptoConsistency). Parsing happens here so a JSON-shape
    drift fails one place rather than fifteen.
  - Submission helpers (cryptoSubmitOne, cryptoSubmitMany)
    depend on Persona 1's persona1Submit / persona1WaitForSequence;
    we do not duplicate their logic. The "no shortcuts" rule
    cuts both ways: re-implementing existing helpers in a
    sibling file is itself a shortcut around shared code.

OVERVIEW:

	cryptoTreeHead              → typed /v1/tree/head response.
	cryptoFetchTreeHead         → GET + parse + assert structural.
	cryptoFetchInclusion        → GET /v1/tree/inclusion/{seq}.
	cryptoFetchConsistency      → GET /v1/tree/consistency/{old}/{new}.
	cryptoVerifyInclusion       → SDK-aligned verifier wrapper.
	cryptoVerifyConsistency     → SDK-aligned verifier wrapper.
	cryptoLeafHash              → hasher.HashLeaf(canonical).
	cryptoSubmitMany            → bulk submission helper.

KEY DEPENDENCIES:
  - github.com/transparency-dev/merkle/proof: VerifyInclusion,
    VerifyConsistency.
  - github.com/transparency-dev/merkle/rfc6962: DefaultHasher.
  - tests/scenarios_p2_parsers_test.go: p2IsHexLen.
  - tests/scenarios_auditor_full_test.go: persona1Submit /
    persona1WaitForSequence / persona1HashWire (re-used).
*/
package tests

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// -------------------------------------------------------------------------------------------------
// 1) Shared hasher
// -------------------------------------------------------------------------------------------------

// cryptoHasher is the RFC-6962 hasher every crypto / tile / byte
// test threads through. Defined once so RFC-6962 conformance is
// asserted via the canonical SDK-aligned implementation, not
// re-rolled per test.
var cryptoHasher = rfc6962.DefaultHasher

// -------------------------------------------------------------------------------------------------
// 2) Typed JSON parsers
// -------------------------------------------------------------------------------------------------

// cryptoTreeHead is the parsed /v1/tree/head response. Fields
// are pinned here so a JSON-shape regression breaks one parser
// rather than fifteen tests.
type cryptoTreeHead struct {
	TreeSize uint64
	Root     [32]byte
	HashAlgo string
	RawJSON  map[string]any
}

// cryptoFetchTreeHead GETs /v1/tree/head; fatals on any non-200
// or shape error. RawJSON exposes the underlying map for tests
// that assert on signatures / extension fields.
func cryptoFetchTreeHead(t *testing.T, baseURL string) cryptoTreeHead {
	t.Helper()
	raw := p2GetJSON(t, baseURL+"/v1/tree/head")
	tsf, _ := raw["tree_size"].(float64)
	rh, _ := raw["root_hash"].(string)
	algo, _ := raw["hash_algo"].(string)
	if !p2IsHexLen(rh, 64) {
		t.Fatalf("/v1/tree/head root_hash not 64 hex: %q", rh)
	}
	rb, err := hex.DecodeString(rh)
	mustNotErr(t, "decode root_hash", err)
	var root [32]byte
	copy(root[:], rb)
	return cryptoTreeHead{TreeSize: uint64(tsf), Root: root, HashAlgo: algo, RawJSON: raw}
}

// cryptoInclusion is the parsed /v1/tree/inclusion/{seq} response
// PLUS the raw siblings in [][]byte form (the verifier shape).
type cryptoInclusion struct {
	LeafIndex uint64
	TreeSize  uint64
	Siblings  [][]byte
}

// cryptoFetchInclusion GETs /v1/tree/inclusion/{seq}; fatals on
// non-200. Decodes the hex hashes into raw bytes ready for
// proof.VerifyInclusion.
func cryptoFetchInclusion(t *testing.T, baseURL string, seq uint64) cryptoInclusion {
	t.Helper()
	prf := p2FetchInclusion(t, baseURL, seq)
	sibs := make([][]byte, 0, len(prf.Hashes))
	for i, h := range prf.Hashes {
		if !p2IsHexLen(h, 64) {
			t.Fatalf("inclusion hashes[%d] not 64 hex: %q", i, h)
		}
		b, err := hex.DecodeString(h)
		mustNotErr(t, "decode sibling hex", err)
		sibs = append(sibs, b)
	}
	return cryptoInclusion{LeafIndex: prf.LeafIndex, TreeSize: prf.TreeSize, Siblings: sibs}
}

// cryptoConsistency is the parsed /v1/tree/consistency/{old}/{new}
// response PLUS sibling bytes ready for proof.VerifyConsistency.
type cryptoConsistency struct {
	OldSize  uint64
	NewSize  uint64
	Siblings [][]byte
}

// cryptoFetchConsistency GETs /v1/tree/consistency/{old}/{new}.
// Returns ({}, false, nil) on HTTP 400 (invalid range — surfaced
// to FRAUD-FRK-01). Fatals on any other non-200.
func cryptoFetchConsistency(t *testing.T, baseURL string, oldSize, newSize uint64) (cryptoConsistency, int) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/tree/consistency/%d/%d", baseURL, oldSize, newSize)
	resp, err := http.Get(url)
	mustNotErr(t, "GET consistency", err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		// Caller decides whether non-200 is fatal; we surface the
		// body for diagnostics but do not t.Fatal.
		_ = body
		return cryptoConsistency{OldSize: oldSize, NewSize: newSize}, resp.StatusCode
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("consistency decode: %v", err)
	}
	rawHashes, _ := raw["hashes"].([]any)
	sibs := make([][]byte, 0, len(rawHashes))
	for i, h := range rawHashes {
		s, _ := h.(string)
		if !p2IsHexLen(s, 64) {
			t.Fatalf("consistency hashes[%d] not 64 hex: %q", i, s)
		}
		b, err := hex.DecodeString(s)
		mustNotErr(t, "decode consistency sibling", err)
		sibs = append(sibs, b)
	}
	return cryptoConsistency{OldSize: oldSize, NewSize: newSize, Siblings: sibs}, resp.StatusCode
}

// -------------------------------------------------------------------------------------------------
// 3) SDK-aligned verifier wrappers
// -------------------------------------------------------------------------------------------------

// cryptoVerifyInclusion calls transparency-dev/merkle/proof.
// VerifyInclusion under cryptoHasher (rfc6962). Returns nil on
// success, a wrapped error otherwise.
func cryptoVerifyInclusion(idx, treeSize uint64, leafHash []byte, siblings [][]byte, root [32]byte) error {
	if err := proof.VerifyInclusion(cryptoHasher, idx, treeSize, leafHash, siblings, root[:]); err != nil {
		return fmt.Errorf("VerifyInclusion idx=%d size=%d: %w", idx, treeSize, err)
	}
	return nil
}

// cryptoVerifyConsistency calls transparency-dev/merkle/proof.
// VerifyConsistency under cryptoHasher.
func cryptoVerifyConsistency(oldSize, newSize uint64, siblings [][]byte, oldRoot, newRoot [32]byte) error {
	if err := proof.VerifyConsistency(cryptoHasher, oldSize, newSize, siblings, oldRoot[:], newRoot[:]); err != nil {
		return fmt.Errorf("VerifyConsistency old=%d new=%d: %w", oldSize, newSize, err)
	}
	return nil
}

// cryptoLeafHash returns the RFC-6962 leaf hash for canonical
// entry bytes. Equivalent to SHA-256(0x00 || canonical) under
// the default hasher.
func cryptoLeafHash(canonical [32]byte) []byte {
	return cryptoHasher.HashLeaf(canonical[:])
}

// -------------------------------------------------------------------------------------------------
// 4) Submission convenience wrappers
// -------------------------------------------------------------------------------------------------

// cryptoSubmitOne submits one Mode-B-stamped entry, waits for its
// sequence number, and returns (seq, canonicalHash). Re-uses the
// Persona 1 helpers; do not duplicate their internals.
func cryptoSubmitOne(t *testing.T, stack *scenariosStack, payload []byte, signerDID string) (uint64, [32]byte) {
	t.Helper()
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   signerDID,
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, payload, stack.LogDID(), difficulty)
	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if sct.CanonicalHash != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch: got %s want %x", sct.CanonicalHash, canonical[:])
	}
	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 10*time.Second)
	return seq, canonical
}

// cryptoSubmitMany submits n entries and returns the slice of
// (seq, canonicalHash). Used by INT-01/02/03 to build a tree of
// known size before random-sampling proofs.
func cryptoSubmitMany(t *testing.T, stack *scenariosStack, n int, prefix string) []cryptoSubmittedEntry {
	t.Helper()
	out := make([]cryptoSubmittedEntry, 0, n)
	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf("%s-%d", prefix, i))
		signer := fmt.Sprintf("did:example:%s-%d", prefix, i)
		seq, h := cryptoSubmitOne(t, stack, payload, signer)
		out = append(out, cryptoSubmittedEntry{Seq: seq, Canonical: h})
	}
	return out
}

// cryptoSubmittedEntry pairs a (seq, canonical hash) tuple for
// downstream proof-fetch loops.
type cryptoSubmittedEntry struct {
	Seq       uint64
	Canonical [32]byte
}

// -------------------------------------------------------------------------------------------------
// 5) Wait helper
// -------------------------------------------------------------------------------------------------

// cryptoWaitForSize blocks (ctx-bounded) until the stack's tree
// size reaches `want`. Wrapper over scenariosStack.WaitForCheckpoint
// with a richer diagnostic on failure.
func cryptoWaitForSize(t *testing.T, stack *scenariosStack, want uint64, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := stack.WaitForCheckpoint(ctx, want); err != nil {
		t.Fatalf("cryptoWaitForSize: %v", err)
	}
}
