//go:build scenarios

/*
FILE PATH:

	tests/scenarios_p2_proof_verify_test.go

DESCRIPTION:

	Layer 0 — Persona 2 (Browser-Class Auditor, proof verification +
	deterministic tile path). Two sub-scenarios that prove a downstream
	consumer in another language can:

	  1. Verify an inclusion proof using only crypto/sha256 + the
	     JSON-decoded {leaf_index, tree_size, hashes[]} returned by
	     GET /v1/tree/inclusion/{seq}, with the canonical leaf hash
	     derived from the entry wire bytes the producer originally
	     POSTed.

	  2. Recompute the c2sp.org/tlog-tiles tile path for level 0 from
	     a leaf index, fetch the tile bytes from the CDN with a plain
	     HTTP GET, and find the canonical leaf hash inside.

KEY ARCHITECTURAL DECISIONS:
  - p2VerifyInclusion is a fresh, in-file implementation of the
    RFC 6962 inclusion verifier. It deliberately does NOT call
    auditor.VerifyLeafInclusion (which lives one file away in the
    same package). The whole point of Persona 2 is to prove the
    verification can be done without ANY pre-existing helper —
    a TypeScript implementation would mirror this body line-for-
    line.
  - Tile-path encoding is reproduced inline as p2EncodeTileIndex.
    Same reason: the wire spec lives in c2sp.org/tlog-tiles; the
    Go SDK is one of many consumers; a regression in the Go
    encoder must not be papered over by reusing the encoder for
    the test.
  - RFC 6962 prefixes (0x00 leaf, 0x01 node) are local constants
    so a future reader can see the entire leaf-hash → root-hash
    derivation in this one file without cross-referencing.

OVERVIEW:

	runP2MerkleProofWithSHA256Only — submit, fetch /v1/tree/head +
	    /v1/tree/inclusion/{seq}, run p2VerifyInclusion, assert
	    the recomputed root equals head.root_hash.

	runP2TilePathDeterministic — for a known seq, compute the
	    level-0 tile path locally via p2EncodeTileIndex; fetch
	    from the CDN; assert canonical leaf-hash bytes appear in
	    the bytes; assert the path matches the SDK's HashTilePath
	    (regression guard against drift in either direction).

KEY DEPENDENCIES:
  - tests/scenarios_p2_minimal_auditor_test.go: shared parsers
    (p2FetchTreeHead / p2FetchInclusion) and TestPersona2_MinimalAuditor
    umbrella.
  - github.com/clearcompass-ai/ledger/tessera: HashTilePath, used
    ONLY for the regression guard, not for the path computation.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"

	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) RFC 6962 prefixes — local constants, no cross-file reuse
// -------------------------------------------------------------------------------------------------

// p2RFC6962LeafPrefix and p2RFC6962NodePrefix mirror RFC 6962 §2.1.
// Defined locally rather than reused from scenarios_auditor_test.go
// because the whole purpose of Persona 2 is "what would a minimal
// implementation in another language need to know?". The answer
// is: these two bytes, encoded inline.
const (
	p2RFC6962LeafPrefix byte = 0x00
	p2RFC6962NodePrefix byte = 0x01
)

// p2EntriesPerTile is the c2sp.org/tlog-tiles full-tile size. Any
// tile not at the rightmost frontier carries exactly 256 entries.
const p2EntriesPerTile uint64 = 256

// -------------------------------------------------------------------------------------------------
// 2) MerkleProofWithSHA256Only — fresh stdlib verifier
// -------------------------------------------------------------------------------------------------

// runP2MerkleProofWithSHA256Only proves a TypeScript / Rust / Python
// reimplementation of the verifier needs nothing beyond crypto/sha256
// and the JSON shapes documented at /v1/tree/head and
// /v1/tree/inclusion/{seq}. The signed canonical hash is read from
// the SCT body the ledger returned at submit time.
func runP2MerkleProofWithSHA256Only(t *testing.T, stack *scenariosStack) {
	t.Helper()
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   "did:example:p2-merkle-stdlib",
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, []byte("p2-merkle-stdlib"), stack.LogDID(), difficulty)

	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if sct.CanonicalHash != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch")
	}
	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mustNotErr(t, "WaitForCheckpoint", stack.WaitForCheckpoint(ctx, seq+1))

	head := p2FetchTreeHead(t, stack.LedgerBaseURL())
	prf := p2FetchInclusion(t, stack.LedgerBaseURL(), seq)

	rootBytes, err := hex.DecodeString(head.RootHashHex)
	mustNotErr(t, "decode root_hash", err)
	if len(rootBytes) != 32 {
		t.Fatalf("root_hash decoded len = %d, want 32", len(rootBytes))
	}
	var root [32]byte
	copy(root[:], rootBytes)

	siblings := make([][32]byte, 0, len(prf.Hashes))
	for i, h := range prf.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("hashes[%d] decode: %v", i, err)
		}
		if len(b) != 32 {
			t.Fatalf("hashes[%d] len = %d, want 32", i, len(b))
		}
		var s [32]byte
		copy(s[:], b)
		siblings = append(siblings, s)
	}

	if err := p2VerifyInclusion(canonical, seq, head.TreeSize, siblings, root); err != nil {
		t.Fatalf("p2VerifyInclusion: %v", err)
	}
}

// p2VerifyInclusion is a stdlib-only RFC 6962 inclusion verifier.
//
// Inputs:
//   - leafCanonical: the 32-byte SHA-256 of the entry wire bytes
//     (entry identity == SHA-256(wire); the ledger uses this as
//     the leaf payload before applying the leaf-hash prefix).
//   - idx, treeSize: leaf index and the tree size at proof time.
//   - siblings: the {leaf, tree_size, hashes[]} siblings slice
//     decoded from /v1/tree/inclusion's hashes[] field.
//   - root: the root hash to reach (decoded from
//     /v1/tree/head.root_hash).
//
// Algorithm: per RFC 6962 §2.1.1, hash the leaf with prefix 0x00,
// then walk the siblings, prefixing each combine with 0x01.
// The bit pattern of (idx, treeSize-1) controls the left/right
// orientation at each level.
func p2VerifyInclusion(leafCanonical [32]byte, idx, treeSize uint64, siblings [][32]byte, root [32]byte) error {
	if treeSize == 0 {
		return errors.New("p2VerifyInclusion: treeSize 0")
	}
	if idx >= treeSize {
		return fmt.Errorf("p2VerifyInclusion: idx %d >= treeSize %d", idx, treeSize)
	}

	hashed := sha256.Sum256(append([]byte{p2RFC6962LeafPrefix}, leafCanonical[:]...))
	pos := idx
	last := treeSize - 1
	pi := 0
	for last > 0 {
		if pi >= len(siblings) {
			return errors.New("p2VerifyInclusion: proof exhausted before root")
		}
		sib := siblings[pi]
		pi++
		var combined [32]byte
		if pos&1 == 1 || pos == last {
			combined = p2HashChildren(sib[:], hashed[:])
		} else {
			combined = p2HashChildren(hashed[:], sib[:])
		}
		hashed = combined
		pos >>= 1
		last >>= 1
	}
	if pi != len(siblings) {
		return fmt.Errorf("p2VerifyInclusion: %d unconsumed sibling(s)",
			len(siblings)-pi)
	}
	if hashed != root {
		return fmt.Errorf("p2VerifyInclusion: root mismatch (got %x want %x)",
			hashed[:8], root[:8])
	}
	return nil
}

// p2HashChildren computes SHA-256(0x01 || left || right). Local
// implementation; mirrors RFC 6962 §2.1 exactly.
func p2HashChildren(left, right []byte) [32]byte {
	var buf []byte
	buf = append(buf, p2RFC6962NodePrefix)
	buf = append(buf, left...)
	buf = append(buf, right...)
	return sha256.Sum256(buf)
}

// -------------------------------------------------------------------------------------------------
// 3) TilePathDeterministic — recompute c2sp path locally, fetch from CDN
// -------------------------------------------------------------------------------------------------

// runP2TilePathDeterministic submits one entry, derives the tile
// path locally via p2EncodeTileIndex, and fetches the resulting
// path from the CDN. Asserts the canonical leaf-hash bytes appear
// in the tile body. Then asserts our locally-computed path equals
// the SDK's HashTilePath — a guard against drift in either
// direction (if the SDK changes its encoder, this test trips; if
// our encoder drifts from the spec, this test trips).
func runP2TilePathDeterministic(t *testing.T, stack *scenariosStack) {
	t.Helper()
	if stack.CDNBaseURL() == "" {
		t.Fatal("runP2TilePathDeterministic: CDN not mounted (test misconfigured)")
	}
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   "did:example:p2-tilepath",
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, []byte("p2-tilepath"), stack.LogDID(), difficulty)
	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if sct.CanonicalHash != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch")
	}
	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mustNotErr(t, "WaitForCheckpoint", stack.WaitForCheckpoint(ctx, seq+1))

	tileIdx := seq / p2EntriesPerTile
	localPath := p2HashTilePath(0, tileIdx)
	sdkPath := optessera.HashTilePath(0, tileIdx)
	if localPath != sdkPath {
		t.Fatalf("tile path drift: local=%q sdk=%q", localPath, sdkPath)
	}

	// Fetch via the CDN. The path served by cdnFileServer is /tile/...
	// (it strips no prefix); HashTilePath returns "tile/0/..." so we
	// prepend a slash.
	url := stack.CDNBaseURL() + "/" + localPath
	tileBytes := p2FetchBytes(t, url)
	if len(tileBytes) == 0 {
		t.Fatalf("CDN returned 0 bytes for %s", url)
	}

	// Hash-only architecture: the level-0 hash tile holds Merkle
	// node hashes (NOT raw leaves). For canonical-hash presence we
	// fetch the entry tile too.
	entryURL := stack.CDNBaseURL() + "/" + optessera.EntryTilePath(tileIdx)
	entryBytes := p2FetchBytes(t, entryURL)
	if !p2BytesContain(entryBytes, canonical[:]) {
		t.Fatalf("entry tile (size=%d) missing canonical hash %x at seq=%d",
			len(entryBytes), canonical[:8], seq)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Local c2sp.org/tlog-tiles encoder
// -------------------------------------------------------------------------------------------------

// p2EncodeTileIndex reproduces the c2sp.org/tlog-tiles three-digit
// encoding inline. A reimplementation in another language has the
// entire logic visible in this one function:
//
//	0       → "000"
//	42      → "042"
//	1234    → "x001/234"
//	1234067 → "x001/x234/067"
//
// Non-final 3-digit groups carry the 'x' prefix indicating "full
// tile group"; the final group's prefix-or-absence is what tells a
// reader where to stop.
func p2EncodeTileIndex(index uint64) string {
	if index == 0 {
		return "000"
	}
	s := fmt.Sprintf("%d", index)
	for len(s)%3 != 0 {
		s = "0" + s
	}
	parts := make([]string, 0, len(s)/3)
	for i := 0; i < len(s); i += 3 {
		parts = append(parts, s[i:i+3])
	}
	for i := 0; i < len(parts)-1; i++ {
		parts[i] = "x" + parts[i]
	}
	return strings.Join(parts, "/")
}

// p2HashTilePath reproduces HashTilePath inline. tile/{level}/{N}.
func p2HashTilePath(level, index uint64) string {
	return fmt.Sprintf("tile/%d/%s", level, p2EncodeTileIndex(index))
}

// -------------------------------------------------------------------------------------------------
// 5) Stdlib byte-fetch helper
// -------------------------------------------------------------------------------------------------

// p2FetchBytes GETs url and returns the body. Fatals on any non-200
// or transport error. Caps the body at scenarioTileMaxBytes — the
// c2sp.org full-tile ceiling.
func p2FetchBytes(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	mustNotErr(t, "GET "+url, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("%s status=%d body=%s", url, resp.StatusCode, body)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, scenarioTileMaxBytes))
	mustNotErr(t, "read body", err)
	return body
}

// p2BytesContain reports whether haystack contains needle (32-byte
// canonical hash). bytes.Contains would suffice; this name
// documents the call site for the reader of the test body.
func p2BytesContain(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}
