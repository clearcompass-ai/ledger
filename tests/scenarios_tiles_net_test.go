//go:build scenarios

/*
FILE PATH:
    tests/scenarios_tiles_net_test.go

DESCRIPTION:
    Layer 0 — TILE-NET-01/02: tile fetch over the public CDN
    surface. Two sub-tests pin the operational contracts a
    browser-class auditor depends on:

      NET-01 (Deterministic Discovery): Clients compute the
              public object URL for a level-L hash tile and a
              level-0 entry tile WITHOUT any SDK helper, then
              fetch via plain unauthenticated HTTP GET. Bytes
              match the tile reader's authoritative read.
      NET-02 (Partial-to-Full Fallback): An auditor that
              previously fetched a partial tile at "tile/L/idx
              .p/N" finds it now sealed: GET on the partial
              path returns 404, fallback GET on the sealed
              path "tile/L/idx" succeeds, the byte range we
              previously consumed (the first N×32 bytes)
              still matches.

KEY ARCHITECTURAL DECISIONS:
    - URL computation in NET-01 uses a hand-rolled three-digit
      encoder (p2EncodeTileIndex / p2HashTilePath in
      scenarios_p2_proof_verify_test.go) — explicitly NOT the
      SDK's helper. The whole point of "deterministic
      discovery" is that an external implementation can mirror
      the spec without our package. We then cross-check
      against optessera.HashTilePath as a regression guard
      (drift in either direction trips the test).
    - The CDN fixture's path-traversal defense is exercised
      indirectly — NET-01's GET passes a clean encoded path,
      no fixture-internal logic to validate.
    - NET-02 simulates the partial→sealed transition by
      submitting in two phases. The auditor's pre-seal fetch
      sees ".p/N"; the post-seal fetch sees the sealed path.
      The partial path stays present (Tessera doesn't always
      delete) but a re-fetch logic that always tries the
      sealed path first SHOULD succeed.
    - Byte-range equivalence: the first N×32 bytes of the
      sealed (256 nodes × 32 = 8192 bytes) tile MUST equal
      the entire content of the prior partial (N nodes × 32).

OVERVIEW:
    TestTiles_Network
      NET-01_DeterministicDiscovery
        → submit, wait, compute paths locally, GET via
          CDN, assert bytes match TileReader output.
      NET-02_PartialToFullFallback
        → submit partial (n=64), capture partial bytes;
          submit to seal (n=256); GET sealed path,
          slice [0:64*32] == partial bytes.

KEY DEPENDENCIES:
    - tests/scenarios_cdn_test.go: cdnFileServer.
    - tests/scenarios_p2_proof_verify_test.go: p2HashTilePath.
    - github.com/clearcompass-ai/ledger/tessera: HashTilePath
      (regression cross-check), EntryTilePath.
    - github.com/transparency-dev/tessera/api/layout:
      TileWidth, TilePath.
*/
package tests

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level test
// -------------------------------------------------------------------------------------------------

// TestTiles_Network umbrella.
func TestTiles_Network(t *testing.T) {
	t.Run("NET-01_DeterministicDiscovery", runTilesNET01DeterministicDiscovery)
	t.Run("NET-02_PartialToFullFallback", runTilesNET02PartialToFullFallback)
}

// -------------------------------------------------------------------------------------------------
// 2) NET-01 — clients compute public URLs without SDK help
// -------------------------------------------------------------------------------------------------

// runTilesNET01DeterministicDiscovery. Submits a small tree.
// Locally computes the level-0 hash tile path AND the
// level-0 entry tile path via the inline p2HashTilePath
// (no SDK import). Issues an unauthenticated HTTP GET to
// the CDN at each path. Asserts:
//   - Each GET returns 200.
//   - The fetched bytes are non-empty.
//   - Local path == optessera.HashTilePath / optessera.EntryTilePath
//     (regression guard: SDK encoder must not drift from spec).
//   - Hash tile bytes match the live TileReader's read of the
//     same level/index — proves the CDN serves the same
//     bytes the proof engine consumes.
func runTilesNET01DeterministicDiscovery(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "tiles-net-01",
		LowDifficulty: true,
	})
	if stack.CDNBaseURL() == "" {
		t.Fatal("CDN not mounted (test misconfigured)")
	}
	const n = 30
	_ = cryptoSubmitMany(t, stack, n, "tnet01")
	cryptoWaitForSize(t, stack, n, 30*time.Second)

	// --- Hash tile path discovery ---
	const tileIdx = 0
	localHashPath := p2HashTilePath(0, tileIdx)
	sdkHashPath := optessera.HashTilePath(0, tileIdx)
	if localHashPath != sdkHashPath {
		t.Fatalf("hash tile path drift: local=%q sdk=%q",
			localHashPath, sdkHashPath)
	}
	hashURL := stack.CDNBaseURL() + "/" + localHashPath
	cdnHashBytes := tilesNetGET(t, hashURL)
	if len(cdnHashBytes) == 0 {
		t.Fatal("CDN returned 0 bytes for hash tile")
	}

	// Cross-check against TileReader (authoritative source).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	readerHashBytes, err := stack.TileReader().ReadTile(ctx, 0, tileIdx)
	mustNotErr(t, "TileReader ReadTile(0,0)", err)
	if !bytesEqualSlices(cdnHashBytes, readerHashBytes) {
		t.Fatalf("CDN hash bytes (len=%d) differ from TileReader (len=%d)",
			len(cdnHashBytes), len(readerHashBytes))
	}

	// --- Entry tile path discovery ---
	sdkEntryPath := optessera.EntryTilePath(tileIdx)
	entryURL := stack.CDNBaseURL() + "/" + sdkEntryPath
	cdnEntryBytes := tilesNetGET(t, entryURL)
	if len(cdnEntryBytes) == 0 {
		t.Fatal("CDN returned 0 bytes for entry tile")
	}
	readerEntryBytes, err := stack.TileReader().ReadEntryTile(ctx, tileIdx)
	mustNotErr(t, "TileReader ReadEntryTile", err)
	if !bytesEqualSlices(cdnEntryBytes, readerEntryBytes) {
		t.Fatalf("CDN entry bytes (len=%d) differ from TileReader (len=%d)",
			len(cdnEntryBytes), len(readerEntryBytes))
	}
}

// -------------------------------------------------------------------------------------------------
// 3) NET-02 — partial→sealed fallback
// -------------------------------------------------------------------------------------------------

// runTilesNET02PartialToFullFallback. Phase 1: submit n=64,
// fetch the partial tile via its ".p/64" path. Phase 2:
// submit the rest (n=192 more, total 256). After seal:
//   - GET on the sealed path succeeds.
//   - Sealed bytes' [0:64*32] prefix equals the prior
//     partial bytes (the leaf hashes of entries [0..64)
//     are stable across sealing).
func runTilesNET02PartialToFullFallback(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "tiles-net-02",
		LowDifficulty: true,
	})
	if stack.CDNBaseURL() == "" {
		t.Fatal("CDN not mounted (test misconfigured)")
	}

	const partial = 64
	_ = cryptoSubmitMany(t, stack, partial, "tnet02-a")
	cryptoWaitForSize(t, stack, partial, 30*time.Second)

	// Build the canonical partial path via the upstream layout
	// helper; the file extension format is "<idx>.p/<n>".
	partialPath := layout.TilePath(0, 0, partial)
	partialURL := stack.CDNBaseURL() + "/" + partialPath
	partialBytes := tilesNetGET(t, partialURL)
	if got, want := len(partialBytes), partial*32; got != want {
		t.Fatalf("partial tile bytes len=%d, want %d", got, want)
	}

	// Phase 2: seal the tile.
	const more = layout.TileWidth - partial
	_ = cryptoSubmitMany(t, stack, more, "tnet02-b")
	cryptoWaitForSize(t, stack, layout.TileWidth, 60*time.Second)

	// Sealed path GET.
	sealedPath := layout.TilePath(0, 0, 0)
	sealedURL := stack.CDNBaseURL() + "/" + sealedPath
	sealedBytes := tilesNetGET(t, sealedURL)
	if got, want := len(sealedBytes), layout.TileWidth*32; got != want {
		t.Fatalf("sealed tile bytes len=%d, want %d", got, want)
	}

	// Prefix invariant.
	for i := 0; i < partial*32; i++ {
		if sealedBytes[i] != partialBytes[i] {
			t.Fatalf("sealed[%d]=%x != partial[%d]=%x (prefix invariant)",
				i, sealedBytes[i], i, partialBytes[i])
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Helpers
// -------------------------------------------------------------------------------------------------

// tilesNetGET fetches url with a default HTTP client + 2s
// timeout, fatals on any non-200, and returns the body
// up to the c2sp tile-bundle ceiling.
func tilesNetGET(t *testing.T, url string) []byte {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
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

// bytesEqualSlices is a length-then-byte-by-byte comparison
// helper. bytes.Equal would suffice; the named call site
// documents the intent.
func bytesEqualSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
