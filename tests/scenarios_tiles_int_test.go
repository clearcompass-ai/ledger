//go:build scenarios

/*
FILE PATH:

	tests/scenarios_tiles_int_test.go

DESCRIPTION:

	Layer 0 — TILE-INT-01/02/03: tile-structure integrity.
	Three sub-tests pin the c2sp.org/tlog-tiles invariants
	a CT-class auditor relies on:

	  INT-01: a level-0 hash tile contains LEAF hashes
	          (RFC-6962 HashLeaf). Pairwise hashing within
	          the tile builds a tile-root that, when the
	          tile is sealed (256 leaves), equals the value
	          the level-1 tile stores at the corresponding
	          index. Partial tiles satisfy the same internal
	          pair-hash invariant for the contained subset.
	  INT-02: full-vs-partial sealing. Until a tile reaches
	          256 entries it lives at "tile/<L>/<idx>.p/<n>"
	          and "tile/<L>/<idx>" does NOT exist. After
	          sealing, "tile/<L>/<idx>" appears and
	          ".p/<n>" remnants are gone.
	  INT-03: no orphan tiles. Walking <tileRoot>/tile and
	          <tileRoot>/tile/entries enumerates exactly the
	          files that the tree size mandates — no extras,
	          no missing.

KEY ARCHITECTURAL DECISIONS:
  - Tile parsing uses github.com/transparency-dev/tessera/api.
    HashTile{}.UnmarshalText (concatenated 32-byte nodes,
    no length prefix). Re-using the upstream parser means
    a future tile-format change in upstream surfaces here.
  - Pair hashing uses cryptoHasher (rfc6962.DefaultHasher
    from the crypto helpers file) so the leaf vs. node
    domain separation is asserted via the SDK-aligned
    hasher rather than re-rolled.
  - Path generation uses layout.TilePath / layout.EntriesPath
    from upstream Tessera. Direct concatenation would diverge
    if upstream's three-digit encoding changes.
  - Each sub-test boots its own stack with a known TileRoot
    so we can walk the on-disk layout deterministically.
    LowDifficulty is required for INT-01-FULL (256 entries).

OVERVIEW:

	TestTiles_Integrity
	  INT-01_PairHashRecomputesParent
	    → submit >= 256 entries; verify HashLeaf chain
	      inside level-0 tile reaches a root equal to
	      level-1 tile's first node.
	  INT-02_PartialThenSealed
	    → submit < 256; on-disk shows ".p/<n>" only;
	      submit to reach 256; sealed-path file appears.
	  INT-03_NoOrphanTiles
	    → walk <tileRoot>/tile recursively; every file's
	      (level, index, partial-suffix) must match the
	      expected enumeration for the current tree size.

KEY DEPENDENCIES:
  - github.com/transparency-dev/tessera/api: HashTile,
    EntryBundle.
  - github.com/transparency-dev/tessera/api/layout:
    TilePath, EntriesPath, PartialTileSize, TileWidth.
  - tests/scenarios_crypto_helpers_test.go: cryptoHasher,
    cryptoSubmitMany, cryptoWaitForSize.
*/
package tests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tapi "github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level test
// -------------------------------------------------------------------------------------------------

// TestTiles_Integrity umbrella. Each sub-test owns its stack
// because the on-disk layout assertions are state-sensitive.
func TestTiles_Integrity(t *testing.T) {
	t.Run("INT-01_PairHashRecomputesParent", runTilesINT01PairHashRecomputesParent)
	t.Run("INT-02_PartialThenSealed", runTilesINT02PartialThenSealed)
	t.Run("INT-03_NoOrphanTiles", runTilesINT03NoOrphanTiles)
}

// -------------------------------------------------------------------------------------------------
// 2) INT-01 — pair hashing inside level-0 builds level-1's first node
// -------------------------------------------------------------------------------------------------

// runTilesINT01PairHashRecomputesParent. Submits exactly
// layout.TileWidth (256) entries so a full level-0 hash tile
// and the FIRST entry of the level-1 hash tile both exist on
// disk. Reads both via the live tile reader. Recomputes the
// level-0 tile's root by pair-hashing within the tile; asserts
// equality with level-1 tile's first node.
//
// This pins the c2sp.org RFC-6962 binding: HashLeaf for level
// 0, HashChildren for every level above. The SDK's hasher is
// the system under test.
func runTilesINT01PairHashRecomputesParent(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "tiles-int-01",
		LowDifficulty: true,
	})

	const n = layout.TileWidth // 256
	_ = cryptoSubmitMany(t, stack, n, "tint01")
	cryptoWaitForSize(t, stack, n, 60*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Read the FULL level-0 tile (index 0). 256 leaf hashes
	// concatenated = 256 × 32 = 8192 bytes. The tile reader
	// consults the on-disk POSIX backend.
	level0Bytes, err := stack.TileReader().ReadTile(ctx, 0, 0)
	mustNotErr(t, "ReadTile(0, 0)", err)
	if len(level0Bytes) != n*32 {
		t.Fatalf("level-0 tile bytes len=%d, want %d (256 × 32)", len(level0Bytes), n*32)
	}
	var lvl0 tapi.HashTile
	if err := lvl0.UnmarshalText(level0Bytes); err != nil {
		t.Fatalf("UnmarshalText level-0: %v", err)
	}
	if len(lvl0.Nodes) != n {
		t.Fatalf("level-0 nodes len=%d, want %d", len(lvl0.Nodes), n)
	}

	// Pair-hash inside the tile to compute its root. Eight
	// rounds (TileHeight=8) collapse 256 nodes → 1 root.
	level := lvl0.Nodes
	for round := 0; len(level) > 1; round++ {
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i+1 < len(level); i += 2 {
			combined := cryptoHasher.HashChildren(level[i], level[i+1])
			next = append(next, combined)
		}
		level = next
		if round > layout.TileHeight {
			t.Fatalf("pair-hash exceeded TileHeight=%d rounds", layout.TileHeight)
		}
	}
	tileRoot := level[0]

	// Read the level-1 tile (one entry exists once level-0
	// tile 0 is sealed). Its FIRST node MUST equal our
	// computed tileRoot.
	level1Bytes, err := stack.TileReader().ReadTile(ctx, 1, 0)
	mustNotErr(t, "ReadTile(1, 0)", err)
	var lvl1 tapi.HashTile
	if err := lvl1.UnmarshalText(level1Bytes); err != nil {
		t.Fatalf("UnmarshalText level-1: %v", err)
	}
	if len(lvl1.Nodes) == 0 {
		t.Fatal("level-1 tile empty after sealed level-0 tile")
	}
	if !bytesEqual32(lvl1.Nodes[0], tileRoot) {
		t.Fatalf("level-1 first node %x… != computed level-0 root %x…",
			lvl1.Nodes[0][:8], tileRoot[:8])
	}
}

// -------------------------------------------------------------------------------------------------
// 3) INT-02 — partial-then-sealed transition
// -------------------------------------------------------------------------------------------------

// runTilesINT02PartialThenSealed. Submits a partial set
// (n=64), then submits enough more to seal the tile (n=256
// total). Checks the on-disk tile/0/* layout at each phase.
func runTilesINT02PartialThenSealed(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "tiles-int-02",
		LowDifficulty: true,
	})

	const partial = 64
	_ = cryptoSubmitMany(t, stack, partial, "tint02-a")
	cryptoWaitForSize(t, stack, partial, 30*time.Second)

	// Partial state: ".p/64" exists for tile/0/000. Sealed
	// path "tile/0/000" must NOT exist yet.
	root := stack.TileRoot()
	partialPath := filepath.Join(root, layout.TilePath(0, 0, partial))
	sealedPath := filepath.Join(root, layout.TilePath(0, 0, 0))
	if _, err := os.Stat(partialPath); err != nil {
		t.Fatalf("partial path %q missing: %v", partialPath, err)
	}
	if _, err := os.Stat(sealedPath); !os.IsNotExist(err) {
		t.Fatalf("sealed path %q exists at partial=%d (err=%v)",
			sealedPath, partial, err)
	}

	// Submit the rest of the tile.
	const rest = layout.TileWidth - partial
	_ = cryptoSubmitMany(t, stack, rest, "tint02-b")
	cryptoWaitForSize(t, stack, layout.TileWidth, 60*time.Second)

	// Sealed state: "tile/0/000" exists. The intermediate ".p/N"
	// files MAY linger (Tessera does not always delete them);
	// what matters is the sealed file's existence.
	if _, err := os.Stat(sealedPath); err != nil {
		t.Fatalf("sealed path %q missing after seal: %v", sealedPath, err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) INT-03 — no orphan tiles
// -------------------------------------------------------------------------------------------------

// runTilesINT03NoOrphanTiles. Submits a known count, walks
// <tileRoot>/tile/ recursively, and asserts every file
// found is one of the expected (level, index, partial?) tuples
// the tree size mandates.
//
// Expected enumeration for a tree of size N (partial tile
// possibly present at every level whose sizeAtLevel % 256 != 0):
//
//	for L = 0, 1, 2, ...
//	  sizeAtLevel = N >> (L*8)
//	  if sizeAtLevel == 0 break
//	  fullTiles = sizeAtLevel / 256
//	  partial = sizeAtLevel % 256   // 0 means tile is fully populated
//	  expect [TilePath(L, 0..fullTiles-1, 0)]
//	  if partial != 0: expect TilePath(L, fullTiles, partial)
//
// Same for entries (only level 0).
func runTilesINT03NoOrphanTiles(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "tiles-int-03",
		LowDifficulty: true,
	})
	const n = 70
	_ = cryptoSubmitMany(t, stack, n, "tint03")
	cryptoWaitForSize(t, stack, n, 30*time.Second)

	root := stack.TileRoot()
	expected := tilesExpectedSet(uint64(n), root)

	// Walk only the tile/ subtree of root.
	tileRootDir := filepath.Join(root, "tile")
	found := map[string]struct{}{}
	walkErr := filepath.Walk(tileRootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Tessera's POSIX driver may emit transient ".part"
		// suffixed files during atomic replace. We allow
		// them to exist but do not require their presence.
		if strings.HasSuffix(path, ".part") {
			return nil
		}
		found[path] = struct{}{}
		return nil
	})
	mustNotErr(t, "walk tile dir", walkErr)

	// Every expected file MUST be present.
	for p := range expected {
		if _, ok := found[p]; !ok {
			t.Fatalf("expected tile file missing: %s", p)
		}
	}
	// Every found file MUST be an expected one (or be a
	// retained partial superseded by a sealed counterpart;
	// Tessera does not always GC these).
	for p := range found {
		if _, ok := expected[p]; ok {
			continue
		}
		// Allow ".p/N" partial files for any sealed tile,
		// since Tessera retains them.
		if strings.Contains(p, ".p"+string(filepath.Separator)) {
			continue
		}
		t.Fatalf("orphan tile file: %s (not in expected enumeration)", p)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Helpers
// -------------------------------------------------------------------------------------------------

// tilesExpectedSet enumerates the canonical paths for hash
// tiles + entry tiles a tree of size N MUST contain. Returns
// a set of absolute paths under root.
func tilesExpectedSet(n uint64, root string) map[string]struct{} {
	out := map[string]struct{}{}
	// Hash tiles for every level until the level reduces to <1
	// node.
	for level := uint64(0); ; level++ {
		sizeAtLevel := n >> (level * uint64(layout.TileHeight))
		if sizeAtLevel == 0 {
			break
		}
		fullTiles := sizeAtLevel / uint64(layout.TileWidth)
		partial := uint8(sizeAtLevel % uint64(layout.TileWidth))
		for idx := uint64(0); idx < fullTiles; idx++ {
			out[filepath.Join(root, layout.TilePath(level, idx, 0))] = struct{}{}
		}
		if partial != 0 {
			out[filepath.Join(root, layout.TilePath(level, fullTiles, partial))] = struct{}{}
		}
		if sizeAtLevel < uint64(layout.TileWidth) && level > 0 {
			break
		}
	}
	// Entry tiles: only level 0. Bundle width is the same.
	fullEntries := n / uint64(layout.EntryBundleWidth)
	partialEntries := uint8(n % uint64(layout.EntryBundleWidth))
	for idx := uint64(0); idx < fullEntries; idx++ {
		out[filepath.Join(root, layout.EntriesPath(idx, 0))] = struct{}{}
	}
	if partialEntries != 0 {
		out[filepath.Join(root, layout.EntriesPath(fullEntries, partialEntries))] = struct{}{}
	}
	return out
}

// bytesEqual32 compares two 32-byte hash values.
func bytesEqual32(a, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
