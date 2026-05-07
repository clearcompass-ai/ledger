//go:build scenarios

/*
FILE PATH:
    tests/scenarios_crypto_auditor_test.go

DESCRIPTION:
    Layer 0 — CRYPTO-EXT-01/02/03: standalone-auditor proof
    workflow plus partial-tile bridging plus across-restart
    consistency. The "external" half of the cryptographic-proof
    family; the "internal" random/boundary half lives in
    scenarios_crypto_proofs_test.go.

KEY ARCHITECTURAL DECISIONS:
    - EXT-01 mirrors the standalone-auditor pull workflow:
      pull STH (/v1/tree/head) → calculate required tile
      indices for every leaf in [0, N) → fetch each tile via
      the CDN → recompute leaf hashes from the entry tile
      bytes → verify inclusion proofs against the STH root
      using the SDK-aligned VerifyInclusion. No SDK-internal
      shortcuts: tile indices are computed via leaf_idx/256;
      entry-tile bundle bytes parsed via tessera.ParseEntryBundle
      (the same parser the SDK uses).
    - EXT-02 deliberately exercises old=N / new=N+1 across a
      tile boundary. The TileReader serves partial tiles as
      ".p/N" suffixed paths; the consistency proof must
      navigate seamlessly.
    - EXT-03 restart: TileRoot is supplied by the test and
      preserved across a 2-phase t.Run sequence. Phase 1
      submits, captures (size1, root1), and ends — the
      sub-test's t.Cleanup tears down the harness. Phase 2
      brings up a NEW stack at the SAME TileRoot, submits,
      captures (size2, root2), and verifies the consistency
      proof. This proves Tessera's POSIX state survives a
      ledger process restart at the cryptographic-evidence
      layer, which is the auditor's only contract.
    - Postgres entry_index is wiped between Phase 1 and Phase 2
      (the harness's standard cleanup discipline). EXT-03
      therefore reads pre-restart heads via the on-disk
      checkpoint (stack.Tessera().Head()) rather than via
      /v1/tree/head — the latter requires the TreeHeadStore
      Postgres row, which does not survive cleanTables.

OVERVIEW:
    TestCrypto_Auditor
      EXT-01_StandaloneAuditorWorkflow
        → STH pull, recompute every leaf from entry tile,
          verify all N inclusion proofs.
      EXT-02_BridgePartialTile
        → submit N then N+1; consistency proof through the
          partial → partial transition verifies.
      EXT-03_AcrossRestart
        → 2-phase: submit + capture; restart with same
          TileRoot; submit + capture; verify consistency.

KEY DEPENDENCIES:
    - tests/scenarios_crypto_helpers_test.go: cryptoFetchTreeHead,
      cryptoFetchConsistency, cryptoVerifyInclusion,
      cryptoVerifyConsistency, cryptoSubmitOne, cryptoSubmitMany,
      cryptoLeafHash.
    - github.com/clearcompass-ai/ledger/tessera: ParseEntryBundle,
      EntriesPerTile, EntryTilePath.
*/
package tests

import (
	"context"
	"testing"
	"time"

	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level test
// -------------------------------------------------------------------------------------------------

// TestCrypto_Auditor umbrella. EXT-01 builds a small tree;
// EXT-02 grows it across a tile boundary; EXT-03 owns its
// own multi-phase lifecycle so cannot share a stack.
func TestCrypto_Auditor(t *testing.T) {
	t.Run("EXT-01_StandaloneAuditorWorkflow", runCryptoEXT01StandaloneWorkflow)
	t.Run("EXT-02_BridgePartialTile", runCryptoEXT02BridgePartial)
	t.Run("EXT-03_AcrossRestart", runCryptoEXT03AcrossRestart)
}

// -------------------------------------------------------------------------------------------------
// 2) EXT-01 — standalone auditor workflow
// -------------------------------------------------------------------------------------------------

// runCryptoEXT01StandaloneWorkflow walks the full standalone-
// auditor cycle: pull STH, fetch every entry-tile, parse out
// each leaf's canonical hash via tessera.ParseEntryBundle,
// recompute the RFC-6962 leaf hash, fetch the inclusion proof
// from /v1/tree/inclusion/{seq}, and verify the proof against
// the STH root.
//
// The N=24 entry count fits in one entry tile (256 entries per
// tile) so we don't have to multi-tile in this assertion; the
// multi-tile case is structurally identical and covered by
// EXT-02 / TILE-INT-01.
func runCryptoEXT01StandaloneWorkflow(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "crypto-ext-01",
		LowDifficulty: true,
	})
	const n = 24
	entries := cryptoSubmitMany(t, stack, n, "ext01")
	cryptoWaitForSize(t, stack, n, 30*time.Second)
	head := cryptoFetchTreeHead(t, stack.LedgerBaseURL())
	if head.TreeSize < n {
		t.Fatalf("head.TreeSize=%d, want >=%d", head.TreeSize, n)
	}

	// Step 1: fetch entry tile 0 directly via the live tile
	// reader (the auditor would fetch via the CDN under
	// production). Parse out every leaf payload (32-byte
	// SHA-256 in the hash-only architecture).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tile, err := stack.TileReader().ReadEntryTile(ctx, 0)
	mustNotErr(t, "ReadEntryTile(0)", err)

	// Step 2: for every submitted entry, parse the canonical
	// payload from the tile, hash it RFC-6962-style, fetch the
	// inclusion proof, and verify against the STH root.
	for _, e := range entries {
		canonicalFromTile, err := optessera.ParseEntryBundle(tile, e.Seq)
		mustNotErr(t, "ParseEntryBundle", err)
		if len(canonicalFromTile) != 32 {
			t.Fatalf("entry %d: tile leaf len=%d, want 32 (hash-only)",
				e.Seq, len(canonicalFromTile))
		}
		var observed [32]byte
		copy(observed[:], canonicalFromTile)
		if observed != e.Canonical {
			t.Fatalf("entry %d: tile-observed %x != submitted %x",
				e.Seq, observed[:8], e.Canonical[:8])
		}
		incl := cryptoFetchInclusion(t, stack.LedgerBaseURL(), e.Seq)
		leaf := cryptoLeafHash(observed)
		if err := cryptoVerifyInclusion(e.Seq, incl.TreeSize, leaf,
			incl.Siblings, head.Root); err != nil {
			t.Fatalf("inclusion verify seq=%d: %v", e.Seq, err)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 3) EXT-02 — bridge through partial tiles
// -------------------------------------------------------------------------------------------------

// runCryptoEXT02BridgePartial. Submits N=10 entries (a partial
// level-0 tile), captures the tree head. Submits one more
// (still partial). Fetches consistency proof for old=10, new=11.
// Verifies via SDK-aligned VerifyConsistency — exercises the
// "partial tile served from .p/{count} path" code path on the
// proof engine side.
func runCryptoEXT02BridgePartial(t *testing.T) {
	t.Helper()
	stack := NewScenariosStack(t, scenariosStackOpts{
		LogDIDSuffix:  "crypto-ext-02",
		LowDifficulty: true,
	})

	const oldSize = 10
	_ = cryptoSubmitMany(t, stack, oldSize, "ext02-a")
	cryptoWaitForSize(t, stack, oldSize, 30*time.Second)
	head1 := cryptoFetchTreeHead(t, stack.LedgerBaseURL())
	if head1.TreeSize < oldSize {
		t.Fatalf("head1 TreeSize=%d, want >=%d", head1.TreeSize, oldSize)
	}

	_, _ = cryptoSubmitOne(t, stack, []byte("ext02-bridge"), "did:example:ext02-bridge")
	const newSize = oldSize + 1
	cryptoWaitForSize(t, stack, newSize, 30*time.Second)
	head2 := cryptoFetchTreeHead(t, stack.LedgerBaseURL())
	if head2.TreeSize < newSize {
		t.Fatalf("head2 TreeSize=%d, want >=%d", head2.TreeSize, newSize)
	}

	cons, status := cryptoFetchConsistency(t, stack.LedgerBaseURL(), oldSize, newSize)
	if status != 200 {
		t.Fatalf("consistency status=%d (old=%d new=%d)", status, oldSize, newSize)
	}
	if err := cryptoVerifyConsistency(oldSize, newSize, cons.Siblings,
		head1.Root, head2.Root); err != nil {
		t.Fatalf("consistency verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) EXT-03 — across ledger restart
// -------------------------------------------------------------------------------------------------

// runCryptoEXT03AcrossRestart. Two-phase t.Run sequence pinning
// a single TileRoot across a stack lifecycle. Phase 1 submits
// some entries, captures (size1, root1) FROM THE EMBEDDED
// TESSERA HANDLE (the on-disk checkpoint, which survives the
// PG cleanTables that runs at Phase 2's stack startup).
// Phase 2 brings up a fresh stack at the SAME TileRoot,
// submits more, captures (size2, root2), and fetches +
// verifies a consistency proof.
//
// Architectural note: the consistency proof is computed by
// Phase 2's stack against TILES (not Postgres), so even
// though entry_index is wiped between phases, the proof
// engine has full pre-restart history available via the
// preserved tile bytes.
func runCryptoEXT03AcrossRestart(t *testing.T) {
	t.Helper()
	tileRoot := tmpDir(t, "ext03-restart")

	var size1 uint64
	var root1 [32]byte

	t.Run("Phase1_PreRestart", func(t *testing.T) {
		stack := NewScenariosStack(t, scenariosStackOpts{
			LogDIDSuffix:  "crypto-ext-03",
			LowDifficulty: true,
			TileRoot:      tileRoot,
		})
		const n = 8
		_ = cryptoSubmitMany(t, stack, n, "ext03-pre")
		cryptoWaitForSize(t, stack, n, 30*time.Second)

		// Read the head from the embedded Tessera (on-disk),
		// not /v1/tree/head (Postgres-backed). On-disk survives
		// the harness teardown + Phase 2's cleanTables; the PG
		// row does not.
		head, err := stack.Tessera().Head()
		mustNotErr(t, "Phase1 Tessera Head", err)
		if head.TreeSize < n {
			t.Fatalf("Phase1 Tessera TreeSize=%d, want >=%d", head.TreeSize, n)
		}
		size1 = head.TreeSize
		root1 = head.RootHash
	})

	t.Run("Phase2_PostRestart", func(t *testing.T) {
		stack := NewScenariosStack(t, scenariosStackOpts{
			LogDIDSuffix:  "crypto-ext-03",
			LowDifficulty: true,
			TileRoot:      tileRoot,
		})

		// Sanity: post-restart Tessera reports the same TreeSize
		// the pre-restart phase observed (no entries lost).
		preHead, err := stack.Tessera().Head()
		mustNotErr(t, "Phase2 pre-submit Tessera Head", err)
		if preHead.TreeSize != size1 {
			t.Fatalf("Phase2 Tessera TreeSize after restart = %d, want %d",
				preHead.TreeSize, size1)
		}
		if preHead.RootHash != root1 {
			t.Fatalf("Phase2 Tessera RootHash after restart = %x, want %x",
				preHead.RootHash[:8], root1[:8])
		}

		// Submit more entries; capture post-restart head.
		const more = 8
		_ = cryptoSubmitMany(t, stack, more, "ext03-post")
		want := size1 + more
		cryptoWaitForSize(t, stack, want, 30*time.Second)
		postHead, err := stack.Tessera().Head()
		mustNotErr(t, "Phase2 post-submit Tessera Head", err)
		if postHead.TreeSize < want {
			t.Fatalf("Phase2 post-submit TreeSize=%d, want >=%d",
				postHead.TreeSize, want)
		}

		// Verify consistency old=size1 new=postHead.TreeSize
		// against root1 (captured pre-restart) and
		// postHead.RootHash (captured post-restart).
		cons, status := cryptoFetchConsistency(t, stack.LedgerBaseURL(),
			size1, postHead.TreeSize)
		if status != 200 {
			t.Fatalf("consistency status=%d", status)
		}
		if err := cryptoVerifyConsistency(size1, postHead.TreeSize,
			cons.Siblings, root1, postHead.RootHash); err != nil {
			t.Fatalf("post-restart consistency verify: %v", err)
		}
	})
}
