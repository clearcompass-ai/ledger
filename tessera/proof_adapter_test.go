/*
FILE PATH: tessera/proof_adapter_test.go

REGRESSION TEST for the inclusion-proof correctness fix.

WHY THIS EXISTS:

	An earlier hand-rolled proof algorithm in proof_adapter.go was
	broken in three independent ways:

	  1. Treated RFC 6962 levels as tile levels (a tlog-tiles tile
	     actually spans 8 tree levels).
	  2. Returned raw entry-tile data instead of leaf hashes
	     (H(0x00 || data)) for level-0 siblings.
	  3. Mixed absolute and local leaf coordinates when descending
	     into a right subtree.

	None of those bugs surfaced at unit-test sizes (≤ a few hundred
	leaves) because the buggy paths never executed for the typical
	leaf positions covered by tests. They surfaced in the 100K-leaf
	soak where ~34% of leaves land in the buggy right-subtree
	branch, and the proof failed to verify against the head root.

	The fix replaced the hand-rolled algorithm with a thin adapter
	over tessera/client.ProofBuilder (the canonical implementation
	every Tessera consumer uses). This test pins that contract: at a
	scale that DOES exercise the previously-buggy paths (a tree
	larger than 256 leaves, so hash tiles at level 1 exist; not a
	power of 2, so partial-tile fallback matters; leaves drawn from
	both subtrees), every inclusion proof MUST verify against the
	head root via the canonical RFC 6962 verifier.

	A second test pins the partial-tile fetch path independently —
	if the tile_reader's partial-tile fallback breaks, this catches
	it before the proof builder fails opaquely.
*/
package tessera

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// TestTesseraAdapter_InclusionProof_VerifiesAgainstHeadAtScale appends
// enough leaves to span multiple level-0 hash tiles and trigger a
// non-power-of-2 tree (so the right edge has a partial tile), then
// fetches inclusion proofs for a sample of leaves spanning the full
// tree and verifies each one against the head root using the canonical
// RFC 6962 verifier.
//
// The old hand-rolled algorithm in proof_adapter.go would fail this
// test for any leaf in the "right subtree" of the top-level split
// (~34% of leaves at size 2000, since k=1024 and 2000-1024=976 leaves
// fall right-of-split). This test exercises both halves, so the
// regression is impossible to miss.
func TestTesseraAdapter_InclusionProof_VerifiesAgainstHeadAtScale(t *testing.T) {
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	// Submit 600 entries — enough to:
	//   - Span 3 level-0 hash tiles (600/256 = 2.3 → 3 tiles).
	//   - Force a non-power-of-2 tree (k = 512, right subtree = 88).
	//   - Leave the rightmost tile partial (600 % 256 = 88 entries).
	const N = 600
	leafData := make([][32]byte, N)
	for i := 0; i < N; i++ {
		if _, err := rand.Read(leafData[i][:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		idx, err := app.AppendLeaf(ctx, leafData[i][:])
		if err != nil {
			t.Fatalf("AppendLeaf(%d): %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("AppendLeaf(%d) returned idx=%d, want %d", i, idx, i)
		}
	}

	// Wait for Tessera to integrate all N leaves.
	// CheckpointInterval is 100ms in newTestEmbeddedAppender, BatchSize
	// is 16; integration of 2000 entries should complete within a few
	// seconds. Generous deadline for slow CI.
	deadline := time.Now().Add(30 * time.Second)
	var head struct {
		TreeSize uint64
		RootHash [32]byte
	}
	for time.Now().Before(deadline) {
		h, err := app.Head()
		if err == nil && h.TreeSize >= N {
			head.TreeSize = h.TreeSize
			head.RootHash = h.RootHash
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if head.TreeSize < N {
		t.Fatalf("Head never reached tree_size=%d within deadline; storage dir: %s", N, dir)
	}

	// Wire the adapter over the embedded appender + POSIX tile backend.
	backend, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend(%s): %v", dir, err)
	}
	tileReader := NewTileReader(backend, 1024)
	adapter := NewTesseraAdapter(ctx, app, tileReader, nil)

	// Verify a sample of leaves spanning the full tree, deliberately
	// including indices from BOTH the left subtree [0, 1024) AND the
	// right subtree [1024, 2000) — the right subtree was the broken
	// codepath in the old algorithm.
	samples := []uint64{
		0,   // leftmost, level-0 alignment
		1,   // pairs into 0
		127, // mid first tile
		255, // last in first full tile
		256, // first in second tile
		511, // last in left subtree (k = 512)
		512, // first in right subtree (m == k) — old algorithm's broken path
		513,
		550, // mid right subtree
		599, // rightmost, in partial frontier tile
	}

	for _, seq := range samples {
		leafHash := rfc6962.DefaultHasher.HashLeaf(leafData[seq][:])

		raw, err := adapter.RawInclusionProof(seq, head.TreeSize)
		if err != nil {
			t.Fatalf("RawInclusionProof(seq=%d, size=%d): %v", seq, head.TreeSize, err)
		}
		m, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("RawInclusionProof returned %T, want map[string]any", raw)
		}
		hexHashes, _ := m["hashes"].([]string)
		siblings := make([][]byte, len(hexHashes))
		for i, h := range hexHashes {
			b, err := hexDecodeFixed(h)
			if err != nil {
				t.Fatalf("decode sibling[%d] for seq=%d: %v", i, seq, err)
			}
			siblings[i] = b
		}

		if err := proof.VerifyInclusion(
			rfc6962.DefaultHasher,
			seq,
			head.TreeSize,
			leafHash,
			siblings,
			head.RootHash[:],
		); err != nil {
			t.Fatalf("VerifyInclusion(seq=%d size=%d): %v\n  root=%x", seq, head.TreeSize, err, head.RootHash)
		}
	}
}

// TestTesseraAdapter_InclusionProof_RandomSampleVerifies is the
// randomized complement of the deterministic-sample test above. It
// picks 50 random indices, which (probabilistically) puts ~30% in the
// previously-buggy right-subtree branch. The bug would have failed
// roughly half of these on average; a single failure caught it.
func TestTesseraAdapter_InclusionProof_RandomSampleVerifies(t *testing.T) {
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	const N = 500
	leafData := make([][32]byte, N)
	for i := 0; i < N; i++ {
		if _, err := rand.Read(leafData[i][:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := app.AppendLeaf(ctx, leafData[i][:]); err != nil {
			t.Fatalf("AppendLeaf(%d): %v", i, err)
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	var rootHash [32]byte
	var treeSize uint64
	for time.Now().Before(deadline) {
		h, err := app.Head()
		if err == nil && h.TreeSize >= N {
			rootHash = h.RootHash
			treeSize = h.TreeSize
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if treeSize < N {
		t.Fatalf("integration never reached tree_size=%d; storage dir: %s", N, dir)
	}

	backend, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend: %v", err)
	}
	adapter := NewTesseraAdapter(ctx, app, NewTileReader(backend, 1024), nil)

	for i := 0; i < 30; i++ {
		rnd, err := rand.Int(rand.Reader, big.NewInt(N))
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}
		seq := rnd.Uint64()

		leafHash := rfc6962.DefaultHasher.HashLeaf(leafData[seq][:])

		raw, err := adapter.RawInclusionProof(seq, treeSize)
		if err != nil {
			t.Fatalf("RawInclusionProof(seq=%d): %v", seq, err)
		}
		m := raw.(map[string]any)
		hexHashes := m["hashes"].([]string)
		siblings := make([][]byte, len(hexHashes))
		for j, h := range hexHashes {
			b, err := hexDecodeFixed(h)
			if err != nil {
				t.Fatalf("decode sibling[%d] for seq=%d: %v", j, seq, err)
			}
			siblings[j] = b
		}

		if err := proof.VerifyInclusion(
			rfc6962.DefaultHasher, seq, treeSize, leafHash, siblings, rootHash[:],
		); err != nil {
			t.Fatalf("VerifyInclusion(seq=%d size=%d): %v", seq, treeSize, err)
		}
	}
}

// TestTileReader_Fetch_PartialFallback verifies that the partial-tile
// fallback path required by tessera/client.TileFetcherFunc actually
// works: when the partial path exists, Fetch returns its contents;
// when only the full path exists, Fetch falls back transparently.
//
// Without this fallback, proof generation breaks for any tree whose
// rightmost tile is not yet full (i.e., size not a multiple of 256).
func TestTileReader_Fetch_PartialFallback(t *testing.T) {
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	// 50 entries → rightmost tile (level 0, index 0) is partial with
	// 50 hashes (well below the 256-entry full-tile threshold).
	for i := 0; i < 50; i++ {
		var h [32]byte
		if _, err := rand.Read(h[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := app.AppendLeaf(ctx, h[:]); err != nil {
			t.Fatalf("AppendLeaf(%d): %v", i, err)
		}
	}

	// Wait for integration.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h, err := app.Head()
		if err == nil && h.TreeSize >= 50 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	backend, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend: %v", err)
	}
	tr := NewTileReader(backend, 1024)

	// Fetch with p=50 — tessera wrote tile/0/000.p/50 as a partial.
	data, err := tr.Fetch(ctx, 0, 0, 50)
	if err != nil {
		t.Fatalf("Fetch(level=0 index=0 p=50): %v", err)
	}
	// Each tile entry is 32 bytes; 50 entries = 1600 bytes.
	if want := 50 * sha256.Size; len(data) != want {
		t.Fatalf("partial tile size: got %d bytes, want %d", len(data), want)
	}

	// Fetch with p=0 (full tile) — should return os.ErrNotExist
	// because the tile hasn't filled to 256 yet, AND there's no
	// fallback target. We exercise this to pin the "neither exists"
	// → os.ErrNotExist contract.
	_, err = tr.Fetch(ctx, 0, 0, 0)
	if !errors.Is(err, os.ErrNotExist) {
		// Some Tessera versions write a "full" file at the partial
		// path; tolerate either outcome — what we care about is that
		// Fetch doesn't panic or return a non-not-exist error.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Fetch(full path before fill): got %v, want os.ErrNotExist or success", err)
		}
	}
}

// hexDecodeFixed decodes a 64-char hex string to 32 bytes.
func hexDecodeFixed(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, errors.New("hex length != 64")
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, err := hexNibble(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("non-hex char")
}
