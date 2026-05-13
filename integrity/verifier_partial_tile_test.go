/*
FILE PATH: integrity/verifier_partial_tile_test.go

Regression test for the partial-tile-not-found bug.

PRE-FIX BEHAVIOR (the bug):

	The verifier opened the FULL-tile filesystem path
	(tile/entries/000) via *tessera.TileReader.ReadEntryTile. When
	Tessera had only flushed a partial file (tile/entries/000.p/N),
	the open returned ENOENT and the verifier propagated a FATAL
	through the Detector's fatal channel, terminating the ledger
	~60s after a kill-restart chaos run that committed fewer than
	256 entries.

POST-FIX BEHAVIOR (this test):

	The verifier consumes an upstream tessera/client.TileFetcherFunc
	and asks for the partial count matching its offset (offset+1,
	wrapping to 0 for offset==255). The fetcher contract guarantees
	partial→full fallback. When neither the requested partial nor
	the full tile exists, the verifier surfaces ErrTileNotYetFlushed
	(the Detector treats this as a skip, not a divergence).

This test exercises three properties:
  (1) Verifier asks the fetcher for partial=offset+1.
  (2) When the fetcher returns os.ErrNotExist, the verifier
      surfaces ErrTileNotYetFlushed (transient skip).
  (3) When offset==255 the verifier asks for the full tile (p=0).
*/
package integrity

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
)

// recordingFetcher is a tessera/client.TileFetcherFunc that records
// every (level, index, p) invocation and serves canned tile bytes.
type recordingFetcher struct {
	// tiles[index] keyed by partial count p. p=0 is the full tile.
	tiles map[uint64]map[uint8][]byte
	calls []recordedCall
}

type recordedCall struct {
	level uint64
	index uint64
	p     uint8
}

func newRecordingFetcher() *recordingFetcher {
	return &recordingFetcher{tiles: map[uint64]map[uint8][]byte{}}
}

func (r *recordingFetcher) put(index uint64, p uint8, data []byte) {
	if _, ok := r.tiles[index]; !ok {
		r.tiles[index] = map[uint8][]byte{}
	}
	r.tiles[index][p] = data
}

// Fetch is shaped exactly as tessera/client.TileFetcherFunc.
// Implements the contract: if p>0 and the partial exists, return
// it. Otherwise fall back to p=0 (full). If neither exists, return
// os.ErrNotExist.
func (r *recordingFetcher) Fetch(_ context.Context, level, index uint64, p uint8) ([]byte, error) {
	r.calls = append(r.calls, recordedCall{level: level, index: index, p: p})
	byP, ok := r.tiles[index]
	if !ok {
		return nil, os.ErrNotExist
	}
	if p > 0 {
		if data, ok := byP[p]; ok {
			return data, nil
		}
	}
	if data, ok := byP[0]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

// packEntryBundle returns a tlog-tiles-formatted entry bundle
// holding `count` 32-byte hashes. Each slot is 2 bytes of big-
// endian length prefix + 32 bytes of hash.
func packEntryBundle(t *testing.T, count int) []byte {
	t.Helper()
	out := make([]byte, 0, count*34)
	for i := 0; i < count; i++ {
		h := sha256.Sum256([]byte("entry-" + string(rune('0'+i%10))))
		out = append(out, 0x00, 0x20) // length=32 big-endian
		out = append(out, h[:]...)
	}
	return out
}

// TestVerifier_AsksForPartial_OffsetPlusOne pins the partial-count
// derivation. seq=7 lives at (tileIndex=0, offset=7), so the
// verifier MUST ask the fetcher for p=8. If a refactor reverts to
// asking for the full tile (p=0), the test fails.
func TestVerifier_AsksForPartial_OffsetPlusOne(t *testing.T) {
	const seq = 7
	const wantP = uint8(seq + 1) // 8

	fetcher := newRecordingFetcher()
	// Only the partial-p=8 tile exists (mimics Tessera's lazy flush
	// at the requested count). Pre-fix this would have failed.
	fetcher.put(0, wantP, packEntryBundle(t, int(wantP)))

	v := NewVerifier(fetcher.Fetch)

	if _, err := v.HashAt(context.Background(), seq); err != nil {
		t.Fatalf("HashAt(seq=%d): %v", seq, err)
	}
	if len(fetcher.calls) != 1 {
		t.Fatalf("expected exactly 1 fetcher call, got %d: %v", len(fetcher.calls), fetcher.calls)
	}
	if got := fetcher.calls[0].p; got != wantP {
		t.Errorf("fetcher call p = %d, want %d (offset+1)", got, wantP)
	}
	if got := fetcher.calls[0].index; got != 0 {
		t.Errorf("fetcher call index = %d, want 0", got)
	}
	if got := fetcher.calls[0].level; got != 0 {
		t.Errorf("fetcher call level = %d, want 0 (entry tile)", got)
	}
}

// TestVerifier_AsksForFullTile_WhenOffsetIs255 pins the wrap-to-0
// boundary. seq=255 means the tile is full at that offset, so the
// verifier MUST ask for p=0 (the full-tile path). Asking for p=256
// would be a contract violation (uint8 max is 255).
func TestVerifier_AsksForFullTile_WhenOffsetIs255(t *testing.T) {
	const seq = 255

	fetcher := newRecordingFetcher()
	fetcher.put(0, 0, packEntryBundle(t, 256))

	v := NewVerifier(fetcher.Fetch)

	if _, err := v.HashAt(context.Background(), seq); err != nil {
		t.Fatalf("HashAt(seq=%d): %v", seq, err)
	}
	if got := fetcher.calls[0].p; got != 0 {
		t.Errorf("fetcher call p = %d, want 0 (full tile when offset==255)", got)
	}
}

// TestVerifier_FetcherENOENT_SurfacesTileNotYetFlushed pins the
// transient-skip path: when neither the requested partial nor any
// fallback exists, the fetcher returns os.ErrNotExist; the verifier
// MUST translate to ErrTileNotYetFlushed so the Detector knows to
// skip the sample (not panic on divergence).
func TestVerifier_FetcherENOENT_SurfacesTileNotYetFlushed(t *testing.T) {
	fetcher := newRecordingFetcher()
	// No tile data inserted — every Fetch returns os.ErrNotExist.

	v := NewVerifier(fetcher.Fetch)

	_, err := v.HashAt(context.Background(), 11)
	if err == nil {
		t.Fatal("expected error when fetcher returns ENOENT")
	}
	if !errors.Is(err, ErrTileNotYetFlushed) {
		t.Errorf("err = %v, want errors.Is(err, ErrTileNotYetFlushed)", err)
	}
	// Verify the fetcher WAS called (the verifier didn't short-circuit
	// before reaching the I/O surface).
	if len(fetcher.calls) != 1 {
		t.Errorf("fetcher should be called once even on ENOENT; got %d calls",
			len(fetcher.calls))
	}
}

// TestVerifier_PostBugFix_SecondTileIndex pins that the partial-
// count derivation works correctly for non-zero tile indices.
// seq=300 lives at (tileIndex=1, offset=44), so the verifier MUST
// ask for (level=0, index=1, p=45).
func TestVerifier_PostBugFix_SecondTileIndex(t *testing.T) {
	const seq = 300
	const wantIndex = uint64(1)
	const wantP = uint8(45) // offset=44, +1=45

	fetcher := newRecordingFetcher()
	fetcher.put(wantIndex, wantP, packEntryBundle(t, int(wantP)))

	v := NewVerifier(fetcher.Fetch)

	if _, err := v.HashAt(context.Background(), seq); err != nil {
		t.Fatalf("HashAt(seq=%d): %v", seq, err)
	}
	if got := fetcher.calls[0].index; got != wantIndex {
		t.Errorf("fetcher call index = %d, want %d", got, wantIndex)
	}
	if got := fetcher.calls[0].p; got != wantP {
		t.Errorf("fetcher call p = %d, want %d", got, wantP)
	}
}
