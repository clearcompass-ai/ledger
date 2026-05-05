/*
FILE PATH: integrity/integrity_test.go

Evidence-based unit tests for the integrity package — read-only
verifier surface only. Establishes:

	Verifier round-trip:
	  HashAt(seq) returns the hash extracted from the entry tile at
	  (seq/256, seq%256). Tile-format-compatible with the existing
	  tessera package.

	TesseraAdapter Verifier surface:
	  HashAt routed correctly through the adapter to the embedded
	  TileReader.

	Detector SampleVerify:
	  - HWM=0 → nil (no sampling).
	  - All samples agree → nil.
	  - One mismatch → ErrDiverged with seq + both hashes in message.
	  - WAL miss (GC'd entry) → skip, no divergence.

	Detector Loop:
	  - Returns ctx.Err() on cancellation.
	  - Returns ErrDiverged on first sample-cycle mismatch.

WHAT'S ABSENT (and why):

	Reasserter and Reconcile tests: deleted alongside the Reasserter
	package itself. The Sequencer (sequencer/) now owns boot recovery,
	and its drainOnce-on-Run-start replaces what Reconcile used to
	do, with the added benefit of also INSERTing entry_index rows.
	Sequencer tests live in sequencer/sequencer_test.go.
*/
package integrity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// fakeTileReader satisfies TileReader by returning canned tiles.
// Each tile is a 256 × 32-byte block of leaf hashes (Tessera tile
// format). Tests seed by writing to the (level=0, index=tileIndex)
// slot via putHashAtSeq.
type fakeTileReader struct {
	tiles map[uint64][]byte
}

func newFakeTileReader() *fakeTileReader {
	return &fakeTileReader{tiles: map[uint64][]byte{}}
}

// putHashAtSeq packs hash at (seq/256, seq%256) into the fake tile
// using the tlog-tiles entry-bundle format: each slot is 2 bytes
// of big-endian length prefix followed by the leaf hash. The
// real Tessera tile parser (tessera.ParseEntryBundle) expects
// this shape; a naive flat-array layout would parse-fail.
func (f *fakeTileReader) putHashAtSeq(t *testing.T, seq uint64, hash [32]byte) {
	t.Helper()
	tileIdx := seq / EntriesPerEntryTile
	off := seq % EntriesPerEntryTile

	tile := f.tiles[tileIdx]
	// Each entry is 2 bytes length + 32 bytes hash = 34 bytes.
	required := int((off + 1) * 34)
	for len(tile) < required {
		// Pad with a zero-hash entry so subsequent puts at higher
		// offsets don't break the length-prefix invariant.
		tile = append(tile, 0x00, 0x20) // length=32 big-endian
		tile = append(tile, make([]byte, 32)...)
	}
	pos := int(off) * 34
	tile[pos] = 0x00
	tile[pos+1] = 0x20
	copy(tile[pos+2:pos+2+32], hash[:])
	f.tiles[tileIdx] = tile
}

func (f *fakeTileReader) ReadEntryTile(ctx context.Context, index uint64) ([]byte, error) {
	tile, ok := f.tiles[index]
	if !ok {
		return nil, fmt.Errorf("fakeTileReader: tile %d not found", index)
	}
	return tile, nil
}

// fakeWAL satisfies WALReader. Tests pre-populate hashAt + hwm.
type fakeWAL struct {
	hwm uint64
	hashAt map[uint64][32]byte
	hashErr map[uint64]error // optional per-seq error injection
}

func (f *fakeWAL) HashAt(ctx context.Context, seq uint64) ([32]byte, error) {
	if e, ok := f.hashErr[seq]; ok {
		return [32]byte{}, e
	}
	h, ok := f.hashAt[seq]
	if !ok {
		return [32]byte{}, errors.New("fakeWAL: no hash at seq")
	}
	return h, nil
}

func (f *fakeWAL) HWM(ctx context.Context) (uint64, error) {
	return f.hwm, nil
}

// discardLogger returns a slog.Logger that drops every record.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ─────────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────────

func TestVerifier_HashAt_RoundTrip(t *testing.T) {
	tiles := newFakeTileReader()
	want := sha256.Sum256([]byte("hash-at-seq-42"))
	tiles.putHashAtSeq(t, 42, want)

	v := NewVerifier(tiles)
	got, err := v.HashAt(context.Background(), 42)
	if err != nil {
		t.Fatalf("HashAt: %v", err)
	}
	if got != want {
		t.Fatalf("HashAt: got %x, want %x", got[:8], want[:8])
	}
}

func TestVerifier_HashAt_DistinctSeqs(t *testing.T) {
	tiles := newFakeTileReader()
	a := sha256.Sum256([]byte("seq-1"))
	b := sha256.Sum256([]byte("seq-300")) // different tile
	tiles.putHashAtSeq(t, 1, a)
	tiles.putHashAtSeq(t, 300, b)

	v := NewVerifier(tiles)
	gotA, err := v.HashAt(context.Background(), 1)
	if err != nil || gotA != a {
		t.Fatalf("seq=1: got %x err=%v, want %x", gotA[:8], err, a[:8])
	}
	gotB, err := v.HashAt(context.Background(), 300)
	if err != nil || gotB != b {
		t.Fatalf("seq=300: got %x err=%v, want %x", gotB[:8], err, b[:8])
	}
}

func TestVerifier_HashAt_TileMissingErrors(t *testing.T) {
	tiles := newFakeTileReader()
	v := NewVerifier(tiles)
	if _, err := v.HashAt(context.Background(), 7); err == nil {
		t.Fatal("expected error for missing tile")
	}
}

func TestVerifier_NilReader_Errors(t *testing.T) {
	v := NewVerifier(nil)
	if _, err := v.HashAt(context.Background(), 1); err == nil {
		t.Fatal("expected error from nil-reader Verifier")
	}
}

// ─────────────────────────────────────────────────────────────────────
// TesseraAdapter — Verifier surface only
// ─────────────────────────────────────────────────────────────────────

func TestTesseraAdapter_VerifierSurface(t *testing.T) {
	tiles := newFakeTileReader()
	id := sha256.Sum256([]byte("adapter-test"))
	tiles.putHashAtSeq(t, 7, id)

	a := NewTesseraAdapter(tiles)
	got, err := a.HashAt(context.Background(), 7)
	if err != nil {
		t.Fatalf("HashAt: %v", err)
	}
	if got != id {
		t.Fatalf("HashAt: got %x, want %x", got[:8], id[:8])
	}
}

// ─────────────────────────────────────────────────────────────────────
// Detector — SampleVerify
// ─────────────────────────────────────────────────────────────────────

func TestDetector_SampleVerify_HWMZeroIsNoOp(t *testing.T) {
	d := NewDetector(
		&fakeWAL{hwm: 0},
		NewVerifier(newFakeTileReader()),
		DetectorConfig{SamplesPerCycle: 5, Logger: discardLogger()},
	)
	if err := d.SampleVerify(context.Background()); err != nil {
		t.Fatalf("HWM=0 SampleVerify: %v", err)
	}
}

func TestDetector_SampleVerify_AllAgree(t *testing.T) {
	tiles := newFakeTileReader()
	wal := &fakeWAL{hwm: 5, hashAt: map[uint64][32]byte{}}
	for seq := uint64(1); seq <= 5; seq++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("seq-%d", seq)))
		wal.hashAt[seq] = h
		tiles.putHashAtSeq(t, seq, h)
	}
	d := NewDetector(
		wal,
		NewVerifier(tiles),
		DetectorConfig{
			SamplesPerCycle: 5,
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	if err := d.SampleVerify(context.Background()); err != nil {
		t.Fatalf("all-agree SampleVerify: %v", err)
	}
}

func TestDetector_SampleVerify_DivergenceReturnsErrDiverged(t *testing.T) {
	tiles := newFakeTileReader()
	wal := &fakeWAL{hwm: 5, hashAt: map[uint64][32]byte{}}
	walHash := sha256.Sum256([]byte("wal-version"))
	tessHash := sha256.Sum256([]byte("tessera-version"))
	for seq := uint64(1); seq <= 5; seq++ {
		var h [32]byte
		if seq == 3 {
			h = walHash
		} else {
			h = sha256.Sum256([]byte(fmt.Sprintf("seq-%d", seq)))
		}
		wal.hashAt[seq] = h
		tileH := h
		if seq == 3 {
			tileH = tessHash
		}
		tiles.putHashAtSeq(t, seq, tileH)
	}
	d := NewDetector(
		wal,
		NewVerifier(tiles),
		DetectorConfig{
			SamplesPerCycle: 20, // hit seq 3 with high probability
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	err := d.SampleVerify(context.Background())
	if err == nil {
		t.Fatal("expected ErrDiverged")
	}
	if !errors.Is(err, ErrDiverged) {
		t.Fatalf("error does not wrap ErrDiverged: %v", err)
	}
}

func TestDetector_SampleVerify_WALMissDoesNotDiverge(t *testing.T) {
	tiles := newFakeTileReader()
	wal := &fakeWAL{
		hwm:     3,
		hashAt:  map[uint64][32]byte{},
		hashErr: map[uint64]error{2: errors.New("WAL: GC'd")},
	}
	for seq := uint64(1); seq <= 3; seq++ {
		if seq == 2 {
			continue
		}
		h := sha256.Sum256([]byte(fmt.Sprintf("seq-%d", seq)))
		wal.hashAt[seq] = h
		tiles.putHashAtSeq(t, seq, h)
	}
	d := NewDetector(
		wal,
		NewVerifier(tiles),
		DetectorConfig{
			SamplesPerCycle: 10,
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	if err := d.SampleVerify(context.Background()); err != nil {
		t.Fatalf("WAL miss should be skipped, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Detector — Loop
// ─────────────────────────────────────────────────────────────────────

func TestDetector_Loop_ContextCancelReturnsCancelErr(t *testing.T) {
	d := NewDetector(
		&fakeWAL{},
		NewVerifier(newFakeTileReader()),
		DetectorConfig{
			SampleInterval: 50 * time.Millisecond,
			Logger:         discardLogger(),
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Loop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Loop on cancelled ctx: %v, want context.Canceled", err)
	}
}

func TestDetector_Loop_DivergenceStopsLoop(t *testing.T) {
	tiles := newFakeTileReader()
	wal := &fakeWAL{
		hwm:    1,
		hashAt: map[uint64][32]byte{1: sha256.Sum256([]byte("wal"))},
	}
	tiles.putHashAtSeq(t, 1, sha256.Sum256([]byte("tessera")))

	d := NewDetector(
		wal,
		NewVerifier(tiles),
		DetectorConfig{
			SampleInterval:  10 * time.Millisecond,
			SamplesPerCycle: 1,
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := d.Loop(ctx)
	if !errors.Is(err, ErrDiverged) {
		t.Fatalf("Loop did not surface ErrDiverged: %v", err)
	}
}
