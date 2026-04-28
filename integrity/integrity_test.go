/*
FILE PATH: integrity/integrity_test.go

Evidence-based unit tests for the integrity package. Establishes
the load-bearing invariants:

  Reasserter idempotency:
    Calling Reassert twice for the same identity returns the same
    seq both times (relies on AppenderBackend's dedup behavior).

  Verifier round-trip:
    HashAt(seq) returns the hash extracted from the entry tile at
    (seq/256, seq%256). Tile-format-compatible with the existing
    tessera package.

  Detector Reconcile:
    - Iterates inflight, reasserts each, pushes seq via sink.
    - Tolerates per-entry failures (logs + continues).
    - Hard-errors on iterator transport failure.

  Detector SampleVerify:
    - HWM=0 → nil (no sampling).
    - All samples agree → nil.
    - One mismatch → ErrDiverged with seq + both hashes in message.
    - WAL miss (GC'd entry) → skip, no divergence.

  Detector Loop:
    - Returns ctx.Err() on cancellation.
    - Returns ErrDiverged on first sample-cycle mismatch.
*/
package integrity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// fakeAppender records every AppendLeaf and returns either a canned
// seq or an error. Idempotent on identity (mirrors Tessera dedup).
type fakeAppender struct {
	mu       sync.Mutex
	dedup    map[[32]byte]uint64
	nextSeq  uint64
	failHash *[32]byte
	calls    int
}

func newFakeAppender() *fakeAppender {
	return &fakeAppender{dedup: map[[32]byte]uint64{}, nextSeq: 100}
}

func (f *fakeAppender) AppendLeaf(data []byte) (uint64, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("fakeAppender: AppendLeaf len=%d, want 32", len(data))
	}
	var id [32]byte
	copy(id[:], data)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.failHash != nil && *f.failHash == id {
		return 0, errors.New("fakeAppender: configured to fail")
	}
	if seq, ok := f.dedup[id]; ok {
		return seq, nil
	}
	seq := f.nextSeq
	f.nextSeq++
	f.dedup[id] = seq
	return seq, nil
}

// fakeTileReader builds entry tiles in the c2sp.org/tlog-tiles format
// (uint16 length-prefix per entry, 32 bytes per hash).
type fakeTileReader struct {
	tiles map[uint64][]byte // tileIndex → packed tile body
	err   error             // if non-nil, every read returns this
}

func newFakeTileReader() *fakeTileReader {
	return &fakeTileReader{tiles: map[uint64][]byte{}}
}

// putHashAtSeq packs hash at (seq/256, seq%256) in the fake tile.
func (f *fakeTileReader) putHashAtSeq(t *testing.T, seq uint64, hash [32]byte) {
	t.Helper()
	tileIdx := seq / EntriesPerEntryTile
	off := seq % EntriesPerEntryTile

	tile := f.tiles[tileIdx]
	// Each entry is 2 bytes length + 32 bytes hash = 34 bytes.
	required := int((off + 1) * 34)
	for len(tile) < required {
		// Pad with a zero-hash entry so subsequent puts can land at
		// any offset without breaking the length-prefix invariant.
		tile = append(tile, 0x00, 0x20) // length=32 big-endian
		tile = append(tile, make([]byte, 32)...)
	}
	// Overwrite the slot at off with the real hash.
	pos := int(off) * 34
	tile[pos] = 0x00
	tile[pos+1] = 0x20
	copy(tile[pos+2:pos+2+32], hash[:])
	f.tiles[tileIdx] = tile
}

func (f *fakeTileReader) ReadEntryTile(ctx context.Context, index uint64) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	tile, ok := f.tiles[index]
	if !ok {
		return nil, fmt.Errorf("fakeTileReader: tile %d not found", index)
	}
	return tile, nil
}

// fakeWAL satisfies WALReader. The iterator is wired separately via
// the InflightIterator function type.
type fakeWAL struct {
	hwm     uint64
	hashAt  map[uint64][32]byte
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

// fakeSink records Sequence calls.
type fakeSink struct {
	mu      sync.Mutex
	calls   []sinkCall
	failOn  *[32]byte
}

type sinkCall struct {
	hash [32]byte
	seq  uint64
}

func (s *fakeSink) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failOn != nil && *s.failOn == hash {
		return errors.New("fakeSink: configured to fail")
	}
	s.calls = append(s.calls, sinkCall{hash: hash, seq: seq})
	return nil
}

func (s *fakeSink) Calls() []sinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sinkCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// inflightFromList returns an InflightIterator that yields each hash
// in the supplied list in order.
func inflightFromList(list [][32]byte) InflightIterator {
	return func(ctx context.Context, fn func([32]byte) error) error {
		for _, h := range list {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(h); err != nil {
				return err
			}
		}
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────────
// Reasserter
// ─────────────────────────────────────────────────────────────────────

func TestReasserter_RoundTrip(t *testing.T) {
	app := newFakeAppender()
	r := NewReasserter(app)

	id := sha256.Sum256([]byte("entry-1"))
	seq, err := r.Reassert(context.Background(), id)
	if err != nil {
		t.Fatalf("Reassert: %v", err)
	}
	if seq == 0 {
		t.Fatal("expected non-zero seq")
	}

	// Second call returns the same seq (dedup).
	seq2, err := r.Reassert(context.Background(), id)
	if err != nil {
		t.Fatalf("Reassert (idempotent): %v", err)
	}
	if seq2 != seq {
		t.Fatalf("idempotency violated: first=%d second=%d", seq, seq2)
	}
}

func TestReasserter_DistinctIdentitiesGetDistinctSeqs(t *testing.T) {
	app := newFakeAppender()
	r := NewReasserter(app)
	ctx := context.Background()

	id1 := sha256.Sum256([]byte("a"))
	id2 := sha256.Sum256([]byte("b"))
	s1, _ := r.Reassert(ctx, id1)
	s2, _ := r.Reassert(ctx, id2)
	if s1 == s2 {
		t.Fatalf("distinct identities aliased: s1=%d s2=%d", s1, s2)
	}
}

func TestReasserter_ForwardsAppenderError(t *testing.T) {
	app := newFakeAppender()
	id := sha256.Sum256([]byte("oops"))
	app.failHash = &id
	r := NewReasserter(app)

	_, err := r.Reassert(context.Background(), id)
	if err == nil {
		t.Fatal("expected error from appender")
	}
}

func TestReasserter_NilAppender_Errors(t *testing.T) {
	r := NewReasserter(nil)
	_, err := r.Reassert(context.Background(), [32]byte{})
	if err == nil {
		t.Fatal("expected nil-appender error")
	}
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
	wantA := sha256.Sum256([]byte("A"))
	wantB := sha256.Sum256([]byte("B"))
	tiles.putHashAtSeq(t, 0, wantA)
	tiles.putHashAtSeq(t, 1, wantB)

	v := NewVerifier(tiles)
	gotA, _ := v.HashAt(context.Background(), 0)
	gotB, _ := v.HashAt(context.Background(), 1)
	if gotA != wantA {
		t.Fatalf("seq=0: got %x, want %x", gotA[:8], wantA[:8])
	}
	if gotB != wantB {
		t.Fatalf("seq=1: got %x, want %x", gotB[:8], wantB[:8])
	}
}

func TestVerifier_HashAt_TileMissingErrors(t *testing.T) {
	v := NewVerifier(newFakeTileReader())
	_, err := v.HashAt(context.Background(), 99999)
	if err == nil {
		t.Fatal("expected error on missing tile")
	}
}

func TestVerifier_NilReader_Errors(t *testing.T) {
	v := NewVerifier(nil)
	_, err := v.HashAt(context.Background(), 0)
	if err == nil {
		t.Fatal("expected nil-reader error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// TesseraAdapter — composition of Verifier + Reasserter
// ─────────────────────────────────────────────────────────────────────

func TestTesseraAdapter_BothSurfaces(t *testing.T) {
	app := newFakeAppender()
	tiles := newFakeTileReader()

	id := sha256.Sum256([]byte("adapter-test"))
	tiles.putHashAtSeq(t, 7, id)

	a := NewTesseraAdapter(app, tiles)

	// Verifier surface.
	got, err := a.HashAt(context.Background(), 7)
	if err != nil {
		t.Fatalf("HashAt: %v", err)
	}
	if got != id {
		t.Fatalf("HashAt: got %x, want %x", got[:8], id[:8])
	}

	// Reasserter surface.
	seq, err := a.Reassert(context.Background(), id)
	if err != nil {
		t.Fatalf("Reassert: %v", err)
	}
	if seq == 0 {
		t.Fatal("Reassert: zero seq")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Detector — Reconcile
// ─────────────────────────────────────────────────────────────────────

func TestDetector_Reconcile_HappyPath(t *testing.T) {
	app := newFakeAppender()
	app.nextSeq = 200
	r := NewReasserter(app)
	sink := &fakeSink{}

	hashes := [][32]byte{
		sha256.Sum256([]byte("a")),
		sha256.Sum256([]byte("b")),
		sha256.Sum256([]byte("c")),
	}
	d := NewDetector(
		&fakeWAL{},
		inflightFromList(hashes),
		sink,
		nil, // no verifier needed for Reconcile
		r,
		DetectorConfig{Logger: discardLogger()},
	)

	if err := d.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := sink.Calls()
	if len(got) != 3 {
		t.Fatalf("expected 3 sink calls, got %d", len(got))
	}
	for i, c := range got {
		if c.hash != hashes[i] {
			t.Errorf("call %d: hash %x != %x", i, c.hash[:8], hashes[i][:8])
		}
		if c.seq < 200 {
			t.Errorf("call %d: seq %d below appender start", i, c.seq)
		}
	}
}

func TestDetector_Reconcile_PartialFailureContinues(t *testing.T) {
	app := newFakeAppender()
	bad := sha256.Sum256([]byte("bad"))
	app.failHash = &bad
	r := NewReasserter(app)
	sink := &fakeSink{}

	hashes := [][32]byte{
		sha256.Sum256([]byte("good-1")),
		bad,
		sha256.Sum256([]byte("good-2")),
	}
	d := NewDetector(
		&fakeWAL{},
		inflightFromList(hashes),
		sink,
		nil,
		r,
		DetectorConfig{Logger: discardLogger()},
	)

	if err := d.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile (partial fail): %v", err)
	}
	got := sink.Calls()
	if len(got) != 2 {
		t.Fatalf("expected 2 sink calls (one failed entry skipped), got %d", len(got))
	}
}

func TestDetector_Reconcile_SinkFailureSkipped(t *testing.T) {
	app := newFakeAppender()
	r := NewReasserter(app)
	sink := &fakeSink{}
	bad := sha256.Sum256([]byte("sink-fail"))
	sink.failOn = &bad

	hashes := [][32]byte{
		sha256.Sum256([]byte("good")),
		bad,
	}
	d := NewDetector(
		&fakeWAL{},
		inflightFromList(hashes),
		sink,
		nil,
		r,
		DetectorConfig{Logger: discardLogger()},
	)

	if err := d.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(sink.Calls()) != 1 {
		t.Fatalf("expected 1 successful sink call, got %d", len(sink.Calls()))
	}
}

func TestDetector_Reconcile_IteratorErrorPropagates(t *testing.T) {
	d := NewDetector(
		&fakeWAL{},
		func(ctx context.Context, fn func([32]byte) error) error {
			return errors.New("badger transport failure")
		},
		&fakeSink{},
		nil,
		NewReasserter(newFakeAppender()),
		DetectorConfig{Logger: discardLogger()},
	)
	err := d.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected iterator transport error")
	}
}

func TestDetector_Reconcile_ContextCancel(t *testing.T) {
	r := NewReasserter(newFakeAppender())
	hashes := [][32]byte{
		sha256.Sum256([]byte("a")),
		sha256.Sum256([]byte("b")),
	}
	d := NewDetector(
		&fakeWAL{},
		inflightFromList(hashes),
		&fakeSink{},
		nil,
		r,
		DetectorConfig{Logger: discardLogger()},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Reconcile starts
	err := d.Reconcile(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Detector — SampleVerify
// ─────────────────────────────────────────────────────────────────────

func TestDetector_SampleVerify_HWMZeroIsNoOp(t *testing.T) {
	d := NewDetector(
		&fakeWAL{hwm: 0},
		inflightFromList(nil),
		&fakeSink{},
		NewVerifier(newFakeTileReader()),
		NewReasserter(newFakeAppender()),
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
		wal, inflightFromList(nil), &fakeSink{},
		NewVerifier(tiles),
		NewReasserter(newFakeAppender()),
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
	// Seed seq=3 with DIFFERENT hashes in WAL vs Tessera.
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
	// Seed=2 → first sample picks seq 3 (deterministic with this rand).
	d := NewDetector(
		wal, inflightFromList(nil), &fakeSink{},
		NewVerifier(tiles),
		NewReasserter(newFakeAppender()),
		DetectorConfig{
			SamplesPerCycle: 20, // sample heavily so we hit seq 3
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	err := d.SampleVerify(context.Background())
	if err == nil {
		t.Fatal("expected ErrDiverged")
	}
	if !errors.Is(err, ErrDiverged) {
		t.Fatalf("expected ErrDiverged, got %v", err)
	}
	// Error message must include the seq + both hashes for forensics.
	msg := err.Error()
	if want := "seq=3"; !contains(msg, want) {
		t.Errorf("error message missing %q: %s", want, msg)
	}
}

func TestDetector_SampleVerify_WALMissDoesNotDiverge(t *testing.T) {
	tiles := newFakeTileReader()
	wal := &fakeWAL{
		hwm:    1,
		hashAt: map[uint64][32]byte{}, // seq=1 NOT in WAL (already GC'd)
	}
	tiles.putHashAtSeq(t, 1, sha256.Sum256([]byte("only-in-tessera")))

	d := NewDetector(
		wal, inflightFromList(nil), &fakeSink{},
		NewVerifier(tiles),
		NewReasserter(newFakeAppender()),
		DetectorConfig{
			SamplesPerCycle: 1,
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	if err := d.SampleVerify(context.Background()); err != nil {
		t.Fatalf("WAL-miss SampleVerify: %v (want nil — GC is normal)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Detector — Loop
// ─────────────────────────────────────────────────────────────────────

func TestDetector_Loop_ContextCancelReturnsCancelErr(t *testing.T) {
	d := NewDetector(
		&fakeWAL{hwm: 0},
		inflightFromList(nil),
		&fakeSink{},
		NewVerifier(newFakeTileReader()),
		NewReasserter(newFakeAppender()),
		DetectorConfig{
			SampleInterval: 5 * time.Millisecond,
			Logger:         discardLogger(),
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := d.Loop(ctx)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error, got %v", err)
	}
}

func TestDetector_Loop_DivergenceStopsLoop(t *testing.T) {
	tiles := newFakeTileReader()
	wal := &fakeWAL{hwm: 1, hashAt: map[uint64][32]byte{1: sha256.Sum256([]byte("wal"))}}
	tiles.putHashAtSeq(t, 1, sha256.Sum256([]byte("tessera"))) // diverges

	d := NewDetector(
		wal, inflightFromList(nil), &fakeSink{},
		NewVerifier(tiles),
		NewReasserter(newFakeAppender()),
		DetectorConfig{
			SampleInterval:  5 * time.Millisecond,
			SamplesPerCycle: 1,
			Rand:            rand.New(rand.NewSource(1)),
			Logger:          discardLogger(),
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := d.Loop(ctx)
	if !errors.Is(err, ErrDiverged) {
		t.Fatalf("expected ErrDiverged, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{
		Level: slog.LevelError + 1, // suppress everything
	}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
