/*
FILE PATH: store/fetcher_test.go

Evidence-based tests for the CompositeByteReader. Establishes the
load-bearing routing invariants:

 1. WAL hit → bytestore not consulted.
 2. WAL miss (ErrNotFound) → bytestore consulted.
 3. WAL transport error → returned, NOT silently masked by bytestore.
 4. WAL absent + bytestore-only → all reads go through bytestore.
 5. Bytestore absent + WAL miss → error (no silent partial state).
 6. Batch ordering preserved across mixed WAL/bytestore hits.
 7. Batch failure on any single read fails the whole batch.
 8. Context cancel respected per-read and across batches.

The composite's interface compatibility (it satisfies bytestore.Reader)
is statically pinned by the var-decl in fetcher.go; the tests focus
on routing semantics where the load-bearing correctness lives.
*/
package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// fakeWALReader satisfies WALByteReader. Returns canned wire bytes
// or wal.ErrNotFound for unknown hashes; an injected non-NotFound
// error path exercises the alarm-don't-mask invariant.
type fakeWALReader struct {
	wires map[[32]byte][]byte
	hardErr error // returned for ANY hash read (transport-fail simulation)
	missedHash *[32]byte // returned as ErrNotFound; used to force fallback
	calls map[[32]byte]int
}

func newFakeWALReader() *fakeWALReader {
	return &fakeWALReader{
		wires: map[[32]byte][]byte{},
		calls: map[[32]byte]int{},
	}
}

func (f *fakeWALReader) put(hash [32]byte, wire []byte) {
	f.wires[hash] = wire
}

func (f *fakeWALReader) Read(_ context.Context, hash [32]byte) ([]byte, error) {
	f.calls[hash]++
	if f.hardErr != nil {
		return nil, f.hardErr
	}
	w, ok := f.wires[hash]
	if !ok {
		return nil, fmt.Errorf("fakeWAL: %w", wal.ErrNotFound)
	}
	cp := make([]byte, len(w))
	copy(cp, w)
	return cp, nil
}

// fakeBytestore satisfies bytestore.Reader. Counts calls per
// (seq, hash) so tests can assert "WAL hit didn't fall through".
type fakeBytestore struct {
	wires map[[32]byte][]byte
	calls map[uint64]int
	err error
}

func newFakeBytestore() *fakeBytestore {
	return &fakeBytestore{
		wires: map[[32]byte][]byte{},
		calls: map[uint64]int{},
	}
}

func (f *fakeBytestore) put(hash [32]byte, wire []byte) {
	f.wires[hash] = wire
}

func (f *fakeBytestore) ReadEntry(_ context.Context, seq uint64, hash [32]byte) ([]byte, error) {
	f.calls[seq]++
	if f.err != nil {
		return nil, f.err
	}
	w, ok := f.wires[hash]
	if !ok {
		return nil, fmt.Errorf("fakeBytestore: %w", bytestore.ErrNotFound)
	}
	cp := make([]byte, len(w))
	copy(cp, w)
	return cp, nil
}

func (f *fakeBytestore) ReadEntryBatch(ctx context.Context, refs []bytestore.EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		w, err := f.ReadEntry(ctx, r.Seq, r.Hash)
		if err != nil {
			return nil, err
		}
		out[i] = w
	}
	return out, nil
}

func hashFor(name string) [32]byte { return sha256.Sum256([]byte(name)) }

// ─────────────────────────────────────────────────────────────────────
// 1) WAL hit → bytestore not consulted
// ─────────────────────────────────────────────────────────────────────

func TestComposite_WALHit_BytestoreNotConsulted(t *testing.T) {
	w := newFakeWALReader()
	bs := newFakeBytestore()

	hash := hashFor("hot-entry")
	wire := []byte("hot bytes")
	w.put(hash, wire)

	c := NewCompositeByteReader(w, bs, nil)
	got, err := c.ReadEntry(context.Background(), 42, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != string(wire) {
		t.Fatalf("got %q, want %q", got, wire)
	}
	if bs.calls[42] != 0 {
		t.Errorf("bytestore should NOT have been called on WAL hit, got %d calls",
			bs.calls[42])
	}
	if w.calls[hash] != 1 {
		t.Errorf("WAL should have been called once, got %d", w.calls[hash])
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2) WAL miss → bytestore fallback
// ─────────────────────────────────────────────────────────────────────

func TestComposite_WALMiss_BytestoreFallback(t *testing.T) {
	w := newFakeWALReader()
	bs := newFakeBytestore()

	hash := hashFor("shipped-entry")
	wire := []byte("cold bytes")
	bs.put(hash, wire)
	// Note: NOT putting in WAL — fall through expected.

	c := NewCompositeByteReader(w, bs, nil)
	got, err := c.ReadEntry(context.Background(), 99, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != string(wire) {
		t.Fatalf("got %q, want %q", got, wire)
	}
	if w.calls[hash] != 1 {
		t.Errorf("WAL should have been called once, got %d", w.calls[hash])
	}
	if bs.calls[99] != 1 {
		t.Errorf("bytestore should have been called once after WAL miss, got %d", bs.calls[99])
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3) WAL transport error → returned, NOT masked
// ─────────────────────────────────────────────────────────────────────

func TestComposite_WALTransportError_DoesNotFallThrough(t *testing.T) {
	w := newFakeWALReader()
	bs := newFakeBytestore()

	hash := hashFor("oops")
	// Even if bytestore HAS the entry, we should NOT fall through —
	// a Badger transport failure is an operational alarm.
	bs.put(hash, []byte("would-be-fallback"))
	w.hardErr = errors.New("badger: I/O error")

	c := NewCompositeByteReader(w, bs, nil)
	_, err := c.ReadEntry(context.Background(), 1, hash)
	if err == nil {
		t.Fatal("expected WAL transport error to surface")
	}
	if !errors.Is(err, w.hardErr) && !contains(err.Error(), "badger: I/O error") {
		t.Errorf("expected WAL error to be wrapped, got %v", err)
	}
	if bs.calls[1] != 0 {
		t.Errorf("bytestore should NOT be consulted on WAL transport error, got %d calls",
			bs.calls[1])
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4) WAL absent + bytestore-only mode
// ─────────────────────────────────────────────────────────────────────

func TestComposite_NilWAL_GoesStraightToBytestore(t *testing.T) {
	bs := newFakeBytestore()
	hash := hashFor("only-cold")
	bs.put(hash, []byte("from cold storage"))

	c := NewCompositeByteReader(nil, bs, nil)
	got, err := c.ReadEntry(context.Background(), 7, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != "from cold storage" {
		t.Fatalf("got %q, want from cold storage", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5) Bytestore absent + WAL miss → error
// ─────────────────────────────────────────────────────────────────────

func TestComposite_NilBytestore_WALMissErrors(t *testing.T) {
	w := newFakeWALReader()
	c := NewCompositeByteReader(w, nil, nil)
	_, err := c.ReadEntry(context.Background(), 1, hashFor("nowhere"))
	if err == nil {
		t.Fatal("expected error when both sources are unavailable")
	}
}

func TestComposite_NilBytestore_WALHitStillWorks(t *testing.T) {
	w := newFakeWALReader()
	hash := hashFor("hot")
	w.put(hash, []byte("hot bytes"))
	c := NewCompositeByteReader(w, nil, nil)
	got, err := c.ReadEntry(context.Background(), 1, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != "hot bytes" {
		t.Fatalf("got %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6) Bytestore not-found surfaces as bytestore.ErrNotFound
// ─────────────────────────────────────────────────────────────────────

func TestComposite_BothMiss_ReturnsErrNotFound(t *testing.T) {
	w := newFakeWALReader()
	bs := newFakeBytestore()

	c := NewCompositeByteReader(w, bs, nil)
	_, err := c.ReadEntry(context.Background(), 1, hashFor("ghost"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, bytestore.ErrNotFound) {
		t.Errorf("expected bytestore.ErrNotFound chain, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7) Batch: input order preserved across mixed sources
// ─────────────────────────────────────────────────────────────────────

func TestComposite_Batch_MixedSources_PreservesOrder(t *testing.T) {
	w := newFakeWALReader()
	bs := newFakeBytestore()

	// seqs 1, 2, 3. seq 2 is in WAL only; seqs 1 and 3 are in
	// bytestore only (post-shipping, post-GC).
	h1 := hashFor("e1")
	h2 := hashFor("e2")
	h3 := hashFor("e3")
	w.put(h2, []byte("hot-e2"))
	bs.put(h1, []byte("cold-e1"))
	bs.put(h3, []byte("cold-e3"))

	c := NewCompositeByteReader(w, bs, nil)
	refs := []bytestore.EntryRef{
		{Seq: 1, Hash: h1},
		{Seq: 2, Hash: h2},
		{Seq: 3, Hash: h3},
	}
	got, err := c.ReadEntryBatch(context.Background(), refs)
	if err != nil {
		t.Fatalf("ReadEntryBatch: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len: got %d, want 3", len(got))
	}
	wants := []string{"cold-e1", "hot-e2", "cold-e3"}
	for i, w := range wants {
		if string(got[i]) != w {
			t.Errorf("position %d: got %q, want %q", i, got[i], w)
		}
	}
	// And the routing actually went where we expected:
	if bs.calls[1] != 1 || bs.calls[3] != 1 {
		t.Errorf("bytestore calls: %v (want 1@seq=1, 1@seq=3)", bs.calls)
	}
	if bs.calls[2] != 0 {
		t.Errorf("seq=2 should NOT have hit bytestore, got %d", bs.calls[2])
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8) Batch: any single failure fails the whole batch (no silent short slice)
// ─────────────────────────────────────────────────────────────────────

func TestComposite_Batch_AnyFailureFailsAll(t *testing.T) {
	w := newFakeWALReader()
	bs := newFakeBytestore()

	h1 := hashFor("ok-1")
	h2 := hashFor("missing")
	h3 := hashFor("ok-3")
	w.put(h1, []byte("a"))
	w.put(h3, []byte("c"))
	// h2 is in neither source.

	c := NewCompositeByteReader(w, bs, nil)
	refs := []bytestore.EntryRef{
		{Seq: 1, Hash: h1},
		{Seq: 2, Hash: h2},
		{Seq: 3, Hash: h3},
	}
	_, err := c.ReadEntryBatch(context.Background(), refs)
	if err == nil {
		t.Fatal("expected fatal batch error on missing entry")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9) Context cancel
// ─────────────────────────────────────────────────────────────────────

func TestComposite_ContextCanceled_ReadEntryReturnsCancel(t *testing.T) {
	w := newFakeWALReader()
	c := NewCompositeByteReader(w, newFakeBytestore(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.ReadEntry(ctx, 1, hashFor("anything"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestComposite_ContextCanceled_BatchReturnsCancel(t *testing.T) {
	w := newFakeWALReader()
	c := NewCompositeByteReader(w, newFakeBytestore(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.ReadEntryBatch(ctx, []bytestore.EntryRef{{Seq: 1, Hash: [32]byte{}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 10) Static interface compatibility
// ─────────────────────────────────────────────────────────────────────

// The composite slots into PostgresEntryFetcher / PostgresCommitmentFetcher
// /  PostgresQueryAPI without any signature change. Pinned at compile
// time via the var-decl in fetcher.go; this test makes that intent
// visible to readers of the test file.
func TestComposite_SatisfiesBytestoreReader(t *testing.T) {
	var _ bytestore.Reader = (*CompositeByteReader)(nil)
}

// ─────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
