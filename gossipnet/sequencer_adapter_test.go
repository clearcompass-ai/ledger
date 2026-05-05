/*
FILE PATH: gossipnet/sequencer_adapter_test.go

Tests for the two thin adapters that bridge the sequencer's
type-defined hooks (SplitIDIndexWriter, EntryLookupWriter) to
gossipstore.BadgerStore. The adapters are mechanical — but the
mechanical translation IS the load-bearing test surface, since a
field misnamed here would silently break detection (0x0A) or
read serving (0x0C).

Coverage:

  SequencerSplitIDAdapter
    - nil store → nil adapter (sequencer's nil-tolerant path)
    - nil adapter is callable (no-op)
    - write round-trips through gossipstore.ListSplitIDIndexEntriesAt
    - field mapping: EquivocatorDID, CanonicalHash, SigBytes preserved

  SequencerEntryLookupAdapter
    - nil store → nil adapter
    - nil adapter is callable (no-op)
    - write round-trips through gossipstore.ListEntryLookupEntriesAt
    - field mapping: CanonicalBytes, LogTimeMicros, LogDID preserved
    - static interface check (var _ ... = ...)
*/
package gossipnet

import (
	"bytes"
	"context"
	"testing"

	"github.com/dgraph-io/badger/v4"

	"github.com/clearcompass-ai/ledger/gossipstore"
	"github.com/clearcompass-ai/ledger/sequencer"
)

func adapterTestStore(t *testing.T) *gossipstore.BadgerStore {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("badger.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := gossipstore.New(gossipstore.Config{DB: db, GCInterval: -1})
	if err != nil {
		t.Fatalf("gossipstore.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	return st
}

func TestNewSequencerSplitIDAdapter_NilStore(t *testing.T) {
	if a := NewSequencerSplitIDAdapter(nil); a != nil {
		t.Errorf("nil store should produce nil adapter, got %v", a)
	}
}

func TestNewSequencerEntryLookupAdapter_NilStore(t *testing.T) {
	if a := NewSequencerEntryLookupAdapter(nil); a != nil {
		t.Errorf("nil store should produce nil adapter, got %v", a)
	}
}

func TestSequencerSplitIDAdapter_NilAdapterIsNoOp(t *testing.T) {
	var a *SequencerSplitIDAdapter
	if err := a.WriteSplitIDIndexEntry(
		context.Background(), "schema", [32]byte{0x01}, 1,
		sequencer.SplitIDIndexEntry{
			EquivocatorDID: "did:web:op",
			CanonicalHash:  [32]byte{0xab},
			SigBytes:       []byte("sig"),
		}); err != nil {
		t.Errorf("nil adapter write should be no-op, got error: %v", err)
	}
}

func TestSequencerEntryLookupAdapter_NilAdapterIsNoOp(t *testing.T) {
	var a *SequencerEntryLookupAdapter
	if err := a.WriteEntryLookupEntry(
		context.Background(), "schema", [32]byte{0x01}, 1,
		sequencer.EntryLookupIndexEntry{
			CanonicalBytes: []byte("x"),
			LogTimeMicros:  1,
			LogDID:         "did:web:op",
		}); err != nil {
		t.Errorf("nil adapter write should be no-op, got error: %v", err)
	}
}

func TestSequencerSplitIDAdapter_RoundTripsFields(t *testing.T) {
	st := adapterTestStore(t)
	a := NewSequencerSplitIDAdapter(st)
	if a == nil {
		t.Fatal("expected non-nil adapter")
	}

	want := sequencer.SplitIDIndexEntry{
		EquivocatorDID: "did:web:op",
		CanonicalHash:  [32]byte{0x01, 0x02, 0x03},
		SigBytes:       []byte("operator-signature"),
	}

	if err := a.WriteSplitIDIndexEntry(
		context.Background(), "schema-X", [32]byte{0xAA}, 7, want,
	); err != nil {
		t.Fatalf("WriteSplitIDIndexEntry: %v", err)
	}

	hits, err := st.ListSplitIDIndexEntriesAt(
		context.Background(), "schema-X", [32]byte{0xAA})
	if err != nil {
		t.Fatalf("ListSplitIDIndexEntriesAt: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].EntrySeq != 7 {
		t.Errorf("EntrySeq = %d, want 7", hits[0].EntrySeq)
	}
	if hits[0].Entry.EquivocatorDID != want.EquivocatorDID {
		t.Errorf("EquivocatorDID drift: %q vs %q",
			hits[0].Entry.EquivocatorDID, want.EquivocatorDID)
	}
	if hits[0].Entry.CanonicalHash != want.CanonicalHash {
		t.Errorf("CanonicalHash drift: %x vs %x",
			hits[0].Entry.CanonicalHash, want.CanonicalHash)
	}
	if !bytes.Equal(hits[0].Entry.SigBytes, want.SigBytes) {
		t.Errorf("SigBytes drift: %x vs %x",
			hits[0].Entry.SigBytes, want.SigBytes)
	}
}

func TestSequencerEntryLookupAdapter_RoundTripsFields(t *testing.T) {
	st := adapterTestStore(t)
	a := NewSequencerEntryLookupAdapter(st)
	if a == nil {
		t.Fatal("expected non-nil adapter")
	}

	want := sequencer.EntryLookupIndexEntry{
		CanonicalBytes: []byte("canonical-wire-bytes"),
		LogTimeMicros:  1714659120_000000,
		LogDID:         "did:web:operator.example",
	}

	if err := a.WriteEntryLookupEntry(
		context.Background(), "schema-Y", [32]byte{0xBB}, 42, want,
	); err != nil {
		t.Fatalf("WriteEntryLookupEntry: %v", err)
	}

	hits, err := st.ListEntryLookupEntriesAt(
		context.Background(), "schema-Y", [32]byte{0xBB})
	if err != nil {
		t.Fatalf("ListEntryLookupEntriesAt: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].EntrySeq != 42 {
		t.Errorf("EntrySeq = %d, want 42", hits[0].EntrySeq)
	}
	if !bytes.Equal(hits[0].Entry.CanonicalBytes, want.CanonicalBytes) {
		t.Errorf("CanonicalBytes drift")
	}
	if hits[0].Entry.LogTimeMicros != want.LogTimeMicros {
		t.Errorf("LogTimeMicros = %d, want %d",
			hits[0].Entry.LogTimeMicros, want.LogTimeMicros)
	}
	if hits[0].Entry.LogDID != want.LogDID {
		t.Errorf("LogDID = %q, want %q",
			hits[0].Entry.LogDID, want.LogDID)
	}
}

// TestSequencerEntryLookupAdapter_StaticInterfaceCheck pins the
// compile-time guarantee that the adapter satisfies
// sequencer.EntryLookupWriter — drift in either side's signature
// fails this assignment at build time.
func TestSequencerEntryLookupAdapter_StaticInterfaceCheck(t *testing.T) {
	var _ sequencer.EntryLookupWriter = (*SequencerEntryLookupAdapter)(nil)
}

// TestSequencerSplitIDAdapter_StaticInterfaceCheck mirrors the
// guarantee for the splitid adapter.
func TestSequencerSplitIDAdapter_StaticInterfaceCheck(t *testing.T) {
	var _ sequencer.SplitIDIndexWriter = (*SequencerSplitIDAdapter)(nil)
}

// ─────────────────────────────────────────────────────────────────────
// SequencerReplayCursorAdapter (PT-4)
// ─────────────────────────────────────────────────────────────────────

func TestNewSequencerReplayCursorAdapter_NilStore(t *testing.T) {
	if a := NewSequencerReplayCursorAdapter(nil); a != nil {
		t.Errorf("nil store should produce nil adapter, got %v", a)
	}
}

func TestSequencerReplayCursorAdapter_NilAdapterIsNoOp(t *testing.T) {
	var a *SequencerReplayCursorAdapter
	got, err := a.SplitIDReplayHWM(context.Background())
	if err != nil {
		t.Errorf("nil adapter HWM read should return (0, nil), got error: %v", err)
	}
	if got != 0 {
		t.Errorf("nil adapter HWM read should return 0, got %d", got)
	}
	if err := a.SetSplitIDReplayHWM(context.Background(), 1); err != nil {
		t.Errorf("nil adapter Set should be no-op, got error: %v", err)
	}
}

func TestSequencerReplayCursorAdapter_RoundTripsHWM(t *testing.T) {
	st := adapterTestStore(t)
	a := NewSequencerReplayCursorAdapter(st)
	if a == nil {
		t.Fatal("expected non-nil adapter")
	}
	ctx := context.Background()

	// First read: HWM = 0 (no record).
	got, err := a.SplitIDReplayHWM(ctx)
	if err != nil {
		t.Fatalf("SplitIDReplayHWM: %v", err)
	}
	if got != 0 {
		t.Errorf("first read HWM = %d, want 0", got)
	}

	// Advance.
	if err := a.SetSplitIDReplayHWM(ctx, 100); err != nil {
		t.Fatalf("SetSplitIDReplayHWM: %v", err)
	}
	got, err = a.SplitIDReplayHWM(ctx)
	if err != nil {
		t.Fatalf("SplitIDReplayHWM: %v", err)
	}
	if got != 100 {
		t.Errorf("HWM after Set = %d, want 100", got)
	}

	// Backward Set is silently rejected (handled in gossipstore).
	if err := a.SetSplitIDReplayHWM(ctx, 50); err != nil {
		t.Fatalf("backwards Set: %v", err)
	}
	got, err = a.SplitIDReplayHWM(ctx)
	if err != nil {
		t.Fatalf("SplitIDReplayHWM: %v", err)
	}
	if got != 100 {
		t.Errorf("HWM after backwards Set = %d, want 100 (stuck)", got)
	}
}

func TestSequencerReplayCursorAdapter_StaticInterfaceCheck(t *testing.T) {
	var _ sequencer.SplitIDReplayCursor = (*SequencerReplayCursorAdapter)(nil)
}
