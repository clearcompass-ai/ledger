/*
FILE PATH: gossipstore/commitment_fetcher_test.go

Coverage tests for BadgerCommitmentFetcher — the Postgres-free
implementation of types.CommitmentFetcher backing
/v1/commitments/by-split-id under the Pure CQRS principle.

  - nil store at construction panics (no silent empty results).
  - Empty schemaID is rejected.
  - Zero rows → nil, nil (handler maps to 404).
  - Single row → one EntryWithMetadata with field round-trip.
  - Multiple rows → seq-ascending order (Decision 4 equivocation).
  - LogTime reconstruction from LogTimeMicros is UTC + correct.
  - LogDID is preserved per-row (multi-tenant operator support).
  - CanonicalBytes are returned independently of the underlying
    Badger value (no aliased memory).
  - Static interface check vs. types.CommitmentFetcher.
*/
package gossipstore

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/types"
)

func TestNewBadgerCommitmentFetcher_NilStorePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil store")
		}
	}()
	_ = NewBadgerCommitmentFetcher(nil)
}

func TestBadgerCommitmentFetcher_RejectsEmptySchemaID(t *testing.T) {
	st := testStore(t)
	f := NewBadgerCommitmentFetcher(st)
	if _, err := f.FindCommitmentEntries("", [32]byte{0x01}); err == nil {
		t.Error("expected error on empty schemaID")
	}
}

func TestBadgerCommitmentFetcher_NoMatch_ReturnsNil(t *testing.T) {
	st := testStore(t)
	f := NewBadgerCommitmentFetcher(st)
	got, err := f.FindCommitmentEntries("schema-x", [32]byte{0xff})
	if err != nil {
		t.Fatalf("FindCommitmentEntries: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on no-match, got %v", got)
	}
}

func TestBadgerCommitmentFetcher_SingleRow_RoundTrips(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "attesta.network/schema/pre-grant-commitment/v1"
	split := [32]byte{0xab, 0xcd}
	wantBytes := []byte("canonical-wire-bytes-for-single-row")
	wantMicros := int64(1714659120_000000)
	wantDID := "did:web:operator.example"

	if err := st.WriteEntryLookupEntry(ctx, schema, split, 7, EntryLookupIndexEntry{
		CanonicalBytes: wantBytes,
		LogTimeMicros:  wantMicros,
		LogDID:         wantDID,
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	f := NewBadgerCommitmentFetcher(st)
	got, err := f.FindCommitmentEntries(schema, split)
	if err != nil {
		t.Fatalf("FindCommitmentEntries: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].CanonicalBytes, wantBytes) {
		t.Errorf("CanonicalBytes drift")
	}
	wantTime := time.UnixMicro(wantMicros).UTC()
	if !got[0].LogTime.Equal(wantTime) {
		t.Errorf("LogTime = %v, want %v", got[0].LogTime, wantTime)
	}
	if got[0].LogTime.Location() != time.UTC {
		t.Errorf("LogTime location = %v, want UTC", got[0].LogTime.Location())
	}
	if got[0].Position.Sequence != 7 {
		t.Errorf("Sequence = %d, want 7", got[0].Position.Sequence)
	}
	if got[0].Position.LogDID != wantDID {
		t.Errorf("LogDID = %q, want %q", got[0].Position.LogDID, wantDID)
	}
}

func TestBadgerCommitmentFetcher_MultipleRows_SeqAscending(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "schema-y"
	split := [32]byte{0x01}

	// Write three entries at the same (schema, split_id) — the
	// equivocation case (Decision 4: admit all, surface evidence).
	// Insert out of order to verify the fetcher orders by seq ASC.
	rows := []struct {
		seq    uint64
		bytes  []byte
		micros int64
	}{
		{42, []byte("entry-42"), 4242},
		{7, []byte("entry-7"), 707},
		{100, []byte("entry-100"), 10000},
	}
	for _, r := range rows {
		if err := st.WriteEntryLookupEntry(ctx, schema, split, r.seq,
			EntryLookupIndexEntry{
				CanonicalBytes: r.bytes,
				LogTimeMicros:  r.micros,
				LogDID:         "did:web:op",
			}); err != nil {
			t.Fatalf("Write seq=%d: %v", r.seq, err)
		}
	}

	f := NewBadgerCommitmentFetcher(st)
	got, err := f.FindCommitmentEntries(schema, split)
	if err != nil {
		t.Fatalf("FindCommitmentEntries: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	wantOrder := []uint64{7, 42, 100}
	for i, e := range got {
		if e.Position.Sequence != wantOrder[i] {
			t.Errorf("got[%d].Sequence = %d, want %d",
				i, e.Position.Sequence, wantOrder[i])
		}
	}
}

func TestBadgerCommitmentFetcher_PerRowLogDID(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "schema-multi-tenant"
	split := [32]byte{0x42}

	// Different LogDIDs per seq — supports a future multi-tenant
	// operator binary serving multiple log DIDs.
	for i, did := range []string{"did:web:op-A", "did:web:op-B"} {
		if err := st.WriteEntryLookupEntry(ctx, schema, split, uint64(i+1),
			EntryLookupIndexEntry{
				CanonicalBytes: []byte{byte(i + 1)},
				LogTimeMicros:  int64(i + 1),
				LogDID:         did,
			}); err != nil {
			t.Fatalf("Write i=%d: %v", i, err)
		}
	}

	f := NewBadgerCommitmentFetcher(st)
	got, err := f.FindCommitmentEntries(schema, split)
	if err != nil {
		t.Fatalf("FindCommitmentEntries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].Position.LogDID != "did:web:op-A" {
		t.Errorf("got[0].LogDID = %q, want did:web:op-A", got[0].Position.LogDID)
	}
	if got[1].Position.LogDID != "did:web:op-B" {
		t.Errorf("got[1].LogDID = %q, want did:web:op-B", got[1].Position.LogDID)
	}
}

func TestBadgerCommitmentFetcher_CanonicalBytesAreCopies(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "schema"
	split := [32]byte{0x01}
	want := []byte("payload-bytes")

	if err := st.WriteEntryLookupEntry(ctx, schema, split, 1, EntryLookupIndexEntry{
		CanonicalBytes: want,
		LogTimeMicros:  1,
		LogDID:         "did:web:op",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	f := NewBadgerCommitmentFetcher(st)
	got, err := f.FindCommitmentEntries(schema, split)
	if err != nil {
		t.Fatalf("FindCommitmentEntries: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}

	// Mutating the returned bytes must not affect a subsequent
	// fetch — the fetcher returns independent copies.
	got[0].CanonicalBytes[0] = 0xff

	got2, err := f.FindCommitmentEntries(schema, split)
	if err != nil {
		t.Fatalf("FindCommitmentEntries (2): %v", err)
	}
	if !bytes.Equal(got2[0].CanonicalBytes, want) {
		t.Errorf("second fetch returned mutated bytes — copies aren't independent")
	}
}

func TestBadgerCommitmentFetcher_StaticInterfaceCheck(t *testing.T) {
	var _ types.CommitmentFetcher = (*BadgerCommitmentFetcher)(nil)
}
