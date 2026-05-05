/*
FILE PATH: gossipstore/entry_lookup_test.go

Tests for the 0x0C entry-lookup projection (keyspace encoders +
public Read/Write methods) that backs /v1/commitments/by-split-id
under the Pure CQRS principle (P8). Co-authored with the
sequencer-driven write path: the sequencer is the only writer,
api/ is the only reader.

Coverage goals:

  - Key encoding round-trips: entryLookupKey ↔ entryLookupKeyParts.
  - Prefix matching: entryLookupPrefix is byte-prefix of every
    entryLookupKey at the same (schema, split_id).
  - Encode/Decode round-trip: EntryLookupIndexEntry preserves all
    fields and rejects empties.
  - Schema-ID truncation matches between key + prefix paths.
  - Write → List round-trip returns rows in seq-ascending order.
  - Empty schema rejected at Write + List boundaries.
  - Length contract: 0 / 1 / N+ rows mapped correctly.
  - Different (schema_id, split_id) tuples don't cross-contaminate.
*/
package gossipstore

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestEntryLookupKey_RoundTrips(t *testing.T) {
	cases := []struct {
		name     string
		schemaID string
		splitID  [32]byte
		seq      uint64
	}{
		{"basic", "schema-x", [32]byte{0x01}, 1},
		{"high-seq", "schema-y", [32]byte{0xff, 0xfe}, 1<<63 + 7},
		{"zero-seq", "z", [32]byte{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := entryLookupKey(tc.schemaID, tc.splitID, tc.seq)
			schema, split, seq, err := entryLookupKeyParts(k)
			if err != nil {
				t.Fatalf("entryLookupKeyParts: %v", err)
			}
			if schema != tc.schemaID {
				t.Errorf("schema = %q, want %q", schema, tc.schemaID)
			}
			if split != tc.splitID {
				t.Errorf("split mismatch: %x vs %x", split, tc.splitID)
			}
			if seq != tc.seq {
				t.Errorf("seq = %d, want %d", seq, tc.seq)
			}
		})
	}
}

func TestEntryLookupKey_PrefixMatchesKey(t *testing.T) {
	schemaID := "attesta.network/schema/pre-grant-commitment/v1"
	splitID := [32]byte{0xaa, 0xbb, 0xcc}

	prefix := entryLookupPrefix(schemaID, splitID)
	for seq := uint64(0); seq < 5; seq++ {
		k := entryLookupKey(schemaID, splitID, seq)
		if !bytes.HasPrefix(k, prefix) {
			t.Errorf("seq=%d: key does not start with prefix; key=%x prefix=%x", seq, k, prefix)
		}
	}
}

func TestEntryLookupKey_DistinctSplitIDsDoNotShareScan(t *testing.T) {
	schemaID := "schema"
	splitA := [32]byte{0x01}
	splitB := [32]byte{0x02}

	prefixA := entryLookupPrefix(schemaID, splitA)
	keyB := entryLookupKey(schemaID, splitB, 1)

	if bytes.HasPrefix(keyB, prefixA) {
		t.Error("split B key matched split A prefix; cross-tuple contamination")
	}
}

func TestEntryLookupKeyParts_RejectsBadInputs(t *testing.T) {
	cases := []struct {
		name string
		k    []byte
	}{
		{"too short", []byte{prefixGossipRoot, subEntryLookup}},
		{"wrong root", []byte{0x00, subEntryLookup, 0, 0}},
		{"wrong sub", []byte{prefixGossipRoot, 0x00, 0, 0}},
		{"length mismatch", []byte{prefixGossipRoot, subEntryLookup, 0, 4, 'a', 'b', 'c'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := entryLookupKeyParts(tc.k); err == nil {
				t.Errorf("expected error on %s", tc.name)
			}
		})
	}
}

func TestEntryLookupKey_LongSchemaIDIsTruncated(t *testing.T) {
	long := strings.Repeat("z", MaxSchemaIDLen+50)
	k := entryLookupKey(long, [32]byte{0xab}, 1)
	prefix := entryLookupPrefix(long, [32]byte{0xab})
	if !bytes.HasPrefix(k, prefix) {
		t.Error("truncation drift: key/prefix produced different schema lengths")
	}
}

func TestEncodeDecodeEntryLookupIndexEntry(t *testing.T) {
	in := EntryLookupIndexEntry{
		CanonicalBytes: []byte("canonical-bytes-payload"),
		LogTimeMicros:  1714659120_000000,
		LogDID:         "did:web:ledger.example",
	}
	raw, err := EncodeEntryLookupIndexEntry(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := DecodeEntryLookupIndexEntry(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.CanonicalBytes, in.CanonicalBytes) {
		t.Errorf("CanonicalBytes drift")
	}
	if out.LogTimeMicros != in.LogTimeMicros {
		t.Errorf("LogTimeMicros = %d, want %d", out.LogTimeMicros, in.LogTimeMicros)
	}
	if out.LogDID != in.LogDID {
		t.Errorf("LogDID = %q, want %q", out.LogDID, in.LogDID)
	}
}

func TestEncodeEntryLookupIndexEntry_RejectsEmpties(t *testing.T) {
	if _, err := EncodeEntryLookupIndexEntry(EntryLookupIndexEntry{
		LogDID: "did:web:x",
	}); err == nil {
		t.Error("expected error on empty CanonicalBytes")
	}
	if _, err := EncodeEntryLookupIndexEntry(EntryLookupIndexEntry{
		CanonicalBytes: []byte("x"),
	}); err == nil {
		t.Error("expected error on empty LogDID")
	}
}

func TestDecodeEntryLookupIndexEntry_RejectsBadJSON(t *testing.T) {
	if _, err := DecodeEntryLookupIndexEntry([]byte("{not json")); err == nil {
		t.Error("expected error on invalid JSON")
	}
	if _, err := DecodeEntryLookupIndexEntry([]byte(`{"log_did":"x"}`)); err == nil {
		t.Error("expected error on empty CanonicalBytes after decode")
	}
	if _, err := DecodeEntryLookupIndexEntry([]byte(`{"canonical_bytes":"eA=="}`)); err == nil {
		t.Error("expected error on empty LogDID after decode")
	}
}

func TestWriteAndListEntryLookupEntriesAt_Empty(t *testing.T) {
	st := testStore(t)
	hits, err := st.ListEntryLookupEntriesAt(
		context.Background(), "schema-x", [32]byte{0x01})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("expected 0 hits on empty store, got %d", len(hits))
	}
}

func TestWriteAndListEntryLookupEntriesAt_SingleRow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "attesta.network/schema/pre-grant-commitment/v1"
	split := [32]byte{0xab, 0xcd}

	want := EntryLookupIndexEntry{
		CanonicalBytes: []byte("entry-bytes-1"),
		LogTimeMicros:  111,
		LogDID:         "did:web:op",
	}
	if err := st.WriteEntryLookupEntry(ctx, schema, split, 7, want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	hits, err := st.ListEntryLookupEntriesAt(ctx, schema, split)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].EntrySeq != 7 {
		t.Errorf("EntrySeq = %d, want 7", hits[0].EntrySeq)
	}
	if !bytes.Equal(hits[0].Entry.CanonicalBytes, want.CanonicalBytes) {
		t.Errorf("CanonicalBytes drift")
	}
	if hits[0].Entry.LogTimeMicros != want.LogTimeMicros {
		t.Errorf("LogTimeMicros drift")
	}
	if hits[0].Entry.LogDID != want.LogDID {
		t.Errorf("LogDID drift")
	}
}

func TestWriteAndListEntryLookupEntriesAt_EquivocationOrder(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "schema-y"
	split := [32]byte{0xff}

	// Write three entries at the same (schema, split_id) — the
	// equivocation case (Decision 4: admit all, surface as evidence).
	// Insert out of order to verify the iterator returns by seq ASC.
	for _, seq := range []uint64{42, 7, 100} {
		entry := EntryLookupIndexEntry{
			CanonicalBytes: []byte{byte(seq)},
			LogTimeMicros:  int64(seq),
			LogDID:         "did:web:op",
		}
		if err := st.WriteEntryLookupEntry(ctx, schema, split, seq, entry); err != nil {
			t.Fatalf("Write seq=%d: %v", seq, err)
		}
	}

	hits, err := st.ListEntryLookupEntriesAt(ctx, schema, split)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(hits) != 3 {
		t.Fatalf("hits = %d, want 3", len(hits))
	}
	wantOrder := []uint64{7, 42, 100}
	for i, h := range hits {
		if h.EntrySeq != wantOrder[i] {
			t.Errorf("hits[%d].EntrySeq = %d, want %d", i, h.EntrySeq, wantOrder[i])
		}
	}
}

func TestWriteAndListEntryLookupEntriesAt_NoCrossContamination(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	splitA := [32]byte{0x01}
	splitB := [32]byte{0x02}

	if err := st.WriteEntryLookupEntry(ctx, "schema-A", splitA, 1, EntryLookupIndexEntry{
		CanonicalBytes: []byte("A"), LogTimeMicros: 1, LogDID: "did:web:op",
	}); err != nil {
		t.Fatalf("Write A: %v", err)
	}
	if err := st.WriteEntryLookupEntry(ctx, "schema-B", splitB, 2, EntryLookupIndexEntry{
		CanonicalBytes: []byte("B"), LogTimeMicros: 2, LogDID: "did:web:op",
	}); err != nil {
		t.Fatalf("Write B: %v", err)
	}

	if hits, _ := st.ListEntryLookupEntriesAt(ctx, "schema-A", splitA); len(hits) != 1 {
		t.Errorf("schema-A hits = %d, want 1", len(hits))
	}
	if hits, _ := st.ListEntryLookupEntriesAt(ctx, "schema-B", splitB); len(hits) != 1 {
		t.Errorf("schema-B hits = %d, want 1", len(hits))
	}
	if hits, _ := st.ListEntryLookupEntriesAt(ctx, "schema-A", splitB); len(hits) != 0 {
		t.Errorf("schema-A/splitB hits = %d, want 0 (cross contamination)", len(hits))
	}
	if hits, _ := st.ListEntryLookupEntriesAt(ctx, "schema-B", splitA); len(hits) != 0 {
		t.Errorf("schema-B/splitA hits = %d, want 0 (cross contamination)", len(hits))
	}
}

func TestWriteEntryLookupEntry_Idempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "schema-z"
	split := [32]byte{0x42}
	entry := EntryLookupIndexEntry{
		CanonicalBytes: []byte("payload"),
		LogTimeMicros:  555,
		LogDID:         "did:web:op",
	}
	for i := 0; i < 3; i++ {
		if err := st.WriteEntryLookupEntry(ctx, schema, split, 1, entry); err != nil {
			t.Fatalf("Write iter=%d: %v", i, err)
		}
	}
	hits, err := st.ListEntryLookupEntriesAt(ctx, schema, split)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(hits) != 1 {
		t.Errorf("hits = %d, want 1 (idempotent overwrite)", len(hits))
	}
}

func TestWriteEntryLookupEntry_RejectsEmptySchemaID(t *testing.T) {
	st := testStore(t)
	err := st.WriteEntryLookupEntry(
		context.Background(), "", [32]byte{0x01}, 1,
		EntryLookupIndexEntry{
			CanonicalBytes: []byte("x"), LogTimeMicros: 1, LogDID: "did:web:op",
		})
	if err == nil {
		t.Error("expected error on empty schemaID")
	}
}

func TestListEntryLookupEntriesAt_RejectsEmptySchemaID(t *testing.T) {
	st := testStore(t)
	if _, err := st.ListEntryLookupEntriesAt(
		context.Background(), "", [32]byte{0x01}); err == nil {
		t.Error("expected error on empty schemaID")
	}
}

func TestWriteEntryLookupEntry_ContextCancelled(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := st.WriteEntryLookupEntry(ctx, "schema", [32]byte{0x01}, 1,
		EntryLookupIndexEntry{
			CanonicalBytes: []byte("x"), LogTimeMicros: 1, LogDID: "did:web:op",
		})
	if err == nil {
		t.Error("expected ctx error on cancelled context")
	}
}

func TestListEntryLookupEntriesAt_ContextCancelled(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.ListEntryLookupEntriesAt(ctx, "schema", [32]byte{0x01}); err == nil {
		t.Error("expected ctx error on cancelled context")
	}
}
