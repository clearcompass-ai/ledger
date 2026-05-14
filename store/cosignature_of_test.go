/*
FILE PATH: store/cosignature_of_test.go

PR-G — binding test for the cosignature_of index and serializer
round-trip.

The cosignature_of column (BYTEA) + idx_cosignature_of partial
index have existed since 0001_initial.sql; the sequencer
(sequencer/loop.go) populates the column via SerializeLogPosition.
This test pins the round-trip end to end:

  1. Insert primary at seq=100, plus N cosignature entries whose
     CosignatureOf points at primary (encoded via
     SerializeLogPosition).
  2. SELECT WHERE cosignature_of = <same encoded bytes> returns
     exactly those N entries, in ascending sequence_number order.
  3. The encoded bytes round-trip through DeserializeLogPosition
     back to the same LogPosition struct.

Without this pin, a regression in SerializeLogPosition encoding
or in the sequencer populate path would silently break PR-H's
FetchByCosignatureOf — and through it, the read-time policy
verifier in judicial-network (which queries this index for
attestation candidates).

Skips when ATTESTA_TEST_DSN is unset (same convention as
sequence_cursor_test.go).
*/
package store

import (
	"context"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/types"
)

func TestEntryIndex_CosignatureOf_RoundTripAndQuery(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Truncate entry_index so test runs in a known state. CASCADE
	// because entry_index is FK'd from commitment_split_id.
	if _, err := pool.Exec(ctx, "TRUNCATE entry_index CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	store := NewEntryStore(pool)
	primary := types.LogPosition{LogDID: "did:web:cosig-test.log", Sequence: 100}
	primaryBytes := SerializeLogPosition(primary)

	// (1) Serializer round-trip — independent of any DB call.
	round, err := DeserializeLogPosition(primaryBytes)
	if err != nil {
		t.Fatalf("DeserializeLogPosition: %v", err)
	}
	if !round.Equal(primary) {
		t.Errorf("round-trip differs: got %+v, want %+v", round, primary)
	}

	// (2) Insert the primary entry (no CosignatureOf).
	primaryHash := [32]byte{}
	primaryHash[0] = 0xAA
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := store.Insert(ctx, tx, EntryRow{
		SequenceNumber: 100,
		CanonicalHash:  primaryHash,
		LogTime:        time.Now().UTC(),
		SignerDID:      "did:web:primary-author",
		Status:         StatusLive,
	}); err != nil {
		t.Fatalf("Insert primary: %v", err)
	}

	// (3) Insert three cosignature entries bound to the primary
	// via CosignatureOf = SerializeLogPosition(primary). They
	// MUST land in the cosignature_of index.
	cosigSeqs := []uint64{101, 102, 103}
	for _, seq := range cosigSeqs {
		var hash [32]byte
		hash[0] = byte(seq)
		if err := store.Insert(ctx, tx, EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hash,
			LogTime:        time.Now().UTC(),
			SignerDID:      "did:web:attestor",
			CosignatureOf:  primaryBytes,
			Status:         StatusLive,
		}); err != nil {
			t.Fatalf("Insert cosig %d: %v", seq, err)
		}
	}

	// (4) Query via the index. The partial index
	// idx_cosignature_of WHERE cosignature_of IS NOT NULL is
	// exactly the access path PR-H's FetchByCosignatureOf will
	// use. Order by sequence_number for determinism.
	rows, err := tx.Query(ctx, `
		SELECT sequence_number FROM entry_index
		 WHERE cosignature_of = $1
		 ORDER BY sequence_number`,
		primaryBytes)
	if err != nil {
		t.Fatalf("query by cosignature_of: %v", err)
	}
	defer rows.Close()
	var got []uint64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, uint64(s))
	}
	if rows.Err() != nil {
		t.Fatalf("rows.Err: %v", rows.Err())
	}
	if len(got) != len(cosigSeqs) {
		t.Errorf("returned %d rows, want %d (cosignature_of index missed entries)",
			len(got), len(cosigSeqs))
	}
	for i, s := range got {
		if s != cosigSeqs[i] {
			t.Errorf("row %d: seq=%d, want %d", i, s, cosigSeqs[i])
		}
	}
}

func TestEntryIndex_CosignatureOf_NullColumnNotMatchedByQuery(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := pool.Exec(ctx, "TRUNCATE entry_index CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	store := NewEntryStore(pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback(ctx)

	// Insert a non-cosignature entry (CosignatureOf nil). The
	// idx_cosignature_of partial index MUST NOT include it —
	// queries for any cosignature_of value must return zero rows.
	var hash [32]byte
	hash[0] = 0x42
	if err := store.Insert(ctx, tx, EntryRow{
		SequenceNumber: 7,
		CanonicalHash:  hash,
		LogTime:        time.Now().UTC(),
		SignerDID:      "did:web:author",
		CosignatureOf:  nil,
		Status:         StatusLive,
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	primary := types.LogPosition{LogDID: "did:web:any.log", Sequence: 9999}
	rows, err := tx.Query(ctx,
		"SELECT sequence_number FROM entry_index WHERE cosignature_of = $1",
		SerializeLogPosition(primary))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		count++
	}
	if count != 0 {
		t.Errorf("got %d rows for unknown cosignature_of; want 0", count)
	}
}

func TestSerializeLogPosition_DistinctPositionsProduceDistinctBytes(t *testing.T) {
	t.Parallel()

	// Pure unit test (no DB). Pins that the encoder produces
	// distinct bytes for distinct positions — load-bearing for
	// the index's discrimination across primaries on the same
	// log AND across logs at the same sequence.
	cases := []types.LogPosition{
		{LogDID: "did:web:log-a", Sequence: 1},
		{LogDID: "did:web:log-a", Sequence: 2},   // same log, different seq
		{LogDID: "did:web:log-b", Sequence: 1},   // different log, same seq
		{LogDID: "did:web:log-aa", Sequence: 1},  // prefix collision risk
	}
	seen := make(map[string]types.LogPosition, len(cases))
	for _, p := range cases {
		bs := string(SerializeLogPosition(p))
		if dup, conflict := seen[bs]; conflict {
			t.Errorf("encoder collision: %+v and %+v produced same bytes", p, dup)
		}
		seen[bs] = p
	}
}
