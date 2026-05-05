/*
FILE PATH: gossipstore/badger_store_test.go

Round-trip tests for BadgerStore against a real Badger DB. Each
test opens an in-memory Badger to keep the suite hermetic.

# COVERAGE GOALS

  - Append → Get round-trip preserves the event byte-for-byte.
  - Chain discipline: PrevHash + Lamport monotonicity rejected
    correctly.
  - I9 idempotency: re-receiving the same EventID is a no-op.
  - Iterate honors the Originator and Kind filters.
  - IterSince advances cursor.Lamport to the highest observed.
  - LatestSTH returns the most recent KindCosignedTreeHead per
    originator.
  - Stats counters track EventCount + OriginatorCount inside the
    Append txn (no external observer race).
  - Close cancels the GC goroutine cleanly + multiple Close
    calls return nil.
*/
package gossipstore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dgraph-io/badger/v4"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/gossip"
)

// memDB opens an in-memory Badger DB for one test and registers a
// cleanup hook. Tests share the same fixture style as the SDK's
// reference store tests.
func memDB(t *testing.T) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true).
		WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("badger.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// testStore returns a BadgerStore wired to memDB. GC is disabled
// (negative interval) so tests don't race the ticker.
func testStore(t *testing.T) *BadgerStore {
	t.Helper()
	st, err := New(Config{DB: memDB(t), GCInterval: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	return st
}

// stubEvent is a minimal real Event for round-trip tests. Body is
// JSON-encoded {"data":"x"}; canonical bytes are kind|data so two
// stubEvents with the same data produce the same EventID.
type stubEvent struct {
	kind gossip.Kind
	data string
}

func (s stubEvent) Kind() gossip.Kind     { return s.kind }
func (s stubEvent) Bindings() [][32]byte  { return nil }
func (s stubEvent) Validate() error       { return nil }
func (s stubEvent) CanonicalBytes() []byte {
	out := []byte(s.kind)
	out = append(out, '|')
	return append(out, s.data...)
}
func (s stubEvent) EncodeWireBody() (json.RawMessage, error) {
	return json.RawMessage(`{"data":"` + s.data + `"}`), nil
}

// fixture returns a (signer, did) pair backed by a fresh ECDSA key
// and a registered did:key VerifierRegistry.
type fixture struct {
	signer cosign.WitnessSigner
	did    string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	_ = signatures.SchemeECDSA // keep import live
	return fixture{
		signer: cosign.NewECDSAWitnessSigner(kp.PrivateKey),
		did:    kp.DID,
	}
}

func networkID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// signed signs a stubEvent under the fixture's DID + key.
func signed(t *testing.T, f fixture, kind gossip.Kind, prev [32]byte, lamport uint64, data string) gossip.SignedEvent {
	t.Helper()
	se, err := gossip.Sign(context.Background(),
		stubEvent{kind: kind, data: data},
		f.signer, networkID(), f.did, prev, lamport)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return se
}

func TestAppendFirst_GetRoundTrip(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)
	se := signed(t, f, gossip.KindEquivocationFinding, [32]byte{}, 1, "x")

	if err := st.Append(context.Background(), se); err != nil {
		t.Fatalf("Append: %v", err)
	}
	id, _ := gossip.EventIDOf(se)
	got, err := st.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Originator != se.Originator || got.LamportTime != se.LamportTime {
		t.Errorf("round-trip mismatch: got=%+v want=%+v", got, se)
	}
}

func TestAppendChain_HeadAdvances(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)

	se1 := signed(t, f, gossip.KindEquivocationFinding, [32]byte{}, 1, "a")
	if err := st.Append(context.Background(), se1); err != nil {
		t.Fatal(err)
	}
	id1, _ := gossip.EventIDOf(se1)

	prev, lamport, _ := st.Head(context.Background(), f.did)
	if prev != id1 || lamport != 1 {
		t.Errorf("head after se1 = (%x, %d), want (%x, 1)", prev[:8], lamport, id1[:8])
	}

	se2 := signed(t, f, gossip.KindEquivocationFinding, id1, 2, "b")
	if err := st.Append(context.Background(), se2); err != nil {
		t.Fatal(err)
	}
	id2, _ := gossip.EventIDOf(se2)
	prev, lamport, _ = st.Head(context.Background(), f.did)
	if prev != id2 || lamport != 2 {
		t.Errorf("head after se2 = (%x, %d), want (%x, 2)", prev[:8], lamport, id2[:8])
	}
}

func TestAppendChainBreak_RejectsBadPrev(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)
	se1 := signed(t, f, gossip.KindEquivocationFinding, [32]byte{}, 1, "x")
	st.Append(context.Background(), se1)

	se2 := signed(t, f, gossip.KindEquivocationFinding, [32]byte{0xFF}, 2, "y")
	err := st.Append(context.Background(), se2)
	if err == nil {
		t.Fatal("err = nil, want chain break")
	}
}

func TestAppend_LamportRegression(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)
	se1 := signed(t, f, gossip.KindEquivocationFinding, [32]byte{}, 5, "x")
	st.Append(context.Background(), se1)
	id1, _ := gossip.EventIDOf(se1)

	se2 := signed(t, f, gossip.KindEquivocationFinding, id1, 5, "y")
	err := st.Append(context.Background(), se2)
	if err == nil {
		t.Fatal("err = nil, want lamport regression")
	}
}

func TestAppend_Idempotent(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)
	se := signed(t, f, gossip.KindEquivocationFinding, [32]byte{}, 1, "x")
	if err := st.Append(context.Background(), se); err != nil {
		t.Fatal(err)
	}
	// Re-append same event: I9 idempotency.
	if err := st.Append(context.Background(), se); err != nil {
		t.Errorf("re-append err = %v, want nil", err)
	}
	stats, _ := st.Stats(context.Background())
	if stats.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (idempotent)", stats.EventCount)
	}
}

func TestIterSince_AdvancesCursor(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)
	prev := [32]byte{}
	for i := uint64(1); i <= 5; i++ {
		se := signed(t, f, gossip.KindEquivocationFinding, prev, i, "x")
		if err := st.Append(context.Background(), se); err != nil {
			t.Fatal(err)
		}
		prev, _ = gossip.EventIDOf(se)
	}
	cursor := gossip.IterCursor{Originator: f.did, Lamport: 0}
	hits, next, err := st.IterSince(context.Background(), cursor, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 3 {
		t.Errorf("hits = %d, want 3", len(hits))
	}
	if next.Lamport != 3 {
		t.Errorf("next.Lamport = %d, want 3", next.Lamport)
	}
	hits2, next2, _ := st.IterSince(context.Background(), next, 5)
	if len(hits2) != 2 {
		t.Errorf("page 2 hits = %d, want 2", len(hits2))
	}
	if next2.Lamport != 5 {
		t.Errorf("next2.Lamport = %d, want 5", next2.Lamport)
	}
}

func TestLatestSTH_RetrievesMostRecent(t *testing.T) {
	f := newFixture(t)
	st := testStore(t)
	prev := [32]byte{}
	// Mix kinds; LatestSTH should ignore non-STH entries.
	se1 := signed(t, f, gossip.KindEquivocationFinding, prev, 1, "a")
	st.Append(context.Background(), se1)
	prev, _ = gossip.EventIDOf(se1)

	se2 := signed(t, f, gossip.KindCosignedTreeHead, prev, 2, "b")
	st.Append(context.Background(), se2)
	prev, _ = gossip.EventIDOf(se2)

	se3 := signed(t, f, gossip.KindCosignedTreeHead, prev, 3, "c")
	st.Append(context.Background(), se3)

	got, ok, err := st.LatestSTH(context.Background(), f.did)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("found = false, want true")
	}
	if got.LamportTime != 3 {
		t.Errorf("LatestSTH lamport = %d, want 3", got.LamportTime)
	}
}

func TestStats_CountsCorrectly(t *testing.T) {
	f1 := newFixture(t)
	f2 := newFixture(t)
	st := testStore(t)

	// 3 from originator 1
	prev := [32]byte{}
	for i := uint64(1); i <= 3; i++ {
		se := signed(t, f1, gossip.KindEquivocationFinding, prev, i, "x")
		st.Append(context.Background(), se)
		prev, _ = gossip.EventIDOf(se)
	}
	// 2 from originator 2
	prev = [32]byte{}
	for i := uint64(1); i <= 2; i++ {
		se := signed(t, f2, gossip.KindEquivocationFinding, prev, i, "y")
		st.Append(context.Background(), se)
		prev, _ = gossip.EventIDOf(se)
	}

	stats, _ := st.Stats(context.Background())
	if stats.EventCount != 5 {
		t.Errorf("EventCount = %d, want 5", stats.EventCount)
	}
	if stats.OriginatorCount != 2 {
		t.Errorf("OriginatorCount = %d, want 2", stats.OriginatorCount)
	}
	if stats.Heads[f1.did] != 3 {
		t.Errorf("Heads[f1] = %d, want 3", stats.Heads[f1.did])
	}
	if stats.Heads[f2.did] != 2 {
		t.Errorf("Heads[f2] = %d, want 2", stats.Heads[f2.did])
	}
}

func TestClose_Idempotent(t *testing.T) {
	st := testStore(t)
	if err := st.Close(context.Background()); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := st.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
