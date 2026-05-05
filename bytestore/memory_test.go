/*
FILE PATH: bytestore/memory_test.go

Evidence-based unit tests for the byte-store interface and the
in-memory implementation. Establishes the load-bearing invariants
that production callers rely on:

	Tessera-alignment invariant:
	  The byte store treats entries as opaque []byte blobs, identical
	  to the upstream Tessera library's storage shape (driver.Add
	  takes []byte, driver.ReadEntries returns []byte). A blob
	  written via WriteEntry round-trips byte-identically through
	  ReadEntry — no in-band length prefix, no split, no
	  interpretation.

	Hash-keyed storage invariant:
	  Entries are keyed by (seq, hash), not seq alone. Two writes
	  with the same seq but different hash are STORED AS DISTINCT
	  entries — the byte store does not collapse them. This matches
	  the upstream Tessera storage model where each integration
	  produces a unique (sequence, identity) tuple.

	Envelope round-trip invariant:
	  For any *envelope.Entry e produced by envelope.NewEntry +
	  Sign + Validate, the bytes envelope.Serialize(e) round-trip
	  through the byte store and recover an Entry equal to e via
	  envelope.Deserialize. EntryIdentity stable across the round
	  trip (Tessera dedup load-bearing property).

	Defensive copy invariant:
	  Mutating the input slice after WriteEntry returns must not
	  corrupt the stored value. Mutating the output slice from
	  ReadEntry must not corrupt the stored value.

The GCS and S3 implementations reuse many of the same scenarios in
their respective _test.go files against fake-gcs-server / RustFS;
together the suites cover both the in-memory hot path and the
network-bound impls.
*/
package bytestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// wireHash returns sha256(wire) — matches envelope.EntryIdentity
// when wire == envelope.Serialize(entry), so production and test
// code derive the storage key identically.
func wireHash(wire []byte) [32]byte {
	return sha256.Sum256(wire)
}

// ─────────────────────────────────────────────────────────────────────
// 1) Round-trip identity
// ─────────────────────────────────────────────────────────────────────

func TestMemory_RoundTrip_PreservesBytes(t *testing.T) {
	binarySeed := sha256.Sum256([]byte("k"))
	cases := []struct {
		name string
		wire []byte
	}{
		{"single-byte", []byte{0xAB}},
		{"ascii", []byte("the quick brown fox")},
		{"binary", append([]byte{0x00, 0xFF, 0x7F, 0x80}, binarySeed[:]...)},
		{"large-1MB", bytes.Repeat([]byte{0x42}, 1<<20)},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemory()
			h := wireHash(tc.wire)
			if err := s.WriteEntry(ctx, 7, h, tc.wire); err != nil {
				t.Fatalf("WriteEntry: %v", err)
			}
			got, err := s.ReadEntry(ctx, 7, h)
			if err != nil {
				t.Fatalf("ReadEntry: %v", err)
			}
			if !bytes.Equal(got, tc.wire) {
				t.Fatalf("round-trip mismatch:\n  got=%x\n want=%x", got, tc.wire)
			}
			if sha256.Sum256(got) != h {
				t.Fatal("hash differs after round-trip")
			}
		})
	}
}

// TestMemory_Opacity_StoresArbitraryBytes proves the store is opaque
// w.r.t. envelope structure. Random bytes that are NOT a valid
// envelope serialize identically — the store has no envelope-semantic
// dependency.
func TestMemory_Opacity_StoresArbitraryBytes(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	random := []byte("\x00\x01\x02\x03\xff\xfe\xfd\xfcRANDOMNOTANENVELOPE")
	h := wireHash(random)
	if err := s.WriteEntry(ctx, 1, h, random); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	got, err := s.ReadEntry(ctx, 1, h)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, random) {
		t.Fatalf("opacity violated: got=%x want=%x", got, random)
	}
	// And: envelope.Deserialize on this blob should fail (not an
	// envelope), proving the store didn't accidentally re-encode.
	if _, err := envelope.Deserialize(got); err == nil {
		t.Fatal("Deserialize on random bytes succeeded; the test fixture is no longer non-envelope")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2) Envelope round-trip — Tessera-alignment evidence
// ─────────────────────────────────────────────────────────────────────

func TestMemory_Envelope_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	original := mustNewSignedEntry(t, "did:web:envelope-rt.example", []byte("payload-rt"))
	wire := envelope.Serialize(original)
	hash := envelope.EntryIdentity(original)

	if err := s.WriteEntry(ctx, 99, hash, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	got, err := s.ReadEntry(ctx, 99, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("wire bytes mutated through store")
	}

	parsed, err := envelope.Deserialize(got)
	if err != nil {
		t.Fatalf("Deserialize after round-trip: %v", err)
	}

	// Identity stability — Tessera dedup keys on this hash.
	if envelope.EntryIdentity(parsed) != hash {
		t.Fatal("EntryIdentity changed across store round-trip — Tessera dedup would break")
	}
	if parsed.Header.SignerDID != original.Header.SignerDID {
		t.Fatalf("SignerDID changed: %q → %q",
			original.Header.SignerDID, parsed.Header.SignerDID)
	}
	if len(parsed.Signatures) != len(original.Signatures) {
		t.Fatalf("Signatures count changed: %d → %d",
			len(original.Signatures), len(parsed.Signatures))
	}
}

func TestMemory_Envelope_MultipleEntries_DistinctIdentities(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	const N = 8
	originals := make([]*envelope.Entry, N)
	wires := make([][]byte, N)
	hashes := make([][32]byte, N)
	for i := 0; i < N; i++ {
		originals[i] = mustNewSignedEntry(t,
			fmt.Sprintf("did:web:multi-rt-%d.example", i),
			[]byte(fmt.Sprintf("payload-%d", i)))
		wires[i] = envelope.Serialize(originals[i])
		hashes[i] = envelope.EntryIdentity(originals[i])
		if err := s.WriteEntry(ctx, uint64(i), hashes[i], wires[i]); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	// Read in reverse order to catch seq aliasing.
	for i := N - 1; i >= 0; i-- {
		got, err := s.ReadEntry(ctx, uint64(i), hashes[i])
		if err != nil {
			t.Fatalf("ReadEntry seq=%d: %v", i, err)
		}
		if !bytes.Equal(got, wires[i]) {
			t.Fatalf("seq=%d: wire bytes mutated", i)
		}
		parsed, err := envelope.Deserialize(got)
		if err != nil {
			t.Fatalf("seq=%d: Deserialize: %v", i, err)
		}
		if envelope.EntryIdentity(parsed) != hashes[i] {
			t.Fatalf("seq=%d: identity drift", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3) Hash-keyed storage — distinguishing same-seq-different-hash
// ─────────────────────────────────────────────────────────────────────

// TestMemory_SameSeqDifferentHash_StoredAsDistinct: two writes at the
// same seq with different content (different hash) are stored as
// SEPARATE entries — the store does not collapse on seq alone. This
// is required for the equivocation-evidence path: two distinct
// commitments at "the same" sequence (under malicious dealer
// equivocation) must both be recoverable.
func TestMemory_SameSeqDifferentHash_StoredAsDistinct(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	wireA := []byte("content-a")
	wireB := []byte("content-b")
	hashA := wireHash(wireA)
	hashB := wireHash(wireB)
	if hashA == hashB {
		t.Fatal("test setup: distinct content must yield distinct hashes")
	}

	if err := s.WriteEntry(ctx, 5, hashA, wireA); err != nil {
		t.Fatalf("WriteEntry A: %v", err)
	}
	if err := s.WriteEntry(ctx, 5, hashB, wireB); err != nil {
		t.Fatalf("WriteEntry B: %v", err)
	}

	gotA, err := s.ReadEntry(ctx, 5, hashA)
	if err != nil || !bytes.Equal(gotA, wireA) {
		t.Fatalf("ReadEntry A: err=%v got=%q want=%q", err, gotA, wireA)
	}
	gotB, err := s.ReadEntry(ctx, 5, hashB)
	if err != nil || !bytes.Equal(gotB, wireB) {
		t.Fatalf("ReadEntry B: err=%v got=%q want=%q", err, gotB, wireB)
	}
	if s.Len() != 2 {
		t.Fatalf("expected 2 entries stored, got %d", s.Len())
	}
}

// TestMemory_SameSeqSameHash_LastWriteWins: writing the same
// (seq, hash) twice — guaranteed identical content if the producer
// hashed deterministically — is idempotent at the store level. The
// stored bytes match either write equivalently.
func TestMemory_SameSeqSameHash_LastWriteWins(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	wire := []byte("content-x")
	hash := wireHash(wire)
	if err := s.WriteEntry(ctx, 5, hash, wire); err != nil {
		t.Fatalf("WriteEntry first: %v", err)
	}
	if err := s.WriteEntry(ctx, 5, hash, wire); err != nil {
		t.Fatalf("WriteEntry second: %v", err)
	}
	got, err := s.ReadEntry(ctx, 5, hash)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("ReadEntry: err=%v got=%q want=%q", err, got, wire)
	}
	if s.Len() != 1 {
		t.Fatalf("expected 1 entry stored, got %d", s.Len())
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4) Cross-impl parity (in-mem ↔ GCS ↔ S3 contract)
// ─────────────────────────────────────────────────────────────────────

// TestStore_InterfaceContract_RoundTrip exercises Store on the Memory
// impl. The GCS and S3 stores reuse this through their _test.go files
// against fake-gcs / RustFS. If a future impl is added, it should
// pass this same scenario.
func TestStore_InterfaceContract_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := Store(NewMemory())

	wire := []byte("contract-test-blob")
	hash := wireHash(wire)
	if err := s.WriteEntry(ctx, 33, hash, wire); err != nil {
		t.Fatalf("WriteEntry via interface: %v", err)
	}
	got, err := s.ReadEntry(ctx, 33, hash)
	if err != nil {
		t.Fatalf("ReadEntry via interface: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("interface round-trip mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5) Defensive copy semantics
// ─────────────────────────────────────────────────────────────────────

func TestMemory_DefensiveCopy_OnWrite(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	buf := []byte{0x01, 0x02, 0x03}
	hash := wireHash(buf)
	if err := s.WriteEntry(ctx, 11, hash, buf); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	// Mutate the caller's buffer.
	buf[0] = 0xFF
	got, err := s.ReadEntry(ctx, 11, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if got[0] != 0x01 {
		t.Fatalf("store retained alias to caller buffer: got[0]=%x", got[0])
	}
}

func TestMemory_DefensiveCopy_OnRead(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	want := []byte{0x10, 0x11, 0x12}
	hash := wireHash(want)
	if err := s.WriteEntry(ctx, 12, hash, want); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	first, err := s.ReadEntry(ctx, 12, hash)
	if err != nil {
		t.Fatalf("first ReadEntry: %v", err)
	}
	first[0] = 0xFF
	second, err := s.ReadEntry(ctx, 12, hash)
	if err != nil {
		t.Fatalf("second ReadEntry: %v", err)
	}
	if !bytes.Equal(second, want) {
		t.Fatalf("store retained alias to caller's read slice: second=%x", second)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6) Edge cases
// ─────────────────────────────────────────────────────────────────────

func TestMemory_RejectsEmptyWire(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	hash := wireHash([]byte("x"))
	if err := s.WriteEntry(ctx, 1, hash, nil); err == nil {
		t.Error("WriteEntry(nil) should error")
	}
	if err := s.WriteEntry(ctx, 1, hash, []byte{}); err == nil {
		t.Error("WriteEntry([]) should error")
	}
}

func TestMemory_ReadMissing_Errors(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	_, err := s.ReadEntry(ctx, 99999, wireHash([]byte("x")))
	if err == nil {
		t.Fatal("ReadEntry on absent (seq, hash) should error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestMemory_ReadWrongHash_Errors: the hash arg is part of the key.
// Reading with the right seq but the wrong hash returns ErrNotFound,
// not the entry written under a different hash.
func TestMemory_ReadWrongHash_Errors(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	wire := []byte("real")
	hash := wireHash(wire)
	if err := s.WriteEntry(ctx, 7, hash, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	wrongHash := wireHash([]byte("not-real"))
	if hash == wrongHash {
		t.Fatal("test setup: hashes must differ")
	}
	_, err := s.ReadEntry(ctx, 7, wrongHash)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for (seq=7, wrong hash), got %v", err)
	}
}

func TestMemory_BatchPreservesInputOrder(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	hashes := make(map[uint64][32]byte, 5)
	for i := uint64(1); i <= 5; i++ {
		wire := []byte{byte(i)}
		h := wireHash(wire)
		hashes[i] = h
		if err := s.WriteEntry(ctx, i, h, wire); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}
	wantOrder := []uint64{4, 1, 5, 3, 2}
	refs := make([]EntryRef, len(wantOrder))
	for i, seq := range wantOrder {
		refs[i] = EntryRef{Seq: seq, Hash: hashes[seq]}
	}
	got, err := s.ReadEntryBatch(ctx, refs)
	if err != nil {
		t.Fatalf("ReadEntryBatch: %v", err)
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(wantOrder))
	}
	for i, seq := range wantOrder {
		if !bytes.Equal(got[i], []byte{byte(seq)}) {
			t.Errorf("position %d: got %v, want [%d]", i, got[i], seq)
		}
	}
}

func TestMemory_BatchMissingSeqIsFatal(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	wire := []byte("x")
	h := wireHash(wire)
	if err := s.WriteEntry(ctx, 1, h, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	missing := EntryRef{Seq: 99999, Hash: wireHash([]byte("nope"))}
	_, err := s.ReadEntryBatch(ctx, []EntryRef{{Seq: 1, Hash: h}, missing})
	if err == nil {
		t.Fatal("expected fatal error on batch with missing entry")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7) Concurrency
// ─────────────────────────────────────────────────────────────────────

func TestMemory_Concurrent_WritesAndReads(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	const goroutines = 8
	const perGoroutine = 64

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				seq := uint64(g*perGoroutine + i)
				want := []byte{byte(g), byte(i), byte(g ^ i)}
				h := wireHash(want)
				if err := s.WriteEntry(ctx, seq, h, want); err != nil {
					t.Errorf("WriteEntry seq=%d: %v", seq, err)
					return
				}
				got, err := s.ReadEntry(ctx, seq, h)
				if err != nil {
					t.Errorf("ReadEntry seq=%d: %v", seq, err)
					return
				}
				if !bytes.Equal(got, want) {
					t.Errorf("seq=%d: read mismatch", seq)
				}
			}
		}(g)
	}
	wg.Wait()

	if got, want := s.Len(), goroutines*perGoroutine; got != want {
		t.Errorf("Len: got %d, want %d", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8) Helpers
// ─────────────────────────────────────────────────────────────────────

func mustNewSignedEntry(t *testing.T, signerDID string, payload []byte) *envelope.Entry {
	t.Helper()
	ent, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   signerDID,
		Destination: "did:web:roundtrip-log.example",
		EventTime:   1700000000,
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	signingPayload := envelope.SigningPayload(ent)
	digest := sha256.Sum256(signingPayload)
	sig := make([]byte, 64)
	copy(sig, digest[:])
	copy(sig[32:], digest[:])

	ent.Signatures = []envelope.Signature{{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}

	if err := ent.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	return ent
}

var _ = mustNewSignedEntry
