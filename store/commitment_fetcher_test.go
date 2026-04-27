/*
FILE PATH: store/commitment_fetcher_test.go

Multi-row contract tests for PostgresCommitmentFetcher (Wave 1 v3 §C5).

The single load-bearing invariant under test: when commitment_split_id
has more than one row matching (schema_id, split_id), the fetcher
returns ALL of them as []*EntryWithMetadata. The SDK's
*CommitmentEquivocationError construction depends on this signal;
collapsing to a single row would silently destroy the cryptographic
evidence that ADR-005 §3 instructs verifiers to act on.

Test isolation: tests requiring a live Postgres skip when
ORTHOLOG_TEST_DSN is unset. The CI2 docker-compose harness
(integration/) wires the env var so these tests run on every PR.
Local developers can run them by exporting ORTHOLOG_TEST_DSN to a
disposable Postgres database.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────
// Test doubles
// ─────────────────────────────────────────────────────────────────────

// fakeEntryReader satisfies tessera.EntryReader by returning canned
// RawEntry values keyed by sequence number. Reads of unknown
// sequences return an error so the test surfaces the fetcher's
// error path on Tessera-side misses.
//
// tessera.EntryReader's full interface (per tessera/entry_reader.go):
//
//	ReadEntry(seq uint64) (RawEntry, error)
//	ReadEntryBatch(seqs []uint64) ([]RawEntry, error)
//
// Both methods are implemented below. The fetcher under test calls
// ReadEntry sequentially today; ReadEntryBatch is here so the fake
// also satisfies the interface for any future fetcher path that
// switches to batch reads.
type fakeEntryReader struct {
	entries map[uint64]tessera.RawEntry
}

func (f *fakeEntryReader) ReadEntry(seq uint64) (tessera.RawEntry, error) {
	raw, ok := f.entries[seq]
	if !ok {
		return tessera.RawEntry{}, fmt.Errorf("fakeEntryReader: no entry seq=%d", seq)
	}
	return raw, nil
}

// ReadEntryBatch returns each requested sequence's entry in the
// same order as the input slice. Mirrors the real
// InMemoryEntryStore.ReadEntryBatch semantics: any missing sequence
// is a fatal error for the whole batch (so callers don't get a
// silent short slice).
func (f *fakeEntryReader) ReadEntryBatch(seqs []uint64) ([]tessera.RawEntry, error) {
	out := make([]tessera.RawEntry, len(seqs))
	for i, seq := range seqs {
		raw, ok := f.entries[seq]
		if !ok {
			return nil, fmt.Errorf("fakeEntryReader: no entry seq=%d (batch)", seq)
		}
		out[i] = raw
	}
	return out, nil
}

// Compile-time check: a future tessera.EntryReader change surfaces
// here as a build error rather than at the call site.
var _ tessera.EntryReader = (*fakeEntryReader)(nil)

// ─────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────

const testLogDID = "did:web:test-operator.example"

// requireDB returns a connected pool or skips the test if no DSN
// is provided. The Wave 1 v3 CI2 harness sets ORTHOLOG_TEST_DSN to
// the docker-compose Postgres; local developers point it at any
// disposable database.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ORTHOLOG_TEST_DSN")
	if dsn == "" {
		t.Skip("ORTHOLOG_TEST_DSN unset; skipping integration-style fetcher test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("RunMigrations: %v", err)
	}
	return pool
}

// seedEntry inserts a synthetic entry_index + commitment_split_id
// row pair for the supplied sequence and SplitID. Used to construct
// happy-path and equivocation fixtures without going through the
// full admission pipeline.
func seedEntry(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	seq uint64, splitID [32]byte,
) {
	t.Helper()
	hash := make([]byte, 32)
	hash[0] = byte(seq) // distinct canonical_hash per row
	_, err := pool.Exec(ctx, `
		INSERT INTO entry_index
			(sequence_number, canonical_hash, log_time, signer_did)
		VALUES ($1, $2, NOW(), 'did:web:test-signer.example')
		ON CONFLICT (sequence_number) DO NOTHING`,
		seq, hash,
	)
	if err != nil {
		t.Fatalf("seed entry_index seq=%d: %v", seq, err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO commitment_split_id (sequence_number, schema_id, split_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (sequence_number) DO NOTHING`,
		seq, artifact.PREGrantCommitmentSchemaID, splitID[:],
	)
	if err != nil {
		t.Fatalf("seed commitment_split_id seq=%d: %v", seq, err)
	}
}

// resetFixtures truncates the tables this test writes to. Called
// before each test so suites that share a database stay isolated.
func resetFixtures(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, stmt := range []string{
		`TRUNCATE TABLE commitment_split_id`,
		`TRUNCATE TABLE entry_index CASCADE`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset fixtures: %v", err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

// TestFindCommitmentEntries_NoMatch asserts that an unknown SplitID
// returns (nil, nil) rather than an error. The SDK treats nil as
// "no commitment on log" — a normal recovery / history-replay
// outcome.
func TestFindCommitmentEntries_NoMatch(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	reader := &fakeEntryReader{entries: map[uint64]tessera.RawEntry{}}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	var splitID [32]byte
	splitID[0] = 0xAB
	got, err := fetcher.FindCommitmentEntries(
		artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(got))
	}
}

// TestFindCommitmentEntries_SingleRow exercises the normal path:
// one entry indexed under one SplitID returns a one-element slice
// populated with the canonical bytes the fake reader supplied and
// the entry_index metadata.
func TestFindCommitmentEntries_SingleRow(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	var splitID [32]byte
	splitID[0] = 0x01
	const seq uint64 = 100
	seedEntry(t, ctx, pool, seq, splitID)

	reader := &fakeEntryReader{
		entries: map[uint64]tessera.RawEntry{
			seq: {CanonicalBytes: []byte("canonical-100"), SigBytes: []byte("sig-100")},
		},
	}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	got, err := fetcher.FindCommitmentEntries(
		artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	assertEntryShape(t, got[0], seq, []byte("canonical-100"))
}

// TestFindCommitmentEntries_Equivocation is the load-bearing test:
// two entries indexed under the SAME SplitID must both be returned,
// in ascending sequence order. The SDK's
// *CommitmentEquivocationError construction depends on this multi-
// row signal; collapsing here would silently destroy cryptographic
// evidence per ADR-005 §3 / Wave 1 v3 Decision 3.
func TestFindCommitmentEntries_Equivocation(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	var splitID [32]byte
	splitID[0] = 0xEE
	// Insert in non-ascending sequence order to confirm the ASC sort
	// in the fetcher's SQL is what determines the returned order.
	seedEntry(t, ctx, pool, 200, splitID)
	seedEntry(t, ctx, pool, 100, splitID)

	reader := &fakeEntryReader{
		entries: map[uint64]tessera.RawEntry{
			100: {CanonicalBytes: []byte("canonical-100"), SigBytes: []byte("sig-100")},
			200: {CanonicalBytes: []byte("canonical-200"), SigBytes: []byte("sig-200")},
		},
	}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	got, err := fetcher.FindCommitmentEntries(
		artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (equivocation), got %d", len(got))
	}
	assertEntryShape(t, got[0], 100, []byte("canonical-100"))
	assertEntryShape(t, got[1], 200, []byte("canonical-200"))
}

// TestFindCommitmentEntries_TesseraReadError surfaces a Tessera
// read failure as a fetcher error rather than swallowing it. Loss
// of one entry's bytes should not cause the SDK to silently see a
// shorter equivocation set.
func TestFindCommitmentEntries_TesseraReadError(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	var splitID [32]byte
	splitID[0] = 0xCC
	seedEntry(t, ctx, pool, 300, splitID)

	// Reader has no entry for seq=300 so ReadEntry returns an error.
	reader := &fakeEntryReader{entries: map[uint64]tessera.RawEntry{}}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	_, err := fetcher.FindCommitmentEntries(
		artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err == nil {
		t.Fatal("expected error from missing Tessera entry, got nil")
	}
}

// TestFindCommitmentEntries_NilReader asserts the defensive guard
// at the top of FindCommitmentEntries — a nil tessera.EntryReader
// would otherwise panic on the first ReadEntry call.
func TestFindCommitmentEntries_NilReader(t *testing.T) {
	fetcher := NewPostgresCommitmentFetcher(nil, nil, testLogDID)
	_, err := fetcher.FindCommitmentEntries(
		artifact.PREGrantCommitmentSchemaID, [32]byte{},
	)
	if err == nil {
		t.Fatal("expected error from nil reader, got nil")
	}
}

// TestFindCommitmentEntries_EmptySchemaID asserts the explicit
// rejection of an empty schemaID. An empty schema id would silently
// match no rows under any normal index population and is more likely
// a programmer error than a legitimate query.
func TestFindCommitmentEntries_EmptySchemaID(t *testing.T) {
	fetcher := NewPostgresCommitmentFetcher(nil, &fakeEntryReader{}, testLogDID)
	_, err := fetcher.FindCommitmentEntries("", [32]byte{})
	if err == nil {
		t.Fatal("expected error from empty schemaID, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// assertEntryShape pins the v6 EntryWithMetadata field set:
// CanonicalBytes, LogTime, Position. SignatureBytes / SignatureAlgoID
// are gone (signatures live inside CanonicalBytes; callers that need
// them call envelope.Deserialize). The fakeEntryReader still
// populates SigBytes on tessera.RawEntry — the operator's byte
// store carries the inline signature bytes — but the fetcher does
// not surface them through EntryWithMetadata, so this assertion
// does not check them.
func assertEntryShape(
	t *testing.T,
	got *types.EntryWithMetadata,
	wantSeq uint64,
	wantCanonical []byte,
) {
	t.Helper()
	if got == nil {
		t.Fatalf("seq=%d: nil EntryWithMetadata", wantSeq)
	}
	if got.Position.Sequence != wantSeq {
		t.Errorf("seq mismatch: got %d, want %d",
			got.Position.Sequence, wantSeq)
	}
	if got.Position.LogDID != testLogDID {
		t.Errorf("LogDID mismatch: got %q, want %q",
			got.Position.LogDID, testLogDID)
	}
	if !bytesEqual(got.CanonicalBytes, wantCanonical) {
		t.Errorf("canonical bytes mismatch: got %q, want %q",
			got.CanonicalBytes, wantCanonical)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compile-time pinning: ensure the test still references the SDK's
// CommitmentFetcher interface so a future SDK signature change
// surfaces here as a build error rather than a runtime miss.
var _ types.CommitmentFetcher = (*PostgresCommitmentFetcher)(nil)

// errFakeReaderMissReserved is exported for callers that want to
// match on the canned miss error from fakeEntryReader.
var errFakeReaderMissReserved = errors.New("fakeEntryReader: miss")

func init() {
	// Touch the reserved error so the import isn't dropped if the
	// fake reader's miss path is ever inlined or refactored.
	_ = errFakeReaderMissReserved
}
