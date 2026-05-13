/*
FILE PATH: store/commitment_fetcher_test.go

Multi-row contract tests for PostgresCommitmentFetcher.

The single load-bearing invariant under test: when commitment_split_id
has more than one row matching (schema_id, split_id), the fetcher
returns ALL of them as []*EntryWithMetadata. The SDK's
*CommitmentEquivocationError construction depends on this signal;
collapsing to a single row would silently destroy the cryptographic
evidence verifiers act on.

Test isolation: tests requiring a live Postgres skip when
ATTESTA_TEST_DSN is unset. The integration/ docker-compose harness
wires the env var so these tests run on every PR. Local developers
can run them by exporting ATTESTA_TEST_DSN to a disposable Postgres
database.
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

	"github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/bytestore"
)

// ─────────────────────────────────────────────────────────────────────
// Test doubles
// ─────────────────────────────────────────────────────────────────────

// fakeEntryReader satisfies bytestore.Reader by returning canned
// wire bytes keyed by sequence number. Reads of unknown sequences
// return an error so the test surfaces the fetcher's error path
// on byte-store misses. The hash arg is ignored — these tests
// don't exercise the hash-suffix layout, only the seq-keyed lookup
// the fetcher contract relies on.
type fakeEntryReader struct {
	entries map[uint64][]byte
}

func (f *fakeEntryReader) ReadEntry(_ context.Context, seq uint64, _ [32]byte) ([]byte, error) {
	wire, ok := f.entries[seq]
	if !ok {
		return nil, fmt.Errorf("fakeEntryReader: no entry seq=%d", seq)
	}
	return wire, nil
}

func (f *fakeEntryReader) ReadEntryBatch(_ context.Context, refs []bytestore.EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		wire, ok := f.entries[r.Seq]
		if !ok {
			return nil, fmt.Errorf("fakeEntryReader: no entry seq=%d (batch)", r.Seq)
		}
		out[i] = wire
	}
	return out, nil
}

// Compile-time check: a future bytestore.Reader change surfaces
// here as a build error rather than at the call site.
var _ bytestore.Reader = (*fakeEntryReader)(nil)

// ─────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────

const testLogDID = "did:web:test-ledger.example"

// requireDB returns a connected pool or skips the test if no DSN
// is provided. The integration docker-compose harness sets
// ATTESTA_TEST_DSN to its Postgres; local developers point it at
// any disposable database.
//
// LEDGER_TEST_SERIAL: warn-only guard for the shared-DB serialization
// contract. The Makefile's `test` and `test-chaos` targets set it;
// `go test ./...` directly (or IDE-launched runs) does not. The
// warning is reversible — strict failure would block IDE debugging
// — but the log line is visible in CI so accidental parallel runs
// show up in test output rather than as flaky "Count=18 want 16".
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset; skipping integration-style fetcher test")
	}
	if os.Getenv("LEDGER_TEST_SERIAL") != "1" {
		t.Logf("WARNING: LEDGER_TEST_SERIAL != 1; tests are running outside `make test`. " +
			"Cross-package contamination is possible. Use `make test` for deterministic runs.")
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

// Named convenience sets — declared at package scope so each test
// names its working set by intent rather than by literal table
// list. New tables that join the package's write surface are added
// here once; the test that introduces them references the right
// set. Drift between "what a test writes" and "what its
// resetFixtures clears" surfaces in code review as a mismatched
// constant name, not as a silent leak three migrations later.
//
// smt_root_state is intentionally absent: singleton (id=1) under a
// CHECK constraint, TRUNCATE would violate it. builder_cursor and
// schema_migrations are likewise singleton/control tables and must
// not appear here.
var (
	commitmentFixtureTables = []string{
		"commitment_split_id",
		"entry_index CASCADE",
	}
	smtFixtureTables = []string{
		"smt_leaves",
		"jellyfish_nodes",
	}
)

// resetFixtures truncates the named tables in order. Tests pass
// the convenience sets (`commitmentFixtureTables...`,
// `smtFixtureTables...`) declaring their working set explicitly.
//
// Calling with no tables is an error — the empty-set bug was the
// original "Count = 18, want 16" leak, and silent no-op would
// re-introduce it. Tests must declare their set; the compiler can't
// help, so the helper does.
func resetFixtures(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		t.Fatal("resetFixtures: no tables specified; pass commitmentFixtureTables... / smtFixtureTables... explicitly")
	}
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+table); err != nil {
			t.Fatalf("reset fixtures (%s): %v", table, err)
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
	resetFixtures(t, ctx, pool, commitmentFixtureTables...)

	reader := &fakeEntryReader{entries: map[uint64][]byte{}}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	var splitID [32]byte
	splitID[0] = 0xAB
	got, err := fetcher.FindCommitmentEntries(
		ctx, artifact.PREGrantCommitmentSchemaID, splitID,
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
	resetFixtures(t, ctx, pool, commitmentFixtureTables...)

	var splitID [32]byte
	splitID[0] = 0x01
	const seq uint64 = 100
	seedEntry(t, ctx, pool, seq, splitID)

	reader := &fakeEntryReader{
		entries: map[uint64][]byte{
			seq: []byte("wire-100"),
		},
	}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	got, err := fetcher.FindCommitmentEntries(
		ctx, artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	assertEntryShape(t, got[0], seq, []byte("wire-100"))
}

// TestFindCommitmentEntries_Equivocation is the load-bearing test:
// two entries indexed under the SAME SplitID must both be returned,
// in ascending sequence order. The SDK's
// *CommitmentEquivocationError construction depends on this multi-
// row signal; collapsing here would silently destroy cryptographic
// evidence verifiers depend on.
func TestFindCommitmentEntries_Equivocation(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool, commitmentFixtureTables...)

	var splitID [32]byte
	splitID[0] = 0xEE
	// Insert in non-ascending sequence order to confirm the ASC sort
	// in the fetcher's SQL is what determines the returned order.
	seedEntry(t, ctx, pool, 200, splitID)
	seedEntry(t, ctx, pool, 100, splitID)

	reader := &fakeEntryReader{
		entries: map[uint64][]byte{
			100: []byte("wire-100"),
			200: []byte("wire-200"),
		},
	}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	got, err := fetcher.FindCommitmentEntries(
		ctx, artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (equivocation), got %d", len(got))
	}
	assertEntryShape(t, got[0], 100, []byte("wire-100"))
	assertEntryShape(t, got[1], 200, []byte("wire-200"))
}

// TestFindCommitmentEntries_TesseraReadError surfaces a Tessera
// read failure as a fetcher error rather than swallowing it. Loss
// of one entry's bytes should not cause the SDK to silently see a
// shorter equivocation set.
func TestFindCommitmentEntries_TesseraReadError(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool, commitmentFixtureTables...)

	var splitID [32]byte
	splitID[0] = 0xCC
	seedEntry(t, ctx, pool, 300, splitID)

	// Reader has no entry for seq=300 so ReadEntry returns an error.
	reader := &fakeEntryReader{entries: map[uint64][]byte{}}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	_, err := fetcher.FindCommitmentEntries(
		ctx, artifact.PREGrantCommitmentSchemaID, splitID,
	)
	if err == nil {
		t.Fatal("expected error from missing Tessera entry, got nil")
	}
}

// TestFindCommitmentEntries_NilReader asserts the defensive guard
// at the top of FindCommitmentEntries — a nil bytestore.Reader
// would otherwise panic on the first ReadEntry call.
func TestFindCommitmentEntries_NilReader(t *testing.T) {
	fetcher := NewPostgresCommitmentFetcher(nil, nil, testLogDID)
	_, err := fetcher.FindCommitmentEntries(
		context.Background(), artifact.PREGrantCommitmentSchemaID, [32]byte{},
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
	_, err := fetcher.FindCommitmentEntries(context.Background(), "", [32]byte{})
	if err == nil {
		t.Fatal("expected error from empty schemaID, got nil")
	}
}

// TestFindCommitmentEntries_ContextCancelled pins Tier 1.2's
// load-bearing contract: the SDK now propagates ctx into
// CommitmentFetcher, so cancellation MUST reach the bottom-layer
// pgxpool driver instead of being silently absorbed by a struct-
// bound context (the P2 fallback this commit eliminated).
//
// We cancel BEFORE issuing the call so pgxpool returns immediately
// rather than racing the test deadline; the assertion is purely
// "did the cancellation propagate".
func TestFindCommitmentEntries_ContextCancelled(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	resetFixtures(t, context.Background(), pool, commitmentFixtureTables...)

	reader := &fakeEntryReader{entries: map[uint64][]byte{}}
	fetcher := NewPostgresCommitmentFetcher(pool, reader, testLogDID)

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fetcher.FindCommitmentEntries(
		cancelledCtx, artifact.PREGrantCommitmentSchemaID, [32]byte{},
	)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected error chain to contain context.Canceled, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// assertEntryShape pins the v6 EntryWithMetadata field set:
// CanonicalBytes, LogTime, Position. Wire bytes ARE the canonical
// bytes under (signatures section embedded); callers that
// need the signature call envelope.Deserialize.
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

// TestResetFixtures_LeavesNoRows is the regression test for the
// original "Count = 18, want 16" / "Count = 19, want 1" leak. It
// seeds every table in this package's write surface with a known
// row, runs resetFixtures with both convenience sets, and asserts
// each table is empty afterward.
//
// If someone adds a new table to the write surface without listing
// it in {commitment,smt}FixtureTables, the seed in this test for
// that table won't get cleaned up — the final assertion fires, the
// CI build fails, and the omission is caught at the moment it
// ships rather than three migrations later when a flaky soak run
// surfaces "Count = N + previous_residue".
func TestResetFixtures_LeavesNoRows(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()

	// Seed entry_index + commitment_split_id via the existing helper.
	var splitID [32]byte
	splitID[0] = 0xFF
	seedEntry(t, ctx, pool, 1, splitID)

	// Seed smt_leaves with a raw INSERT (no test helper for this
	// table; the production smt_state.go exec path uses identical
	// SQL, so this is faithful to the real write surface).
	var leafKey [32]byte
	leafKey[0] = 0xAA
	if _, err := pool.Exec(ctx, `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		VALUES ($1, $2, $3, NOW())`,
		leafKey[:], []byte("origin-tip-bytes"), []byte("authority-tip-bytes"),
	); err != nil {
		t.Fatalf("seed smt_leaves: %v", err)
	}

	// Seed jellyfish_nodes with a content-addressed payload.
	var nodeHash [32]byte
	nodeHash[0] = 0xBB
	if _, err := pool.Exec(ctx, `
		INSERT INTO jellyfish_nodes (node_hash, payload)
		VALUES ($1, $2)
		ON CONFLICT (node_hash) DO NOTHING`,
		nodeHash[:], []byte("payload-bytes"),
	); err != nil {
		t.Fatalf("seed jellyfish_nodes: %v", err)
	}

	// Pre-flight: every seeded table should have a row.
	preflightTables := []string{"entry_index", "commitment_split_id", "smt_leaves", "jellyfish_nodes"}
	for _, table := range preflightTables {
		var count int
		if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("pre-flight count %s: %v", table, err)
		}
		if count == 0 {
			t.Fatalf("pre-flight %s: count=0, expected > 0 — seed didn't land", table)
		}
	}

	// Reset both convenience sets — covers the full write surface.
	resetFixtures(t, ctx, pool, commitmentFixtureTables...)
	resetFixtures(t, ctx, pool, smtFixtureTables...)

	// Every table must be empty. If a new table joins the write
	// surface without joining a fixture set, its row survives this
	// step and the assertion below fires.
	for _, table := range preflightTables {
		var count int
		if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("post-reset count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("post-reset %s: %d rows, expected 0 "+
				"— table is in the write surface but not in any fixture set",
				table, count)
		}
	}
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
