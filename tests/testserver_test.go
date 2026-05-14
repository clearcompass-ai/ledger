/*
FILE PATH:

	tests/testserver_test.go

DESCRIPTION:

	Wires up a complete ledger HTTP server for integration testing.
	Real Postgres, real middleware chain, real builder loop.

KEY ARCHITECTURAL DECISIONS:
  - Postgres is an index. Entry bytes live in EntryReader.
    InMemoryEntryStore satisfies both EntryReader and EntryWriter.
  - MerkleAppender and WitnessCosigner use in-process stubs.
  - stubMerkleAppender.AppendLeaf accepts 32-byte SHA-256 hashes
    (hash-only architecture). The builder computes the hash in loop.go
    step 6 and passes only the digest.
  - SubmissionDeps uses the cohesive sub-struct shape (StorageDeps +
    AdmissionConfig + IdentityDeps).

OVERVIEW:

	startTestLedger creates: Postgres pool → clean tables → stores →
	builder loop → HTTP server on random port. Returns testLedger with
	all dependencies accessible for test assertions.

KEY DEPENDENCIES:
  - All api/ handlers wired with real Postgres stores.
  - builder/loop.go runs in background goroutine.
  - tessera/entry_reader.go InMemoryEntryStore for byte storage.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// Compile-time guarantee: *store.CompositeByteReader satisfies
// bytestore.Reader. testLedger.EntryReader holds the composite so
// tests assert against the same abstraction production read paths
// use (PostgresEntryFetcher, builder, /v1/entries handlers).
var _ opbytestore.Reader = (*store.CompositeByteReader)(nil)

// -------------------------------------------------------------------------------------------------
// Test ledger instance
// -------------------------------------------------------------------------------------------------

// testLedger bundles every dependency a test might need to inspect.
// Real-Tessera fields (RealTesseraDir / RealEmbedded / RealTileReader)
// are nil under the legacy stub path; scenarios / persona tests
// gate via HasRealTessera() before dereferencing them.
//
// EntryReader vs EntryBytes — read the rule before choosing:
//
//   - EntryReader is the production read abstraction (composite of
//     WAL + bytestore). It returns bytes from whichever surface holds
//     them at the moment of the read, transparently bridging the
//     StateSequenced → StateShipped transition window. This is what
//     PostgresEntryFetcher and the /v1/entries handler read through.
//     Tests that assert "EntryReader is the source of truth" (see
//     entry_storage_rule_test.go) MUST use this field — anything else
//     races the shipper.
//
//   - EntryBytes is the bare in-memory bytestore. Use only when the
//     test specifically asserts post-ship bytestore content (e.g.,
//     verifying durability after WAL eviction). Such tests must
//     explicitly wait for StateShipped before reading.
type testLedger struct {
	BaseURL     string
	Pool        *pgxpool.Pool
	Cursor      *store.SequenceCursor
	CreditStore *store.CreditStore
	EntryStore  *store.EntryStore
	EntryBytes  *opbytestore.Memory
	EntryReader opbytestore.Reader
	cancel      context.CancelFunc

	// Real-Tessera handles. Populated only when
	// startTestLedgerWithOpts was called with UseRealTessera=true;
	// nil otherwise.
	RealTesseraDir string
	RealEmbedded   *optessera.EmbeddedAppender
	RealTileReader *optessera.TileReader
}

// HasRealTessera reports whether this ledger was constructed with
// the real Tessera POSIX stack. Persona / scenarios tests use
// this to gate proof-fetch assertions.
func (op *testLedger) HasRealTessera() bool {
	return op.RealEmbedded != nil
}

// startTestLedger is the legacy 600+-test entry point. Delegates
// to startTestLedgerWithOpts with zero options — the stub default
// every existing test depends on. New scenarios / persona tests
// call startTestLedgerWithOpts directly so they can request
// UseRealTessera.
func startTestLedger(t *testing.T) *testLedger {
	t.Helper()
	return startTestLedgerWithOpts(t, testLedgerOpts{})
}

// seedSession inserts a valid session token + credits.
func (op *testLedger) seedSession(t *testing.T, token, exchangeDID string, credits int64) {
	t.Helper()
	ctx := context.Background()
	_, err := op.Pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO NOTHING`,
		token, exchangeDID, time.Now().UTC().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if credits > 0 {
		if _, err := op.CreditStore.BulkPurchase(ctx, exchangeDID, credits); err != nil {
			t.Fatalf("seed credits: %v", err)
		}
	}
}

// stubMerkleAppender + stubWitnessCosigner WERE defined here.
// Both deleted — tests now exercise the production-shape Tessera
// + httptest cosign fixture via newWitnessedTestHarness (see
// tests/witnessed_harness_test.go) and the canonical
// startTestLedgerWithOpts wiring (see tests/testserver_setup_test.go).
//
// Physics, not mocks: every test boots a real
// tessera.EmbeddedAppender backed by t.TempDir() and a real
// witnessclient.HeadSync against an httptest.Server running
// the SDK's cosign.NewWitnessHandler. After a builder cycle,
// the cosigned-checkpoint file lands on disk at
// <tempdir>/cosigned-checkpoint and tests assert against its
// existence + contents.

// -------------------------------------------------------------------------------------------------
// Lightweight test-server adapter for destination_binding_test.go
// -------------------------------------------------------------------------------------------------
//
// destination_binding_test.go was authored against a hypothetical
// newTestServer(t) helper whose docstring says:
//
//     "test harness returning *httptest.Server configured with testLogDID
//     as cfg.LogDID and testLedgerDID as cfg.LedgerDID. Assumed
//     present in testserver_test.go. If unavailable, port the factory
//     pattern from http_integration_test.go."
//
// Rather than duplicate the factory (risking drift between two
// implementations of the same wiring), this helper delegates to
// startTestLedger and exposes a minimal .URL/.Close() surface — the
// only surface destination_binding_test.go actually uses.
//
// The return type is a local *testServer rather than literal
// *httptest.Server because startTestLedger already runs a real
// HTTP server on a net.Listener. Creating an httptest.Server on top
// would be a second server; wrapping the existing one with a type
// that satisfies the call-site contract is both simpler and more
// honest about what's happening.

type testServer struct {
	URL string
	op  *testLedger // kept for lifetime ownership; teardown is via t.Cleanup.
}

// Close is a no-op. startTestLedger registers a t.Cleanup that
// cancels the context, shuts down the HTTP server, cleans tables,
// and closes the pool. This method exists only to satisfy the
// `defer srv.Close()` idiom used by destination_binding_test.go.
func (s *testServer) Close() {}

// defaultTestSessionToken is auto-seeded by newTestServer so any
// test using newTestServer + postEntry can submit authenticated
// requests without per-test session bookkeeping. The Authorization
// header is set on every postEntry; tests that exercise
// unauthenticated paths post directly via http.Post.
const (
	defaultTestSessionToken    = "default-test-session-token"
	defaultTestSessionExchange = "did:test:default-exchange"
)

// newTestServer returns a lightweight test-server handle for tests that
// only need a running HTTP endpoint bound to testLogDID. Auto-seeds a
// default session token + 1M credits so destination/admission tests
// can post well-formed entries without each test seeding its own
// session. The default token is what postEntry attaches via the
// Authorization header.
//
// For tests that need richer access (seedSession with custom tokens,
// direct Pool queries, CreditStore inspection), use startTestLedger
// directly.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	op := startTestLedger(t)
	op.seedSession(t, defaultTestSessionToken, defaultTestSessionExchange, 1_000_000)
	return &testServer{URL: op.BaseURL, op: op}
}

// Suppress unused imports.
var _ = sha256.Sum256
