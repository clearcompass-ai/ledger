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

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"

	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// Test ledger instance
// -------------------------------------------------------------------------------------------------

// testLedger bundles every dependency a test might need to inspect.
// Real-Tessera fields (RealTesseraDir / RealEmbedded / RealTileReader)
// are nil under the legacy stub path; scenarios / persona tests
// gate via HasRealTessera() before dereferencing them.
type testLedger struct {
	BaseURL     string
	Pool        *pgxpool.Pool
	Cursor      *store.SequenceCursor
	CreditStore *store.CreditStore
	EntryStore  *store.EntryStore
	EntryBytes  *opbytestore.Memory
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

// -------------------------------------------------------------------------------------------------
// Stubs
// -------------------------------------------------------------------------------------------------

// stubMerkleAppender implements MerkleAppender for tests.
//
// Hash-only architecture: AppendLeaf receives 32-byte SHA-256 hashes from
// builder/loop.go step 6. The stub passes the hash directly to the
// StubMerkleTree (which further hashes it for the Merkle leaf as
// H(0x00 || data), matching RFC 6962).
type stubMerkleAppender struct {
	mt *smt.StubMerkleTree
}

func (s *stubMerkleAppender) AppendLeaf(_ context.Context, data []byte) (uint64, error) {
	return s.mt.AppendLeaf(data)
}

func (s *stubMerkleAppender) Head() (types.TreeHead, error) {
	return s.mt.Head()
}

func (s *stubMerkleAppender) RawInclusionProof(position, treeSize uint64) (any, error) {
	return s.mt.InclusionProof(position, treeSize)
}

func (s *stubMerkleAppender) ConsistencyProof(oldSize, newSize uint64) (any, error) {
	return map[string]any{"old_size": oldSize, "new_size": newSize}, nil
}

type stubWitnessCosigner struct{}

func (s *stubWitnessCosigner) RequestCosignatures(_ context.Context, _ types.TreeHead) error {
	return nil
}

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

// newTestServer returns a lightweight test-server handle for tests that
// only need a running HTTP endpoint bound to testLogDID — no credit
// seeding, no session tokens, no queue introspection. Currently used
// by destination_binding_test.go's five security invariants.
//
// For tests that need richer access (seedSession, direct Pool queries,
// CreditStore inspection), use startTestLedger directly.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	op := startTestLedger(t)
	return &testServer{URL: op.BaseURL, op: op}
}

// Suppress unused imports.
var _ = sha256.Sum256
