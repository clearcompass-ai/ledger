/*
FILE PATH:

	tests/testserver_test.go

DESCRIPTION:

	Wires up a complete operator HTTP server for integration testing.
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

	startTestOperator creates: Postgres pool → clean tables → stores →
	builder loop → HTTP server on random port. Returns testOperator with
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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	opbytestore "github.com/clearcompass-ai/ortholog-operator/bytestore"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// -------------------------------------------------------------------------------------------------
// Test operator instance
// -------------------------------------------------------------------------------------------------

type testOperator struct {
	BaseURL     string
	Pool        *pgxpool.Pool
	Cursor      *store.SequenceCursor
	CreditStore *store.CreditStore
	EntryStore  *store.EntryStore
	EntryBytes  *opbytestore.Memory
	cancel      context.CancelFunc
}

func startTestOperator(t *testing.T) *testOperator {
	t.Helper()

	dsn := os.Getenv("ORTHOLOG_TEST_DSN")
	if dsn == "" {
		t.Skip("ORTHOLOG_TEST_DSN not set — skipping HTTP integration test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// ── Postgres ───────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		cancel()
		t.Fatalf("migrations: %v", err)
	}
	cleanTables(t, pool)

	// ── Entry byte store ───────────────────────────────────────────────
	entryBytes := opbytestore.NewMemory()

	// ── Stores ─────────────────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	sequenceCursor := store.NewSequenceCursor(pool)
	reader := opbuilder.NewCursorReader(sequenceCursor)
	treeHeadStore := store.NewTreeHeadStore(pool)
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool, 10000)
	tree := smt.NewTree(leafStore, nodeCache)
	fetcher := store.NewPostgresEntryFetcher(pool, entryBytes, testLogDID)
	commitmentStore := store.NewCommitmentStore(pool)

	// ── WAL ────────────────────────────────────────────────────────────
	// In-memory Badger for tests. DisableSync mirrors the production
	// "no WAL to fsync" flag; in-memory mode has no on-disk WAL.
	walDB, err := wal.OpenInMemory(nil)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("wal open: %v", err)
	}
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{DisableSync: true})
	t.Cleanup(func() {
		_ = walc.Close()
		_ = walDB.Close()
	})

	// ── Delta buffer ───────────────────────────────────────────────────
	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer, _ := bufferStore.Load(ctx)
	if deltaBuffer == nil {
		deltaBuffer = sdkbuilder.NewDeltaWindowBuffer(10)
	}

	// ── Stubs ──────────────────────────────────────────────────────────
	merkle := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}
	witnessCosigner := &stubWitnessCosigner{}

	// ── Commitment publisher ───────────────────────────────────────────
	commitPub := opbuilder.NewCommitmentPublisher(
		testLogDID,
		testLogDID,
		opbuilder.CommitmentPublisherConfig{IntervalEntries: 100000, IntervalTime: 24 * time.Hour},
		func(e *envelope.Entry) error { return nil },
		logger,
	)

	// ── Builder loop ───────────────────────────────────────────────────
	loopCfg := opbuilder.DefaultLoopConfig(testLogDID)
	loopCfg.PollInterval = 50 * time.Millisecond
	loopCfg.BatchSize = 100

	builderLoop := opbuilder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		reader, fetcher, nil, deltaBuffer, bufferStore, commitPub,
		merkle, witnessCosigner, logger,
	)
	go builderLoop.Run(ctx)

	// ── Difficulty controller ──────────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		sequenceCursor, middleware.DefaultDifficultyConfig(), logger,
	)

	// ── HTTP handlers ──────────────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool, entryBytes, testLogDID)

	// SubmissionDeps using the cohesive sub-struct shape.
	// stubMerkleAppender doubles as the api.TesseraAppender for
	// tests — its AppendLeaf signature satisfies the interface
	// even though its primary role is as the builder-side
	// MerkleAppender. Production wires *tessera.EmbeddedAppender.
	opSignerPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("operator signer key: %v", err)
	}
	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			DB:         pool,
			EntryStore: entryStore,
			WAL:        walc,
			Tessera:    merkle,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    3600, // 1 hour
			EpochAcceptanceWindow: 1,    // accept current ± 1
		},
		Identity: api.IdentityDeps{
			CreditStore: creditStore,
			DIDResolver: nil,
		},
		LogDID:             testLogDID,
		OperatorDID:        testOperatorDID,
		OperatorSignerPriv: opSignerPriv,
		MaxEntrySize:       1 << 20,
		Logger:             logger,
	}

	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: merkle,
		Consistency: merkle, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		EntryStore: entryStore,
		WAL:        walc,
		// Tests don't exercise the 302 redirect path; the in-memory
		// bytestore is reachable but doesn't presign. Setting
		// Presigner to nil makes the handler return 500 if it hits
		// the redirect branch — desirable for tests, since any
		// redirect attempt indicates an unexpected state transition.
		Presigner: nil,
		LogDID:    testLogDID,
		Logger:    logger,
	}
	commitDeps := &api.CommitmentDeps{
		CommitmentStore: commitmentStore, Logger: logger,
	}

	handlers := api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		TreeHead:        api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:   api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency: api.NewTreeConsistencyHandler(treeDeps),
		SMTProof:        api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:   api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:         api.NewSMTRootHandler(smtDeps),
		CosignatureOf:   api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:      api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:       api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:       api.NewQuerySchemaRefHandler(queryDeps),
		Scan:            api.NewQueryScanHandler(queryDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		WitnessCosign:   nil,
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:        api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewCommitmentQueryHandler(commitDeps),
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = "127.0.0.1:0"
	server := api.NewServer(serverCfg, pool, handlers, logger)

	// ── Start on random port ───────────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		pool.Close()
		t.Fatalf("listen: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	go server.Serve(ln)

	op := &testOperator{
		BaseURL: baseURL, Pool: pool, Cursor: sequenceCursor,
		CreditStore: creditStore, EntryStore: entryStore,
		EntryBytes: entryBytes, cancel: cancel,
	}

	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
		cleanTables(t, pool)
		pool.Close()
	})

	// Wait for readiness.
	for i := 0; i < 50; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return op
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("test operator did not become ready in 2.5s")
	return nil
}

// seedSession inserts a valid session token + credits.
func (op *testOperator) seedSession(t *testing.T, token, exchangeDID string, credits int64) {
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

func (s *stubMerkleAppender) AppendLeaf(data []byte) (uint64, error) {
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
//     as cfg.LogDID and testOperatorDID as cfg.OperatorDID. Assumed
//     present in testserver_test.go. If unavailable, port the factory
//     pattern from http_integration_test.go."
//
// Rather than duplicate the factory (risking drift between two
// implementations of the same wiring), this helper delegates to
// startTestOperator and exposes a minimal .URL/.Close() surface — the
// only surface destination_binding_test.go actually uses.
//
// The return type is a local *testServer rather than literal
// *httptest.Server because startTestOperator already runs a real
// HTTP server on a net.Listener. Creating an httptest.Server on top
// would be a second server; wrapping the existing one with a type
// that satisfies the call-site contract is both simpler and more
// honest about what's happening.

type testServer struct {
	URL string
	op  *testOperator // kept for lifetime ownership; teardown is via t.Cleanup.
}

// Close is a no-op. startTestOperator registers a t.Cleanup that
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
// CreditStore inspection), use startTestOperator directly.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	op := startTestOperator(t)
	return &testServer{URL: op.BaseURL, op: op}
}

// Suppress unused imports.
var _ = sha256.Sum256
