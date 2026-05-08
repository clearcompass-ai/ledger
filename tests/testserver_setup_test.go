/*
FILE PATH:

	tests/testserver_setup_test.go

DESCRIPTION:

	Opts-driven entry point for the integration-test ledger harness.
	startTestLedger delegates here with a zero-value opts (legacy
	stub default); scenarios / persona tests pass UseRealTessera=true
	to wire production-shape Tessera (POSIX + EmbeddedAppender +
	TesseraAdapter) instead.

KEY ARCHITECTURAL DECISIONS:
  - Sibling, not flag mutation. Existing 600+ tests reach this
    function via the unchanged startTestLedger delegator; their
    stub path is byte-for-byte equivalent.
  - Single decision point. buildTesseraForTests returns a
    tesseraSlots struct filling all four production roles
    (admission TesseraAppender, builder MerkleAppender,
    InclusionProver, ConsistencyProver). Every slot uses the
    same source of truth.
  - Lifecycle ordering. Real Tessera owns background batchers +
    a checkpoint signer; cleanup drains them before pool.Close.

OVERVIEW:

	startTestLedgerWithOpts → pool → tessera slots → builder loop
	→ handlers → http.Server on random port → testLedger.
	buildTesseraForTests → (admission, builder, incl, consist,
	embedded?, tileReader?, tileRoot, closer).

KEY DEPENDENCIES:
  - testserver_test.go: testLedger + stubs + testServer.
  - ledger/tessera: NewEmbeddedAppender, NewPOSIXTileBackend,
    NewTileReader, NewTesseraAdapter, GenerateEphemeralSigner.
  - transparency-dev/tessera/storage/posix: driver.
*/
package tests

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/signatures"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	opbuilder "github.com/clearcompass-ai/ledger/builder"
	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	"github.com/clearcompass-ai/ledger/wal"
)

// -------------------------------------------------------------------------------------------------
// 1) Opts struct
// -------------------------------------------------------------------------------------------------

// testLedgerOpts carries the knobs scenarios / persona tests use
// to drive the harness toward production-shape wiring. The zero
// value reproduces the legacy stub-Merkle behaviour every existing
// test depends on; only fields the caller sets non-zero override.
type testLedgerOpts struct {
	// UseRealTessera replaces the in-process stubMerkleAppender
	// with a real tessera.EmbeddedAppender + tessera.TesseraAdapter
	// pair, matching cmd/ledger/main.go's production wiring. Tile
	// bytes are written to TileRoot (or a fresh tmpDir if empty).
	UseRealTessera bool

	// TileRoot is the POSIX directory the embedded Tessera writes
	// tile + checkpoint files into. Empty under UseRealTessera=true
	// → a fresh tmp dir registered for cleanup. Ignored when
	// UseRealTessera is false.
	TileRoot string

	// CheckpointInterval / BatchSize / BatchMaxAge override the
	// upstream Tessera batcher tunables. Zero → SDK defaults
	// scaled down for fast tests (500 ms / 4 / 100 ms). Ignored
	// when UseRealTessera is false.
	CheckpointInterval time.Duration
	BatchSize          int
	BatchMaxAge        time.Duration

	// Origin is the Tessera "origin" line written into every
	// signed checkpoint. Defaults to testLogDID. Ignored when
	// UseRealTessera is false.
	Origin string

	// LowDifficulty caps admission PoW at 4-bit min / 8-bit
	// initial / 12-bit max. Default config is 16/8/24 — too
	// expensive when a single test submits 256+ entries.
	// Crypto / tile / byte tests opt in; persona tests keep
	// the production-shape default.
	LowDifficulty bool

	// PublicURLer wires the /v1/entries/{seq}/raw 302 redirect
	// path. Default nil → handler returns 500 on shipped
	// entries (fail-closed). BYTE-VER-02 supplies a static
	// fixture that maps (seq, hash) → an http test fixture URL.
	PublicURLer api.PublicURLer
}

// tesseraSlots and buildTesseraForTests live in testserver_tessera_test.go
// to keep this file under the project's per-file LoC ceiling.

// -------------------------------------------------------------------------------------------------
// 2) startTestLedgerWithOpts — the full constructor
// -------------------------------------------------------------------------------------------------

// startTestLedgerWithOpts boots the integration-test ledger with
// the supplied options. Skips on missing ATTESTA_TEST_DSN. Returns
// the testLedger with real-Tessera fields populated when
// opts.UseRealTessera was true.
func startTestLedgerWithOpts(t *testing.T, opts testLedgerOpts) *testLedger {
	t.Helper()

	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping HTTP integration test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

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

	entryBytes := opbytestore.NewMemory()
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	sequenceCursor := store.NewSequenceCursor(pool)
	reader := opbuilder.NewCursorReader(sequenceCursor)
	treeHeadStore := store.NewTreeHeadStore(pool)
	leafStore := store.NewPostgresLeafStore(ctx, pool)
	nodeCache := store.NewPostgresNodeCache(ctx, pool, 10000)
	tree := smt.NewTree(leafStore, nodeCache)
	fetcher := store.NewPostgresEntryFetcher(ctx, pool, entryBytes, testLogDID)
	commitmentStore := store.NewCommitmentStore(pool)

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

	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer, _ := bufferStore.Load(ctx)
	if deltaBuffer == nil {
		deltaBuffer = sdkbuilder.NewDeltaWindowBuffer(10)
	}

	ts := buildTesseraForTests(t, ctx, opts, logger)
	witnessCosigner := &stubWitnessCosigner{}

	commitPub := opbuilder.NewCommitmentPublisher(
		testLogDID,
		testLogDID,
		opbuilder.CommitmentPublisherConfig{IntervalEntries: 100000, IntervalTime: 24 * time.Hour},
		func(e *envelope.Entry) error { return nil },
		logger,
	)

	loopCfg := opbuilder.DefaultLoopConfig(testLogDID)
	loopCfg.PollInterval = 50 * time.Millisecond
	loopCfg.BatchSize = 100

	builderLoop := opbuilder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		reader, fetcher, nil, deltaBuffer, bufferStore, commitPub,
		ts.builder, witnessCosigner, logger,
	)
	loopDone := make(chan struct{})
	go func() {
		builderLoop.Run(ctx)
		close(loopDone)
	}()

	diffCfg := middleware.DefaultDifficultyConfig()
	if opts.LowDifficulty {
		diffCfg.InitialDifficulty = 8
		diffCfg.MinDifficulty = 4
		diffCfg.MaxDifficulty = 12
	}
	diffController := middleware.NewDifficultyController(
		sequenceCursor, diffCfg, logger,
	)
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, entryBytes, testLogDID)

	opSignerPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("ledger signer key: %v", err)
	}
	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: entryStore,
			WAL:        walc,
			Tessera:    ts.admission,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    3600,
			EpochAcceptanceWindow: 1,
		},
		Identity:         api.IdentityDeps{Credits: creditStore},
		LogDID:           testLogDID,
		LedgerDID:        testLedgerDID,
		LedgerSignerPriv: opSignerPriv,
		MaxEntrySize:     1 << 20,
		Logger:           logger,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: ts.inclusion,
		Consistency: ts.consistency, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		EntryStore: entryStore, WAL: walc,
		// PublicURLer is opt-driven: scenarios tests that exercise
		// the 302 redirect (BYTE-VER-02) supply a static fixture;
		// everything else leaves it nil and the handler fails 500
		// on shipped-entry hits (fail-closed).
		PublicURLer: opts.PublicURLer, LogDID: testLogDID, Logger: logger,
	}
	commitDeps := &api.DerivationCommitmentDeps{
		CommitmentStore: commitmentStore, Logger: logger,
	}
	cryptoCommitDeps := &api.CryptographicCommitmentDeps{
		Fetcher: store.NewPostgresCommitmentFetcher(ctx, pool, entryBytes, testLogDID),
		Logger:  logger,
	}

	handlers := buildTestHandlers(submissionDeps, treeDeps, smtDeps, queryDeps, entryReadDeps, commitDeps)
	handlers.CommitmentLookup = api.NewCommitmentLookupHandler(cryptoCommitDeps)

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = "127.0.0.1:0"
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool), handlers, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		pool.Close()
		t.Fatalf("listen: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	go server.Serve(ln)

	op := &testLedger{
		BaseURL: baseURL, Pool: pool, Cursor: sequenceCursor,
		CreditStore: creditStore, EntryStore: entryStore,
		EntryBytes: entryBytes, cancel: cancel,
		RealTesseraDir: ts.tileRoot,
		RealEmbedded:   ts.embedded,
		RealTileReader: ts.tileReader,
	}

	// Cleanup ordering matters when ts.embedded is non-nil:
	//   1. cancel() signals the builder loop to stop.
	//   2. wait loopDone so the loop's last AppendLeaf completes.
	//   3. ts.closer drains pending Tessera integrations.
	//   4. server.Shutdown drains in-flight HTTP.
	//   5. cleanTables + pool.Close.
	t.Cleanup(func() {
		cancel()
		select {
		case <-loopDone:
		case <-time.After(5 * time.Second):
			t.Logf("builder loop did not exit in 5s after cancel; proceeding")
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = ts.closer(shutdownCtx)
		_ = server.Shutdown(shutdownCtx)
		cleanTables(t, pool)
		pool.Close()
	})

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
	t.Fatal("test ledger did not become ready in 2.5s")
	return nil
}

// -------------------------------------------------------------------------------------------------
// 5) Handler-construction helper
// -------------------------------------------------------------------------------------------------

// buildTestHandlers factors the api.Handlers literal out of the
// main constructor so startTestLedgerWithOpts stays under the
// project's per-file LoC ceiling. Returns a fully-populated
// Handlers map matching cmd/ledger/main.go's mount set, except
// WitnessCosign which test scenarios mount on a per-test basis.
func buildTestHandlers(
	submissionDeps *api.SubmissionDeps,
	treeDeps *api.TreeDeps,
	smtDeps *api.SMTDeps,
	queryDeps *api.QueryDeps,
	entryReadDeps *api.EntryReadDeps,
	commitDeps *api.DerivationCommitmentDeps,
) api.Handlers {
	return api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		BatchSubmission: api.NewBatchSubmissionHandler(submissionDeps),
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
		CommitmentQuery: api.NewDerivationCommitmentQueryHandler(commitDeps),
	}
}
