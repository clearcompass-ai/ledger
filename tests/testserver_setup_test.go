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
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/network"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	opbuilder "github.com/clearcompass-ai/ledger/builder"
	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/sequencer"
	"github.com/clearcompass-ai/ledger/shipper"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	"github.com/clearcompass-ai/ledger/wal"
	"github.com/clearcompass-ai/ledger/witnessclient"
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

	// AuditMode flips the witness setup into auditor-grade
	// chain-walk shape:
	//
	//   1. WitnessCount keypairs are generated FIRST via
	//      did.GenerateDIDKeySecp256k1 so their DIDs are known
	//      before any other config exists.
	//   2. A network.BootstrapDocument is built listing those
	//      DIDs in GenesisWitnessSet.
	//   3. The doc is written to t.TempDir()/network-bootstrap.json
	//      and its path exposed via testLedger.BootstrapPath.
	//   4. NetworkID = SHA-256(JCS(bootstrap doc))[:32] is derived
	//      and threaded through the witness fixture +
	//      witnessclient.HeadSync.
	//   5. /v1/log-info is wired with the derived NetworkID so the
	//      auditor can verify the ledger is serving the network
	//      whose bootstrap doc they hold.
	//
	// An audit-grade test (e.g., TestScale_AuditLookup) then walks:
	//   bootstrap doc (out-of-band trust root) →
	//   derived NetworkID →
	//   resolve did:key witness DIDs to ECDSA pubkeys →
	//   construct WitnessKeySet →
	//   verify /v1/tree/head cosignatures
	// without any back-channel from the test harness — every step
	// is cryptographic.
	AuditMode bool

	// WitnessCount is the number of witness signers the fixture
	// constructs. Default 1. Audit-mode tests typically pass 3+
	// to exercise K-of-N quorum (paired with WitnessQuorumK).
	// Ignored when AuditMode is false (legacy tests use the
	// witness-fixture default of 1).
	WitnessCount int

	// WitnessQuorumK is the K in the K-of-N quorum. Must satisfy
	// 1 <= K <= WitnessCount. Default 1 (single-witness ack).
	// Threaded into both witnessclient.HeadSync (signs path) and
	// (audit mode) the auditor's cosign.NewWitnessKeySet (verify
	// path).
	WitnessQuorumK int

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
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeStore(ctx, pool, 10000)
	tree := smt.NewTree(leafStore, nodeCache)
	commitmentStore := store.NewCommitmentStore(pool)

	walDB, err := wal.OpenInMemory(nil)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("wal open: %v", err)
	}
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{DisableSync: true})
	// walc + walDB cleanup is handled by the single shutdownChain
	// registered at the end of this function; do NOT register another
	// t.Cleanup here. LIFO ordering across multiple Cleanups was the
	// source of the AppendLeaf-future goroutine leak we just fixed.

	// Composite byte reader: WAL first, then in-memory bytestore.
	// In production the Shipper writes WAL→bytestore; the test harness
	// has no shipper, so a bare bytestore.Reader returns "not found"
	// for every hydrate call. The composite mirrors the e2e harness
	// (e2e_shipper_redirect_test.go:216) and lets read-path tests
	// hydrate from WAL even when nothing has shipped yet.
	composite := store.NewCompositeByteReader(walc, entryBytes, logger)
	fetcher := store.NewPostgresEntryFetcher(pool, composite, testLogDID)

	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer, _ := bufferStore.Load(ctx)
	if deltaBuffer == nil {
		deltaBuffer = sdkbuilder.NewDeltaWindowBuffer(10)
	}

	ts := buildTesseraForTests(t, ctx, opts, logger)

	// Witness setup splits on opts.AuditMode:
	//
	//   default path: legacy witness fixture with a deterministic
	//     test NetworkID (nonZeroTestNetworkID). Single witness,
	//     K=1. Used by 600+ existing tests; do not change this
	//     without auditing every caller.
	//
	//   audit path: pre-generate WitnessCount keypairs (so their
	//     DIDs are known), build a network.BootstrapDocument
	//     listing those DIDs, derive NetworkID from JCS(doc), and
	//     thread the derived NetworkID through both the witness
	//     fixture (which signs with it) and the head-sync client
	//     (which submits with it). Bootstrap doc is written to
	//     t.TempDir()/network-bootstrap.json; the path goes onto
	//     testLedger.BootstrapPath so the audit test can read it
	//     as the out-of-band trust root.
	witnessQuorumK := 1
	var (
		witnessNetID     cosign.NetworkID
		witnessFx        *witnessFixture
		bootstrapPath    string
		auditWitnessDIDs []string
	)
	if opts.AuditMode {
		wc := opts.WitnessCount
		if wc < 1 {
			wc = 1
		}
		wk := opts.WitnessQuorumK
		if wk < 1 {
			wk = 1
		}
		if wk > wc {
			cancel()
			pool.Close()
			t.Fatalf("AuditMode: WitnessQuorumK (%d) cannot exceed WitnessCount (%d)", wk, wc)
		}
		witnessQuorumK = wk

		// 1. Pre-generate keypairs so their DIDs are known before
		//    the bootstrap doc is built.
		keypairs := make([]*did.DIDKeyPairSecp256k1, wc)
		auditWitnessDIDs = make([]string, wc)
		for i := 0; i < wc; i++ {
			kp, kpErr := did.GenerateDIDKeySecp256k1()
			if kpErr != nil {
				cancel()
				pool.Close()
				t.Fatalf("AuditMode: GenerateDIDKeySecp256k1 %d: %v", i, kpErr)
			}
			keypairs[i] = kp
			auditWitnessDIDs[i] = kp.DID
		}

		// 2. Build the bootstrap doc with those DIDs. The
		//    ExchangeDID + NetworkName combine into the JCS
		//    canonical form whose SHA-256 IS the NetworkID; we
		//    pick t-prefixed values so collision with any
		//    production NetworkID is impossible.
		doc := network.BootstrapDocument{
			ProtocolVersion:   "v1",
			ExchangeDID:       "did:test:audit-exchange",
			NetworkName:       "audit-test",
			GenesisWitnessSet: append([]string(nil), auditWitnessDIDs...),
			GenesisTreeHead: network.GenesisTreeHead{
				RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
				TreeSize: 0,
			},
		}
		canonical, jcsErr := doc.CanonicalBytes()
		if jcsErr != nil {
			cancel()
			pool.Close()
			t.Fatalf("AuditMode: bootstrap doc CanonicalBytes: %v", jcsErr)
		}

		// 3. Derive NetworkID = SHA-256(JCS(doc))[:32]. Identical
		//    to what an auditor computes locally from the same
		//    bytes; cosign.NetworkID is a [32]byte alias.
		hash := sha256.Sum256(canonical)
		copy(witnessNetID[:], hash[:])

		// 4. Persist the bootstrap doc to disk under t.TempDir()
		//    so the audit test can read it as the out-of-band
		//    trust root. The file format is the canonical JCS
		//    form (not pretty-printed JSON) — the auditor MUST
		//    re-canonicalize before computing the NetworkID, but
		//    pinning the on-disk form to the canonical bytes
		//    guarantees byte-for-byte agreement.
		bootstrapDir := t.TempDir()
		bootstrapPath = filepath.Join(bootstrapDir, "network-bootstrap.json")
		if writeErr := os.WriteFile(bootstrapPath, canonical, 0o600); writeErr != nil {
			cancel()
			pool.Close()
			t.Fatalf("AuditMode: write bootstrap doc: %v", writeErr)
		}

		// 5. Construct the witness fixture from the pre-generated
		//    keypairs + the derived NetworkID. The fixture's
		//    witnesses sign with this NetworkID; the auditor
		//    derives the same NetworkID from the bootstrap doc
		//    and verifies signatures against it.
		witnessFx = newWitnessFixtureFromKeypairs(t, witnessNetID, keypairs)
	} else {
		// Legacy path. Unchanged from pre-AuditMode behavior.
		witnessNetID = nonZeroTestNetworkID()
		witnessFx = newWitnessFixture(t, witnessNetID, 1)
	}
	witnessCosigner, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  witnessFx.URLs(),
		QuorumK:           witnessQuorumK,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         witnessNetID,
	}, treeHeadStore, logger)
	if err != nil {
		cancel()
		pool.Close()
		t.Fatalf("real witness HeadSync: %v", err)
	}

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

	// Sequencer (WAL Admitted → Tessera AppendLeaf → entry_index INSERT
	// → WAL Sequenced). Without this goroutine, submissions land in WAL
	// but never reach entry_index, so /v1/entries-hash/{hash} stays a
	// 404 and submitEntry's polling loop times out. Mirrors the e2e
	// harness wiring at e2e_shipper_redirect_test.go:348-361.
	seq := sequencer.NewSequencer(walc, ts.admission, pool, entryStore, sequencer.Config{
		PollInterval: 10 * time.Millisecond,
		Logger:       logger,
	})
	seqDone := make(chan struct{})
	go func() {
		_ = seq.Run(ctx)
		close(seqDone)
	}()

	// Shipper (WAL Sequenced → bytestore WriteEntry → WAL Shipped).
	// Production has a shipper that migrates wire bytes from the WAL
	// into the durable bytestore. TestRule_EndToEnd_BytesNeverTouchPostgres
	// asserts entryBytes contains the bytes after submission — without
	// a shipper that's never true.
	ship := shipper.NewShipper(walc, entryBytes, shipper.Config{
		PollInterval: 50 * time.Millisecond,
		MaxInFlight:  4,
		Logger:       logger,
	})
	shipDone := make(chan struct{})
	go func() {
		_ = ship.Run(ctx)
		close(shipDone)
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
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, composite, testLogDID)

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
		EntryStore: entryStore, QueryAPI: queryAPI, DiffController: diffController,
		WAL: walc, Logger: logger,
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
		Fetcher: store.NewPostgresCommitmentFetcher(pool, composite, testLogDID),
		Logger:  logger,
	}

	handlers := buildTestHandlers(submissionDeps, treeDeps, smtDeps, queryDeps, entryReadDeps, commitDeps)
	handlers.CommitmentLookup = api.NewCommitmentLookupHandler(cryptoCommitDeps)

	// AuditMode: wire /v1/log-info with the derived NetworkID so
	// the auditor can verify the ledger is serving the network
	// whose bootstrap doc they hold (STEP 4 of the chain-walk).
	// log_did + ledger_did + witness_quorum_k + network_id are the
	// minimum fields the audit chain checks; other LogInfo fields
	// (gossip topology, sequencer cadence) are not part of the
	// trustless verification path so we omit them here.
	if opts.AuditMode {
		handlers.LogInfo = api.NewLogInfoHandler(api.LogInfo{
			"log_did":                testLogDID,
			"ledger_did":             testLedgerDID,
			"network_id":             fmt.Sprintf("%x", witnessNetID[:]),
			"witness_quorum_k":       witnessQuorumK,
			"witness_endpoint_count": len(witnessFx.URLs()),
		})
	}

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
		EntryBytes: entryBytes,
		// EntryReader is the SAME composite that fetcher (production
		// read path) uses. Tests asserting against the EntryReader
		// abstraction MUST go through this field — reading EntryBytes
		// directly races the shipper's StateSequenced→StateShipped
		// transition. See testLedger docstring.
		EntryReader: composite,
		cancel:      cancel,
		RealTesseraDir: ts.tileRoot,
		RealEmbedded:   ts.embedded,
		RealTileReader: ts.tileReader,
		// Audit-mode handles. Zero-valued unless opts.AuditMode was
		// set; the audit branch above writes the bootstrap doc and
		// derives the NetworkID, both of which we surface here so
		// the test can walk the chain just like a real auditor.
		BootstrapPath:    bootstrapPath,
		DerivedNetworkID: witnessNetID,
		WitnessQuorumK:   witnessQuorumK,
		WitnessDIDs:      auditWitnessDIDs,
	}

	// Single ordered teardown — see tests/shutdownchain_test.go for
	// the spec-order rationale. Do NOT add other t.Cleanup calls in
	// this function: LIFO ordering across multiple Cleanups is what
	// caused the AppendLeaf-future goroutine leak.
	t.Cleanup(shutdownChain{
		Logger:        logger,
		Server:        server,
		Tessera:       ts.embedded,
		Cancel:        cancel,
		GoroutineDone: []<-chan struct{}{loopDone, seqDone, shipDone},
		WALC:          walc,
		WALDB:         walDB,
		Pool:          pool,
		CleanTables:   func() { cleanTables(t, pool) },
	}.Run)

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
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryByHash:     api.NewHashLookupHandler(queryDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:        api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewDerivationCommitmentQueryHandler(commitDeps),
	}
}
