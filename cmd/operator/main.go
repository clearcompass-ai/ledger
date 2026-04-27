/*
FILE PATH: cmd/operator/main.go

DESCRIPTION:

	Operator binary entry point. Wires config → Postgres → stores → byte
	store → Tessera personality → builder deps → HTTP handlers → goroutines.
	Runs the admission HTTP server, builder loop, and (optional) anchor
	publisher under a shared cancellable context.

SDK v0.3.0 WIRING CHANGES (addressed in this rewrite):
 1. anchor.PublisherConfig requires LogDID — threaded from cfg.LogDID.
 2. builder.NewCommitmentPublisher is (operatorDID, logDID, cfg, submitFn,
    logger) — both DIDs passed explicitly.
 3. api.SubmissionDeps has FreshnessTolerance (defaults to
    policy.FreshnessInteractive = 5 min if zero). Explicit here for
    auditability.
 4. Phase 4 DID verifier scaffolded behind a nil — when ready, swap
    for did.DefaultVerifierRegistry(cfg.LogDID, resolver).

OPERATOR INTERNAL SIGNATURES (the ones the last attempt got wrong):
  - tessera.NewClient(ClientConfig{BaseURL, Timeout}, logger) → *Client.
    Struct config, single return, no Close method.
  - tessera.NewTesseraAdapter(client, tileReader, logger) → MerkleAppender.
    Builder/anchor talk to the adapter, not the raw client.
  - tessera.NewInMemoryEntryStore() → *InMemoryEntryStore. The only
    byte-store implementation shipped today. A persistent backend is the
    operator's responsibility to swap in.
  - store.NewPostgresNodeCache(pool, cacheSize) → *PostgresNodeCache.
    Cache size MUST be passed; zero would be a pathological no-cache path.
  - builder.NewDeltaBufferStore(pool, windowSize, logger) → *DeltaBufferStore.
  - bufferStore.Load(ctx) → (*sdkbuilder.DeltaWindowBuffer, error).
    Returns a fresh buffer. We do NOT pass our own buffer in.
  - middleware.NewDifficultyController(queue, cfg, logger) → takes the
    queue FIRST (it polls queue depth for auto-adjustment).
  - middleware.DefaultDifficultyConfig() returns a ready-to-use config
    with all seven fields populated (InitialDifficulty, Min/Max,
    LowThreshold, HighThreshold, AdjustInterval, HashFunction).

INVARIANTS:
  - cfg.LogDID MUST be non-empty: submission handler panics at
    construction otherwise (destination-binding enforcement gate).
  - cfg.OperatorDID defaults to cfg.LogDID for single-exchange
    deployments where the operator IS the exchange.
  - ByteStore here is NewInMemoryEntryStore() — bytes are lost on
    restart. Production deployments MUST replace this with a
    persistent implementation of tessera.EntryReader + EntryWriter.
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/tessera/storage/posix"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/anchor"
	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// loadOrGenerateTesseraSigner resolves the checkpoint signer.
// Priority:
//   - keyFile non-empty: load note.Signer from disk; fail if
//     unreadable. Production deployments MUST use this.
//   - keyFile empty: generate an ephemeral Ed25519 signer with a
//     loud warning log. Local-dev only — the verifier key is
//     printed once and lost on next restart.
//
// origin / logDID are used to derive the signer name when
// generating ephemerally (Tessera's signer name appears in every
// checkpoint and identifies the log).
func loadOrGenerateTesseraSigner(keyFile, origin, logDID string, logger *slog.Logger) (note.Signer, string, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read tessera signer key %q: %w", keyFile, err)
		}
		signer, err := note.NewSigner(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("parse tessera signer key %q: %w", keyFile, err)
		}
		logger.Info("tessera signer loaded from file", "key_file", keyFile, "name", signer.Name())
		return signer, "", nil
	}
	// Ephemeral fallback for local dev.
	name := origin
	if name == "" {
		name = logDID
	}
	signer, vkey, err := tessera.GenerateEphemeralSigner(name)
	if err != nil {
		return nil, "", err
	}
	logger.Warn("tessera signer is ephemeral — NOT for production",
		"name", signer.Name(),
		"verifier_key", vkey,
	)
	return signer, vkey, nil
}

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

type Config struct {
	ServerAddr            string
	DatabaseURL           string
	LogDID                string // Destination for self-published entries (anchors, commitments).
	OperatorDID           string // Signer DID for operator-authored commentary.
	MaxEntrySize          int64
	BatchSize             int
	PollInterval          time.Duration
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	AnchorInterval        time.Duration
	AnchorSources         []anchor.AnchorSource
	// Tessera embedding — Phase 1B replaces the standalone
	// tessera-personality binary with in-process upstream Tessera.
	// TesseraStorageDir is the POSIX directory the embedded
	// Tessera POSIX driver writes tiles, entry bundles, and the
	// checkpoint to. Operator-reader and operator-writer must
	// agree on this path.
	// TesseraSignerKeyFile is the path to a note.Signer private
	// key file. When empty, an ephemeral key is generated at boot
	// (with a logged warning) — fine for local dev, never for
	// production.
	// TesseraOrigin is the c2sp.org/tlog-tiles origin string
	// embedded in every signed checkpoint. Defaults to LogDID.
	TesseraStorageDir    string
	TesseraSignerKeyFile string
	TesseraOrigin        string
	TileCacheSize         int
	SMTNodeCacheSize      int
	DeltaWindow           int
	WitnessEndpoints      []string
	WitnessQuorumK        int

	// BuilderReaderMode selects the builder's pending-work source.
	//   - "queue" (default) — legacy builder_queue table. Admission
	//     INSERTs a row per entry; the builder dequeues and marks
	//     processed.
	//   - "cursor" — CT-native log-tailing follower. Admission writes
	//     entry_index only; the builder reads
	//     entry_index WHERE sequence_number > builder_cursor and
	//     advances the cursor in its atomic commit.
	// Default stays "queue" so existing deployments behave exactly
	// as before. The cursor path eliminates the per-entry MVCC
	// pressure on builder_queue at 10B+ scale; flip the default in
	// a follow-up release once the cursor path has run stably.
	BuilderReaderMode string
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerAddr:            envOr("OPERATOR_ADDR", ":8080"),
		DatabaseURL:           os.Getenv("OPERATOR_DATABASE_URL"),
		LogDID:                os.Getenv("OPERATOR_LOG_DID"),
		OperatorDID:           os.Getenv("OPERATOR_DID"),
		MaxEntrySize:          1 << 20, // 1 MB, matches SDK-D11.
		BatchSize:             1000,
		PollInterval:          100 * time.Millisecond,
		EpochWindowSeconds:    3600, // 1h — matches testEpochWindowSeconds.
		EpochAcceptanceWindow: 1,
		AnchorInterval:        1 * time.Hour,
		TesseraStorageDir:     envOr("OPERATOR_TESSERA_STORAGE_DIR", "/var/lib/ortholog/tessera"),
		TesseraSignerKeyFile:  os.Getenv("OPERATOR_TESSERA_SIGNER_KEY_FILE"),
		TesseraOrigin:         os.Getenv("OPERATOR_TESSERA_ORIGIN"), // defaults to LogDID below
		TileCacheSize:         10_000,
		SMTNodeCacheSize:      100_000,
		DeltaWindow:           10,
		WitnessQuorumK:        1,
		BuilderReaderMode:     envOr("OPERATOR_BUILDER_READER", "queue"),
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("OPERATOR_DATABASE_URL required")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("OPERATOR_LOG_DID required (destination-binding)")
	}
	if cfg.OperatorDID == "" {
		cfg.OperatorDID = cfg.LogDID
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "error", err)
		os.Exit(1)
	}

	// Fail-fast sanity check on LogDID before we touch Postgres.
	if valErr := envelope.ValidateDestination(cfg.LogDID); valErr != nil {
		logger.Error("invalid OPERATOR_LOG_DID", "error", valErr)
		os.Exit(1)
	}

	logger.Info("operator starting",
		"log_did", cfg.LogDID,
		"operator_did", cfg.OperatorDID,
		"addr", cfg.ServerAddr,
		"tessera_storage_dir", cfg.TesseraStorageDir,
		"sdk_version", "v0.3.0-tessera",
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Postgres ──────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("pgxpool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := store.RunMigrations(ctx, pool); err != nil {
		logger.Error("migrations", "error", err)
		os.Exit(1)
	}

	// ── Stores ────────────────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	commitStore := store.NewCommitmentStore(pool)
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool, cfg.SMTNodeCacheSize)

	// ── Byte store ────────────────────────────────────────────────────
	//
	// WARNING: InMemoryEntryStore is the ONLY implementation shipped today.
	// It holds entry bytes in a sync.RWMutex-guarded map; everything is
	// lost on process exit. For production, build a persistent
	// EntryReader/EntryWriter (disk, S3, GCS) and substitute it here.
	//
	// Single process contains both byte writer (admission path) and byte
	// reader (builder fetcher, query API). Crossing process boundaries
	// would require a shared backing store.
	byteStore := tessera.NewInMemoryEntryStore()
	logger.Warn("byte store is InMemoryEntryStore — bytes are lost on restart. Wire a persistent backend for production.")

	// ── Tessera personality ───────────────────────────────────────────
	//
	// Embedded Tessera (Phase 1B): in-process upstream Tessera
	// over a POSIX storage driver. The standalone
	// tessera-personality binary is gone — sequencing,
	// integration, and checkpoint signing all run inside this
	// process. TileReader reads tiles directly off the same
	// directory Tessera writes to. Adapter satisfies the
	// MerkleAppender interface the builder loop holds.
	if err := os.MkdirAll(cfg.TesseraStorageDir, 0o755); err != nil {
		logger.Error("tessera storage dir", "error", err, "dir", cfg.TesseraStorageDir)
		os.Exit(1)
	}
	tesseraDriver, err := posix.New(ctx, posix.Config{Path: cfg.TesseraStorageDir})
	if err != nil {
		logger.Error("tessera posix driver", "error", err, "dir", cfg.TesseraStorageDir)
		os.Exit(1)
	}
	tesseraSigner, vkey, err := loadOrGenerateTesseraSigner(cfg.TesseraSignerKeyFile, cfg.TesseraOrigin, cfg.LogDID, logger)
	if err != nil {
		logger.Error("tessera signer", "error", err)
		os.Exit(1)
	}
	tesseraOrigin := cfg.TesseraOrigin
	if tesseraOrigin == "" {
		tesseraOrigin = cfg.LogDID
	}
	embeddedAppender, err := tessera.NewEmbeddedAppender(ctx, tesseraDriver, tessera.AppenderOptions{
		Origin: tesseraOrigin,
		Signer: tesseraSigner,
		// Defaults applied for CheckpointInterval / BatchSize /
		// BatchMaxAge — see tessera/embedded_appender.go.
	}, logger)
	if err != nil {
		logger.Error("tessera embedded appender", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := embeddedAppender.Close(shutdownCtx); err != nil {
			logger.Warn("tessera shutdown", "error", err)
		}
	}()
	logger.Info("tessera embedded ready",
		"storage_dir", cfg.TesseraStorageDir,
		"origin", tesseraOrigin,
		"verifier_key", vkey,
	)

	tileBackend, err := tessera.NewPOSIXTileBackend(cfg.TesseraStorageDir)
	if err != nil {
		logger.Error("tessera posix tile backend", "error", err)
		os.Exit(1)
	}
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	tesseraAdapter := tessera.NewTesseraAdapter(embeddedAppender, tileReader, logger)

	// ── Builder dependencies ──────────────────────────────────────────
	fetcher := store.NewPostgresEntryFetcher(pool, byteStore, cfg.LogDID)
	bufferStore := builder.NewDeltaBufferStore(pool, cfg.DeltaWindow, logger)
	// Builder pending-work source: queue (legacy) or cursor
	// (CT-native log-tailing). queue is the *builder.Queue passed
	// to api.SubmissionDeps for the admission-side Enqueue write
	// (nil under cursor mode → admission skips the queue write).
	// reader is the builder.BatchReader the builder loop holds —
	// either the queue or the cursor reader, never both.
	var (
		queue  *builder.Queue
		reader builder.BatchReader
	)
	switch cfg.BuilderReaderMode {
	case "queue", "":
		queue = builder.NewQueue(pool)
		reader = queue
		logger.Info("builder reader",
			"mode", "queue",
			"note", "legacy builder_queue path; cursor mode eliminates per-entry MVCC pressure")
	case "cursor":
		reader = builder.NewCursorReader(store.NewSequenceCursor(pool))
		// queue stays nil — admission's Enqueue is gated on
		// deps.Queue != nil (see api/submission.go and
		// api/batch.go nil-guards from commit 7/8).
		logger.Info("builder reader",
			"mode", "cursor",
			"note", "log-tailing follower; admission skips builder_queue write")
	default:
		logger.Error("unknown OPERATOR_BUILDER_READER",
			"value", cfg.BuilderReaderMode, "want", "queue|cursor")
		os.Exit(1)
	}
	tree := smt.NewTree(leafStore, nodeCache)

	// Load buffer from persistence (cold start = strict OCC per SDK-D9).
	// Load returns a fresh *DeltaWindowBuffer — we do NOT pass our own in.
	buffer, loadErr := bufferStore.Load(ctx)
	if loadErr != nil {
		logger.Warn("delta buffer load — starting cold", "error", loadErr)
		buffer = sdkbuilder.NewDeltaWindowBuffer(cfg.DeltaWindow)
	}

	// ── Commitment publisher (v0.3.0: LogDID threaded) ────────────────
	commitPub := builder.NewCommitmentPublisher(
		cfg.OperatorDID,
		cfg.LogDID,
		builder.CommitmentPublisherConfig{
			IntervalEntries: 1000,
			IntervalTime:    1 * time.Hour,
		},
		anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
		logger,
	).WithCommitmentStore(commitStore)

	// ── Difficulty controller (queue-depth-driven) ────────────────────
	//
	// DefaultDifficultyConfig() is the ready-made production preset:
	//   Initial=16, Min=8, Max=24, Low=100, High=10000, Interval=30s, SHA-256.
	// NewDifficultyController takes (queue, cfg, logger) — queue first.
	diffController := middleware.NewDifficultyController(
		queue, middleware.DefaultDifficultyConfig(), logger,
	)

	// ── Witness cosigner (optional) ───────────────────────────────────
	//
	// Left nil for now. The operator's witness/ package today implements
	// the witness-as-server side (serve.go, head_sync.go) — the
	// witness-as-client requester (one operator asking N peer witnesses
	// to cosign its checkpoints) is a separate subsystem not yet wired.
	// BuilderLoop tolerates a nil cosigner: the cosignature step is
	// skipped and self-signed checkpoints are published unwitnessed.
	//
	// TODO: wire a real requester when multi-witness deployments go live.
	// At that point cfg.WitnessEndpoints + cfg.WitnessQuorumK become live.
	var cosigner builder.WitnessCosigner = nil

	// ── Builder loop ──────────────────────────────────────────────────
	loopCfg := builder.DefaultLoopConfig(cfg.LogDID)
	loopCfg.BatchSize = cfg.BatchSize
	loopCfg.PollInterval = cfg.PollInterval
	loopCfg.DeltaWindow = cfg.DeltaWindow

	bl := builder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		reader, fetcher,
		nil, // schema resolver — nil is valid; SDK builder tolerates it.
		buffer, bufferStore,
		commitPub,
		tesseraAdapter, // MerkleAppender
		cosigner,
		logger,
	)

	// ── Anchor publisher (v0.3.0: LogDID threaded) ────────────────────
	anchorPub := anchor.NewPublisher(
		anchor.PublisherConfig{
			OperatorDID:   cfg.OperatorDID,
			LogDID:        cfg.LogDID,
			Interval:      cfg.AnchorInterval,
			AnchorSources: cfg.AnchorSources,
		},
		tesseraAdapter,
		anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
		logger,
	)

	// ── Submission handler (v0.3.0: 13-step pipeline) ─────────────────
	submitHandler := api.NewSubmissionHandler(&api.SubmissionDeps{
		Storage: api.StorageDeps{
			DB:          pool,
			EntryStore:  entryStore,
			EntryWriter: byteStore, // same store the fetcher reads from.
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			CreditStore: creditStore,
			DIDResolver: nil, // Phase 4: wire did.DefaultVerifierRegistry.
		},
		Queue:              queue,
		LogDID:             cfg.LogDID,
		MaxEntrySize:       cfg.MaxEntrySize,
		Logger:             logger,
		FreshnessTolerance: policy.FreshnessInteractive, // 5-min window.
	})

	// ── Shared stores for read handlers ───────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool, byteStore, cfg.LogDID)
	treeHeadStore := store.NewTreeHeadStore(pool)

	// ── Handler struct for api.Server ─────────────────────────────────
	queryDeps := &api.QueryDeps{
		EntryStore:     entryStore,
		QueryAPI:       queryAPI,
		DiffController: diffController,
		Logger:         logger,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore,
		Inclusion:     tesseraAdapter,
		Consistency:   tesseraAdapter,
		Logger:        logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher:  fetcher,
		QueryAPI: queryAPI,
		LogDID:   cfg.LogDID,
		Logger:   logger,
	}
	commitDeps := &api.CommitmentDeps{CommitmentStore: commitStore, Logger: logger}

	handlers := api.Handlers{
		Submission:      submitHandler,
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
		WitnessCosign:   nil, // TODO: wire witness.NewCosignServer when this operator is also a witness.
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewCommitmentQueryHandler(commitDeps),
	}

	// ── HTTP server ───────────────────────────────────────────────────
	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	serverCfg.MaxEntrySize = cfg.MaxEntrySize
	server := api.NewServer(serverCfg, pool, handlers, logger)

	// ── Goroutines ────────────────────────────────────────────────────
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := bl.Run(ctx); err != nil {
			logger.Error("builder loop exited with error", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		diffController.Run(ctx, 30*time.Second)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		anchorPub.Run(ctx)
	}()

	// ── Shutdown ──────────────────────────────────────────────────────
	<-ctx.Done()
	logger.Info("shutdown initiated")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown", "error", err)
	}

	wg.Wait()

	b, e, errs := bl.Stats()
	logger.Info("operator stopped",
		"batches", b, "entries", e, "errors", errs,
	)
}
