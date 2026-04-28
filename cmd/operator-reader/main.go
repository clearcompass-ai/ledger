/*
FILE PATH:
    cmd/operator-reader/main.go

DESCRIPTION:
    Read-only Ortholog log operator. Serves all GET endpoints.
    Does NOT run the builder loop, accept submissions, or write anything.

KEY ARCHITECTURAL DECISIONS:
    - Hash-only tiles: TesseraEntryReader removed because entry tiles now contain
      32-byte SHA-256 hashes, not full wire bytes. The reader needs access to the
      same byte store as the writer for full entry bytes.
    - Production: shared persistent byte store (DiskEntryStore, GCS-backed, etc.).
      The reader and writer operator both access the same backing store.
    - Local dev: InMemoryEntryStore — the reader process has an EMPTY byte store
      unless it shares the writer's process or backing directory. Entry byte
      hydration will fail for entries not in the store. This is acceptable for
      local dev where the read-write operator is the primary deployment.
    - All GET endpoints remain functional for Postgres-only queries (tree head,
      SMT proofs, difficulty). Entry byte hydration endpoints (entry fetch, query
      results with canonical_bytes) require the shared byte store.

OVERVIEW:
    Same startup as the read-write operator, minus:
    - No builder loop (no advisory lock, no queue drain).
    - No submission handler (POST /v1/entries returns 404).
    - No witness cosign endpoint.
    - Entry byte store: InMemoryEntryStore (empty on start — production uses shared persistent).
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

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"

	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/bytestore"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("operator-reader fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := loadConfig()
	logger.Info("config loaded (read-only mode)", "log_did", cfg.LogDID, "addr", cfg.ServerAddr)

	// ── Postgres read pool ─────────────────────────────────────────────
	dsn := cfg.ReplicaDSN
	if dsn == "" {
		dsn = cfg.PostgresDSN
	}
	pool, err := store.InitPool(ctx, store.PoolConfig{
		DSN:             dsn,
		MaxConns:        int32(cfg.MaxConns),
		MinConns:        int32(cfg.MinConns),
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("postgres pool: %w", err)
	}
	defer pool.Close()
	logger.Info("postgres read pool initialized", "replica", cfg.ReplicaDSN != "")

	// ── Tessera (read-only) ─────────────────────────────────────
	// Phase 1B: the reader binary no longer talks HTTP to a
	// separate personality. Instead it reads tiles + checkpoint
	// directly off the POSIX directory the writer operator's
	// embedded Tessera writes to (shared volume in k8s, same
	// host in single-node deployments). ReadOnlyAppender's
	// AppendLeaf returns ErrReadOnly — a loud rejection if any
	// future code path mistakenly tries to write from the reader.
	tileBackend, err := tessera.NewPOSIXTileBackend(cfg.TesseraStorageDir)
	if err != nil {
		return fmt.Errorf("tessera posix tile backend: %w", err)
	}
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	roAppender := tessera.NewReadOnlyAppender(tileBackend)
	tesseraAdapter := tessera.NewTesseraAdapter(roAppender, tileReader, logger)
	logger.Info("tessera initialized (read-only)", "storage_dir", cfg.TesseraStorageDir)

	// ── Entry byte store ──────────────────────────────────────────────
	// Reader points at the same backend + prefix the writer operator
	// uses, so byte hydration on GET requests returns the same bytes
	// the writer admitted. OPERATOR_BYTE_STORE_BACKEND is required;
	// only "gcs" is supported today.
	if cfg.ByteStoreBackend == "" {
		return fmt.Errorf("OPERATOR_BYTE_STORE_BACKEND required (only valid value: gcs)")
	}
	if cfg.ByteStoreBackend != "gcs" {
		return fmt.Errorf("OPERATOR_BYTE_STORE_BACKEND=%q not supported (only valid value: gcs)", cfg.ByteStoreBackend)
	}
	if cfg.ByteStoreGCSBucket == "" {
		return fmt.Errorf("OPERATOR_BYTE_STORE_GCS_BUCKET required when OPERATOR_BYTE_STORE_BACKEND=gcs")
	}
	gcsStore, gerr := bytestore.NewGCS(ctx, bytestore.GCSConfig{
		Bucket:       cfg.ByteStoreGCSBucket,
		Endpoint:     cfg.ByteStoreGCSEndpoint,
		Anonymous:    cfg.ByteStoreGCSAnon,
		ObjectPrefix: cfg.ByteStoreGCSPrefix,
		CacheSize:    cfg.ByteStoreCacheSize,
	})
	if gerr != nil {
		return fmt.Errorf("byte store GCS: %w", gerr)
	}
	defer func() {
		if err := gcsStore.Close(); err != nil {
			logger.Warn("gcs byte store close", "error", err)
		}
	}()
	var entryBytes bytestore.Store = gcsStore
	logger.Info("operator-reader byte store is bytestore.GCS",
		"bucket", cfg.ByteStoreGCSBucket,
		"prefix", cfg.ByteStoreGCSPrefix,
		"endpoint_override", cfg.ByteStoreGCSEndpoint != "",
		"anonymous", cfg.ByteStoreGCSAnon,
	)

	// ── SMT (read-only) ────────────────────────────────────────────────
	leafStore := store.NewPostgresLeafStore(pool.DB)
	nodeCache := store.NewPostgresNodeCache(pool.DB, cfg.SMTCacheSize)
	tree := smt.NewTree(leafStore, nodeCache)
	if err := nodeCache.WarmCache(ctx, cfg.WarmTopLevels); err != nil {
		logger.Warn("cache warm failed (non-fatal)", "error", err)
	}

	// ── Stores ─────────────────────────────────────────────────────────
	treeHeadStore := store.NewTreeHeadStore(pool.DB)
	commitmentStore := store.NewCommitmentStore(pool.DB)
	fetcher := store.NewPostgresEntryFetcher(pool.DB, entryBytes, cfg.LogDID)

	// ── Difficulty (static) ────────────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		nil,
		middleware.DifficultyConfig{
			InitialDifficulty: uint32(cfg.InitialDifficulty),
			MinDifficulty:     uint32(cfg.MinDifficulty),
			MaxDifficulty:     uint32(cfg.MaxDifficulty),
			HashFunction:      cfg.HashFunction,
		}, logger,
	)

	// ── Stores (read-only) ─────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool.DB)

	// ── Query API ──────────────────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool.DB, entryBytes, cfg.LogDID)

	// ── HTTP handlers ──────────────────────────────────────────────────
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: tesseraAdapter,
		Consistency: tesseraAdapter, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		EntryStore: entryStore,
		// Read-only operator has no WAL — the /raw handler degrades
		// to "always 302 to byte store". Un-shipped entries surface
		// as bytestore 404; consumers retry against the writer.
		WAL:       nil,
		Presigner: gcsStore,
		LogDID:    cfg.LogDID,
		Logger:    logger,
	}
	commitDeps := &api.CommitmentDeps{
		CommitmentStore: commitmentStore, Logger: logger,
	}

	handlers := api.Handlers{
		Submission:      nil, // No POST /v1/entries in read-only mode.
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
	serverCfg.Addr = cfg.ServerAddr
	server := api.NewServer(serverCfg, pool.DB, handlers, logger)

	// ── Start + shutdown ───────────────────────────────────────────────
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server exited", "error", err)
		}
	}()
	logger.Info("HTTP server started (read-only)", "addr", cfg.ServerAddr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	cancel()
	wg.Wait()
	logger.Info("operator-reader stopped cleanly")
	return nil
}

// -------------------------------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------------------------------

type readerConfig struct {
	LogDID            string
	PostgresDSN       string
	ReplicaDSN        string
	MaxConns          int
	MinConns          int
	ServerAddr        string
	TesseraStorageDir string // shared POSIX dir with the writer operator
	TileCacheSize     int
	WarmTopLevels     int
	SMTCacheSize      int
	InitialDifficulty int
	MinDifficulty     int
	MaxDifficulty     int
	HashFunction      string

	// Byte store (Phase 2). Reader and writer must agree on
	// backend + bucket + prefix so reads return the same bytes
	// the writer admitted.
	ByteStoreBackend     string
	ByteStoreGCSBucket   string
	ByteStoreGCSEndpoint string
	ByteStoreGCSAnon     bool
	ByteStoreGCSPrefix   string
	ByteStoreCacheSize   int
}

func loadConfig() readerConfig {
	return readerConfig{
		LogDID:            envOr("ORTHOLOG_LOG_DID", "did:ortholog:operator:001"),
		PostgresDSN:       envOr("ORTHOLOG_POSTGRES_DSN", "postgres://ortholog:ortholog@localhost:5432/ortholog?sslmode=disable"),
		ReplicaDSN:        envOr("ORTHOLOG_REPLICA_DSN", ""),
		MaxConns:          20,
		MinConns:          5,
		ServerAddr:        envOr("ORTHOLOG_SERVER_ADDR", ":8081"),
		TesseraStorageDir: envOr("ORTHOLOG_TESSERA_STORAGE_DIR", "/var/lib/ortholog/tessera"),
		TileCacheSize:     10000,
		WarmTopLevels:     32,
		SMTCacheSize:      100000,
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		HashFunction:      "sha256",

		ByteStoreBackend:     os.Getenv("OPERATOR_BYTE_STORE_BACKEND"),
		ByteStoreGCSBucket:   os.Getenv("OPERATOR_BYTE_STORE_GCS_BUCKET"),
		ByteStoreGCSEndpoint: os.Getenv("OPERATOR_BYTE_STORE_GCS_ENDPOINT"),
		ByteStoreGCSAnon:     os.Getenv("OPERATOR_BYTE_STORE_GCS_ANONYMOUS") == "true",
		ByteStoreGCSPrefix:   envOr("OPERATOR_BYTE_STORE_GCS_PREFIX", "entries"),
		ByteStoreCacheSize:   4096,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
