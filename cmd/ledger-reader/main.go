/*
FILE PATH:

	cmd/ledger-reader/main.go

DESCRIPTION:

	Read-only Attesta log ledger. Serves all GET endpoints.
	Does NOT run the builder loop, accept submissions, or write anything.

KEY ARCHITECTURAL DECISIONS:
  - Hash-only tiles: TesseraEntryReader removed because entry tiles now contain
    32-byte SHA-256 hashes, not full wire bytes. The reader needs access to the
    same byte store as the writer for full entry bytes.
  - Production: shared persistent byte store (DiskEntryStore, GCS-backed, etc.).
    The reader and writer ledger both access the same backing store.
  - Local dev: InMemoryEntryStore — the reader process has an EMPTY byte store
    unless it shares the writer's process or backing directory. Entry byte
    hydration will fail for entries not in the store. This is acceptable for
    local dev where the read-write ledger is the primary deployment.
  - All GET endpoints remain functional for Postgres-only queries (tree head,
    SMT proofs, difficulty). Entry byte hydration endpoints (entry fetch, query
    results with canonical_bytes) require the shared byte store.

OVERVIEW:

	Same startup as the read-write ledger, minus:
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

	"github.com/clearcompass-ai/attesta/core/smt"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	"github.com/clearcompass-ai/ledger/tessera"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("ledger-reader fatal", "error", err)
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
	// directly off the POSIX directory the writer ledger's
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
	// Reader points at the same backend + prefix the writer ledger
	// uses, so byte hydration on GET requests returns the same bytes
	// the writer admitted. Backend selected via LEDGER_BYTE_STORE_BACKEND
	// (gcs|s3); the factory enforces per-backend required fields.
	switch cfg.ByteStoreBackend {
	case "":
		return fmt.Errorf("LEDGER_BYTE_STORE_BACKEND required (gcs|s3)")
	case "gcs":
		if cfg.ByteStoreGCSBucket == "" {
			return fmt.Errorf("LEDGER_BYTE_STORE_GCS_BUCKET required when LEDGER_BYTE_STORE_BACKEND=gcs")
		}
	case "s3":
		if cfg.ByteStoreS3Bucket == "" {
			return fmt.Errorf("LEDGER_BYTE_STORE_S3_BUCKET required when LEDGER_BYTE_STORE_BACKEND=s3")
		}
	default:
		return fmt.Errorf("LEDGER_BYTE_STORE_BACKEND=%q not supported (gcs|s3)", cfg.ByteStoreBackend)
	}
	entryBytes, gerr := bytestore.NewFromConfig(ctx, cfg.toBytestoreConfig())
	if gerr != nil {
		return fmt.Errorf("byte store init: %w", gerr)
	}
	defer func() {
		if closer, ok := entryBytes.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				logger.Warn("byte store close", "error", err)
			}
		}
	}()
	logger.Info("ledger-reader byte store ready",
		"backend", cfg.ByteStoreBackend,
		"prefix", cfg.ByteStorePrefix,
		"cache_size", cfg.ByteStoreCacheSize,
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
		// Read-only ledger has no WAL — the /raw handler degrades
		// to "always 302 to byte store". Un-shipped entries surface
		// as bytestore 404; consumers retry against the writer.
		WAL:       nil,
		Presigner: entryBytes,
		LogDID:    cfg.LogDID,
		Logger:    logger,
	}
	commitDeps := &api.DerivationCommitmentDeps{
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
		CommitmentQuery: api.NewDerivationCommitmentQueryHandler(commitDeps),
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool.DB), handlers, logger)

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
	logger.Info("ledger-reader stopped cleanly")
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
	TesseraStorageDir string // shared POSIX dir with the writer ledger
	TileCacheSize     int
	WarmTopLevels     int
	SMTCacheSize      int
	InitialDifficulty int
	MinDifficulty     int
	MaxDifficulty     int
	HashFunction      string

	// Byte store (Phase 2 + 3+4). Reader and writer must agree on
	// backend + bucket + prefix so reads return the same bytes
	// the writer admitted. Backend selection mirrors the writer
	// ledger: "gcs" or "s3" via LEDGER_BYTE_STORE_BACKEND.
	ByteStoreBackend   string
	ByteStorePrefix    string
	ByteStoreCacheSize int
	// GCS-specific.
	ByteStoreGCSBucket   string
	ByteStoreGCSEndpoint string
	ByteStoreGCSAnon     bool
	// S3-specific.
	ByteStoreS3Bucket    string
	ByteStoreS3Endpoint  string
	ByteStoreS3Region    string
	ByteStoreS3AccessKey string
	ByteStoreS3SecretKey string
	ByteStoreS3PathStyle bool
}

func loadConfig() readerConfig {
	return readerConfig{
		LogDID:            envOr("ATTESTA_LOG_DID", "did:attesta:ledger:001"),
		PostgresDSN:       envOr("ATTESTA_POSTGRES_DSN", "postgres://attesta:attesta@localhost:5432/attesta?sslmode=disable"),
		ReplicaDSN:        envOr("ATTESTA_REPLICA_DSN", ""),
		MaxConns:          20,
		MinConns:          5,
		ServerAddr:        envOr("ATTESTA_SERVER_ADDR", ":8081"),
		TesseraStorageDir: envOr("ATTESTA_TESSERA_STORAGE_DIR", "/var/lib/attesta/tessera"),
		TileCacheSize:     10000,
		WarmTopLevels:     32,
		SMTCacheSize:      100000,
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		HashFunction:      "sha256",

		ByteStoreBackend:   os.Getenv("LEDGER_BYTE_STORE_BACKEND"),
		ByteStorePrefix:    envOr("LEDGER_BYTE_STORE_PREFIX", "entries"),
		ByteStoreCacheSize: 4096,
		// GCS family.
		ByteStoreGCSBucket:   os.Getenv("LEDGER_BYTE_STORE_GCS_BUCKET"),
		ByteStoreGCSEndpoint: os.Getenv("LEDGER_BYTE_STORE_GCS_ENDPOINT"),
		ByteStoreGCSAnon:     os.Getenv("LEDGER_BYTE_STORE_GCS_ANONYMOUS") == "true",
		// S3 family.
		ByteStoreS3Bucket:    os.Getenv("LEDGER_BYTE_STORE_S3_BUCKET"),
		ByteStoreS3Endpoint:  os.Getenv("LEDGER_BYTE_STORE_S3_ENDPOINT"),
		ByteStoreS3Region:    os.Getenv("LEDGER_BYTE_STORE_S3_REGION"),
		ByteStoreS3AccessKey: os.Getenv("LEDGER_BYTE_STORE_S3_ACCESS_KEY"),
		ByteStoreS3SecretKey: os.Getenv("LEDGER_BYTE_STORE_S3_SECRET_KEY"),
		ByteStoreS3PathStyle: os.Getenv("LEDGER_BYTE_STORE_S3_PATH_STYLE") == "true",
	}
}

// toBytestoreConfig flattens the reader config into the bytestore
// factory's Config. Mirrors cmd/ledger/main.go's helper so the
// reader and writer pick identical backends from identical env vars.
func (c readerConfig) toBytestoreConfig() bytestore.Config {
	bc := bytestore.Config{
		Backend:   c.ByteStoreBackend,
		Prefix:    c.ByteStorePrefix,
		CacheSize: c.ByteStoreCacheSize,
	}
	switch c.ByteStoreBackend {
	case "gcs":
		bc.Bucket = c.ByteStoreGCSBucket
		bc.GCSEndpoint = c.ByteStoreGCSEndpoint
		bc.GCSAnonymous = c.ByteStoreGCSAnon
	case "s3":
		bc.Bucket = c.ByteStoreS3Bucket
		bc.S3Endpoint = c.ByteStoreS3Endpoint
		bc.S3Region = c.ByteStoreS3Region
		bc.S3AccessKey = c.ByteStoreS3AccessKey
		bc.S3SecretKey = c.ByteStoreS3SecretKey
		bc.S3PathStyle = c.ByteStoreS3PathStyle
	}
	return bc
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
