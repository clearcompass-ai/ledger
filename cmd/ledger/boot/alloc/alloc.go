// Package alloc implements Phase A of the ledger binary's lifecycle:
// open every I/O resource, register its closer with deps.AppDeps,
// and on the first failure walk the close stack in reverse so the
// caller never observes a partially-allocated AppDeps.
//
// FILE PATH:
//
//	cmd/ledger/boot/alloc/alloc.go
//
// DESCRIPTION:
//
//	Allocate is the single entry point. It runs the resource-open
//	functions in dependency order and returns either a fully-
//	populated *deps.AppDeps (caller proceeds to wire.Wire) or an
//	error (caller exits; AppDeps's resources have already been
//	UnwindReverse-d).
//
//	Order of opens (load-bearing for cleanup correctness — closeStack
//	reverse-walk runs in this order's mirror image):
//
//	  1. Telemetry (TracerProvider always; MeterProvider if enabled).
//	     Open first so any failure in subsequent steps can still log.
//	  2. Postgres pool + migrations + circuit breaker.
//	  3. Builder advisory lock — fail fast if another writer holds it.
//	  4. WAL Badger DB + Committer.
//	  5. Bytestore (SeaweedFS / GCS / S3 / etc.).
//	  6. Tessera POSIX driver + EmbeddedAppender + tile reader +
//	     antispam.
//	  7. Signer keys (ledger entry signer, Tessera checkpoint signer,
//	     witness signer if witness mode active).
//	  8. Gossip BadgerStore (only when gossip enabled).
//	  9. Ethereum RPC client (only when LEDGER_ETH_RPC_ENABLED).
//
//	A failure at step N walks the closeStack in REVERSE — every
//	step ≤ N-1 is closed in the opposite order it was opened.
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - Each step is a private function. Allocate is a thin orchestrator
//     of those steps. This keeps the file readable and makes it
//     trivial to add a step (insert a function call in Allocate; add
//     the helper).
//
//   - Errors carry the step name. The orchestrator wraps every helper
//     error with "alloc: <step>: …" so the supervisor's exit log
//     points at the failing resource immediately.
//
//   - No goroutines started here. Phase A is purely synchronous I/O
//     opens. Background goroutines (the advisory-lock heartbeat, the
//     WAL committer's group-commit goroutine) are started inside the
//     respective constructors — they're tied to the resource's
//     lifecycle, not to wire/run.
//
//   - The fatal channel is plumbed through to constructors that
//     need to surface async failures (specifically the advisory-
//     lock heartbeat). No allocator function panics or sends to
//     fatal directly.
package alloc

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"go.opentelemetry.io/otel"

	tposix "github.com/transparency-dev/tessera/storage/posix"
	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdklog "github.com/clearcompass-ai/attesta/log"

	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/deps"
	"github.com/clearcompass-ai/ledger/gossipstore"
	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/wal"
)

// Config is the alloc-relevant subset of cmd/ledger.Config. Held by
// value so callers can construct a small projection without leaking
// the full config struct into the boot package's import graph.
type Config struct {
	// Postgres
	DatabaseURL          string
	PgMaxConns           int32
	PgStatementTimeout   time.Duration
	SequencerMaxInFlight int

	// Migrations
	DBMigrateMode store.MigrateMode

	// WAL
	WALPath string

	// Bytestore (passed-through to bytestore.NewFromConfig)
	BytestoreConfig bytestore.Config

	// Tessera
	TesseraStorageDir    string
	TesseraSignerKeyFile string
	TesseraOrigin        string
	TesseraAntispamPath  string
	LogDID               string

	// Tile reader
	TileCacheSize int

	// Signers
	LedgerSignerKeyFile string

	// Witness (optional)
	WitnessKeyFile string

	// Gossip (optional)
	GossipDisable bool
	NetworkID     cosign.NetworkID

	// Telemetry
	MetricsEnable      bool
	MetricsEnvironment string
	ServiceVersion     string
	OTLPTracesEndpoint string
}

// SignerLoader is the function signature for the three loadOrGenerate*
// helpers in cmd/ledger. Allocate accepts them as injected
// dependencies so the boot package doesn't import key-loading logic
// directly. main wires them in.
type SignerLoader interface {
	LoadLedgerSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, string, error)
	LoadTesseraSigner(keyFile, origin, logDID string, logger *slog.Logger) (NoteSigner, string, error)
	LoadWitnessSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, error)
}

// NoteSigner mirrors the upstream golang.org/x/mod/sumdb/note.Signer
// interface so this package doesn't have to import note directly
// (note is an SDK-side concern; the loader wraps it).
type NoteSigner interface {
	Name() string
	Sign(msg []byte) ([]byte, error)
	KeyHash() uint32
}

// Allocate runs Phase A: opens every I/O resource in dependency
// order, populates *deps.AppDeps. On any error walks UnwindReverse
// before returning. The caller (main) holds the returned pointer and
// hands it to wire.Wire.
//
// The fatal channel is for async failures from background goroutines
// the constructors spawn (the advisory-lock heartbeat is the only
// current sender). Allocate itself never sends.
func Allocate(ctx context.Context, cfg Config, signers SignerLoader, fatal chan error, logger *slog.Logger) (*deps.AppDeps, error) {
	d := &deps.AppDeps{
		Logger:    logger,
		Fatal:     fatal,
		NetworkID: cfg.NetworkID,
	}

	type step struct {
		name string
		fn   func() error
	}
	steps := []step{
		{"telemetry", func() error { return allocateTelemetry(cfg, d) }},
		{"postgres", func() error { return allocatePostgres(ctx, cfg, fatal, d) }},
		{"wal", func() error { return allocateWAL(cfg, d) }},
		{"bytestore", func() error { return allocateBytestore(ctx, cfg, d) }},
		{"tessera", func() error { return allocateTessera(ctx, cfg, signers, d) }},
		{"signers", func() error { return allocateSigners(cfg, signers, d) }},
		{"antispam", func() error { return allocateAntispam(ctx, cfg, d) }},
		{"gossip-store", func() error { return allocateGossipStore(cfg, d) }},
	}

	for _, s := range steps {
		if err := s.fn(); err != nil {
			d.UnwindReverse(context.Background())
			return nil, fmt.Errorf("alloc: %s: %w", s.name, err)
		}
	}
	return d, nil
}

// allocateTelemetry sets the global TracerProvider (always) and the
// MeterProvider (when cfg.MetricsEnable). Histograms / counters are
// installed in wire.Wire — alloc only opens the providers.
func allocateTelemetry(cfg Config, d *deps.AppDeps) error {
	tp, traceShutdown, err := lifecycle.NewTracerProvider(lifecycle.TracerProviderConfig{
		ServiceName:    "ledger",
		ServiceVersion: cfg.ServiceVersion,
		Environment:    cfg.MetricsEnvironment,
		OTLPEndpoint:   cfg.OTLPTracesEndpoint,
	})
	if err != nil {
		return fmt.Errorf("tracer provider: %w", err)
	}
	otel.SetTracerProvider(tp)
	d.AppendCloser(deps.NamedCloser{
		Name:    "otel-tracer",
		Timeout: 10 * time.Second,
		Close:   traceShutdown,
	})
	if cfg.OTLPTracesEndpoint != "" {
		d.Logger.Info("tracing: enabled", "endpoint", cfg.OTLPTracesEndpoint)
	}

	if !cfg.MetricsEnable {
		d.Logger.Info("metrics: disabled (LEDGER_METRICS_ENABLE=false)")
		return nil
	}
	mp, err := sdklog.NewMeterProvider(sdklog.MeterProviderConfig{
		ServiceName:    "ledger",
		ServiceVersion: cfg.ServiceVersion,
		Environment:    cfg.MetricsEnvironment,
		Exporters:      []sdklog.ExporterKind{sdklog.PrometheusExporter},
	})
	if err != nil {
		return fmt.Errorf("meter provider: %w", err)
	}
	otel.SetMeterProvider(mp.Provider)
	d.MeterProvider = mp.Provider
	d.GossipMeter = mp.Provider.Meter("github.com/clearcompass-ai/ledger/gossip")
	d.MetricsHandler = mp.PrometheusHandler
	d.AppendCloser(deps.NamedCloser{
		Name:    "otel-meter",
		Timeout: 5 * time.Second,
		Close:   mp.Shutdown,
	})
	d.Logger.Info("metrics: enabled",
		"endpoint", "/metrics",
		"environment", cfg.MetricsEnvironment,
		"service_version", cfg.ServiceVersion,
	)
	return nil
}

// allocatePostgres opens the pool, applies migrations, acquires the
// builder advisory lock, and constructs the circuit breaker.
func allocatePostgres(ctx context.Context, cfg Config, fatal chan error, d *deps.AppDeps) error {
	pgPool, err := store.InitPool(ctx, store.PoolConfig{
		DSN:              cfg.DatabaseURL,
		MaxConns:         cfg.PgMaxConns,
		MinConns:         2,
		MaxConnLifetime:  30 * time.Minute,
		MaxConnIdleTime:  5 * time.Minute,
		StatementTimeout: cfg.PgStatementTimeout,
	})
	if err != nil {
		return fmt.Errorf("pgxpool: %w", err)
	}
	d.PgPool = pgPool
	d.AppendCloser(deps.NamedCloser{
		Name:    "postgres",
		Timeout: 10 * time.Second,
		Close: func(_ context.Context) error {
			pgPool.Close()
			return nil
		},
	})
	d.Logger.Info("postgres pool ready",
		"max_conns", cfg.PgMaxConns,
		"statement_timeout", cfg.PgStatementTimeout,
		"sequencer_max_inflight", cfg.SequencerMaxInFlight,
	)

	if mErr := store.RunMigrationsWithMode(ctx, pgPool.DB, cfg.DBMigrateMode); mErr != nil {
		return fmt.Errorf("migrations (mode=%v): %w", cfg.DBMigrateMode, mErr)
	}

	lock, err := store.AcquireBuilderLock(ctx, pgPool.DB, fatal, d.Logger)
	if err != nil {
		return fmt.Errorf("builder advisory lock: %w", err)
	}
	d.AppendCloser(deps.NamedCloser{
		Name:    "builder-advisory-lock",
		Timeout: 5 * time.Second,
		Close: func(_ context.Context) error {
			lock.Release()
			return nil
		},
	})
	d.Logger.Info("builder advisory lock acquired", "lock_id", store.BuilderLockID)

	d.DBBreaker = store.NewBreaker(pgPool.DB, store.DefaultBreakerFailureThreshold, store.DefaultBreakerCooldown, d.Logger)
	return nil
}

// allocateWAL opens the BadgerDB-backed WAL and constructs the
// committer that fronts it. Two closers (committer first, db last)
// because the committer flushes pending writes on close that the db
// must accept.
func allocateWAL(cfg Config, d *deps.AppDeps) error {
	walDB, err := wal.Open(cfg.WALPath, d.Logger)
	if err != nil {
		return fmt.Errorf("wal open path=%q: %w", cfg.WALPath, err)
	}
	d.WALDB = walDB
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{Logger: d.Logger})
	d.WALCommitter = walc

	// Order matters: register committer FIRST (closer ON TOP of the
	// stack), so reverse-unwind closes the committer BEFORE the db.
	// Committer.Close flushes via the db; db must still be open.
	d.AppendCloser(deps.NamedCloser{
		Name:    "wal-committer",
		Timeout: 5 * time.Second,
		Close: func(_ context.Context) error {
			return walc.Close()
		},
	})
	d.AppendCloser(deps.NamedCloser{
		Name:    "wal-db",
		Timeout: 10 * time.Second,
		Close: func(_ context.Context) error {
			return walDB.Close()
		},
	})
	d.Logger.Info("wal ready", "path", cfg.WALPath)
	return nil
}

// allocateBytestore opens the production bytestore via the hexagonal
// factory. Backend selection (gcs / s3 / seaweedfs-via-s3) lives in
// bytestore.NewFromConfig; loadConfig has already validated the
// per-backend required fields.
func allocateBytestore(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	bs, err := bytestore.NewFromConfig(ctx, cfg.BytestoreConfig)
	if err != nil {
		return fmt.Errorf("bytestore (backend=%q): %w", cfg.BytestoreConfig.Backend, err)
	}
	d.ByteStore = bs
	d.AppendCloser(deps.NamedCloser{
		Name:    "bytestore",
		Timeout: 30 * time.Second,
		Close: func(_ context.Context) error {
			if c, ok := bs.(interface{ Close() error }); ok {
				return c.Close()
			}
			return nil
		},
	})
	d.Logger.Info("byte store ready",
		"backend", cfg.BytestoreConfig.Backend,
		"prefix", cfg.BytestoreConfig.Prefix,
	)
	return nil
}

// allocateTessera opens the POSIX driver, the EmbeddedAppender, the
// tile-backend reader, and loads the checkpoint signer. The signer
// is loaded here (not in allocateSigners) because EmbeddedAppender
// requires it at construction.
func allocateTessera(ctx context.Context, cfg Config, signers SignerLoader, d *deps.AppDeps) error {
	if err := os.MkdirAll(cfg.TesseraStorageDir, 0o755); err != nil {
		return fmt.Errorf("tessera storage dir %q: %w", cfg.TesseraStorageDir, err)
	}
	// G3: refuse to boot on a half-initialized directory (tile
	// artifacts present but no checkpoint file). Re-initializing on
	// top of partial state would silently corrupt the log.
	if err := validateTesseraStorageDir(cfg.TesseraStorageDir); err != nil {
		return fmt.Errorf("tessera storage dir sanity check: %w", err)
	}
	driver, err := tposix.New(ctx, tposix.Config{Path: cfg.TesseraStorageDir})
	if err != nil {
		return fmt.Errorf("tessera posix driver: %w", err)
	}

	origin := cfg.TesseraOrigin
	if origin == "" {
		origin = cfg.LogDID
	}
	signer, _, err := signers.LoadTesseraSigner(cfg.TesseraSignerKeyFile, origin, cfg.LogDID, d.Logger)
	if err != nil {
		return fmt.Errorf("tessera signer: %w", err)
	}

	// tessera.NewEmbeddedAppender requires a note.Signer; the loader
	// returned a NoteSigner-shaped interface. They have the same
	// method set so the conversion is identity at the call boundary.
	//
	// PublicCheckpointPath: the builder publishes the K-of-N
	// CosignedTreeHead to <storage_dir>/cosigned-checkpoint after
	// every successful quorum collect. Sibling-file to upstream
	// Tessera's auto-published checkpoint; auditors fetch THIS file
	// for the network's Strict-STH-Finality attestation.
	embedded, err := tessera.NewEmbeddedAppender(ctx, driver, tessera.AppenderOptions{
		Origin:               origin,
		Signer:               signer,
		PublicCheckpointPath: filepath.Join(cfg.TesseraStorageDir, "cosigned-checkpoint"),
	}, d.Logger)
	if err != nil {
		return fmt.Errorf("embedded appender: %w", err)
	}
	d.TesseraEmbedded = embedded
	d.AppendCloser(deps.NamedCloser{
		Name:    "tessera-embedded",
		Timeout: 30 * time.Second,
		Close:   embedded.Close,
	})

	tileBackend, err := tessera.NewPOSIXTileBackend(cfg.TesseraStorageDir)
	if err != nil {
		return fmt.Errorf("tile backend: %w", err)
	}
	d.TileBackend = tileBackend

	cacheSize := cfg.TileCacheSize
	if cacheSize <= 0 {
		cacheSize = 4096
	}
	d.TileReader = tessera.NewTileReader(tileBackend, cacheSize)

	d.Logger.Info("tessera ready",
		"storage_dir", cfg.TesseraStorageDir,
		"origin", origin,
	)
	return nil
}

// allocateSigners loads the ledger entry signer and (when configured)
// the witness signer.
func allocateSigners(cfg Config, signers SignerLoader, d *deps.AppDeps) error {
	priv, did, err := signers.LoadLedgerSigner(cfg.LedgerSignerKeyFile, d.Logger)
	if err != nil {
		return fmt.Errorf("ledger signer: %w", err)
	}
	d.LedgerSignerPriv = priv
	d.LedgerDID = did

	if cfg.WitnessKeyFile != "" {
		wp, werr := signers.LoadWitnessSigner(cfg.WitnessKeyFile, d.Logger)
		if werr != nil {
			return fmt.Errorf("witness signer: %w", werr)
		}
		d.WitnessSignerPriv = wp
	}
	return nil
}

// allocateAntispam opens the BadgerDB-backed Tessera antispam store.
func allocateAntispam(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	if err := os.MkdirAll(filepath.Dir(cfg.TesseraAntispamPath), 0o755); err != nil {
		return fmt.Errorf("antispam parent dir: %w", err)
	}
	as, err := tposixantispam.NewAntispam(ctx, cfg.TesseraAntispamPath, tposixantispam.AntispamOpts{})
	if err != nil {
		return fmt.Errorf("antispam open path=%q: %w", cfg.TesseraAntispamPath, err)
	}
	d.Antispam = as
	// AntispamStorage's API has no Close (the underlying Badger DB
	// is owned by the parent — antispam shares the WAL Badger handle
	// in some deployment shapes; in others it's its own dir but the
	// upstream type still exposes no Close). We register a no-op
	// closer so the spec-order chain has a step at this position
	// even if it does nothing.
	d.AppendCloser(deps.NamedCloser{
		Name:    "tessera-antispam",
		Timeout: 1 * time.Second,
		Close:   func(_ context.Context) error { return nil },
	})
	d.Logger.Info("tessera antispam ready", "path", cfg.TesseraAntispamPath)
	return nil
}

// validateTesseraStorageDir confirms the Tessera POSIX directory is
// in a consistent state: either empty (fresh init) OR contains a
// `checkpoint` file (resuming an existing log). A dir with tile
// artifacts but no checkpoint indicates a half-initialized volume —
// partial restore, aborted migration, manual file shuffling — and
// re-initializing on top of it would corrupt the log silently. Boot
// fails fast instead.
func validateTesseraStorageDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	checkpoint := dir + string(os.PathSeparator) + "checkpoint"
	if _, err := os.Stat(checkpoint); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat checkpoint: %w", err)
	}
	names := make([]string, 0, len(entries))
	for i, e := range entries {
		if i >= 5 {
			names = append(names, "...")
			break
		}
		names = append(names, e.Name())
	}
	return fmt.Errorf("dir non-empty (%v) but no checkpoint file — "+
		"refusing to re-initialize on top of partial state. "+
		"To start fresh, empty the directory; to resume an existing log, "+
		"restore the checkpoint file alongside the tile artifacts",
		names)
}

// allocateGossipStore co-tenants the WAL's Badger handle under the
// gossipstore keyspace prefix. Only allocates when gossip is enabled
// and a non-zero NetworkID is configured.
func allocateGossipStore(cfg Config, d *deps.AppDeps) error {
	var zero cosign.NetworkID
	if cfg.GossipDisable || cfg.NetworkID == zero {
		d.Logger.Info("gossip store: not allocated (disabled or NetworkID unset)")
		return nil
	}
	gs, err := gossipstore.New(gossipstore.Config{DB: d.WALDB})
	if err != nil {
		return fmt.Errorf("gossipstore open: %w", err)
	}
	d.GossipStore = gs
	d.AppendCloser(deps.NamedCloser{
		Name:    "gossip-store",
		Timeout: 5 * time.Second,
		Close: func(ctx context.Context) error {
			return gs.Close(ctx)
		},
	})
	d.Logger.Info("gossip store ready", "co_tenant_with", "wal-db")
	return nil
}
