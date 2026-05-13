/*
FILE PATH: cmd/ledger/main.go

DESCRIPTION:

	Ledger binary entry point. Three-phase boot under a single
	supervisor:

	  Phase A — alloc.Allocate: open every I/O resource (Postgres,
	            WAL Badger, bytestore, Tessera POSIX driver, Tessera
	            antispam, gossip Badger, signer keys, OTel tracer +
	            meter providers). On any open failure, walks the
	            close-stack in reverse so partial allocations leave
	            no leaked file descriptors.

	  Phase B — wire.Wire: compose the in-memory graph (stores,
	            fetcher, builder loop, sequencer, shipper, gossip
	            bundle, witness cosigner, HTTP handlers, HTTP server)
	            and start every long-running goroutine. Operates on
	            the resources from Phase A; opens nothing new.

	  Phase C — teardown.Register: transcribe the alloc closeStack +
	            wire's runtime steps into the lifecycle.ShutdownChain
	            in spec order, ready for chain.Run() at the end of
	            the supervisor select.

	The lifecycle split eliminates the sync.OnceFunc double-wrapping
	pattern this file used to need: the alloc-failure unwind path and
	the clean-shutdown path are isolated by phase, so no closer can
	be invoked from two places.

INVARIANTS:
  - cfg.LogDID MUST be non-empty: validated at boot via
    envelope.ValidateDestination.
  - cfg.LedgerDID is overridden after Phase A to match the loaded
    signer key's did:key. LEDGER_DID env is informational.
  - The fatal channel is closed only by the supervisor select; sends
    are non-blocking via lifecycle.SafeRun(InWG).
*/
package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/alloc"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/teardown"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/wire"
	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/store"
)

// ─────────────────────────────────────────────────────────────────────
// Build-time version variables (populated via -ldflags).
//
//	go build -ldflags="-X main.Version=$(git describe --tags --always) \
//	                   -X main.Commit=$(git rev-parse HEAD) \
//	                   -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
//	       ./cmd/ledger
//
// SDKVersion is hard-coded at the import-pin level (the SDK version is
// determined by go.mod, not by ldflags), so it is the single source of
// truth for what the binary was built against.
// ─────────────────────────────────────────────────────────────────────

var (
	Version    = "dev"
	Commit     = ""
	BuildTime  = ""
	SDKVersion = "v1.2.0"
)

// signerLoader adapts the package-private loadOrGenerate* helpers in
// signers.go to the alloc.SignerLoader interface. The alloc package
// doesn't import key-loading logic directly; main wires it in.
type signerLoader struct{}

func (signerLoader) LoadLedgerSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, string, error) {
	return loadOrGenerateLedgerSigner(keyFile, logger)
}

func (signerLoader) LoadTesseraSigner(keyFile, origin, logDID string, logger *slog.Logger) (alloc.NoteSigner, string, error) {
	signer, vkey, err := loadOrGenerateTesseraSigner(keyFile, origin, logDID, logger)
	if err != nil {
		return nil, "", err
	}
	// note.Signer's method set is a structural superset of
	// alloc.NoteSigner — interface-to-interface assignment is total.
	return signer, vkey, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// fatal is the supervisor's single-source-of-truth error channel.
	// Background goroutines started in Phase B surface unrecoverable
	// errors via this channel; the supervisor reads from it below.
	fatal := make(chan error, 8)

	// shutdownChain enforces the I1 strict shutdown order. Phase C
	// populates it in spec order; chain.Run executes after the
	// supervisor select fires.
	shutdownChain := lifecycle.NewShutdownChain(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "error", err)
		os.Exit(1)
	}

	if valErr := envelope.ValidateDestination(cfg.LogDID); valErr != nil {
		logger.Error("invalid LEDGER_LOG_DID", "error", valErr)
		os.Exit(1)
	}

	// G7 — Boot banner.
	logger.Info("ledger starting (boot banner)",
		"version", Version,
		"commit", Commit,
		"build_time", BuildTime,
		"sdk_version", SDKVersion,
		"log_did", cfg.LogDID,
		"ledger_did", cfg.LedgerDID,
		"network_id_hex", networkIDHex(cfg.NetworkID),
		"addr", cfg.ServerAddr,
		"tessera_storage_dir", cfg.TesseraStorageDir,
		"byte_store_backend", cfg.ByteStoreBackend,
		"tile_backend", cfg.TileBackend,
		"gossip_enabled", !cfg.GossipDisable,
		"gossip_peer_count", len(cfg.GossipPeerDIDs),
		"witness_endpoint_count", len(cfg.WitnessEndpoints),
		"witness_quorum_k", cfg.WitnessQuorumK,
		"tls_enabled", cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
		"metrics_enabled", cfg.MetricsEnable,
		"otlp_traces_endpoint", lifecycle.PresenceFlag(cfg.OTLPTracesEndpoint),
	)

	// Ethereum RPC for EIP-1271 (smart-contract-wallet sigs). Stays
	// in main: the verifier-registry seam is a future composition
	// point; alloc/wire don't need to know about it yet.
	ethRPCCfg, err := LoadEthereumRPCConfig()
	if err != nil {
		logger.Error("ethereum rpc config", "error", err)
		os.Exit(1)
	}
	ethRPC, err := BuildEthereumRPCClient(ethRPCCfg)
	if err != nil {
		logger.Error("ethereum rpc client", "error", err)
		os.Exit(1)
	}
	if ethRPC == nil {
		logger.Info("eip-1271 verification disabled (LEDGER_ETH_RPC_ENABLED unset)")
	} else {
		logger.Info("eip-1271 verification enabled",
			"timeout_ms", ethRPCCfg.Timeout.Milliseconds(),
			"insecure_http", ethRPCCfg.AllowInsecureHTTP,
		)
	}
	_ = ethRPC // wired into did.DefaultVerifierRegistryWithRPC when DID resolver is enabled.

	migrateMode, err := parseMigrateMode(os.Getenv("LEDGER_DB_MIGRATE_MODE"))
	if err != nil {
		logger.Error("migrate mode", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Phase A: allocate every I/O resource ────────────────────────
	d, err := alloc.Allocate(ctx, allocConfigFromCfg(cfg, migrateMode), signerLoader{}, fatal, logger)
	if err != nil {
		logger.Error("alloc failed", "error", err)
		os.Exit(1)
	}

	// loadOrGenerateLedgerSigner overrode cfg.LedgerDID inside alloc;
	// reflect that here so the wire phase sees the authoritative
	// signing DID.
	if envOpDID := os.Getenv("LEDGER_DID"); envOpDID != "" && envOpDID != d.LedgerDID {
		logger.Warn("LEDGER_DID env var ignored — overridden to match signer key",
			"env_value", envOpDID, "signer_did", d.LedgerDID)
	}
	cfg.LedgerDID = d.LedgerDID

	// ── Phase B: compose the graph + start goroutines ───────────────
	if err := wire.Wire(ctx, wireConfigFromCfg(cfg), d); err != nil {
		logger.Error("wire failed", "error", err)
		d.UnwindReverse(context.Background())
		os.Exit(1)
	}

	// ── Phase C: register the spec-order shutdown chain ─────────────
	teardown.Register(shutdownChain, d)

	// ── Supervisor: shutdown OR fatal ───────────────────────────────
	var fatalErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown initiated (graceful)")
	case fatalErr = <-fatal:
		logger.Error("FATAL: ledger must terminate", "error", fatalErr)
		cancel()
	}

	// ── Pre-drain handshake (B4) ────────────────────────────────────
	// Flip /readyz to 503 BEFORE chain.Run so the load balancer pulls
	// the pod from rotation before HTTP server.Shutdown drains
	// in-flight requests.
	d.HTTPServer.SetReady(false)
	preDrainGrace := envDurationOr("LEDGER_PREDRAIN_GRACE", 5*time.Second)
	if preDrainGrace > 0 {
		logger.Info("pre-drain grace started",
			"grace", preDrainGrace,
			"reason", "load-balancer-rotation-removal",
		)
		select {
		case <-time.After(preDrainGrace):
		case <-time.After(60 * time.Second):
		}
	}

	shutdownChain.Run()

	// I3 — Final shutdown summary log.
	for _, step := range shutdownChain.Summary() {
		status := "ran"
		if !step.Ran {
			status = "skipped"
		}
		logger.Info("shutdown step summary",
			"step", step.Name,
			"status", status,
			"duration", step.Duration,
			"err", errString(step.Err),
		)
	}

	if d.BuilderLoop != nil {
		b, e, errs := d.BuilderLoop.Stats()
		logger.Info("ledger stopped",
			"batches", b, "entries", e, "errors", errs,
		)
	}

	if fatalErr != nil {
		// The only deliberate panic in the binary — orchestrator
		// (k8s, systemd, bare-metal) sees a non-zero exit and
		// decides what's next.
		panic(fmt.Errorf("ledger FATAL: %w", fatalErr))
	}
}

// allocConfigFromCfg projects the binary's full Config onto the
// alloc-relevant subset (alloc.Config). Held by value; alloc never
// reaches back into cmd/ledger.Config.
func allocConfigFromCfg(cfg *Config, migrateMode store.MigrateMode) alloc.Config {
	return alloc.Config{
		DatabaseURL:          cfg.DatabaseURL,
		PgMaxConns:           cfg.PgMaxConns,
		PgStatementTimeout:   cfg.PgStatementTimeout,
		SequencerMaxInFlight: cfg.SequencerMaxInFlight,
		DBMigrateMode:        migrateMode,
		WALPath:              cfg.WALPath,
		BytestoreConfig:      cfg.toBytestoreConfig(),
		TesseraStorageDir:    cfg.TesseraStorageDir,
		TesseraSignerKeyFile: cfg.TesseraSignerKeyFile,
		TesseraOrigin:        cfg.TesseraOrigin,
		TesseraAntispamPath:  cfg.TesseraAntispamPath,
		LogDID:               cfg.LogDID,
		TileCacheSize:        cfg.TileCacheSize,
		LedgerSignerKeyFile:  cfg.LedgerSignerKeyFile,
		GossipDisable:        cfg.GossipDisable,
		NetworkID:            cfg.NetworkID,
		MetricsEnable:        cfg.MetricsEnable,
		MetricsEnvironment:   cfg.MetricsEnvironment,
		ServiceVersion:       cfg.ServiceVersion,
		OTLPTracesEndpoint:   cfg.OTLPTracesEndpoint,
	}
}

// wireConfigFromCfg projects the binary's full Config onto the
// wire-relevant subset.
func wireConfigFromCfg(cfg *Config) wire.Config {
	return wire.Config{
		LogDID:                 cfg.LogDID,
		LedgerDID:              cfg.LedgerDID,
		NetworkID:              cfg.NetworkID,
		BatchSize:              cfg.BatchSize,
		PollInterval:           cfg.PollInterval,
		DeltaWindow:            cfg.DeltaWindow,
		MMD:                    cfg.MMD,
		SequencerInterval:      cfg.SequencerInterval,
		SequencerMaxInFlight:   cfg.SequencerMaxInFlight,
		ShipperPollInterval:    cfg.ShipperPollInterval,
		ShipperMaxInFlight:     cfg.ShipperMaxInFlight,
		SMTNodeCacheSize:       cfg.SMTNodeCacheSize,
		AnchorInterval:         cfg.AnchorInterval,
		AnchorSources:          cfg.AnchorSources,
		EpochWindowSeconds:     cfg.EpochWindowSeconds,
		EpochAcceptanceWindow:  cfg.EpochAcceptanceWindow,
		MaxEntrySize:           cfg.MaxEntrySize,
		GossipPeerEndpoints:    cfg.GossipPeerEndpoints,
		GossipPeerDIDs:         cfg.GossipPeerDIDs,
		WitnessEndpoints:       cfg.WitnessEndpoints,
		WitnessQuorumK:         cfg.WitnessQuorumK,
		GenesisWitnessSet:      cfg.GenesisWitnessSet,
		ServerAddr:             cfg.ServerAddr,
		TLSCertFile:            cfg.TLSCertFile,
		TLSKeyFile:             cfg.TLSKeyFile,
		MaxConcurrentConns:     cfg.MaxConcurrentConns,
		PprofAddr:              cfg.PprofAddr,
		TileServeDisable:       cfg.TileServeDisable,
		TileBackend:            cfg.TileBackend,
		TileBucketPrefix:       cfg.TileBucketPrefix,
		TileCacheSize:          cfg.TileCacheSize,
		ByteStoreBackend:       cfg.ByteStoreBackend,
		ByteStorePublicBaseURL: cfg.ByteStorePublicBaseURL,
		MetricsEnable:          cfg.MetricsEnable,
		Version:                Version,
		Commit:                 Commit,
		BuildTime:              BuildTime,
		SDKVersion:             SDKVersion,
		LogInfo:                buildLogInfo(cfg),
	}
}

// errString returns "" for nil err, err.Error() otherwise. Used by
// the shutdown summary so the log field is empty rather than "<nil>"
// on success.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
