// Package wire implements Phase B of the ledger binary's lifecycle:
// compose the in-memory graph from the resources allocated in Phase A
// (deps.AppDeps), install OTel instruments on the existing
// MeterProvider, and start every long-running goroutine.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/wire.go
//
// DESCRIPTION:
//
//	Wire is the single entry point. It does NOT open new I/O
//	resources — those are alloc.Allocate's job. Wire reads handles
//	from *deps.AppDeps, constructs in-memory components (stores,
//	fetchers, sequencer, shipper, builder loop, gossip bundle, HTTP
//	server), and launches goroutines via lifecycle.SafeRunInWG that
//	join on AppDeps.WG.
//
//	When Wire returns successfully every goroutine is running and
//	the HTTP server is listening; the supervisor can immediately
//	enter its select on ctx.Done() / fatal.
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - Wire is split across several files inside this package so each
//     file is small and cohesive (stores.go, instruments.go,
//     gossip.go, handlers.go, runtime.go). The package boundary is
//     wire/; the file boundaries are organizational.
//
//   - WireConfig is the alloc-relevant + wire-relevant projection of
//     cmd/ledger.Config — passed by value so the boot package never
//     imports the binary's full config struct.
//
//   - Every goroutine joins AppDeps.WG so teardown's
//     "background-goroutines" step can wait once and have all
//     workers drain before the I/O closers fire.
//
//   - Errors during wire abort cleanly: wire returns; main calls
//     deps.UnwindReverse to release the resources alloc opened.
package wire

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"time"

	"golang.org/x/net/netutil"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkdid "github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/exchange/policy"

	"go.opentelemetry.io/otel"

	"github.com/clearcompass-ai/ledger/admission"
	"github.com/clearcompass-ai/ledger/anchor"
	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/builder"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/deps"
	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/schemareg"
	"github.com/clearcompass-ai/ledger/gossipnet"
	"github.com/clearcompass-ai/ledger/gossipstore"
	"github.com/clearcompass-ai/ledger/integrity"
	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/sequencer"
	"github.com/clearcompass-ai/ledger/shipper"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	"github.com/clearcompass-ai/ledger/tessera"
)

// Config is the projection of cmd/ledger.Config relevant to Phase B
// wiring. main.go converts its full Config to this struct before
// calling Wire.
type Config struct {
	// Identities
	LogDID    string
	LedgerDID string
	NetworkID cosign.NetworkID

	// Builder + sequencer + shipper
	BatchSize            int
	PollInterval         time.Duration
	DeltaWindow          int
	MMD                  time.Duration
	SequencerInterval    time.Duration
	SequencerMaxInFlight int
	ShipperPollInterval  time.Duration
	ShipperMaxInFlight   int
	SMTNodeCacheSize     int

	// Anchor + commitment
	AnchorInterval time.Duration
	AnchorSources  []anchor.AnchorSource

	// Admission
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	MaxEntrySize          int64

	// Gossip + witness
	GossipPeerEndpoints []string
	GossipPeerDIDs      []string
	WitnessEndpoints    []string
	WitnessQuorumK      int
	GenesisWitnessSet   []string

	// HTTP
	ServerAddr         string
	TLSCertFile        string
	TLSKeyFile         string
	MaxConcurrentConns int
	PprofAddr          string

	// Tile serving
	TileServeDisable bool
	TileBackend      string
	TileBucketPrefix string
	TileCacheSize    int

	// Bytestore (for routing diagnostic + tile fallback)
	ByteStoreBackend       string
	ByteStorePublicBaseURL string

	// Metrics + version banner (for /version + late-bound gauges)
	MetricsEnable bool
	Version       string
	Commit        string
	BuildTime     string
	SDKVersion    string

	// LogInfo is the api.LogInfo map main wants returned from
	// /v1/log-info — already constructed by main.buildLogInfo.
	LogInfo api.LogInfo
}

// Wire is the Phase B orchestrator. Reads handles from d, composes the
// component graph, installs instruments, and starts every goroutine.
// Returns nil on success; on error the caller (main) is responsible
// for invoking d.UnwindReverse to release alloc resources.
//
// On success, d is fully populated:
//   - all wired-component fields set (stores, builder loop, sequencer,
//     shipper, anchor publisher, HTTP server)
//   - d.WG holds every started goroutine
//   - d.HTTPServer is listening on cfg.ServerAddr
func Wire(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	// 1. In-memory stores + composite reader + builder pipeline.
	tesseraAdapter := composeStores(ctx, cfg, d)

	// 2. Difficulty controller.
	d.DiffController = middleware.NewDifficultyController(
		store.NewSequenceCursor(d.PgPool.DB),
		middleware.DefaultDifficultyConfig(),
		d.Logger,
	)

	// 3. OTel instruments. All install* helpers are no-ops when the
	// MeterProvider is nil (metrics disabled).
	installPrebuilderInstruments(d)

	// 4. Gossip wiring (+ async goroutines: anti-entropy,
	// equivocation monitor, equivocation scanner). nil gossip
	// store ⇒ early-return without setting Bundle / Publisher.
	if err := wireGossip(ctx, cfg, d); err != nil {
		return fmt.Errorf("wire: gossip: %w", err)
	}

	// 5. Witness cosigner (HeadSync) — optional.
	cosigner, err := wireWitnessCosigner(cfg, d)
	if err != nil {
		return fmt.Errorf("wire: witness cosigner: %w", err)
	}

	// 6. Escrow override service — optional.
	escrowOverrideHandler := wireEscrowOverride(cfg, cosigner, d)

	// 7. Builder loop + commitment publisher + anchor publisher.
	bl, anchorPub := composeBuilderLoop(ctx, cfg, d, tesseraAdapter, cosigner)
	d.BuilderLoop = bl
	d.AnchorPublisher = anchorPub

	// 7b. v0.4.0 DI schema admission registry — single source of
	// truth shared by the api submission handler (front-door gate)
	// and the sequencer (post-AppendLeaf SplitID dispatch).
	// schemareg.BuildLedgerSchemaRegistry binds the SDK-shipped
	// commitment validators and returns a frozen *schema.Registry.
	// A bind error here is a programming error in boot/schemareg
	// (e.g., duplicate SchemaID), not a runtime condition — fail
	// fast at boot so the operator notices immediately.
	reg, err := schemareg.BuildLedgerSchemaRegistry()
	if err != nil {
		return fmt.Errorf("wire: schemareg.BuildLedgerSchemaRegistry: %w", err)
	}
	d.SchemaRegistry = reg

	// 8. HTTP handlers (submission, query, tree, smt, entries,
	// commitments, witness, tiles).
	handlers, err := composeHandlers(ctx, cfg, d, tesseraAdapter, escrowOverrideHandler)
	if err != nil {
		return fmt.Errorf("wire: handlers: %w", err)
	}

	// 9. Sequencer + shipper + integrity detector.
	seq := composeSequencer(cfg, d)
	d.Sequencer = seq
	ship := composeShipper(cfg, d)
	d.Shipper = ship
	detector := composeIntegrityDetector(d)

	// 10. Late-bound observable gauges (sequencer + shipper).
	installLateBoundGauges(cfg, d, seq, ship)

	// 11. HTTP + pprof servers.
	if err := composeServers(cfg, d, handlers); err != nil {
		return fmt.Errorf("wire: servers: %w", err)
	}

	// 12. Start every long-running goroutine. WG joins.
	startGoroutines(ctx, d, bl, seq, ship, detector)

	return nil
}

// composeStores builds the in-memory store graph and returns the
// shared Tessera adapter (used by builder loop + tree handlers).
func composeStores(ctx context.Context, cfg Config, d *deps.AppDeps) *tessera.TesseraAdapter {
	pool := d.PgPool.DB
	d.EntryStore = store.NewEntryStore(pool)
	d.CreditStore = store.NewCreditStore(pool)
	d.CommitStore = store.NewCommitmentStore(pool)
	d.LeafStore = store.NewPostgresLeafStore(pool)
	cacheSize := cfg.SMTNodeCacheSize
	if cacheSize <= 0 {
		cacheSize = 4096
	}
	d.NodeStore = store.NewPostgresNodeStore(ctx, pool, cacheSize)
	d.TreeHeadStore = store.NewTreeHeadStore(pool)

	return tessera.NewTesseraAdapter(ctx, d.TesseraEmbedded, d.TileReader, d.Logger)
}

// composeBuilderLoop builds the BuilderLoop + commitment publisher +
// anchor publisher. The self-submit pipeline (sign+submit-via-HTTP) is
// shared between the commitment publisher and the anchor publisher.
func composeBuilderLoop(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	tesseraAdapter *tessera.TesseraAdapter,
	cosigner builder.WitnessCosigner,
) (*builder.BuilderLoop, *anchor.Publisher) {
	pool := d.PgPool.DB

	// Composite byte reader: WAL fast-path → bytestore fallback.
	compositeReader := store.NewCompositeByteReader(d.WALCommitter, d.ByteStore, d.Logger)

	fetcher := store.NewPostgresEntryFetcher(pool, compositeReader, cfg.LogDID)
	bufferStore := builder.NewDeltaBufferStore(pool, cfg.DeltaWindow, d.Logger)
	sequenceCursor := store.NewSequenceCursor(pool)
	reader := builder.NewCursorReader(sequenceCursor)
	tree := smt.NewTree(d.LeafStore, d.NodeStore)

	buffer, loadErr := bufferStore.Load(ctx)
	if loadErr != nil {
		d.Logger.Warn("delta buffer load — starting cold", "error", loadErr)
		buffer = sdkbuilder.NewDeltaWindowBuffer(cfg.DeltaWindow)
	}

	selfSubmitURL := fmt.Sprintf("http://localhost%s", cfg.ServerAddr)
	signedSelfSubmit := anchor.SignAndSubmit(
		d.LedgerSignerPriv,
		d.LedgerDID,
		anchor.SubmitViaHTTP(selfSubmitURL),
	)

	commitPub := builder.NewCommitmentPublisher(
		cfg.LedgerDID,
		cfg.LogDID,
		builder.CommitmentPublisherConfig{
			IntervalEntries: 1000,
			IntervalTime:    1 * time.Hour,
		},
		signedSelfSubmit,
		d.Logger,
	).WithCommitmentStore(d.CommitStore)

	loopCfg := builder.DefaultLoopConfig(cfg.LogDID)
	loopCfg.BatchSize = cfg.BatchSize
	loopCfg.PollInterval = cfg.PollInterval
	loopCfg.DeltaWindow = cfg.DeltaWindow

	bl := builder.NewBuilderLoop(
		loopCfg, pool, tree, d.LeafStore, d.NodeStore,
		reader, fetcher,
		nil, // schema resolver — nil tolerated by SDK builder.
		buffer, bufferStore,
		commitPub,
		tesseraAdapter,
		cosigner,
		d.Logger,
	).WithRootStore(store.NewSMTRootStateStore(pool))

	anchorPub := anchor.NewPublisher(
		anchor.PublisherConfig{
			LedgerDID:     cfg.LedgerDID,
			LogDID:        cfg.LogDID,
			Interval:      cfg.AnchorInterval,
			AnchorSources: cfg.AnchorSources,
		},
		tesseraAdapter,
		signedSelfSubmit,
		d.Logger,
	)

	return bl, anchorPub
}

// composeHandlers builds the api.Handlers struct passed to api.NewServer.
func composeHandlers(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	tesseraAdapter *tessera.TesseraAdapter,
	escrowOverrideHandler http.HandlerFunc,
) (api.Handlers, error) {
	pool := d.PgPool.DB
	compositeReader := store.NewCompositeByteReader(d.WALCommitter, d.ByteStore, d.Logger)
	fetcher := store.NewPostgresEntryFetcher(pool, compositeReader, cfg.LogDID)
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, compositeReader, cfg.LogDID)

	// BLS quorum verifier — embedded-tree-head check; no-op until
	// schemas embed tree heads. Wired iff genesis set + NetworkID.
	var blsQuorumVerifier *admission.BLSQuorumVerifier
	var zeroNetID cosign.NetworkID
	if len(cfg.GenesisWitnessSet) > 0 && cfg.NetworkID != zeroNetID {
		witKeys, wkErr := gossipnet.WitnessKeysFromDIDs(cfg.GenesisWitnessSet)
		if wkErr != nil {
			return api.Handlers{}, fmt.Errorf("admission BLS verifier witness keys: %w", wkErr)
		}
		admSet, ksErr := cosign.NewWitnessKeySet(
			witKeys,
			cfg.NetworkID,
			cfg.WitnessQuorumK,
			cosign.NewProductionBLSVerifier(),
		)
		if ksErr != nil {
			return api.Handlers{}, fmt.Errorf("admission BLS verifier keyset: %w", ksErr)
		}
		blsQuorumVerifier = admission.NewBLSQuorumVerifier(admSet)
		d.Logger.Info("admission: embedded-tree-head BLS verifier enabled",
			"witness_set_size", admSet.Size(),
			"quorum_k", admSet.Quorum(),
		)
	}

	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: d.EntryStore,
			WAL:        d.WALCommitter,
			Tessera:    d.TesseraEmbedded,
		},
		Admission: api.AdmissionConfig{
			DiffController:        d.DiffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			Credits:     d.CreditStore,
			DIDResolver: sdkdid.NewECDSAKeyResolver(),
		},
		LedgerDID:          cfg.LedgerDID,
		LogDID:             cfg.LogDID,
		LedgerSignerPriv:   d.LedgerSignerPriv,
		MaxEntrySize:       cfg.MaxEntrySize,
		Logger:             d.Logger,
		FreshnessTolerance: policy.FreshnessInteractive,
		BLSQuorumVerifier:  blsQuorumVerifier,
		SchemaRegistry:     d.SchemaRegistry,
	}

	tree := smt.NewTree(d.LeafStore, d.NodeStore)
	queryDeps := &api.QueryDeps{
		EntryStore:     d.EntryStore,
		QueryAPI:       queryAPI,
		DiffController: d.DiffController,
		Logger:         d.Logger,
		WAL:            d.WALCommitter,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: d.TreeHeadStore,
		Inclusion:     tesseraAdapter,
		Consistency:   tesseraAdapter,
		Logger:        d.Logger,
	}
	smtDeps := &api.SMTDeps{
		Tree:      tree,
		LeafStore: d.LeafStore,
		RootState: store.NewSMTRootStateStore(pool),
		Logger:    d.Logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher:     fetcher,
		QueryAPI:    queryAPI,
		EntryStore:  d.EntryStore,
		WAL:         d.WALCommitter,
		PublicURLer: d.ByteStore.(api.PublicURLer),
		LogDID:      cfg.LogDID,
		Logger:      d.Logger,
	}
	commitDeps := &api.DerivationCommitmentDeps{CommitmentStore: d.CommitStore, Logger: d.Logger}

	d.Logger.Info("bytestore: routing configured",
		"backend", cfg.ByteStoreBackend,
		"public_base_url", cfg.ByteStorePublicBaseURL,
	)

	// Cryptographic commitment lookup (only when gossip store is wired).
	var commitmentLookupHandler http.HandlerFunc
	if d.GossipStore != nil {
		commitmentLookupHandler = api.NewCommitmentLookupHandler(
			&api.CryptographicCommitmentDeps{
				Fetcher: gossipstore.NewBadgerCommitmentFetcher(d.GossipStore),
				Logger:  d.Logger,
			})
	}

	// Static-CT tile serving.
	checkpointHandler, tileHandler, err := composeTileHandlers(cfg, d)
	if err != nil {
		return api.Handlers{}, err
	}

	mmdHandler := api.NewMMDHandler(cfg.MMD)
	submitHandler := api.NewSubmissionHandler(submissionDeps)
	batchSubmitHandler := api.NewBatchSubmissionHandler(submissionDeps)

	gossipPostH, gossipFeedH := http.Handler(nil), http.Handler(nil)
	if d.GossipBundle != nil {
		gossipPostH = d.GossipBundle.PostHandler
		gossipFeedH = d.GossipBundle.FeedHandler
	}

	return api.Handlers{
		Submission:       submitHandler,
		BatchSubmission:  batchSubmitHandler,
		TreeHead:         api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:    api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency:  api.NewTreeConsistencyHandler(treeDeps),
		SMTProof:         api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:    api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:          api.NewSMTRootHandler(smtDeps),
		CosignatureOf:    api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:       api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:        api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:        api.NewQuerySchemaRefHandler(queryDeps),
		Scan:             api.NewQueryScanHandler(queryDeps),
		Difficulty:       api.NewDifficultyHandler(queryDeps),
		MMD:              mmdHandler,
		EntryByHash:      api.NewHashLookupHandler(queryDeps),
		GossipPost:       gossipPostH,
		GossipFeed:       gossipFeedH,
		EscrowOverride:   escrowOverrideHandler,
		Metrics:          d.MetricsHandler,
		EntryBySequence:  api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:       api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:         api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:          api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:     api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery:  api.NewDerivationCommitmentQueryHandler(commitDeps),
		CommitmentLookup: commitmentLookupHandler,
		Checkpoint:       checkpointHandler,
		Tile:             tileHandler,
		LogInfo:          api.NewLogInfoHandler(cfg.LogInfo),
		Version: api.NewVersionHandler(api.VersionInfo{
			Version:    cfg.Version,
			Commit:     cfg.Commit,
			BuildTime:  cfg.BuildTime,
			SDKVersion: cfg.SDKVersion,
		}),
	}, nil
}

// composeTileHandlers wires /checkpoint + /tile/{level}/{rest...} unless
// LEDGER_TILE_SERVE_DISABLE=true. POSIX backend is the default; "gcs"
// requires LEDGER_BYTE_STORE_BACKEND=gcs (a *bytestore.GCS).
func composeTileHandlers(cfg Config, d *deps.AppDeps) (http.HandlerFunc, http.HandlerFunc, error) {
	if cfg.TileServeDisable {
		d.Logger.Info("static-ct tile serving disabled (LEDGER_TILE_SERVE_DISABLE=true)")
		return nil, nil, nil
	}
	var serving bytestore.TileBackend
	switch cfg.TileBackend {
	case "", "posix":
		serving = d.TileBackend
	case "gcs":
		gcsBackend, ok := d.ByteStore.(*bytestore.GCS)
		if !ok {
			return nil, nil, fmt.Errorf(
				"LEDGER_TILE_BACKEND=gcs requires LEDGER_BYTE_STORE_BACKEND=gcs (have %q)",
				cfg.ByteStoreBackend)
		}
		serving = bytestore.NewGCSTiles(gcsBackend, cfg.TileBucketPrefix, 30*time.Second)
	default:
		return nil, nil, fmt.Errorf("LEDGER_TILE_BACKEND must be one of posix|gcs (got %q)", cfg.TileBackend)
	}
	d.Logger.Info("static-ct tile serving enabled",
		"backend", cfg.TileBackend,
		"prefix", cfg.TileBucketPrefix,
	)
	return api.NewCheckpointHandler(serving, d.Logger), api.NewTileHandler(serving, d.Logger), nil
}

// composeSequencer builds the Sequencer with optional gossip-store
// adapters (split-id index, entry-lookup projection, boot replayer)
// when gossip is enabled.
//
// Backpressure Stall: the sequencer is wired with a LagReader
// (store.SequenceCursor) so its drainOnce gates on builder lag.
// When the builder stalls (e.g., witness quorum failure), the
// sequencer stops draining the WAL and 503s flow to the public
// API — Principle 5 (Melt-Proof) is mathematically secured by
// the WAL's bounded queue.
func composeSequencer(cfg Config, d *deps.AppDeps) *sequencer.Sequencer {
	pool := d.PgPool.DB
	seq := sequencer.NewSequencer(d.WALCommitter, d.TesseraEmbedded, pool, d.EntryStore, sequencer.Config{
		PollInterval: cfg.SequencerInterval,
		MaxInFlight:  cfg.SequencerMaxInFlight,
		Logger:       d.Logger,
	})
	seq = seq.WithLagReader(store.NewSequenceCursor(pool))

	// Wire the supervisor fatal channel so the identical-batch
	// circuit breaker can escalate to process-level termination.
	// Without this the breaker would log ERROR but the broken
	// committer would keep looping (logging + no forward progress)
	// until the operator manually intervenes.
	if d.Fatal != nil {
		seq = seq.WithFatalChannel(d.Fatal)
	}

	// v0.4.0 DI schema registry — built once at Wire (step 7b) and
	// shared with the api submission handler. The sequencer's
	// dispatchCommitmentSchema reads the same frozen instance.
	if d.SchemaRegistry != nil {
		seq = seq.WithSchemaRegistry(d.SchemaRegistry)
	}
	if d.GossipStore != nil {
		seq = seq.WithSplitIDIndex(
			gossipnet.NewSequencerSplitIDAdapter(d.GossipStore))
		seq = seq.WithEntryLookup(
			gossipnet.NewSequencerEntryLookupAdapter(d.GossipStore),
			cfg.LogDID)
		replayer, rerr := sequencer.NewReplayer(sequencer.ReplayConfig{
			DB:           pool,
			Reader:       d.ByteStore,
			SplitIDIndex: gossipnet.NewSequencerSplitIDAdapter(d.GossipStore),
			EntryLookup:  gossipnet.NewSequencerEntryLookupAdapter(d.GossipStore),
			Cursor:       gossipnet.NewSequencerReplayCursorAdapter(d.GossipStore),
			LogDID:       cfg.LogDID,
			Logger:       d.Logger,
		})
		if rerr == nil {
			seq = seq.WithReplayer(replayer)
		} else {
			d.Logger.Warn("sequencer replayer construct failed; continuing without", "error", rerr)
		}
	}
	d.Logger.Info("sequencer ready",
		"poll_interval", cfg.SequencerInterval,
		"max_in_flight", cfg.SequencerMaxInFlight,
		"mmd", cfg.MMD,
		"splitid_index", d.GossipStore != nil,
		"entry_lookup_projection", d.GossipStore != nil,
		"boot_replayer", d.GossipStore != nil,
	)
	return seq
}

// composeShipper builds the Shipper.
func composeShipper(cfg Config, d *deps.AppDeps) *shipper.Shipper {
	ship := shipper.NewShipper(d.WALCommitter, d.ByteStore, shipper.Config{
		PollInterval: cfg.ShipperPollInterval,
		MaxInFlight:  cfg.ShipperMaxInFlight,
		Logger:       d.Logger,
	})
	d.Logger.Info("shipper: configured",
		"max_in_flight", cfg.ShipperMaxInFlight,
		"poll_interval", cfg.ShipperPollInterval)
	return ship
}

// composeIntegrityDetector builds the periodic sample-verify detector.
func composeIntegrityDetector(d *deps.AppDeps) *integrity.Detector {
	return integrity.NewDetector(
		d.WALCommitter,
		integrity.NewTesseraAdapter(d.TileReader),
		integrity.DetectorConfig{Logger: d.Logger},
	)
}

// composeServers wires the public HTTP server (TLS-aware,
// LimitListener-capped) and the optional pprof server. Sets
// d.HTTPServer, d.HTTPListener, d.PprofServer.
func composeServers(cfg Config, d *deps.AppDeps, handlers api.Handlers) error {
	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	serverCfg.MaxEntrySize = cfg.MaxEntrySize
	serverCfg.TLSCertFile = cfg.TLSCertFile
	serverCfg.TLSKeyFile = cfg.TLSKeyFile
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(d.PgPool.DB), handlers, d.Logger)

	server.SetReadinessProbe(func() error {
		probeCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		conn, err := d.DBBreaker.Acquire(probeCtx)
		if err != nil {
			return fmt.Errorf("database unavailable: %w", err)
		}
		conn.Release()
		return nil
	})

	connCap := cfg.MaxConcurrentConns
	if connCap <= 0 {
		connCap = 8 * runtime.NumCPU()
	}
	rawListener, err := net.Listen("tcp", serverCfg.Addr)
	if err != nil {
		return fmt.Errorf("http listen %q: %w", serverCfg.Addr, err)
	}
	d.HTTPListener = netutil.LimitListener(rawListener, connCap)
	d.HTTPServer = server
	d.HTTPTLSEnabled = serverCfg.TLSCertFile != "" && serverCfg.TLSKeyFile != ""
	d.Logger.Info("http listener ready",
		"addr", serverCfg.Addr,
		"max_concurrent_conns", connCap,
		"tls", serverCfg.TLSCertFile != "" && serverCfg.TLSKeyFile != "",
	)

	if cfg.PprofAddr != "" {
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		d.PprofServer = &http.Server{
			Addr:              cfg.PprofAddr,
			Handler:           pprofMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		d.Logger.Info("pprof listener ready", "addr", cfg.PprofAddr)
	}
	return nil
}

// startGoroutines launches every long-running goroutine. All join
// d.WG so the teardown "background-goroutines" step waits once.
func startGoroutines(
	ctx context.Context,
	d *deps.AppDeps,
	bl *builder.BuilderLoop,
	seq *sequencer.Sequencer,
	ship *shipper.Shipper,
	detector *integrity.Detector,
) {
	// HTTP server (TLS-aware).
	lifecycle.SafeRunInWG(ctx, &d.WG, "http-server", d.Logger, d.Fatal, func() error {
		if d.HTTPServer == nil || d.HTTPListener == nil {
			return nil
		}
		// Detect TLS from the server config — api.Server holds it
		// internally; we use its ServeTLSWithListener if a cert is
		// available, else plain Serve.
		if d.HTTPTLSEnabled {
			if err := d.HTTPServer.ServeTLSWithListener(d.HTTPListener); err != nil && err != http.ErrServerClosed {
				d.Logger.Error("http server (tls)", "error", err)
			}
			return nil
		}
		if err := d.HTTPServer.Serve(d.HTTPListener); err != nil && err != http.ErrServerClosed {
			d.Logger.Error("http server", "error", err)
		}
		return nil
	})

	if d.PprofServer != nil {
		lifecycle.SafeRunInWG(ctx, &d.WG, "pprof-server", d.Logger, nil, func() error {
			if err := d.PprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				d.Logger.Warn("pprof server", "error", err)
			}
			return nil
		})
	}

	lifecycle.SafeRunInWG(ctx, &d.WG, "builder-loop", d.Logger, d.Fatal, func() error {
		if err := bl.Run(ctx); err != nil {
			d.Logger.Error("builder loop exited with error", "error", err)
			return err
		}
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "difficulty-controller", d.Logger, d.Fatal, func() error {
		d.DiffController.Run(ctx, 30*time.Second)
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "anchor-publisher", d.Logger, d.Fatal, func() error {
		d.AnchorPublisher.Run(ctx)
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "shipper", d.Logger, d.Fatal, func() error {
		if err := ship.Run(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("shipper: %w", err)
			return err
		}
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "sequencer", d.Logger, d.Fatal, func() error {
		if err := seq.Run(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("sequencer: %w", err)
			return err
		}
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "integrity-detector", d.Logger, d.Fatal, func() error {
		if err := detector.Loop(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("integrity detector: %w", err)
			return err
		}
		return nil
	})

	startAuditTelemetry(ctx, d, detector)
}

// startAuditTelemetry runs a 5-minute heartbeat: integrity counters,
// cosign freshness, gossip-store growth.
func startAuditTelemetry(ctx context.Context, d *deps.AppDeps, detector *integrity.Detector) {
	lifecycle.SafeRunInWG(ctx, &d.WG, "audit-telemetry", d.Logger, nil, func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				d.Logger.Info("integrity audit",
					"invariant_failures_total", detector.InvariantFailures(),
					"samples_verified_total", detector.SamplesVerified(),
				)
				if d.GossipPublisher != nil {
					age := d.GossipPublisher.CosignAgeSeconds()
					if age >= 0 {
						d.Logger.Info("checkpoint cosig age", "age_seconds", age)
					}
				}
				if d.GossipStore != nil {
					statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					stats, err := d.GossipStore.Stats(statsCtx)
					cancel()
					if err == nil {
						d.Logger.Info("gossip store growth",
							"event_count", stats.EventCount,
							"originator_count", stats.OriginatorCount,
						)
					}
				}
			}
		}
	})
}

// installLateBoundGauges installs OTel gauges that depend on the
// sequencer + shipper instances (not available until composeSequencer
// / composeShipper return).
func installLateBoundGauges(
	cfg Config,
	d *deps.AppDeps,
	seq *sequencer.Sequencer,
	ship *shipper.Shipper,
) {
	if !cfg.MetricsEnable || d.MeterProvider == nil {
		return
	}
	mp := otel.GetMeterProvider()
	seqMeter := mp.Meter("github.com/clearcompass-ai/ledger/sequencer")
	if installed := sequencer.InstallDrainLagGauge(seqMeter, seq.CurrentLag); installed {
		d.Logger.Info("metrics: sequencer drain lag gauge installed",
			"metric", "attesta_sequencer_drain_lag_seconds")
	}
	shipMeter := mp.Meter("github.com/clearcompass-ai/ledger/shipper")
	if installed := shipper.InstallPendingGauge(shipMeter, ship.PendingCount); installed {
		d.Logger.Info("metrics: shipper pending gauge installed",
			"metric", "attesta_shipper_pending_total")
	}
	if installed := shipper.InstallCounters(shipMeter, ship); installed {
		d.Logger.Info("metrics: shipper counters installed")
	}
}

// ctxCanceledOrDeadline returns true for ctx.Canceled or
// ctx.DeadlineExceeded — the two errors that mean "graceful shutdown,
// not fatal."
func ctxCanceledOrDeadline(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
