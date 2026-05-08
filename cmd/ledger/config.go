// Ledger binary configuration.
//
// FILE PATH:
//
//	cmd/ledger/config.go
//
// DESCRIPTION:
//
//	Config struct + loadConfig + Validate + the small helpers
//	(defaultPgMaxConns, buildLogInfo, networkIDHex,
//	validateTesseraStorageDir, validatePgPoolSizing,
//	toBytestoreConfig). Extracted from cmd/ledger/main.go as part of
//	the lifecycle-phase decomposition (P3): config loading + boot
//	allocation + topology wiring + teardown registration must each be
//	separable surfaces. This file owns the first.
//
//	Behaviour is unchanged from the inline version. No new fields,
//	no new validation. The split is purely organisational.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/network"

	"github.com/clearcompass-ai/ledger/anchor"
	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/sequencer"
)

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

type Config struct {
	ServerAddr  string
	DatabaseURL string
	PgMaxConns  int32 // LEDGER_PG_MAX_CONNS; defaults to defaultPgMaxConns(MaxInFlight).

	// PgStatementTimeout, when > 0, is applied via the AfterConnect
	// hook on every pool connection so EVERY query gets a DB-side
	// statement_timeout cap. Defense-in-depth on per-call-site
	// context.WithTimeout discipline. Default 5 s; 0 disables (the
	// application is then sole authority on per-query budgets).
	// Set via LEDGER_PG_STATEMENT_TIMEOUT (Go duration syntax).
	PgStatementTimeout time.Duration

	LogDID    string // Destination for self-published entries (anchors, commitments).
	LedgerDID string // Signer DID for ledger-authored commentary.

	// TLSCertFile / TLSKeyFile, when both non-empty, switch the
	// HTTP listener to ListenAndServeTLS. Administrator deployments
	// fronted by a TLS-terminating proxy leave both empty (plain
	// HTTP). Standalone (VM / bare-metal / sigsum-witness) administrators
	// populate both for in-binary TLS termination.
	TLSCertFile string // LEDGER_TLS_CERT_FILE
	TLSKeyFile  string // LEDGER_TLS_KEY_FILE

	// MaxConcurrentConns caps the total simultaneous TCP sockets
	// the public HTTP listener will accept. Defends host physics
	// (sockets, ephemeral ports, file descriptors) independent of
	// per-request body size. 0 disables the cap (NOT recommended
	// in production); the default is computed from runtime.NumCPU
	// at boot.
	MaxConcurrentConns int // LEDGER_MAX_CONCURRENT_CONNS

	// PprofAddr, when non-empty, mounts net/http/pprof on a
	// SEPARATE listener bound to the supplied address (typically
	// "127.0.0.1:6060"). pprof is NEVER mixed onto the public
	// listener — it's diagnostic surface, not user surface. Empty
	// disables pprof entirely.
	PprofAddr string // LEDGER_PPROF_ADDR

	// TileServeDisable, when true, suppresses the public Static-CT
	// tile-serving routes (GET /checkpoint, GET /tile/{level}/...).
	// Private deployments where auditors fetch via a designated
	// witness — not directly from the ledger — set this to true.
	// The default (false) serves tiles publicly so external
	// auditors can use the SDK's log/tessera_fetcher primitive
	// without bespoke ledger config.
	TileServeDisable bool // LEDGER_TILE_SERVE_DISABLE

	// TileBackend selects the tile-storage backend the /tile/ +
	// /checkpoint HTTP routes read from. One of:
	//
	//   "posix" (default) — reads from <LEDGER_TESSERA_STORAGE_DIR>.
	//                       Local POSIX I/O. Path Tessera writes
	//                       to today.
	//   "gcs"             — reads from gs://<LEDGER_BYTE_STORE_GCS_BUCKET>/
	//                       <LEDGER_TILE_BUCKET_PREFIX>/. Reuses
	//                       the entry-bytestore GCS client (one
	//                       auth surface). Suitable when Tessera
	//                       writes tiles directly to GCS or an
	//                       external sync mirrors POSIX → GCS.
	//
	// Both share the bytestore.TileBackend interface; switching
	// requires only this env var (no code change).
	TileBackend string // LEDGER_TILE_BACKEND

	// TileBucketPrefix scopes tile keys under the GCS bucket.
	// Defaults to "tessera/" so entries (under "entries/") and
	// tiles (under "tessera/") never collide in the same bucket.
	// Empty prefix means tiles at bucket root. Only consulted
	// when TileBackend=="gcs".
	TileBucketPrefix string // LEDGER_TILE_BUCKET_PREFIX

	MaxEntrySize          int64
	BatchSize             int
	PollInterval          time.Duration
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	AnchorInterval        time.Duration
	AnchorSources         []anchor.AnchorSource

	// Sequencer settings (SCT/MMD architecture). The Sequencer
	// drains StatePending entries asynchronously; v2 admission
	// returns an SCT immediately after WAL fsync and the
	// Sequencer redeems the promise within MMD.
	SequencerInterval    time.Duration // default 1s; LEDGER_SEQUENCER_INTERVAL
	SequencerMaxInFlight int           // default 4; LEDGER_SEQUENCER_MAX_INFLIGHT
	MMD                  time.Duration // default 24h; LEDGER_MMD

	// ShipperMaxInFlight is the worker-pool size for parallel
	// bytestore uploads. Drain rate ceiling ≈ MaxInFlight ÷
	// per-upload-latency. Default 64 (10M/day capacity with
	// ~100ms GCS latency).
	// Env: LEDGER_SHIPPER_MAX_IN_FLIGHT
	ShipperMaxInFlight int

	// ShipperPollInterval is how often the scanner re-iterates
	// StateSequenced WAL entries. Should track per-upload latency
	// so the in-flight dedupe guard works efficiently. Default
	// 100ms.
	// Env: LEDGER_SHIPPER_POLL_INTERVAL
	ShipperPollInterval time.Duration
	// Tessera embedding — in-process upstream Tessera.
	// TesseraStorageDir is the POSIX directory the embedded
	// Tessera POSIX driver writes tiles, entry bundles, and the
	// checkpoint to. Ledger-reader and ledger-writer must
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
	// LedgerSignerKeyFile is the path to a PEM-encoded
	// secp256k1 ECDSA private key the ledger uses to sign its
	// own entries (anchor publisher, commitment publisher). When
	// empty, an ephemeral key is generated at boot — fine for
	// local dev, never for production. The corresponding did:key
	// is computed from the public key and used as
	// cfg.LedgerDID; LEDGER_DID is ignored if it doesn't
	// match. The same key is what admission's
	// did.NewECDSAKeyResolver verifies signatures against, so
	// the ledger's self-published anchors and commitments
	// satisfy the sig-verification path.
	LedgerSignerKeyFile string
	// TesseraAntispamPath is the BadgerDB directory backing
	// Tessera's antispam (dedup) layer. Required so re-Add via
	// integrity.Reasserter on boot returns the previously-assigned
	// seq instead of allocating a new one. Separate Badger DB
	// from cfg.WALPath — antispam is recoverable from the log
	// (Follower tails entries and rebuilds the index) so the
	// recovery story differs.
	TesseraAntispamPath string

	// Byte store backend selects where the ledger's entry bytes
	// live. The composition root passes
	// these directly to bytestore.NewFromConfig; per-backend
	// validation lives in the factory.
	//
	//   - "gcs" — GCS adapter. ADC credentials by default;
	//     fake-gcs-server via ByteStoreGCSEndpoint +
	//     ByteStoreGCSAnonymous.
	//   - "s3"  — S3 adapter. Default credential chain on AWS;
	//     static creds + endpoint + path-style for RustFS / R2 /
	//     other S3-compatible servers.
	//
	// "memory" is intentionally rejected at the composition root —
	// production must select a real backend. Tests that need a
	// Store-only impl call bytestore.NewMemory directly.
	ByteStoreBackend   string
	ByteStorePrefix    string // empty = "entries"
	ByteStoreCacheSize int

	// GCS-specific.
	ByteStoreGCSBucket   string
	ByteStoreGCSEndpoint string // empty = default GCS endpoint
	ByteStoreGCSAnon     bool   // true = no auth (fake-gcs-server)

	// S3-specific.
	ByteStoreS3Bucket    string
	ByteStoreS3Endpoint  string // empty = default AWS S3 endpoint
	ByteStoreS3Region    string // empty = us-east-1 in factory
	ByteStoreS3AccessKey string // empty = default credential chain
	ByteStoreS3SecretKey string // empty = default credential chain
	ByteStoreS3PathStyle bool   // true for RustFS; false for AWS S3

	// Public-URL routing (transparency-log convention; see
	// bytestore/publicurl.go). The architecture has only one read
	// path: every bucket is anonymous-read by design (RFC 9162,
	// c2sp.org/tlog-tiles), every 302 returns a credential-free
	// public URL. There is no private-bucket / presigned fallback.
	//
	// ByteStorePublicBaseURL — explicit public-URL prefix override.
	// Empty means "use the appropriate default for the backend":
	//   gcs:               https://storage.googleapis.com/{bucket}
	//   s3 (path-style):   {endpoint}/{bucket}
	//   s3 (virtual-host): https://{bucket}.s3.{region}.amazonaws.com
	// Set explicitly to point at a CDN / custom DNS in front of the
	// bucket.
	// Env: LEDGER_BYTE_STORE_PUBLIC_BASE_URL
	ByteStorePublicBaseURL string
	TileCacheSize          int
	SMTNodeCacheSize       int
	DeltaWindow            int
	// WitnessEndpoints is the comma-separated list of peer witness
	// URLs the builder loop's HeadSync requester posts cosign
	// requests to. Empty (default) → no cosignature collection;
	// the BuilderLoop tolerates a nil cosigner and emits self-
	// signed checkpoints unwitnessed.
	//
	// Local-dev "self-witness K=1" pattern: set this to the
	// ledger's own server addr (e.g. http://localhost:8080)
	// and LEDGER_WITNESS_QUORUM_K=1 plus
	// LEDGER_WITNESS_KEY_FILE — same code paths as production
	// K=N witnesses, no test-mode flag.
	WitnessEndpoints []string
	WitnessQuorumK   int

	// WitnessKeyFile is the path to a PEM-encoded secp256k1
	// ECDSA private key the witness cosign endpoint
	// (POST /v1/cosign) signs tree heads with. When set, the
	// endpoint is mounted; when empty, the endpoint is absent
	// from the route table (this ledger does not act as a
	// witness for anyone). Distinct from
	// LEDGER_SIGNER_KEY_FILE — that key signs the ledger's
	// own admitted entries; this key signs cosign responses.
	WitnessKeyFile string

	// NetworkBootstrapFile is the path to a JSON file containing
	// the network's bootstrap document (network.BootstrapDocument).
	// Required when witness mode is active (WitnessKeyFile or
	// WitnessEndpoints set) — the cosign canonical-message preamble
	// rejects a zero NetworkID, so a witness signing or verifying
	// without one fails at runtime. The same document MUST be
	// loaded by every component participating in the network
	// (other ledgers, JN composer, peer witnesses); cross-
	// component signature verification depends on byte-identical
	// bootstrap inputs.
	NetworkBootstrapFile string

	// NetworkID is derived from the bootstrap document at config
	// load and threaded through to witness.NewCosignHandler and
	// any other primitive that calls cosign.Sign/Verify. Zero
	// (and unused) when witness mode is inactive.
	NetworkID cosign.NetworkID

	// GenesisWitnessSet is the slice of witness DIDs extracted
	// from the network bootstrap document. Consumed by the
	// equivocation monitor to verify K-of-N signatures on
	// observed cosigned tree heads. Empty when witness mode is
	// inactive (no bootstrap doc loaded).
	GenesisWitnessSet []string

	// WALPath is the BadgerDB directory the WAL Committer opens.
	// Required for WAL-first admission (commit 10). The Shipper
	// migrates entries from this path into the byte store; the
	// integrity Detector reconciles inflight entries against
	// Tessera at boot.
	WALPath string

	// GossipPeerEndpoints is the comma-separated list of peer
	// ledger base URLs whose /v1/gossip endpoints this ledger
	// fans out to. Empty (default) → no fan-out (NopSink); the
	// gossip handler still accepts inbound publishes and serves
	// the read-side feed.
	GossipPeerEndpoints []string

	// GossipPeerDIDs is parallel to GossipPeerEndpoints — the DID
	// at index i is the peer ledger's originator DID for the
	// endpoint at index i. Required (non-empty) for the
	// anti-entropy loop to know who to ask for events from. If
	// empty, anti-entropy is disabled (the publish + feed paths
	// still work).
	GossipPeerDIDs []string

	// GossipDisable, when true, disables gossip endpoint mounting
	// and publisher wiring. Useful for read-only ledgers or
	// trimmed-down test rigs.
	GossipDisable bool

	// MetricsEnable, when true, constructs an OpenTelemetry
	// MeterProvider at boot, mounts /metrics with Prometheus
	// scrape format, and threads gossip.Instruments into the
	// gossip handler/sink for received_total, published_total,
	// verify_duration_seconds, queue_depth, and drops_total
	// observability. Off by default (zero overhead) — enable
	// per-deployment via LEDGER_METRICS_ENABLE=true.
	MetricsEnable bool

	// MetricsEnvironment is the deployment-context tag used by
	// the OTel resource attributes. Required when MetricsEnable
	// is true. Convention: "production" / "staging" / "dev".
	MetricsEnvironment string

	// ServiceVersion is the binary's git tag or build hash,
	// surfaced as the OTel resource service.version attribute.
	// Defaults to "dev" when unset.
	ServiceVersion string

	// OTLPTracesEndpoint controls D2 tracing:
	//   "" / unset      → NoOp tracer (zero overhead, default)
	//   "stdout"        → stdouttrace (laptop dev — spans to stderr)
	//   "host:port"     → OTLP HTTP exporter (Jaeger / Tempo / collector)
	//   "https://..."   → OTLP HTTP over TLS
	OTLPTracesEndpoint string
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerAddr:            envOr("LEDGER_ADDR", ":8080"),
		DatabaseURL:           os.Getenv("LEDGER_DATABASE_URL"),
		LogDID:                os.Getenv("LEDGER_LOG_DID"),
		LedgerDID:             os.Getenv("LEDGER_DID"),
		MaxEntrySize:          1 << 20, // 1 MB, matches SDK-D11.
		BatchSize:             1000,
		PollInterval:          100 * time.Millisecond,
		EpochWindowSeconds:    3600, // 1h — matches testEpochWindowSeconds.
		EpochAcceptanceWindow: 1,
		AnchorInterval:        1 * time.Hour,
		TesseraStorageDir:     envOr("LEDGER_TESSERA_STORAGE_DIR", "/var/lib/attesta/tessera"),
		TesseraSignerKeyFile:  os.Getenv("LEDGER_TESSERA_SIGNER_KEY_FILE"),
		LedgerSignerKeyFile:   os.Getenv("LEDGER_SIGNER_KEY_FILE"),
		TesseraOrigin:         os.Getenv("LEDGER_TESSERA_ORIGIN"), // defaults to LogDID below
		ByteStoreBackend:      os.Getenv("LEDGER_BYTE_STORE_BACKEND"),
		ByteStorePrefix:       envOr("LEDGER_BYTE_STORE_PREFIX", "entries"),
		ByteStoreCacheSize:    4096,
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
		// Public-URL routing — transparency-log convention is the
		// only read path. Optional CDN / custom-DNS override.
		ByteStorePublicBaseURL: os.Getenv("LEDGER_BYTE_STORE_PUBLIC_BASE_URL"),
		TileCacheSize:          10_000,
		SMTNodeCacheSize:       100_000,
		DeltaWindow:            10,
		WitnessEndpoints:       parseCSV(os.Getenv("LEDGER_WITNESS_ENDPOINTS")),
		WitnessQuorumK:         envIntOr("LEDGER_WITNESS_QUORUM_K", 1),
		WitnessKeyFile:         os.Getenv("LEDGER_WITNESS_KEY_FILE"),
		NetworkBootstrapFile:   os.Getenv("LEDGER_NETWORK_BOOTSTRAP_FILE"),
		GossipPeerEndpoints:    parseCSV(os.Getenv("LEDGER_GOSSIP_PEER_ENDPOINTS")),
		GossipPeerDIDs:         parseCSV(os.Getenv("LEDGER_GOSSIP_PEER_DIDS")),
		GossipDisable:          os.Getenv("LEDGER_GOSSIP_DISABLE") == "true",
		// D1 — Metrics default ON. Disabled-by-default observability
		// is a footgun. Set LEDGER_METRICS_ENABLE=false to opt out
		// (e.g., for resource-constrained edge deployments).
		MetricsEnable:       os.Getenv("LEDGER_METRICS_ENABLE") != "false",
		MetricsEnvironment:  envOr("LEDGER_METRICS_ENVIRONMENT", "dev"),
		ServiceVersion:      envOr("LEDGER_SERVICE_VERSION", "dev"),
		OTLPTracesEndpoint:  os.Getenv("LEDGER_OTLP_TRACES_ENDPOINT"),
		WALPath:             envOr("LEDGER_WAL_PATH", "/var/lib/attesta/wal"),
		TesseraAntispamPath: envOr("LEDGER_TESSERA_ANTISPAM_PATH", "/var/lib/attesta/tessera-antispam"),

		// HTTP-server hardening knobs.
		TLSCertFile:        os.Getenv("LEDGER_TLS_CERT_FILE"),
		TLSKeyFile:         os.Getenv("LEDGER_TLS_KEY_FILE"),
		MaxConcurrentConns: envIntOr("LEDGER_MAX_CONCURRENT_CONNS", 0),
		PprofAddr:          os.Getenv("LEDGER_PPROF_ADDR"),
		TileServeDisable:   os.Getenv("LEDGER_TILE_SERVE_DISABLE") == "true",
		TileBackend:        envOr("LEDGER_TILE_BACKEND", "posix"),
		TileBucketPrefix:   envOr("LEDGER_TILE_BUCKET_PREFIX", "tessera/"),

		SequencerInterval:    envDurationOr("LEDGER_SEQUENCER_INTERVAL", 1*time.Second),
		SequencerMaxInFlight: envIntOr("LEDGER_SEQUENCER_MAX_INFLIGHT", 4),
		MMD:                  envDurationOr("LEDGER_MMD", 24*time.Hour),

		// Shipper drain throughput. Drain rate ceiling is approximately
		// MaxInFlight ÷ per-upload-latency (real GCS ≈ 100ms in observed
		// soak). Default 64 sustains ~640 entries/sec — comfortably above
		// the 116/sec required for 10M/day uniformly-distributed traffic
		// and the ~580/sec sustained admission rate observed under burst.
		// PollInterval=100ms aligns with per-upload latency so the in-
		// flight dedupe guard (shipper.Shipper.inflight) operates
		// efficiently — see soak telemetry: skipInflight ≈ 2× unique.
		ShipperMaxInFlight: envIntOr("LEDGER_SHIPPER_MAX_IN_FLIGHT", 64),
		ShipperPollInterval: envDurationOr("LEDGER_SHIPPER_POLL_INTERVAL",
			100*time.Millisecond),

		// Pool size: env override OR derived from MaxInFlight (set
		// after we know the final MaxInFlight value below).
		PgMaxConns:         int32(envIntOr("LEDGER_PG_MAX_CONNS", 0)),
		PgStatementTimeout: envDurationOr("LEDGER_PG_STATEMENT_TIMEOUT", 5*time.Second),
	}
	if cfg.PgMaxConns == 0 {
		cfg.PgMaxConns = defaultPgMaxConns(cfg.SequencerMaxInFlight)
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("LEDGER_DATABASE_URL required")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("LEDGER_LOG_DID required (destination-binding)")
	}
	if cfg.LedgerDID == "" {
		cfg.LedgerDID = cfg.LogDID
	}
	switch cfg.ByteStoreBackend {
	case "":
		return nil, fmt.Errorf("LEDGER_BYTE_STORE_BACKEND required (gcs|s3)")
	case "gcs":
		if cfg.ByteStoreGCSBucket == "" {
			return nil, fmt.Errorf("LEDGER_BYTE_STORE_GCS_BUCKET required when LEDGER_BYTE_STORE_BACKEND=gcs")
		}
	case "s3":
		if cfg.ByteStoreS3Bucket == "" {
			return nil, fmt.Errorf("LEDGER_BYTE_STORE_S3_BUCKET required when LEDGER_BYTE_STORE_BACKEND=s3")
		}
	default:
		return nil, fmt.Errorf("LEDGER_BYTE_STORE_BACKEND=%q not supported (gcs|s3)", cfg.ByteStoreBackend)
	}
	if err := validatePgPoolSizing(cfg.PgMaxConns, cfg.SequencerMaxInFlight); err != nil {
		return nil, err
	}

	// Witness mode requires a network bootstrap document. The cosign
	// canonical-message preamble rejects a zero NetworkID; a witness
	// signing or verifying without one fails at runtime. Load + derive
	// at config-load so any error surfaces with a clear cause before
	// the ledger advances any further.
	witnessActive := cfg.WitnessKeyFile != "" || len(cfg.WitnessEndpoints) > 0
	if witnessActive {
		if cfg.NetworkBootstrapFile == "" {
			return nil, fmt.Errorf(
				"LEDGER_NETWORK_BOOTSTRAP_FILE required when witness mode is active " +
					"(LEDGER_WITNESS_KEY_FILE or LEDGER_WITNESS_ENDPOINTS set)")
		}
		raw, err := os.ReadFile(cfg.NetworkBootstrapFile)
		if err != nil {
			return nil, fmt.Errorf("read network bootstrap %s: %w",
				cfg.NetworkBootstrapFile, err)
		}
		var doc network.BootstrapDocument
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse network bootstrap %s: %w",
				cfg.NetworkBootstrapFile, err)
		}
		ids, err := doc.IDs()
		if err != nil {
			return nil, fmt.Errorf("network bootstrap %s: %w",
				cfg.NetworkBootstrapFile, err)
		}
		cfg.NetworkID = ids.NetworkID
		cfg.GenesisWitnessSet = append([]string{}, doc.GenesisWitnessSet...)
	}

	// G1: cross-field validation. Anything that requires multiple
	// fields to be set together (or NOT together) is checked here.
	// Per-field "required" checks already happened above.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate runs cross-field consistency checks on a fully-loaded
// Config. Every check is fail-fast: a misconfigured deployment
// surfaces a clear, single-line error at boot instead of a
// runtime surprise.
func (c *Config) Validate() error {
	// TLS: cert + key must be both-set or both-unset. Half-
	// configured TLS would silently fall back to plain HTTP and
	// be an exposure surprise.
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("LEDGER_TLS_CERT_FILE and LEDGER_TLS_KEY_FILE must be both set or both unset (got cert=%q key=%q)",
			c.TLSCertFile, c.TLSKeyFile)
	}
	if c.TLSCertFile != "" {
		if _, err := os.Stat(c.TLSCertFile); err != nil {
			return fmt.Errorf("LEDGER_TLS_CERT_FILE %q: %w", c.TLSCertFile, err)
		}
		if _, err := os.Stat(c.TLSKeyFile); err != nil {
			return fmt.Errorf("LEDGER_TLS_KEY_FILE %q: %w", c.TLSKeyFile, err)
		}
	}

	// Gossip peers: DID and endpoint slices MUST be the same
	// length so each peer has both an identity and a base URL.
	// Mismatched lengths point at a deployment misconfig where
	// one env var was forgotten or has a stale value.
	if len(c.GossipPeerDIDs) != len(c.GossipPeerEndpoints) {
		return fmt.Errorf("LEDGER_GOSSIP_PEER_DIDS (%d) and LEDGER_GOSSIP_PEER_ENDPOINTS (%d) must have the same length",
			len(c.GossipPeerDIDs), len(c.GossipPeerEndpoints))
	}

	// Tile backend: gcs requires the byte-store backend to also
	// be gcs (the GCSTiles handle reuses the *GCS bucket handle).
	if c.TileBackend == "gcs" && c.ByteStoreBackend != "gcs" {
		return fmt.Errorf("LEDGER_TILE_BACKEND=gcs requires LEDGER_BYTE_STORE_BACKEND=gcs (got %q)",
			c.ByteStoreBackend)
	}
	switch c.TileBackend {
	case "", "posix", "gcs":
	default:
		return fmt.Errorf("LEDGER_TILE_BACKEND must be one of posix|gcs (got %q)", c.TileBackend)
	}

	// Durations: every exposed duration MUST be positive. Zero
	// or negative values silently disable the relevant timer
	// (e.g., zero PollInterval = busy loop), which is a footgun.
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"LEDGER_SEQUENCER_INTERVAL", c.SequencerInterval},
		{"LEDGER_MMD", c.MMD},
		{"PgStatementTimeout (LEDGER_PG_STATEMENT_TIMEOUT)", c.PgStatementTimeout},
	} {
		if d.v < 0 {
			return fmt.Errorf("%s must be >= 0 (got %v)", d.name, d.v)
		}
	}

	// Witness quorum K must be positive when witnesses are
	// configured (a 0-of-N quorum would never finalize a head).
	if len(c.WitnessEndpoints) > 0 && c.WitnessQuorumK <= 0 {
		return fmt.Errorf("LEDGER_WITNESS_QUORUM_K must be > 0 when LEDGER_WITNESS_ENDPOINTS is set (got %d)",
			c.WitnessQuorumK)
	}
	if len(c.WitnessEndpoints) > 0 && c.WitnessQuorumK > len(c.WitnessEndpoints) {
		return fmt.Errorf("LEDGER_WITNESS_QUORUM_K (%d) cannot exceed LEDGER_WITNESS_ENDPOINTS count (%d)",
			c.WitnessQuorumK, len(c.WitnessEndpoints))
	}

	return nil
}

// pgPoolHeadroom is the minimum extra connections the pool must
// have above SequencerMaxInFlight, to leave room for HTTP admission,
// auth middleware token lookups, builder + shipper background loops,
// and ad-hoc query handlers.
const pgPoolHeadroom = 8

// defaultPgMaxConns returns the default Postgres pool size derived
// from sequencerMaxInFlight. Floor at 20 so light-load deployments
// have headroom for HTTP + auth + builder + shipper concurrency
// without ledger tuning. Otherwise pick MaxInFlight*4 so the
// sequencer can't exceed a quarter of the pool during a drain
// burst.
func defaultPgMaxConns(sequencerMaxInFlight int) int32 {
	mif := sequencerMaxInFlight
	if mif <= 0 {
		mif = sequencer.DefaultMaxInFlight
	}
	derived := int32(mif * 4)
	if derived < 20 {
		return 20
	}
	return derived
}

// validatePgPoolSizing enforces the boot-time invariant that the
// configured pool has enough connections to support the sequencer
// plus headroom for the rest of the ledger. Returns a clear
// error if the ledger was misconfigured — better to refuse to
// start than to have HTTP admission hang on connection acquisition
// under load.
// buildLogInfo flattens the auditor-facing subset of Config into
// the public deployment-posture payload served by GET /v1/log-info.
// SCOPE: only fields an external auditor needs to verify the log's
// trust posture. Operational tunables (PG pool sizes, statement
// timeout, internal file paths, WAL path) are intentionally absent
// — they're surfaced via the boot banner log (G7) for administrators
// to read from their log shipper.
//
// The ledger is zero-trust by design (L-1 dumb ledger, T-6
// zero-trust dual verification): there is no privileged "admin"
// surface. Anything below this filter is genuinely public —
// never any secret content, never any internal-only telemetry.
func buildLogInfo(cfg *Config) api.LogInfo {
	return api.LogInfo{
		// Identity + addressing — auditors must know which log
		// they're verifying.
		"log_did":     cfg.LogDID,
		"ledger_did":  cfg.LedgerDID,
		"network_id":  networkIDHex(cfg.NetworkID),
		"server_addr": cfg.ServerAddr,

		// Storage backend types — auditor needs to know whether
		// to fetch tiles from POSIX origin or GCS bucket.
		"byte_store_backend": cfg.ByteStoreBackend,
		"tile_backend":       cfg.TileBackend,
		"tile_bucket_prefix": cfg.TileBucketPrefix,
		"tile_serve_disable": cfg.TileServeDisable,

		// Witness topology — drives K-of-N quorum verification.
		"witness_endpoint_count": len(cfg.WitnessEndpoints),
		"witness_quorum_k":       cfg.WitnessQuorumK,

		// Gossip + transport posture.
		"gossip_enabled":    !cfg.GossipDisable,
		"gossip_peer_count": len(cfg.GossipPeerDIDs),
		"tls_enabled":       cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",

		// Sequencer cadence — affects MMD compliance window an
		// auditor evaluates.
		"sequencer_interval": cfg.SequencerInterval.String(),
		"mmd":                cfg.MMD.String(),
	}
}

// networkIDHex returns the first-8-bytes hex prefix of the
// NetworkID, suitable for log correlation. The full 32 bytes
// are not interesting in the boot banner; the prefix is enough
// to disambiguate networks at a glance and it matches the
// convention used elsewhere in the codebase.
func networkIDHex(id cosign.NetworkID) string {
	var zero cosign.NetworkID
	if id == zero {
		return ""
	}
	return fmt.Sprintf("%x", id[:8])
}

// validateTesseraStorageDir confirms the Tessera POSIX directory
// is in a consistent state: either empty (fresh init) OR contains
// a `checkpoint` file (resuming an existing log). A dir with
// tile artifacts but no checkpoint indicates a half-initialized
// volume — partial restore, aborted migration, manual file
// shuffling — and re-initializing on top of it would corrupt
// the log silently. Boot fails fast instead.
func validateTesseraStorageDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	if len(entries) == 0 {
		// Fresh init — Tessera will populate.
		return nil
	}
	checkpoint := dir + string(os.PathSeparator) + "checkpoint"
	if _, err := os.Stat(checkpoint); err == nil {
		// Healthy: existing log with checkpoint. Tessera will
		// resume from where it left off.
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat checkpoint: %w", err)
	}
	// Has files but no checkpoint — half-initialized.
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

func validatePgPoolSizing(maxConns int32, sequencerMaxInFlight int) error {
	mif := sequencerMaxInFlight
	if mif <= 0 {
		mif = sequencer.DefaultMaxInFlight
	}
	required := int32(mif) + pgPoolHeadroom
	if maxConns < required {
		return fmt.Errorf(
			"LEDGER_PG_MAX_CONNS=%d is below the minimum %d "+
				"(SequencerMaxInFlight=%d + headroom=%d). "+
				"Raise LEDGER_PG_MAX_CONNS, lower LEDGER_SEQUENCER_MAX_INFLIGHT, "+
				"or unset LEDGER_PG_MAX_CONNS to use the safe default",
			maxConns, required, mif, pgPoolHeadroom,
		)
	}
	return nil
}

// toBytestoreConfig flattens the ledger config's bytestore-related
// fields into the bytestore.Config the factory expects. Per-backend
// required-field validation already happened in loadConfig; the factory
// applies the remaining defaults (prefix=entries, cache_size, region).
func (cfg *Config) toBytestoreConfig() bytestore.Config {
	bc := bytestore.Config{
		Backend:       cfg.ByteStoreBackend,
		Prefix:        cfg.ByteStorePrefix,
		CacheSize:     cfg.ByteStoreCacheSize,
		PublicBaseURL: cfg.ByteStorePublicBaseURL,
	}
	switch cfg.ByteStoreBackend {
	case "gcs":
		bc.Bucket = cfg.ByteStoreGCSBucket
		bc.GCSEndpoint = cfg.ByteStoreGCSEndpoint
		bc.GCSAnonymous = cfg.ByteStoreGCSAnon
	case "s3":
		bc.Bucket = cfg.ByteStoreS3Bucket
		bc.S3Endpoint = cfg.ByteStoreS3Endpoint
		bc.S3Region = cfg.ByteStoreS3Region
		bc.S3AccessKey = cfg.ByteStoreS3AccessKey
		bc.S3SecretKey = cfg.ByteStoreS3SecretKey
		bc.S3PathStyle = cfg.ByteStoreS3PathStyle
	}
	return bc
}
