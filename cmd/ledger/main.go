/*
FILE PATH: cmd/ledger/main.go

DESCRIPTION:

	Ledger binary entry point. Wires config → Postgres → stores → byte
	store → Tessera personality → builder deps → HTTP handlers → goroutines.
	Runs the admission HTTP server, builder loop, and (optional) anchor
	publisher under a shared cancellable context.

SDK WIRING:
 1. anchor.PublisherConfig requires LogDID — threaded from cfg.LogDID.
 2. builder.NewCommitmentPublisher is (ledgerDID, logDID, cfg, submitFn,
    logger) — both DIDs passed explicitly.
 3. api.SubmissionDeps has FreshnessTolerance (defaults to
    policy.FreshnessInteractive = 5 min if zero). Explicit here for
    auditability.
 4. DID verifier is scaffolded behind a nil — swap for
    did.DefaultVerifierRegistry(cfg.LogDID, resolver) to enable full
    DID-based signature verification.

LEDGER INTERNAL SIGNATURES:
  - tessera.NewEmbeddedAppender(ctx, driver, opts, logger) →
    *EmbeddedAppender. Wraps in-process upstream Tessera; no HTTP.
  - tessera.NewTesseraAdapter(backend, tileReader, logger) →
    MerkleAppender. backend is *EmbeddedAppender or
    *ReadOnlyAppender; both satisfy AppenderBackend.
  - tessera.NewInMemoryEntryStore() → *InMemoryEntryStore. The only
    byte-store implementation shipped today. A persistent backend is the
    ledger's responsibility to swap in.
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
  - cfg.LedgerDID defaults to cfg.LogDID for single-exchange
    deployments where the ledger IS the exchange.
  - ByteStore here is NewInMemoryEntryStore() — bytes are lost on
    restart. Production deployments MUST replace this with a
    persistent implementation of tessera.EntryReader + EntryWriter.
*/
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/netutil"

	"github.com/transparency-dev/tessera/storage/posix"
	posixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkcryptosigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	sdkdid "github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/exchange/policy"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/network"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/clearcompass-ai/ledger/admission"
	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/anchor"
	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/builder"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/gossipnet"
	"github.com/clearcompass-ai/ledger/gossipstore"
	"github.com/clearcompass-ai/ledger/integrity"
	"github.com/clearcompass-ai/ledger/sequencer"
	"github.com/clearcompass-ai/ledger/shipper"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	"github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/wal"
	"github.com/clearcompass-ai/ledger/witness"
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

// loadOrGenerateLedgerSigner resolves the ledger's entry
// signing key. The ledger signs its own entries (anchor
// commentary, commitment commentary) before submitting them to
// admission, which then verifies the signature via
// did.NewECDSAKeyResolver (SDK). Returns the private key plus the
// computed did:key:z... identifier — that string becomes
// cfg.LedgerDID at the composition root.
//
// Priority:
//   - keyFile non-empty: PEM-decode + x509.ParseECPrivateKey.
//     Production deployments MUST use this so the ledger's DID
//     is stable across restarts.
//   - keyFile empty: generate an ephemeral secp256k1 key and log a
//     warning. Local-dev only — entry consumers that pin the
//     ledger's DID will see a different DID on every restart.
func loadOrGenerateLedgerSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, string, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read ledger signer key %q: %w", keyFile, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, "", fmt.Errorf("ledger signer key %q: PEM decode failed", keyFile)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse ledger signer key %q: %w", keyFile, err)
		}
		didKey, err := didKeyFromSecp256k1Priv(priv)
		if err != nil {
			return nil, "", fmt.Errorf("encode did:key from %q: %w", keyFile, err)
		}
		logger.Info("ledger signer loaded from file", "key_file", keyFile, "did", didKey)
		return priv, didKey, nil
	}
	// Ephemeral fallback for local dev.
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		return nil, "", fmt.Errorf("generate ledger signer: %w", err)
	}
	didKey, err := didKeyFromSecp256k1Priv(priv)
	if err != nil {
		return nil, "", fmt.Errorf("encode did:key for ephemeral signer: %w", err)
	}
	logger.Warn("ledger signer is ephemeral — NOT for production",
		"did", didKey,
	)
	return priv, didKey, nil
}

// didKeyFromSecp256k1Priv composes a did:key:z... identifier from
// a secp256k1 private key. Same multibase + multicodec encoding
// the SDK's did.GenerateDIDKeySecp256k1 produces internally; this
// helper exists because the ledger threads in keys loaded from
// disk rather than generating them via the SDK constructor.
func didKeyFromSecp256k1Priv(priv *ecdsa.PrivateKey) (string, error) {
	uncompressed := sdkcryptosigs.PubKeyBytes(&priv.PublicKey)
	compressed, err := sdkcryptosigs.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return "", err
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}

// loadOrGenerateWitnessSigner resolves the witness cosign-server
// signing key. Distinct from the ledger's entry signer — this
// key signs cosign responses (witness/serve.go), and its public
// key fingerprint is what peer ledgers pin in their
// HeadSync.WitnessEndpoints set.
//
// Priority:
//   - keyFile non-empty: PEM-decode + x509.ParseECPrivateKey.
//     Production deployments MUST use this so the witness's
//     identity is stable across restarts.
//   - keyFile empty: generate ephemeral. Local-dev only; peers
//     will see a different witness fingerprint on each restart.
func loadOrGenerateWitnessSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read witness signer key %q: %w", keyFile, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("witness signer key %q: PEM decode failed", keyFile)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse witness signer key %q: %w", keyFile, err)
		}
		logger.Info("witness signer loaded from file", "key_file", keyFile)
		return priv, nil
	}
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate witness signer: %w", err)
	}
	logger.Warn("witness signer is ephemeral — NOT for production")
	return priv, nil
}

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

type Config struct {
	ServerAddr string
	DatabaseURL string
	PgMaxConns int32 // LEDGER_PG_MAX_CONNS; defaults to defaultPgMaxConns(MaxInFlight).
	LogDID string // Destination for self-published entries (anchors, commitments).
	LedgerDID string // Signer DID for ledger-authored commentary.

	// TLSCertFile / TLSKeyFile, when both non-empty, switch the
	// HTTP listener to ListenAndServeTLS. Operator deployments
	// fronted by a TLS-terminating proxy leave both empty (plain
	// HTTP). Standalone (VM / bare-metal / sigsum-witness) operators
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

	MaxEntrySize int64
	BatchSize int
	PollInterval time.Duration
	EpochWindowSeconds int
	EpochAcceptanceWindow int
	AnchorInterval time.Duration
	AnchorSources []anchor.AnchorSource

	// Sequencer settings (SCT/MMD architecture). The Sequencer
	// drains StatePending entries asynchronously; v2 admission
	// returns an SCT immediately after WAL fsync and the
	// Sequencer redeems the promise within MMD.
	SequencerInterval time.Duration // default 1s; LEDGER_SEQUENCER_INTERVAL
	SequencerMaxInFlight int // default 4; LEDGER_SEQUENCER_MAX_INFLIGHT
	MMD time.Duration // default 24h; LEDGER_MMD
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
	TesseraStorageDir string
	TesseraSignerKeyFile string
	TesseraOrigin string
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
	ByteStoreBackend string
	ByteStorePrefix string // empty = "entries"
	ByteStoreCacheSize int

	// GCS-specific.
	ByteStoreGCSBucket string
	ByteStoreGCSEndpoint string // empty = default GCS endpoint
	ByteStoreGCSAnon bool // true = no auth (fake-gcs-server)

	// S3-specific.
	ByteStoreS3Bucket string
	ByteStoreS3Endpoint string // empty = default AWS S3 endpoint
	ByteStoreS3Region string // empty = us-east-1 in factory
	ByteStoreS3AccessKey string // empty = default credential chain
	ByteStoreS3SecretKey string // empty = default credential chain
	ByteStoreS3PathStyle bool // true for RustFS; false for AWS S3
	TileCacheSize int
	SMTNodeCacheSize int
	DeltaWindow int
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
	WitnessQuorumK int

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
		TileCacheSize:        10_000,
		SMTNodeCacheSize:     100_000,
		DeltaWindow:          10,
		WitnessEndpoints:     parseCSV(os.Getenv("LEDGER_WITNESS_ENDPOINTS")),
		WitnessQuorumK:       envIntOr("LEDGER_WITNESS_QUORUM_K", 1),
		WitnessKeyFile:       os.Getenv("LEDGER_WITNESS_KEY_FILE"),
		NetworkBootstrapFile: os.Getenv("LEDGER_NETWORK_BOOTSTRAP_FILE"),
		GossipPeerEndpoints:  parseCSV(os.Getenv("LEDGER_GOSSIP_PEER_ENDPOINTS")),
		GossipPeerDIDs:       parseCSV(os.Getenv("LEDGER_GOSSIP_PEER_DIDS")),
		GossipDisable:        os.Getenv("LEDGER_GOSSIP_DISABLE") == "true",
		MetricsEnable:        os.Getenv("LEDGER_METRICS_ENABLE") == "true",
		MetricsEnvironment:   envOr("LEDGER_METRICS_ENVIRONMENT", "dev"),
		ServiceVersion:       envOr("LEDGER_SERVICE_VERSION", "dev"),
		WALPath:              envOr("LEDGER_WAL_PATH", "/var/lib/attesta/wal"),
		TesseraAntispamPath:  envOr("LEDGER_TESSERA_ANTISPAM_PATH", "/var/lib/attesta/tessera-antispam"),

		// HTTP-server hardening knobs.
		TLSCertFile:        os.Getenv("LEDGER_TLS_CERT_FILE"),
		TLSKeyFile:         os.Getenv("LEDGER_TLS_KEY_FILE"),
		MaxConcurrentConns: envIntOr("LEDGER_MAX_CONCURRENT_CONNS", 0),
		PprofAddr:          os.Getenv("LEDGER_PPROF_ADDR"),

		SequencerInterval:    envDurationOr("LEDGER_SEQUENCER_INTERVAL", 1*time.Second),
		SequencerMaxInFlight: envIntOr("LEDGER_SEQUENCER_MAX_INFLIGHT", 4),
		MMD:                  envDurationOr("LEDGER_MMD", 24*time.Hour),

		// Pool size: env override OR derived from MaxInFlight (set
		// after we know the final MaxInFlight value below).
		PgMaxConns: int32(envIntOr("LEDGER_PG_MAX_CONNS", 0)),
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

	return cfg, nil
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
		Backend:   cfg.ByteStoreBackend,
		Prefix:    cfg.ByteStorePrefix,
		CacheSize: cfg.ByteStoreCacheSize,
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envIntOr reads an env var as a base-10 integer; returns fallback
// if the var is unset or unparseable.
func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// envDurationOr reads an env var as a Go time.Duration string
// (e.g. "1s", "500ms", "24h"); returns fallback on unset or parse
// failure.
func envDurationOr(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// parseCSV splits a comma-separated env value into a slice of
// trimmed non-empty entries. Empty input → nil. Used for
// LEDGER_WITNESS_ENDPOINTS.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
		logger.Error("invalid LEDGER_LOG_DID", "error", valErr)
		os.Exit(1)
	}

	logger.Info("ledger starting",
		"log_did", cfg.LogDID,
		"ledger_did", cfg.LedgerDID,
		"addr", cfg.ServerAddr,
		"tessera_storage_dir", cfg.TesseraStorageDir,
	)

	// ── Ethereum RPC for EIP-1271 (smart-contract-wallet sigs) ────────
	// When LEDGER_ETH_RPC_ENABLED=true the ledger constructs an
	// HTTPEthereumRPC client and is ready to pass it into
	// did.DefaultVerifierRegistryWithRPC at the verifier-registry seam.
	// When disabled (the default) the ledger runs EOA-only and pulls
	// zero network surface. Endpoint URL is NEVER logged (typically
	// embeds an API key); the audit channel is secret-management.
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

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Postgres ──────────────────────────────────────────────────────
	// Pool is sized at max(20, SequencerMaxInFlight*4) by default so
	// the Sequencer can drain at full MaxInFlight without starving
	// the HTTP admission path for connections. Override via
	// LEDGER_PG_MAX_CONNS; validatePgPoolSizing rejects anything
	// below SequencerMaxInFlight + pgPoolHeadroom at boot.
	pgPool, err := store.InitPool(ctx, store.PoolConfig{
		DSN:             cfg.DatabaseURL,
		MaxConns:        cfg.PgMaxConns,
		MinConns:        2,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	})
	if err != nil {
		logger.Error("pgxpool", "error", err)
		os.Exit(1)
	}
	defer pgPool.Close()
	pool := pgPool.DB
	logger.Info("postgres pool ready",
		"max_conns", cfg.PgMaxConns,
		"sequencer_max_inflight", cfg.SequencerMaxInFlight,
	)

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
	treeHeadStore := store.NewTreeHeadStore(pool)

	// ── WAL ───────────────────────────────────────────────────────────
	// BadgerDB-backed WAL provides durable bytes for admission's HTTP
	// 202 promise. Group commit + fsync semantics live in wal/committer.go.
	// The same Badger DB also backs Tessera's deduplicator (commit 12
	// wires tessera.WithDeduplication) so dedup state shares the
	// ledger's single durability medium.
	walDB, err := wal.Open(cfg.WALPath, logger)
	if err != nil {
		logger.Error("wal open", "error", err, "path", cfg.WALPath)
		os.Exit(1)
	}
	defer func() {
		if err := walDB.Close(); err != nil {
			logger.Warn("wal db close", "error", err)
		}
	}()
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{Logger: logger})
	defer func() {
		if err := walc.Close(); err != nil {
			logger.Warn("wal committer close", "error", err)
		}
	}()
	logger.Info("wal ready", "path", cfg.WALPath)

	// ── Byte store ────────────────────────────────────────────────────
	//
	// Construct the production bytestore via the hexagonal factory.
	// LEDGER_BYTE_STORE_BACKEND selects between "gcs" and "s3";
	// loadConfig has already enforced the per-backend required fields.
	// The returned bytestore.Backend is the union of Store + Presigner —
	// composite reader, shipper, and the 302 redirect path all use it
	// without naming the concrete adapter.
	byteStore, err := bytestore.NewFromConfig(ctx, cfg.toBytestoreConfig())
	if err != nil {
		logger.Error("byte store init", "error", err, "backend", cfg.ByteStoreBackend)
		os.Exit(1)
	}
	defer func() {
		if closer, ok := byteStore.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				logger.Warn("byte store close", "error", err)
			}
		}
	}()
	logger.Info("byte store ready",
		"backend", cfg.ByteStoreBackend,
		"prefix", cfg.ByteStorePrefix,
		"cache_size", cfg.ByteStoreCacheSize,
	)

	// ── Tessera personality ───────────────────────────────────────────
	//
	// Embedded Tessera: in-process upstream Tessera over a POSIX
	// storage driver. Sequencing, integration, and checkpoint
	// signing all run inside this process. TileReader reads tiles
	// directly off the same directory Tessera writes to. Adapter
	// satisfies the MerkleAppender interface the builder loop holds.
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

	// ── Ledger entry-signing key + DID ──────────────────────────────
	// The ledger self-publishes anchor commentary and commitment
	// commentary. Both go through admission, which now verifies
	// signatures via did.NewECDSAKeyResolver (SDK). Load (or generate)
	// the secp256k1 signing key, compute its did:key, and override
	// cfg.LedgerDID so the resolver can find the matching public
	// key for the entries we ourselves submit.
	ledgerSignerPriv, ledgerSignerDID, err := loadOrGenerateLedgerSigner(cfg.LedgerSignerKeyFile, logger)
	if err != nil {
		logger.Error("ledger signer", "error", err)
		os.Exit(1)
	}
	if envOpDID := os.Getenv("LEDGER_DID"); envOpDID != "" && envOpDID != ledgerSignerDID {
		logger.Warn("LEDGER_DID env var ignored — overridden to match signer key",
			"env_value", envOpDID, "signer_did", ledgerSignerDID)
	}
	cfg.LedgerDID = ledgerSignerDID

	// ── Tessera antispam (dedup) ──────────────────────────────────────
	// Persistent BadgerDB-backed dedup. Required so
	// integrity.Reasserter is idempotent across boots: re-Add of an
	// already-integrated identity returns the previously-assigned
	// seq instead of polluting the log with a fresh seq.
	if err := os.MkdirAll(cfg.TesseraAntispamPath, 0o755); err != nil {
		logger.Error("tessera antispam dir", "error", err, "dir", cfg.TesseraAntispamPath)
		os.Exit(1)
	}
	antispamStorage, err := posixantispam.NewAntispam(ctx, cfg.TesseraAntispamPath, posixantispam.AntispamOpts{})
	if err != nil {
		logger.Error("tessera antispam open", "error", err, "path", cfg.TesseraAntispamPath)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = shutdownCtx
		if closer, ok := any(antispamStorage).(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				logger.Warn("antispam close", "error", err)
			}
		}
	}()
	logger.Info("tessera antispam ready", "path", cfg.TesseraAntispamPath)

	embeddedAppender, err := tessera.NewEmbeddedAppender(ctx, tesseraDriver, tessera.AppenderOptions{
		Origin:   tesseraOrigin,
		Signer:   tesseraSigner,
		Antispam: antispamStorage,
		// Defaults applied for CheckpointInterval / BatchSize /
		// BatchMaxAge / AntispamInMemEntries — see
		// tessera/embedded_appender.go.
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

	// ── Composite byte reader ─────────────────────────────────────────
	// Routes per-entry: WAL first (local NVMe, fast for un-shipped
	// entries) then bytestore fallback (network, for shipped entries
	// past WAL retention). PostgresEntryFetcher and
	// PostgresQueryAPI take a bytestore.Reader; the composite
	// satisfies that interface so they're unaware of the routing.
	compositeReader := store.NewCompositeByteReader(walc, byteStore, logger)

	// ── Builder dependencies ──────────────────────────────────────────
	fetcher := store.NewPostgresEntryFetcher(pool, compositeReader, cfg.LogDID)
	bufferStore := builder.NewDeltaBufferStore(pool, cfg.DeltaWindow, logger)
	// Builder pending-work source: CT-native log-tailing follower.
	// Admission writes only entry_index; the cursor reader tails it
	// and advances builder_cursor in its atomic commit.
	sequenceCursor := store.NewSequenceCursor(pool)
	reader := builder.NewCursorReader(sequenceCursor)
	tree := smt.NewTree(leafStore, nodeCache)

	// Load buffer from persistence (cold start = strict OCC per SDK-D9).
	// Load returns a fresh *DeltaWindowBuffer — we do NOT pass our own in.
	buffer, loadErr := bufferStore.Load(ctx)
	if loadErr != nil {
		logger.Warn("delta buffer load — starting cold", "error", loadErr)
		buffer = sdkbuilder.NewDeltaWindowBuffer(cfg.DeltaWindow)
	}

	// ── Self-submit pipeline ──────────────────────────────────────────
	// The anchor and commitment publishers self-publish commentary
	// entries to this ledger's own admission endpoint. Both must be
	// signed before submit so admission's ECDSAKeyResolver returns the
	// matching public key. SignAndSubmit closes that gap by wrapping
	// the transport-only SubmitViaHTTP with the per-entry ECDSA
	// signing step.
	selfSubmitURL := fmt.Sprintf("http://localhost%s", cfg.ServerAddr)
	signedSelfSubmit := anchor.SignAndSubmit(
		ledgerSignerPriv,
		ledgerSignerDID,
		anchor.SubmitViaHTTP(selfSubmitURL),
	)

	// ── Commitment publisher ──────────────────────────────────────────
	commitPub := builder.NewCommitmentPublisher(
		cfg.LedgerDID,
		cfg.LogDID,
		builder.CommitmentPublisherConfig{
			IntervalEntries: 1000,
			IntervalTime:    1 * time.Hour,
		},
		signedSelfSubmit,
		logger,
	).WithCommitmentStore(commitStore)

	// ── Difficulty controller (cursor-lag-driven) ─────────────────────
	//
	// DefaultDifficultyConfig() is the ready-made production preset:
	//   Initial=16, Min=8, Max=24, Low=100, High=10000, Interval=30s, SHA-256.
	// SequenceCursor.Lag returns MAX(entry_index.seq) - cursor and
	// drives PoW difficulty via the cursor-mode lag signal.
	diffController := middleware.NewDifficultyController(
		sequenceCursor, middleware.DefaultDifficultyConfig(), logger,
	)

	// ── Witness cosigner (optional) ───────────────────────────────────
	//
	// When LEDGER_WITNESS_ENDPOINTS is set, the builder loop's
	// post-commit cosignature step posts to each peer witness and
	// collects K-of-N signatures over the new tree head. With no
	// endpoints configured, BuilderLoop tolerates a nil cosigner —
	// the cosignature step is skipped and self-signed checkpoints
	// are published unwitnessed.
	//
	// Local-dev "self-witness K=1" pattern: set
	// LEDGER_WITNESS_ENDPOINTS=http://localhost:<port> +
	// LEDGER_WITNESS_QUORUM_K=1 + LEDGER_WITNESS_KEY_FILE — the
	// ledger becomes its own witness, exercising the same code
	// paths as production K=N deployments.
	// ── OpenTelemetry MeterProvider (optional) ─────────────────────
	//
	// Constructed BEFORE gossip wiring so the MeterProvider's
	// metric.Meter can be threaded into gossipnet.Build for
	// gossip.Instruments. /metrics is mounted on the api Handlers
	// struct downstream (Handlers.Metrics).
	//
	// Off by default (zero overhead). Opt-in via
	// LEDGER_METRICS_ENABLE=true. Production deployments scrape
	// /metrics from the same port as the data-plane endpoints —
	// no second listener.
	var (
		meterShutdown func(ctx context.Context) error
		gossipMeter metric.Meter
		metricsHandler http.Handler
	)
	if cfg.MetricsEnable {
		mpResult, mErr := sdklog.NewMeterProvider(sdklog.MeterProviderConfig{
			ServiceName:    "ledger",
			ServiceVersion: cfg.ServiceVersion,
			Environment:    cfg.MetricsEnvironment,
			Exporters:      []sdklog.ExporterKind{sdklog.PrometheusExporter},
		})
		if mErr != nil {
			logger.Error("metrics: NewMeterProvider failed", "error", mErr)
			os.Exit(1)
		}
		otel.SetMeterProvider(mpResult.Provider)
		gossipMeter = mpResult.Provider.Meter("github.com/clearcompass-ai/ledger/gossip")

		// — Install the api/ error counter so every
		// writeTypedError / writeTypedJSONError site emits a
		// typed error_class attribute. Idempotent on the same
		// meter; no-op if already installed.
		apiMeter := mpResult.Provider.Meter("github.com/clearcompass-ai/ledger/api")
		if installed := api.InstallErrorCounter(apiMeter); !installed {
			logger.Warn("metrics: api error counter not installed (already wired?)")
		} else {
			logger.Info("metrics: api error counter installed",
				"metric", "attesta_api_errors_total")
		}

		metricsHandler = mpResult.PrometheusHandler
		meterShutdown = mpResult.Shutdown
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := meterShutdown(ctx); err != nil {
				logger.Warn("metrics: shutdown", "error", err)
			}
		}()
		logger.Info("metrics: enabled",
			"endpoint", "/metrics",
			"environment", cfg.MetricsEnvironment,
			"service_version", cfg.ServiceVersion,
		)
	} else {
		logger.Info("metrics: disabled (LEDGER_METRICS_ENABLE=false)")
	}

	// ── Gossip wiring (BadgerStore + handler + feed + sink) ──────────
	//
	// Co-tenants the WAL's Badger handle under a distinct keyspace
	// prefix (gossipstore/keyspace.go uses 0x07 vs WAL's 0x01..0x06).
	// Mounted iff:
	//   - LEDGER_GOSSIP_DISABLE != "true", and
	//   - NetworkID is non-zero (witness mode active OR the ledger
	//     has loaded a network bootstrap document).
	//
	// Built BEFORE the witness cosigner so HeadSync can reference
	// the gossip Sink as its CosignedHeadPublisher (W6 — fan out
	// every K-of-N tree head as a KindCosignedTreeHead event).
	var (
		gossipBundle *gossipnet.Bundle
		gossipBStore *gossipstore.BadgerStore
		gossipPostH http.Handler
		gossipFeedH http.Handler
		gossipPublisher *gossipnet.STHPublisher
	)
	var zeroNetID cosign.NetworkID
	if !cfg.GossipDisable && cfg.NetworkID != zeroNetID {
		gossipBStore, err = gossipstore.New(gossipstore.Config{DB: walDB})
		if err != nil {
			logger.Error("gossipstore open", "error", err)
			os.Exit(1)
		}
		gossipBundle, err = gossipnet.Build(gossipnet.Config{
			Store:         gossipBStore,
			NetworkID:     cfg.NetworkID,
			PeerEndpoints: cfg.GossipPeerEndpoints,
			Meter:         gossipMeter,
			Logger:        logger,
		})
		if err != nil {
			logger.Error("gossipnet build", "error", err)
			os.Exit(1)
		}
		gossipPostH = gossipBundle.PostHandler
		gossipFeedH = gossipBundle.FeedHandler

		// STH publisher: signs KindCosignedTreeHead events under the
		// ledger's own DID + signing key (the same key used to
		// sign admitted entries; cosign Purpose separation keeps
		// these signing roles non-replayable across one another).
		gossipPublisher, err = gossipnet.NewSTHPublisher(gossipnet.PublisherConfig{
			Store:          gossipBStore,
			Sink:           gossipBundle.Sink,
			Signer:         cosign.NewECDSAWitnessSigner(ledgerSignerPriv),
			NetworkID:      cfg.NetworkID,
			Originator:     cfg.LedgerDID,
			LedgerEndpoint: cfg.ServerAddr,
			Logger:         logger,
		})
		if err != nil {
			logger.Error("gossip STH publisher", "error", err)
			os.Exit(1)
		}

		// Shutdown ordering: drain sink → close handlers → close
		// store. The underlying *badger.DB is owned by wal.Open
		// (the existing defer above closes it last).
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, c := range gossipBundle.Closeables {
				_ = c.Close(ctx)
			}
			_ = gossipBStore.Close(ctx)
		}()

		// gossipWG drains the async goroutines (anti-entropy,
		// equivocation monitor, equivocation scanner) BEFORE
		// the store close defer above fires. Defer-LIFO
		// guarantees the order: cancels signal first → Wait
		// blocks until goroutines exit → store closes safely.
		// Without this, gossipBStore.Close could race a still-
		// running scanner.SubscribeSplitIDIndex callback.
		var gossipWG sync.WaitGroup
		defer gossipWG.Wait()

		logger.Info("gossip endpoints mounted",
			"post_path", "/v1/gossip",
			"feed_path_prefix", "/v1/gossip/",
			"peers", len(cfg.GossipPeerEndpoints),
		)

		// ── Anti-entropy catchup loop (optional) ─────────────────────
		//
		// Pulls peer events we missed via the read-side feed.
		// Disabled when LEDGER_GOSSIP_PEER_DIDS is empty or
		// length-mismatched against LEDGER_GOSSIP_PEER_ENDPOINTS.
		if len(cfg.GossipPeerDIDs) > 0 && len(cfg.GossipPeerDIDs) == len(cfg.GossipPeerEndpoints) {
			peers := make([]gossipnet.AntiEntropyPeer, 0, len(cfg.GossipPeerDIDs))
			for i, did := range cfg.GossipPeerDIDs {
				peers = append(peers, gossipnet.AntiEntropyPeer{
					DID:     did,
					BaseURL: cfg.GossipPeerEndpoints[i],
				})
			}
			ae, aerr := gossipnet.NewAntiEntropy(gossipnet.AntiEntropyConfig{
				Store:  gossipBStore,
				Peers:  peers,
				Logger: logger,
			})
			if aerr != nil {
				logger.Error("anti-entropy construction", "error", aerr)
				os.Exit(1)
			}
			aeCtx, aeCancel := context.WithCancel(ctx)
			gossipWG.Add(1)
			go func() {
				defer gossipWG.Done()
				if rerr := ae.Run(aeCtx); rerr != nil && !errors.Is(rerr, context.Canceled) {
					logger.Warn("anti-entropy: exited with error", "error", rerr)
				}
			}()
			defer aeCancel()
			logger.Info("anti-entropy: enabled", "peers", len(peers))
		} else if len(cfg.GossipPeerDIDs) > 0 {
			logger.Warn("anti-entropy: disabled (peer DID/endpoint length mismatch)",
				"dids", len(cfg.GossipPeerDIDs),
				"endpoints", len(cfg.GossipPeerEndpoints))
		}

		// ── Equivocation monitor (optional) ──────────────────────────
		//
		// Compares each peer's view of their own STH against our
		// local view. On (size-equal, root-different) divergence
		// the SDK's witness.DetectEquivocation(headA, headB, set)
		// verifies both heads against the *cosign.WitnessKeySet
		// (K-of-N read from set.Quorum()), finding.Verify(set)
		// returns nil to clear the publish gate, and the
		// EquivocationPublisher fans the finding out to peers as a
		// KindEquivocationFinding gossip event.
		//
		// Disabled when:
		//   - GenesisWitnessSet is empty (no witness keys to verify
		//     against — bootstrap doc not loaded)
		//   - peer DID/endpoint pairs are not configured
		//   - publisher is not wired (gossip disabled / no signer)
		if len(cfg.GenesisWitnessSet) > 0 &&
			len(cfg.GossipPeerDIDs) > 0 &&
			len(cfg.GossipPeerDIDs) == len(cfg.GossipPeerEndpoints) &&
			gossipPublisher != nil {
			witnessKeys, werr := gossipnet.WitnessKeysFromDIDs(cfg.GenesisWitnessSet)
			if werr != nil {
				logger.Error("equivocation monitor: witness key resolution",
					"error", werr)
				os.Exit(1)
			}
			// v0.1.1: build *cosign.WitnessKeySet once at boot;
			// keys + NetworkID + K-of-N quorum + BLS verifier are
			// encapsulated topology, not separate per-call args.
			witnessSet, wsErr := cosign.NewWitnessKeySet(
				witnessKeys,
				cfg.NetworkID,
				cfg.WitnessQuorumK,
				cosign.NewProductionBLSVerifier(),
			)
			if wsErr != nil {
				logger.Error("equivocation monitor: NewWitnessKeySet failed",
					"error", wsErr,
					"keys", len(witnessKeys),
					"quorum_k", cfg.WitnessQuorumK)
				os.Exit(1)
			}
			equivPub, perr := gossipnet.NewEquivocationPublisher(gossipnet.EquivocationPublisherConfig{
				Store:      gossipBStore,
				Sink:       gossipBundle.Sink,
				Signer:     cosign.NewECDSAWitnessSigner(ledgerSignerPriv),
				NetworkID:  cfg.NetworkID,
				Originator: cfg.LedgerDID,
				Logger:     logger,
			})
			if perr != nil {
				logger.Error("equivocation publisher", "error", perr)
				os.Exit(1)
			}
			equivPeers := make([]gossipnet.AntiEntropyPeer, 0, len(cfg.GossipPeerDIDs))
			for i, did := range cfg.GossipPeerDIDs {
				equivPeers = append(equivPeers, gossipnet.AntiEntropyPeer{
					DID:     did,
					BaseURL: cfg.GossipPeerEndpoints[i],
				})
			}
			eqMon, eerr := gossipnet.NewEquivocationMonitor(gossipnet.EquivocationMonitorConfig{
				Store:      gossipBStore,
				Peers:      equivPeers,
				WitnessSet: witnessSet,
				Publisher:  equivPub,
				Logger:     logger,
			})
			if eerr != nil {
				logger.Error("equivocation monitor", "error", eerr)
				os.Exit(1)
			}
			eqCtx, eqCancel := context.WithCancel(ctx)
			gossipWG.Add(1)
			go func() {
				defer gossipWG.Done()
				if rerr := eqMon.Run(eqCtx); rerr != nil && !errors.Is(rerr, context.Canceled) {
					logger.Warn("equivocation monitor: exited with error", "error", rerr)
				}
			}()
			defer eqCancel()
			logger.Info("equivocation monitor: enabled",
				"peers", len(equivPeers),
				"quorum_k", witnessSet.Quorum(),
				"witness_set_size", witnessSet.Size(),
			)
		} else {
			logger.Info("equivocation monitor: disabled (missing prerequisites)",
				"genesis_witness_set", len(cfg.GenesisWitnessSet),
				"peer_dids", len(cfg.GossipPeerDIDs),
				"peer_endpoints", len(cfg.GossipPeerEndpoints),
				"publisher_wired", gossipPublisher != nil,
			)
		}

		// ── EquivocationScanner (entry-level) ───────────────────────
		//
		// Independent goroutine subscribed to the splitid index
		// (Badger prefix 0x0A). The sequencer writes one entry
		// per commit; the scanner detects collisions (≥ 2 entries
		// at the same (schema_id, split_id)) and publishes a
		// verified KindEntryCommitmentEquivocation event.
		//
		// Hot-path isolation: this runs on its OWN goroutine,
		// never on the admission or sequencer pools. Detection
		// adds zero overhead to the SCT-return latency.
		if gossipBStore != nil && gossipBundle != nil {
			scanner, scerr := gossipnet.NewEquivocationScanner(
				gossipnet.EquivocationScannerConfig{
					Store:       gossipBStore,
					GossipStore: gossipBStore,
					Sink:        gossipBundle.Sink,
					Signer:      cosign.NewECDSAWitnessSigner(ledgerSignerPriv),
					NetworkID:   cfg.NetworkID,
					Originator:  cfg.LedgerDID,
					Logger:      logger,
				})
			if scerr != nil {
				logger.Error("equivocation scanner construction", "error", scerr)
				os.Exit(1)
			}
			scanCtx, scanCancel := context.WithCancel(ctx)
			gossipWG.Add(1)
			go func() {
				defer gossipWG.Done()
				if rerr := scanner.Run(scanCtx); rerr != nil &&
					!errors.Is(rerr, context.Canceled) {
					logger.Warn("equivocation scanner: exited with error", "error", rerr)
				}
			}()
			defer scanCancel()
			logger.Info("equivocation scanner: enabled (subscribed to splitid index 0x0A)")
		}
	} else if cfg.GossipDisable {
		logger.Info("gossip disabled (LEDGER_GOSSIP_DISABLE=true)")
	} else {
		logger.Info("gossip disabled (NetworkID unset; load network bootstrap)")
	}

	var cosigner builder.WitnessCosigner
	if len(cfg.WitnessEndpoints) > 0 {
		var pub witness.CosignedHeadPublisher
		if gossipPublisher != nil {
			pub = gossipPublisher
		}
		hs, err := witness.NewHeadSync(witness.HeadSyncConfig{
			WitnessEndpoints:  cfg.WitnessEndpoints,
			QuorumK:           cfg.WitnessQuorumK,
			PerWitnessTimeout: 30 * time.Second,
			NetworkID:         cfg.NetworkID,
			GossipPublisher:   pub,
		}, treeHeadStore, logger)
		if err != nil {
			logger.Error("witness cosigner construction failed", "error", err)
			os.Exit(1)
		}
		cosigner = hs
		logger.Info("witness cosigner: HeadSync requester enabled",
			"endpoints", cfg.WitnessEndpoints,
			"quorum_k", cfg.WitnessQuorumK,
			"gossip_publisher", gossipPublisher != nil,
		)
	} else {
		logger.Info("witness cosigner: disabled (LEDGER_WITNESS_ENDPOINTS unset)")
	}

	// ── Escrow override service (optional) ──────────────────────────
	//
	// Wired iff the witness cosigner is enabled (so we have a
	// K-of-N collector to share) AND gossip is enabled (so we can
	// publish the cosigned authorization). Either prerequisite
	// missing → no /v1/escrow-override endpoint mounted.
	var escrowOverrideHandler http.HandlerFunc
	if cosigner != nil && gossipBundle != nil && gossipPublisher != nil {
		hs, ok := cosigner.(*witness.HeadSync)
		if !ok || hs.Collector() == nil {
			logger.Warn("escrow override: skipped (cosigner has no Collector exposure)")
		} else {
			escrowSvc, eerr := gossipnet.NewEscrowOverrideService(gossipnet.EscrowOverrideServiceConfig{
				Collector:  hs.Collector(),
				Store:      gossipBStore,
				Sink:       gossipBundle.Sink,
				Signer:     cosign.NewECDSAWitnessSigner(ledgerSignerPriv),
				NetworkID:  cfg.NetworkID,
				Originator: cfg.LedgerDID,
				Logger:     logger,
			})
			if eerr != nil {
				logger.Error("escrow override service", "error", eerr)
				os.Exit(1)
			}
			escrowOverrideHandler = api.EscrowOverrideHandler(escrowSvc, logger)
			logger.Info("escrow override endpoint mounted at POST /v1/escrow-override")
		}
	}

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

	// ── Anchor publisher ──────────────────────────────────────────────
	anchorPub := anchor.NewPublisher(
		anchor.PublisherConfig{
			LedgerDID:     cfg.LedgerDID,
			LogDID:        cfg.LogDID,
			Interval:      cfg.AnchorInterval,
			AnchorSources: cfg.AnchorSources,
		},
		tesseraAdapter,
		signedSelfSubmit,
		logger,
	)

	// ── Submission handlers (v1 facade + v2 SCT) ──────────────────────
	// SubmissionDeps is shared between both endpoints: same fast-path
	// validation via prepareSubmission. v1 polls WAL for the
	// Sequencer to advance; v2 returns an SCT immediately.
	// Embedded-tree-head BLS quorum verifier.
	// Wired iff the genesis witness set is loaded (witness mode
	// active). Today the EntryEmbedsTreeHead detector returns
	// false for every schema, so this verifier is a no-op
	// on the entry surface; wiring it now means the moment a
	// schema starts embedding tree heads the K-of-N check fires
	// without an additional code change.
	var blsQuorumVerifier *admission.BLSQuorumVerifier
	if len(cfg.GenesisWitnessSet) > 0 && cfg.NetworkID != zeroNetID {
		witKeys, wkErr := gossipnet.WitnessKeysFromDIDs(cfg.GenesisWitnessSet)
		if wkErr != nil {
			logger.Error("admission BLS verifier: witness key resolution",
				"error", wkErr)
			os.Exit(1)
		}
		// v0.1.1: cosign.NewWitnessKeySet encapsulates keys +
		// NetworkID + LEDGER_WITNESS_QUORUM_K + BLS verifier.
		// admission.BLSQuorumVerifier takes one *cosign.WitnessKeySet;
		// the prior StaticWitnessKeySet wrapper is gone.
		admSet, ksErr := cosign.NewWitnessKeySet(
			witKeys,
			cfg.NetworkID,
			cfg.WitnessQuorumK,
			cosign.NewProductionBLSVerifier(),
		)
		if ksErr != nil {
			logger.Error("admission BLS verifier: build keyset",
				"error", ksErr,
				"keys", len(witKeys),
				"quorum_k", cfg.WitnessQuorumK)
			os.Exit(1)
		}
		blsQuorumVerifier = admission.NewBLSQuorumVerifier(admSet)
		logger.Info("admission: embedded-tree-head BLS verifier enabled",
			"witness_set_size", admSet.Size(),
			"quorum_k", admSet.Quorum(),
		)
	}

	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: entryStore,
			WAL:        walc,
			Tessera:    embeddedAppender, // unused by facade; kept for API symmetry
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			Credits:     creditStore,
			DIDResolver: sdkdid.NewECDSAKeyResolver(),
		},
		LedgerDID:          cfg.LedgerDID,
		LogDID:             cfg.LogDID,
		LedgerSignerPriv:   ledgerSignerPriv,
		MaxEntrySize:       cfg.MaxEntrySize,
		Logger:             logger,
		FreshnessTolerance: policy.FreshnessInteractive,
		BLSQuorumVerifier:  blsQuorumVerifier, // nil ⇒ check skipped
	}
	submitHandler := api.NewSubmissionHandler(submissionDeps)
	batchSubmitHandler := api.NewBatchSubmissionHandler(submissionDeps)
	mmdHandler := api.NewMMDHandler(cfg.MMD)

	// ── Shared stores for read handlers ───────────────────────────────
	// Query API also reads through the composite (WAL → bytestore
	// fallback) so query-by-* endpoints get the same routing as
	// the single-entry fetcher.
	queryAPI := indexes.NewPostgresQueryAPI(pool, compositeReader, cfg.LogDID)

	// ── Handler struct for api.Server ─────────────────────────────────
	queryDeps := &api.QueryDeps{
		EntryStore:     entryStore,
		QueryAPI:       queryAPI,
		DiffController: diffController,
		Logger:         logger,
		// WAL probe for the hash-lookup endpoint: returns
		// {state:pending} for entries durable in WAL but not yet
		// in entry_index (the SCT/MMD inflight window).
		WAL: walc,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore,
		Inclusion:     tesseraAdapter,
		Consistency:   tesseraAdapter,
		Logger:        logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher:    fetcher,
		QueryAPI:   queryAPI,
		EntryStore: entryStore,
		WAL:        walc,
		Presigner:  byteStore, // bytestore.Backend satisfies api.Presigner
		LogDID:     cfg.LogDID,
		Logger:     logger,
	}
	commitDeps := &api.DerivationCommitmentDeps{CommitmentStore: commitStore, Logger: logger}

	// ── Cryptographic commitment lookup (Pure CQRS — Badger 0x0C) ─────
	//
	// /v1/commitments/by-split-id is served from the 0x0C entry-lookup
	// projection populated by the sequencer at commit time. The
	// handler takes a types.CommitmentFetcher interface, NOT the
	// concrete Postgres-backed fetcher — so the api package's
	// transitive imports avoid pgx for this read path.
	//
	// Disabled when gossip storage is unavailable; the route returns
	// 404 in that case (api/server.go gates the mount on non-nil
	// CommitmentLookup).
	var commitmentLookupHandler http.HandlerFunc
	if gossipBStore != nil {
		commitmentLookupHandler = api.NewCommitmentLookupHandler(
			&api.CryptographicCommitmentDeps{
				Fetcher: gossipstore.NewBadgerCommitmentFetcher(gossipBStore),
				Logger:  logger,
			})
	}

	// ── Witness cosign endpoint (optional) ────────────────────────────
	//
	// Mounted only when LEDGER_WITNESS_KEY_FILE is set (or for local-
	// dev when no key is configured but the self-witness loop is
	// active — keeping things simple, we treat the file as the
	// gate). Peers POSTing to /v1/cosign get a signed tree head
	// back; api/server.go skips the route if WitnessCosign is nil.
	//
	// Type is http.Handler (interface) — NOT http.HandlerFunc.
	// A nil HandlerFunc assigned into a non-nil interface field
	// would survive the nil-guard in api/server.go (typed-nil
	// interface) and panic at mux.Handle("nil handler") at boot.
	var witnessHandler http.Handler
	if cfg.WitnessKeyFile != "" || len(cfg.WitnessEndpoints) > 0 {
		witnessKey, err := loadOrGenerateWitnessSigner(cfg.WitnessKeyFile, logger)
		if err != nil {
			logger.Error("witness signer", "error", err)
			os.Exit(1)
		}
		// Tree-head-only signing surface: the ledger's witness
		// role refuses to cosign rotation or escrow-override
		// payloads even though the SDK handler can serve them. A
		// dedicated rotation/override witness is a separate
		// deployment.
		witnessHandler, err = witness.BuildCosignHandler(witness.ServeConfig{
			WitnessKey: witnessKey,
			NetworkID:  cfg.NetworkID,
			AllowedPurposes: map[cosign.Purpose]struct{}{
				cosign.PurposeTreeHead: {},
			},
			Logger: logger,
		})
		if err != nil {
			logger.Error("witness cosign handler", "error", err)
			os.Exit(1)
		}
		logger.Info("witness cosign endpoint mounted at POST /v1/cosign")
	}

	handlers := api.Handlers{
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
		WitnessCosign:    witnessHandler, // nil unless LEDGER_WITNESS_KEY_FILE / endpoints configured
		GossipPost:       gossipPostH,    // nil unless gossip enabled + NetworkID set
		GossipFeed:       gossipFeedH,
		EscrowOverride:   escrowOverrideHandler, // nil unless witness mode + gossip both wired
		Metrics:          metricsHandler,        // nil unless LEDGER_METRICS_ENABLE=true
		EntryBySequence:  api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:       api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:         api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:          api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:     api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery:  api.NewDerivationCommitmentQueryHandler(commitDeps),
		CommitmentLookup: commitmentLookupHandler, // nil unless gossipBStore is wired
	}

	// ── Integrity Detector (periodic sample-verify) ──────────────────
	//
	// Read-only verifier: samples random sequences below HWM and
	// compares WAL.HashAt to Tessera.HashAt. On disagreement
	// (ErrDiverged) returns; the supervisor below converts that to
	// panic so the ledger stops serving before consumers see
	// corrupt proofs.
	//
	// Boot recovery used to live here (Reconcile) but the Sequencer
	// now subsumes that — its drainOnce on Run start picks up every
	// StatePending entry left from a crash.
	integAdapter := integrity.NewTesseraAdapter(tileReader)
	detector := integrity.NewDetector(
		walc,         // WALReader
		integAdapter, // Verifier
		integrity.DetectorConfig{Logger: logger},
	)

	// Boot reconciliation note: the deleted-in-commit-6 Reasserter
	// no longer exists. Boot recovery is now the Sequencer's
	// responsibility — its Run() drains StatePending immediately
	// before the first ticker tick, which catches every entry left
	// from a crashed previous boot.

	// ── Sequencer ────────────────────────────────────────────────────
	// Asynchronous WAL → Tessera → entry_index pipeline. Drains
	// StatePending entries continuously: AppendLeaf (antispam-
	// idempotent) → entry_index INSERT → wal.Sequence. Supports
	// the SCT/MMD architecture: /v1/entries admission returns an SCT
	// after WAL fsync; the Sequencer redeems within MMD.
	seq := sequencer.NewSequencer(walc, embeddedAppender, pool, entryStore, sequencer.Config{
		PollInterval: cfg.SequencerInterval,
		MaxInFlight:  cfg.SequencerMaxInFlight,
		Logger:       logger,
	})
	if gossipBStore != nil {
		// Wire the splitid index writer. Sequencer continues to
		// write Postgres commitment_split_id (existing read-path
		// consumers); ALSO writes the Badger 0x0A index that the
		// EquivocationScanner subscribes to.
		seq = seq.WithSplitIDIndex(
			gossipnet.NewSequencerSplitIDAdapter(gossipBStore))

		// Wire the entry-lookup projection writer (Pure CQRS —
		// P8). Every commitment-schema admission also writes a
		// 0x0C row carrying canonical_bytes + log_time_micros +
		// log_did so /v1/commitments/by-split-id serves O(1)
		// reads without touching Postgres.
		seq = seq.WithEntryLookup(
			gossipnet.NewSequencerEntryLookupAdapter(gossipBStore),
			cfg.LogDID)

		// Wire the boot replayer (— P3 + I9 + A4). On every
		// boot, the sequencer scans Postgres above the persisted
		// HWM (Badger 0x0D) and back-populates 0x0A + 0x0C for
		// any rows missing — closing the gap between the
		// Postgres source-of-truth and the best-effort Badger
		// projection writes that happen AFTER the Postgres
		// commit. Idempotent (writes are SET on the same key, value
		// the live admission path produces).
		replayer, rerr := sequencer.NewReplayer(sequencer.ReplayConfig{
			DB:           pool,
			Reader:       byteStore,
			SplitIDIndex: gossipnet.NewSequencerSplitIDAdapter(gossipBStore),
			EntryLookup:  gossipnet.NewSequencerEntryLookupAdapter(gossipBStore),
			Cursor:       gossipnet.NewSequencerReplayCursorAdapter(gossipBStore),
			LogDID:       cfg.LogDID,
			Logger:       logger,
		})
		if rerr != nil {
			logger.Error("sequencer replayer construct", "error", rerr)
			os.Exit(1)
		}
		seq = seq.WithReplayer(replayer)
	}
	logger.Info("sequencer ready",
		"poll_interval", cfg.SequencerInterval,
		"max_in_flight", cfg.SequencerMaxInFlight,
		"mmd", cfg.MMD,
		"splitid_index", gossipBStore != nil,
		"entry_lookup_projection", gossipBStore != nil,
		"boot_replayer", gossipBStore != nil,
	)

	// ── Shipper ──────────────────────────────────────────────────────
	// Migrates StateSequenced entries from the WAL to the byte store,
	// marks them StateShipped, advances HWM through contiguous runs.
	// Bytes durability is the load-bearing property: bytestore upload
	// completes BEFORE wal.MarkShipped runs, BEFORE HWM advances.
	ship := shipper.NewShipper(walc, byteStore, shipper.Config{Logger: logger})

	// ── HTTP server ───────────────────────────────────────────────────
	//
	// DoS-immune timeouts come from DefaultServerConfig (Slowloris
	// cap via ReadHeaderTimeout, keep-alive zombie cap via
	// IdleTimeout). TLS termination is in-binary when TLSCertFile +
	// TLSKeyFile are both populated; otherwise the binary speaks
	// plain HTTP and a TLS-terminating proxy (k8s ingress, sidecar)
	// is the operator's responsibility.
	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	serverCfg.MaxEntrySize = cfg.MaxEntrySize
	serverCfg.TLSCertFile = cfg.TLSCertFile
	serverCfg.TLSKeyFile = cfg.TLSKeyFile
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool), handlers, logger)

	// ── pprof on a private listener (optional) ───────────────────────
	//
	// Production-grade profiling: pprof MUST live on a separate
	// listener bound to a non-public address so the public HTTP
	// surface never exposes /debug/pprof. Empty PprofAddr disables.
	var pprofServer *http.Server
	if cfg.PprofAddr != "" {
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofServer = &http.Server{
			Addr:              cfg.PprofAddr,
			Handler:           pprofMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second, // CPU profiles take time
			IdleTimeout:       60 * time.Second,
		}
		logger.Info("pprof listener ready", "addr", cfg.PprofAddr)
	}

	// ── Goroutines + fatal supervisor ─────────────────────────────────
	//
	// Each long-running goroutine reports its terminal error to the
	// fatal channel. The supervisor below reads the FIRST error and
	// panics on it — the only place in the entire codebase that
	// panics deliberately. This is the infra-agnostic boundary:
	// process exit on fatal, orchestrator (k8s/systemd/bare-metal)
	// decides what's next.
	//
	// Distinguished from ctx.Done() (graceful shutdown via SIGTERM):
	// the supervisor closes ctx via the parent cancel before
	// panicking, giving other goroutines a chance to flush, but
	// the panic surfaces the originating error.
	fatal := make(chan error, 8)
	var wg sync.WaitGroup

	// ── Public HTTP listener (TLS-aware + LimitListener-capped) ─────
	//
	// The connection cap defends host physics independent of
	// per-request body size. A cap of 0 (LEDGER_MAX_CONCURRENT_CONNS
	// unset) defaults to 8 × runtime.NumCPU; production deployments
	// typically tune this to match their pod-side ulimits.
	connCap := cfg.MaxConcurrentConns
	if connCap <= 0 {
		connCap = 8 * runtime.NumCPU()
	}
	listenAddr := serverCfg.Addr
	rawListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Error("http listen", "addr", listenAddr, "error", err)
		os.Exit(1)
	}
	cappedListener := netutil.LimitListener(rawListener, connCap)
	logger.Info("http listener ready",
		"addr", listenAddr,
		"max_concurrent_conns", connCap,
		"tls", serverCfg.TLSCertFile != "" && serverCfg.TLSKeyFile != "",
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// In-binary TLS if both cert + key are configured.
		// Otherwise plain HTTP. HTTP/2 enablement is documented
		// in api/server.go::ListenAndServeTLS.
		if serverCfg.TLSCertFile != "" && serverCfg.TLSKeyFile != "" {
			// ServeTLS reuses the listener wrapped by
			// netutil.LimitListener, so the connection cap applies
			// to TLS-terminated traffic too. Manually call
			// http.Server.ServeTLS via a tiny adapter that
			// populates TLSConfig with explicit ALPN.
			if err := server.ServeTLSWithListener(cappedListener); err != nil {
				logger.Error("http server (tls)", "error", err)
			}
			return
		}
		if err := server.Serve(cappedListener); err != nil {
			logger.Error("http server", "error", err)
		}
	}()

	if pprofServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// pprof is bound to a private address (typically
			// 127.0.0.1:6060). Failure to bind is non-fatal —
			// pprof is diagnostic, not load-bearing.
			if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Warn("pprof server", "error", err)
			}
		}()
	}

	// All long-running goroutines are wrapped in lifecycle.SafeRun
	// for bounded panic recovery. A panic in any background loop
	// must surface to the fatal channel so the supervisor can
	// terminate the process cleanly — never crash the binary
	// silently. Mirrors the SDK's HTTP-handler self-encapsulating
	// recovery pattern.

	lifecycle.SafeRunInWG(ctx, &wg, "builder-loop", logger, fatal, func() error {
		if err := bl.Run(ctx); err != nil {
			logger.Error("builder loop exited with error", "error", err)
			return err
		}
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &wg, "difficulty-controller", logger, fatal, func() error {
		diffController.Run(ctx, 30*time.Second)
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &wg, "anchor-publisher", logger, fatal, func() error {
		anchorPub.Run(ctx)
		return nil
	})

	// Shipper: migrates WAL → bytestore. Returns ctx.Err() on shutdown
	// (not fatal); other errors are fatal.
	lifecycle.SafeRunInWG(ctx, &wg, "shipper", logger, fatal, func() error {
		if err := ship.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fatal <- fmt.Errorf("shipper: %w", err)
			return err
		}
		return nil
	})

	// Sequencer: drains WAL StatePending → entry_index. Returns
	// ctx.Err() on shutdown; any other return is fatal — without
	// the Sequencer running, v2 SCTs become unredeemable promises.
	lifecycle.SafeRunInWG(ctx, &wg, "sequencer", logger, fatal, func() error {
		if err := seq.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fatal <- fmt.Errorf("sequencer: %w", err)
			return err
		}
		return nil
	})

	// Integrity Detector loop: returns ErrDiverged on disagreement,
	// ctx.Err() on shutdown. Divergence is FATAL — must panic so
	// consumers stop seeing corrupt proofs.
	lifecycle.SafeRunInWG(ctx, &wg, "integrity-detector", logger, fatal, func() error {
		if err := detector.Loop(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			fatal <- fmt.Errorf("integrity detector: %w", err)
			return err
		}
		return nil
	})

	// ── Supervisor: shutdown OR fatal ────────────────────────────────
	//
	// Two exit paths:
	//   - ctx.Done(): graceful shutdown (SIGTERM/SIGINT). Cancel
	//     all goroutines, drain, exit cleanly with code 0.
	//   - fatal channel: a goroutine returned a non-recoverable
	//     error (Tessera divergence, shipper exhaustion, etc.).
	//     Cancel ctx so other goroutines unwind, then PANIC so
	//     the process exits non-zero and the orchestrator
	//     restart-loops (or escalates per its policy).
	var fatalErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown initiated (graceful)")
	case fatalErr = <-fatal:
		logger.Error("FATAL: ledger must terminate", "error", fatalErr)
		// Cancel ctx so other goroutines see the shutdown signal
		// and unwind. The panic below is what actually terminates
		// the process.
		cancel()
	}

	// ── Pre-drain handshake (B4) ──────────────────────────────────────
	//
	// Flip /readyz to 503 BEFORE httpServer.Shutdown so the load
	// balancer / k8s readiness probe sees the pod as not-ready and
	// removes it from rotation. Then sleep LEDGER_PREDRAIN_GRACE
	// (default 5s) so any in-flight readiness-probe-cycle resolves
	// against a 503 response. THEN call Shutdown which drains
	// in-flight requests.
	//
	// Without this handshake, in-flight HTTP requests can be cut at
	// SIGTERM if they arrive in the window between "process got
	// SIGTERM" and "load balancer removed pod from rotation."
	server.SetReady(false)
	preDrainGrace := envDurationOr("LEDGER_PREDRAIN_GRACE", 5*time.Second)
	if preDrainGrace > 0 {
		logger.Info("pre-drain grace started",
			"grace", preDrainGrace,
			"reason", "load-balancer-rotation-removal",
		)
		select {
		case <-time.After(preDrainGrace):
		case <-time.After(60 * time.Second):
			// Hard ceiling — never block shutdown indefinitely
			// even if env-var is misconfigured to a huge value.
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown", "error", err)
	}
	if pprofServer != nil {
		// pprof has no in-flight admission requests; quick close.
		pprofShutdownCtx, pprofShutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = pprofServer.Shutdown(pprofShutdownCtx)
		pprofShutdownCancel()
	}

	wg.Wait()

	b, e, errs := bl.Stats()
	logger.Info("ledger stopped",
		"batches", b, "entries", e, "errors", errs,
	)

	if fatalErr != nil {
		// Process-level termination on fatal — the only deliberate
		// panic in the entire codebase. The orchestrator (k8s,
		// systemd, bare metal) sees a non-zero exit and decides
		// what's next.
		panic(fmt.Errorf("ledger FATAL: %w", fatalErr))
	}
}
