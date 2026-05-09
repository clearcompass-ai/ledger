//go:build soak
// +build soak

/*
FILE PATH: tests/soak_test.go

High-volume ledger soak test against a real cloud bytestore.
Build-tag-isolated so the default `go test ./...` run never invokes
it — soak runs are minutes-long and cost real cloud spend. Opt-in via:

	ATTESTA_TEST_DSN=postgres://...                        \
	ATTESTA_TEST_GCS_BUCKET=attesta-soak-<your-instance>  \
	GOOGLE_APPLICATION_CREDENTIALS=...                      \
	go test -tags=soak ./tests/ -run TestSoak -v -count=1 -timeout 30m

OR via scripts/run-soak.sh which sets the env wrappers up and reports
a JSON summary at the end.

WHAT IT MEASURES:

	Throughput: aggregate entries/sec sustained across N concurrent
	submitter goroutines.

	Backlog drain: at the end of the submission burst, time-to-drain
	the shipper's StateSequenced backlog to zero. This is the
	load-bearing property the WAL+Shipper architecture promises —
	admission stays fast under sustained load because the slow part
	(bytestore upload) is asynchronous.

	Admission p50/p99: per-request HTTP-layer latency. p99 must stay
	under a configurable bound (default 100ms); regressions surface
	as p99 inflation even when p50 is unchanged.

	Final integrity: a random sample of submitted (seq, hash) pairs is
	reachable via GET /v1/entries/{seq}/raw → 302 → bytes match canonical.

CONFIG VIA ENV (with defaults):

	ATTESTA_SOAK_ENTRIES               total entries to submit (default 1_000_000)
	ATTESTA_SOAK_CONCURRENCY           concurrent submitters (default 8)
	ATTESTA_SOAK_VERIFY_SAMPLES        sample of entries to /raw-check at the end.
	                                   Accepts an absolute count ("100") OR a percentage
	                                   of submitted entries ("5%", "0.5%"). Default 100.
	ATTESTA_SOAK_TREE_PROOF_SAMPLES    sample of inclusion proofs to verify against
	                                   /v1/tree/head root via merkle/proof. Same shape
	                                   as VERIFY_SAMPLES. Default 100.
	ATTESTA_SOAK_P99_BOUND_MS          HTTP admission p99 ceiling, ms (default 100)
	ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT shipper worker pool size (default 16)
	                                   Drain rate ≈ MaxInFlight / per-upload-latency.
	                                   Bump for higher-volume soaks where the
	                                   default 16 × ~113ms per ship = ~141/sec
	                                   ceiling can't drain the backlog within
	                                   the budget.
	ATTESTA_SOAK_DRAIN_TIMEOUT         in-test wait for WAL HWM to reach
	                                   submitted count (default 10m).
	                                   Accepts time.ParseDuration values
	                                   ("30s", "10m", "1h", "1h30m").

The defaults model a 100k-entry soak. The 1M run benefits from
ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT=64 + ATTESTA_SOAK_DRAIN_TIMEOUT=30m.
*/
package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/sequencer"
	"github.com/clearcompass-ai/ledger/shipper"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	"github.com/clearcompass-ai/ledger/wal"
)

// newTunedHTTPClient returns an *http.Client whose Transport is
// keep-alive-friendly under the soak's connection density.
//
// EVIDENCE-BASED RATIONALE:
//
//	Default http.Transport caps MaxIdleConnsPerHost at 2. Under 8
//	admission workers × ~590 req/sec to a single host, the pool
//	churns: every request opens, returns, and the 3rd+ idle conn
//	closes — the kernel parks the closed socket in TIME_WAIT
//	(~15-30s on macOS/Linux) and burns one ephemeral port.
//
//	macOS ephemeral range is 49152-65535 (~16,384 ports). At
//	~5,360 closing conns/sec the pool drains in ~3s and the soak
//	starts failing with "dial tcp: bind: address already in use"
//	or "connect: cannot assign requested address".
//
//	MaxIdleConnsPerHost=256 lets the worker pool fully reuse
//	connections; MaxIdleConns=512 caps the global idle set;
//	IdleConnTimeout stays at the default 90s so idle conns are
//	eventually reaped without thrashing.
func newTunedHTTPClient(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 512
	t.MaxIdleConnsPerHost = 256
	return &http.Client{Transport: t, Timeout: timeout}
}

// newTunedNoRedirectClient mirrors newTunedHTTPClient but disables
// auto-follow on redirects, so the verify pass can inspect Location
// headers directly without burning the redirect target connection.
func newTunedNoRedirectClient(timeout time.Duration) *http.Client {
	c := newTunedHTTPClient(timeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

// soakSubmission records one accepted entry for the post-soak verify
// pass. We hold ONLY the canonical hash because POST /v1/entries
// returns an SCT (Signed Certificate Timestamp), NOT a sequence
// number — sequencing is asynchronous in this transparency-log
// design. The verify pass resolves hash→seq via
// GET /v1/entries-hash/{hash} before fetching the raw bytes.
type soakSubmission struct {
	hash [32]byte
}

// ─────────────────────────────────────────────────────────────────────
// soakLedger — real-GCS variant of e2eLedger
// ─────────────────────────────────────────────────────────────────────

type soakLedger struct {
	BaseURL   string
	Pool      *pgxpool.Pool
	WAL       *wal.Committer
	Backend   opbytestore.Backend
	Sequencer *sequencer.Sequencer
	Shipper   *shipper.Shipper
	cancel    context.CancelFunc
}

func startSoakLedger(t *testing.T) *soakLedger {
	t.Helper()

	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping soak test")
	}

	// Backend selection — default "gcs" preserves existing soak behavior.
	// "s3" routes to the bytestore.S3 adapter (works for SeaweedFS,
	// RustFS, MinIO, AWS S3 — anything that speaks SigV4). When the
	// backend is s3, the soak reads endpoint + creds from
	// ATTESTA_TEST_S3_* env vars and the bucket from
	// ATTESTA_TEST_S3_BUCKET (instead of ATTESTA_TEST_GCS_BUCKET).
	backendType := os.Getenv("ATTESTA_SOAK_BYTESTORE_BACKEND")
	if backendType == "" {
		backendType = "gcs"
	}

	var bucket string
	switch backendType {
	case "gcs":
		bucket = os.Getenv("ATTESTA_TEST_GCS_BUCKET")
		if bucket == "" {
			t.Skip("ATTESTA_TEST_GCS_BUCKET not set — skipping soak test")
		}
	case "s3":
		bucket = os.Getenv("ATTESTA_TEST_S3_BUCKET")
		if bucket == "" {
			t.Skip("ATTESTA_TEST_S3_BUCKET not set — skipping soak test")
		}
	default:
		t.Fatalf("ATTESTA_SOAK_BYTESTORE_BACKEND=%q unsupported (gcs|s3)", backendType)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("pgxpool: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		cancel()
		t.Fatalf("migrations: %v", err)
	}

	// Schema-drift defender. Ran once at boot, before cleanTables
	// or any reads. If a future migration renames or drops any of
	// the columns verifyEvidence queries, this fails LOUDLY at
	// boot — long before the bulk submission burst — instead of
	// 19 seconds in with a SQLSTATE 42703.
	//
	// The columns asserted here are exactly the ones the soak's
	// query path references: SELECT, MIN/MAX, ORDER BY. Anything
	// the soak doesn't read isn't asserted (those drift-defenders
	// belong to whatever code does read them).
	assertEntryIndexSchema(t, ctx, pool)

	cleanTables(t, pool)

	walDB, err := wal.OpenInMemory(nil)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("wal: %v", err)
	}
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{DisableSync: true})

	prefix := fmt.Sprintf("soak/%d", time.Now().UnixNano())
	bsConfig := opbytestore.Config{
		Backend: backendType,
		Bucket:  bucket,
		Prefix:  prefix,
	}
	if backendType == "s3" {
		bsConfig.S3Endpoint = os.Getenv("ATTESTA_TEST_S3_ENDPOINT")
		bsConfig.S3AccessKey = os.Getenv("ATTESTA_TEST_S3_ACCESS_KEY")
		bsConfig.S3SecretKey = os.Getenv("ATTESTA_TEST_S3_SECRET_KEY")
		bsConfig.S3Region = os.Getenv("ATTESTA_TEST_S3_REGION")
		if bsConfig.S3Region == "" {
			bsConfig.S3Region = "us-east-1"
		}
		// SeaweedFS, RustFS, MinIO all use path-style addressing
		// (https://endpoint/bucket/key vs https://bucket.endpoint/key).
		// AWS S3 is virtual-host-style; if you ever point soak at
		// real AWS, set ATTESTA_TEST_S3_PATH_STYLE=false.
		if os.Getenv("ATTESTA_TEST_S3_PATH_STYLE") != "false" {
			bsConfig.S3PathStyle = true
		}
	}
	backend, err := opbytestore.NewFromConfig(ctx, bsConfig)
	if err != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("bytestore.NewFromConfig: %v", err)
	}

	composite := store.NewCompositeByteReader(walc, backend, logger)
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	sequenceCursor := store.NewSequenceCursor(pool)
	fetcher := store.NewPostgresEntryFetcher(pool, composite, testLogDID)
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, composite, testLogDID)

	// Real Tessera in t.TempDir(). Soak test has no builder loop —
	// it exercises admission + sequencer + shipper. We hold the
	// harness for its Adapter/Embedded handles; cosigner is unused
	// here but the fixture is cheap.
	soakHarness := newWitnessedTestHarness(t, ctx, pool, logger)
	merkle := soakHarness.Embedded
	diffController := middleware.NewDifficultyController(
		sequenceCursor, middleware.DefaultDifficultyConfig(), logger,
	)

	opSignerPriv, err := signatures.GenerateKey()
	if err != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("ledger signer key: %v", err)
	}
	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: entryStore, WAL: walc, Tessera: merkle,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    testEpochWindowSeconds,
			EpochAcceptanceWindow: testEpochAcceptanceWindow,
		},
		Identity:         api.IdentityDeps{Credits: creditStore, DIDResolver: nil},
		LogDID:           testLogDID,
		LedgerDID:        testLedgerDID,
		LedgerSignerPriv: opSignerPriv,
		MaxEntrySize:     1 << 20,
		Logger:           logger,
	}
	queryDeps := &api.QueryDeps{
		EntryStore:     entryStore, // hash → seq lookup (FetchByHash)
		QueryAPI:       queryAPI,
		DiffController: diffController,
		WAL:            walc, // WAL probe (Pending/Manual short-circuit)
		Logger:         logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI, EntryStore: entryStore,
		WAL: walc, LogDID: testLogDID, Logger: logger,
		// Transparency-log convention (RFC 9162, c2sp.org/tlog-tiles):
		// the architecture has only one read path — bucket is
		// anonymous-read, 302 handler returns credential-free URLs.
		// The soak's verify pass HARD-ASSERTS no signature query
		// params, catching any regression that injects credentials.
		PublicURLer: backend.(api.PublicURLer),
	}

	handlers := api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryRaw:        api.NewRawEntryHandler(entryReadDeps),
		// EntryByHash wires GET /v1/entries-hash/{hashHex}, which the
		// soak verify pass needs to resolve hash→seq before fetching
		// /v1/entries/{seq}/raw. Without this handler, the route 404s
		// and resolveSeqByHash times out.
		EntryByHash: api.NewHashLookupHandler(queryDeps),
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = "127.0.0.1:0"
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool), handlers, logger)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("listen: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	// Sequencer: WAL StatePending → entry_index INSERT + Tessera append
	// → WAL StateSequenced. Without this goroutine the WAL stays
	// at StatePending indefinitely; the shipper's HWM never advances
	// past 0; the drain wait below times out at 10 minutes.
	// Mirrors startE2ELedger in e2e_shipper_redirect_test.go.
	seq := sequencer.NewSequencer(walc, merkle, pool, entryStore, sequencer.Config{
		PollInterval: 10 * time.Millisecond,
		Logger:       logger,
	})

	// Shipper: WAL StateSequenced → bytestore upload → WAL StateShipped.
	// MaxInFlight is the worker-pool size for parallel GCS uploads.
	// Default 16 matches production cmd/ledger; bump via
	// ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT for high-volume soaks where
	// real-GCS upload latency × workers is the drain bottleneck.
	maxInFlight := envInt("ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT", 16)
	ship := shipper.NewShipper(walc, backend, shipper.Config{
		PollInterval: 100 * time.Millisecond,
		MaxInFlight:  maxInFlight,
		Logger:       logger,
	})

	go func() { _ = server.Serve(ln) }()
	go func() { _ = seq.Run(ctx) }()
	go func() { _ = ship.Run(ctx) }()

	op := &soakLedger{
		BaseURL: baseURL, Pool: pool, WAL: walc,
		Backend: backend, Sequencer: seq, Shipper: ship, cancel: cancel,
	}

	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
		_ = walc.Close()
		_ = walDB.Close()
		// ATTESTA_SOAK_KEEP_DATA=1 preserves the populated entry_index
		// + bytestore objects after the test exits, so the operator
		// can inspect them with their own SQL / S3 tooling. Default
		// (unset) cleans tables on teardown — same behavior soaks
		// have always had — so back-to-back runs start clean.
		if os.Getenv("ATTESTA_SOAK_KEEP_DATA") != "" {
			t.Logf("ATTESTA_SOAK_KEEP_DATA set — skipping cleanTables. " +
				"entry_index + bytestore objects preserved for manual inspection. " +
				"Run `./scripts/run-soak.sh down` when done.")
		} else {
			cleanTables(t, pool)
		}
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
	t.Fatal("soak ledger did not become ready in 2.5s")
	return nil
}

func (op *soakLedger) seedSoakSession(t *testing.T, token, exchangeDID string, credits int64) {
	t.Helper()
	ctx := context.Background()
	_, err := op.Pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO NOTHING`,
		token, exchangeDID, time.Now().UTC().Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if credits > 0 {
		cs := store.NewCreditStore(op.Pool)
		if _, err := cs.BulkPurchase(ctx, exchangeDID, credits); err != nil {
			t.Fatalf("seed credits: %v", err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Latency sampler — reservoir with quantile readout
// ─────────────────────────────────────────────────────────────────────

type latencySampler struct {
	mu      sync.Mutex
	samples []time.Duration
	cap     int
	seen    int
	rng     *rand.Rand
}

func newLatencySampler(capacity int) *latencySampler {
	return &latencySampler{
		samples: make([]time.Duration, 0, capacity),
		cap:     capacity,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *latencySampler) add(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen++
	if len(s.samples) < s.cap {
		s.samples = append(s.samples, d)
		return
	}
	// Reservoir sampling: bound memory at any throughput.
	j := s.rng.Intn(s.seen)
	if j < s.cap {
		s.samples[j] = d
	}
}

func (s *latencySampler) quantiles() (p50, p99 time.Duration) {
	s.mu.Lock()
	cp := make([]time.Duration, len(s.samples))
	copy(cp, s.samples)
	s.mu.Unlock()
	if len(cp) == 0 {
		return 0, 0
	}
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	p50 = cp[len(cp)*50/100]
	p99 = cp[len(cp)*99/100]
	return p50, p99
}

// ─────────────────────────────────────────────────────────────────────
// TestSoak_LedgerBytestore — primary soak test.
//
// Backend-agnostic: routes to gcs / seaweedfs / s3 based on the env
// vars that scripts/run-soak.sh exports. Scale-agnostic: defaults to
// 1M entries but ATTESTA_SOAK_ENTRIES tunes it down to a smoke run
// (1k) or up to a multi-million stress run.
// ─────────────────────────────────────────────────────────────────────

func TestSoak_LedgerBytestore(t *testing.T) {
	op := startSoakLedger(t)
	op.seedSoakSession(t, "tok-soak", "did:example:soak-exchange", 100_000_000)

	total := envInt("ATTESTA_SOAK_ENTRIES", 1_000_000)
	concurrency := envInt("ATTESTA_SOAK_CONCURRENCY", 8)
	verifySamples := envSampleCount("ATTESTA_SOAK_VERIFY_SAMPLES", 100, uint64(total))
	p99BoundMs := envInt("ATTESTA_SOAK_P99_BOUND_MS", 100)
	// Re-read here for the unified config log line; the actual values
	// are also read where they're used (startSoakLedger for
	// MaxInFlight, drain loop for drainTimeout).
	maxInFlightLog := envInt("ATTESTA_SOAK_SHIPPER_MAX_IN_FLIGHT", 16)
	drainTimeoutLog := envDuration("ATTESTA_SOAK_DRAIN_TIMEOUT", 10*time.Minute)

	t.Logf("soak config: entries=%d concurrency=%d verify_samples=%d p99_bound_ms=%d "+
		"shipper_max_in_flight=%d drain_timeout=%s",
		total, concurrency, verifySamples, p99BoundMs,
		maxInFlightLog, drainTimeoutLog)

	resultCh := make(chan soakSubmission, 4096)
	sampler := newLatencySampler(50_000)

	var submitted atomic.Uint64
	var failed atomic.Uint64

	// First-N failure diagnostics. Captures HTTP status + body for the
	// first MaxFailureSamples failures so a soak run that submits
	// zero entries surfaces the rejection reason directly in test
	// output instead of "10000 failed" with no shape.
	const maxFailureSamples = 5
	var (
		failureMu      sync.Mutex
		failureSamples int
	)
	logFailure := func(stage string, status int, body []byte, err error) {
		failureMu.Lock()
		defer failureMu.Unlock()
		if failureSamples >= maxFailureSamples {
			return
		}
		failureSamples++
		const maxBodyBytes = 512
		bodyTrim := body
		if len(bodyTrim) > maxBodyBytes {
			bodyTrim = bodyTrim[:maxBodyBytes]
		}
		t.Logf("FAILURE_SAMPLE[%d/%d] stage=%s status=%d err=%v body=%q",
			failureSamples, maxFailureSamples, stage, status, err, bodyTrim)
	}

	per := total / concurrency
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			client := newTunedHTTPClient(30 * time.Second)
			for i := 0; i < per; i++ {
				idx := workerID*per + i
				wire := buildWireEntry(t, envelope.ControlHeader{
					SignerDID: "did:example:soak-signer",
				}, []byte(fmt.Sprintf("soak-%010d", idx)))

				reqStart := time.Now()
				req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
				req.Header.Set("Authorization", "Bearer tok-soak")
				resp, err := client.Do(req)
				if err != nil {
					logFailure("client.Do", 0, nil, err)
					failed.Add(1)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusAccepted {
					logFailure("non-202", resp.StatusCode, body, nil)
					failed.Add(1)
					continue
				}
				sampler.add(time.Since(reqStart))

				hash, ok := parseSCTCanonicalHash(body)
				if !ok {
					logFailure("parse-202-body", resp.StatusCode, body, nil)
					failed.Add(1)
					continue
				}
				submitted.Add(1)
				select {
				case resultCh <- soakSubmission{hash: hash}:
				default:
				}
			}
		}(w)
	}

	progressCtx, stopProgress := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressCtx.Done():
				return
			case <-ticker.C:
				p50, p99 := sampler.quantiles()
				t.Logf("progress: submitted=%d failed=%d elapsed=%s p50=%s p99=%s",
					submitted.Load(), failed.Load(), time.Since(start).Round(time.Second),
					p50, p99,
				)
			}
		}
	}()
	wg.Wait()
	stopProgress()
	close(resultCh)

	submitDuration := time.Since(start)
	t.Logf("submission complete: %d ok, %d failed, %s elapsed (%.0f entries/s)",
		submitted.Load(), failed.Load(), submitDuration.Round(time.Second),
		float64(submitted.Load())/submitDuration.Seconds(),
	)

	if submitted.Load() == 0 {
		t.Fatal("zero entries submitted — soak did not run")
	}

	p50, p99 := sampler.quantiles()
	t.Logf("admission latency: p50=%s p99=%s", p50, p99)
	if p99 > time.Duration(p99BoundMs)*time.Millisecond {
		t.Errorf("admission p99=%s exceeds bound %dms", p99, p99BoundMs)
	}

	expectedHWM := submitted.Load()
	// Drain budget. Default 10m fits a 50k-100k-entry soak with the
	// in-flight-dedupe fix. Higher-volume soaks (1M+) need a larger
	// budget — at MaxInFlight=16 and ~113ms per ship, drain ceiling
	// is ~141 entries/sec, so 1M backlog needs ~2h. Override via
	// ATTESTA_SOAK_DRAIN_TIMEOUT (any time.ParseDuration value).
	drainTimeout := envDuration("ATTESTA_SOAK_DRAIN_TIMEOUT", 10*time.Minute)
	drainStart := time.Now()
	cycle := 0
	for {
		cycle++
		hwm, hwmErr := op.WAL.HWM(context.Background())
		if hwmErr != nil {
			t.Fatalf("HWM: %v", hwmErr)
		}

		// Methodical evidence dump every cycle. Every observable
		// surface verified via `go doc` so the log columns map
		// 1:1 to the canonical Metrics structs:
		//   - wal.Committer.HWM:                contiguous shipped seq
		//   - wal.Committer.IterateInflight:    pending entries
		//   - wal.Committer.IterateSequenced:   sequenced-not-shipped
		//   - sequencer.MetricsSnapshot:        DrainCycles, Processed,
		//                                       Failures, ManualCount,
		//                                       CurrentLag
		//   - shipper.MetricsSnapshot:          Shipped, Retries, Manual,
		//                                       MarkShippedFailures, HWM,
		//                                       ShipLatencyMeanMillis
		//   - Postgres entry_index COUNT(*):    sequencer commit progress
		//
		// A stuck pipeline narrows in one cycle:
		//   pending>0, seq.Processed=0:    sequencer not running
		//   pending=0, seq.Processed=N,
		//     ship.Shipped=0:              shipper stuck (bytestore?)
		//   ship.Retries growing:          bytestore failing
		//   ship.Shipped=N, wal.HWM<N:     hwmAdvancer stuck
		pendingCount := 0
		_ = op.WAL.IterateInflight(context.Background(), func(wal.PendingHash) error {
			pendingCount++
			return nil
		})
		sequencedCount := 0
		_ = op.WAL.IterateSequenced(context.Background(), 0, func(wal.SequencedEntry) error {
			sequencedCount++
			return nil
		})
		seqMetrics := op.Sequencer.Metrics()
		shipMetrics := op.Shipper.Metrics()
		var entryIndexRows int64
		_ = op.Pool.QueryRow(context.Background(),
			"SELECT COUNT(*) FROM entry_index").Scan(&entryIndexRows)

		// shipDup = (shipped events) - (distinct seqs that completed).
		// Pre-dedupe baseline; with the inflight guard now in place
		// (shipper.Shipper.inflight) this should converge on 0.
		// skipInflight = number of redundant scan→worker dispatches
		// the guard averted. Each one is an avoided GCS WriteEntry
		// (and avoided potential per-object 429) AND an avoided
		// Badger MarkShipped MVCC conflict.
		shipDup := int64(shipMetrics.Shipped) - int64(shipMetrics.UniqueShipped)
		t.Logf("drain[cycle=%d t=%s] expected=%d "+
			"wal{hwm=%d pending=%d sequenced=%d} "+
			"seq{cycles=%d processed=%d failures=%d manual=%d lag=%d} "+
			"ship{shipped=%d unique=%d dup=%d skipInflight=%d retries=%d manual=%d markFail=%d hwm=%d latMs=%.1f} "+
			"pg{entry_index=%d}",
			cycle, time.Since(drainStart).Round(time.Second), expectedHWM,
			hwm, pendingCount, sequencedCount,
			seqMetrics.DrainCycles, seqMetrics.Processed,
			seqMetrics.Failures, seqMetrics.ManualCount, seqMetrics.CurrentLag,
			shipMetrics.Shipped, shipMetrics.UniqueShipped, shipDup,
			shipMetrics.SkippedInflight,
			shipMetrics.Retries, shipMetrics.Manual,
			shipMetrics.MarkShippedFailures, shipMetrics.HWM, shipMetrics.ShipLatencyMeanMillis,
			entryIndexRows,
		)

		// HWM is the LAST contiguous shipped sequence number,
		// zero-indexed. Tessera/sequencer assigns 0-indexed leaf
		// sequences (see tests/e2e_v1_sct_test.go:118-121: "the
		// first admitted entry in a fresh test DB lands at seq 0").
		// So N submitted entries occupy seqs 0..N-1; full drain is
		// hwm == N-1, NOT hwm == N. Comparing hwm+1 >= expectedHWM
		// makes this explicit and avoids the off-by-one that caused
		// the drain to hang at expected=48 / hwm=47 indefinitely.
		if expectedHWM > 0 && hwm+1 >= expectedHWM {
			t.Logf("drained: HWM=%d (=> %d entries shipped) in %s",
				hwm, hwm+1, time.Since(drainStart).Round(time.Second))
			break
		}
		if time.Since(drainStart) > drainTimeout {
			t.Fatalf("drain timeout after %s — see drain[cycle=N] log lines above for stuck-stage isolation",
				drainTimeout)
		}
		time.Sleep(2 * time.Second)
	}

	// Post-drain evidence verification — what the operator would
	// otherwise check by hand:
	//   1. Postgres COUNT(entry_index) == submitted (HARD)
	//   2. sequence space contiguous: 0..submitted-1 (HARD)
	//   3. every (seq, hash) tuple from PG fetchable from the
	//      bytestore via Backend.ReadEntry → non-zero bytes (HARD)
	// Each assertion is end-to-end evidence the system did what it
	// promised; together they replace the manual `psql COUNT`,
	// `psql MIN/MAX`, and `aws s3 ls` commands the operator used
	// to run after every soak.
	verifyEvidence(t, op, submitted.Load())
	verifyTreeIntegrity(t, op, submitted.Load())
	verifySMTConsistency(t, op, submitted.Load())

	results := drainSubmissions(resultCh)
	if len(results) > verifySamples {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(results), func(i, j int) { results[i], results[j] = results[j], results[i] })
		results = results[:verifySamples]
	}
	verifyClient := newTunedNoRedirectClient(30 * time.Second)
	follow := newTunedHTTPClient(30 * time.Second)
	lookupClient := newTunedHTTPClient(30 * time.Second)
	verified := 0
	for i, r := range results {
		hashHex := hex.EncodeToString(r.hash[:])

		// Step 1: hash → seq. Required because POST /v1/entries
		// returns an SCT (no sequence_number); we need seq to
		// build the /raw URL. resolveSeqByHash polls until the
		// sequencer commits the entry_index row, bounded at 5s.
		seq, ok := resolveSeqByHash(t, context.Background(), lookupClient, op.BaseURL, r.hash)
		if !ok {
			t.Errorf("verify[%d/%d] hash=%s: resolveSeqByHash timed out (sequencer commit lag > 5s)",
				i, len(results), hashHex)
			continue
		}

		// Step 2: GET /v1/entries/{seq}/raw — expect 302 to bytestore.
		url := fmt.Sprintf("%s/v1/entries/%d/raw", op.BaseURL, seq)
		resp, err := verifyClient.Get(url)
		if err != nil {
			t.Errorf("verify[%d/%d] seq=%d: GET raw: %v", i, len(results), seq, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("verify[%d/%d] seq=%d: expected 302, got %d",
				i, len(results), seq, resp.StatusCode)
			continue
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			t.Errorf("verify[%d/%d] seq=%d: empty Location", i, len(results), seq)
			continue
		}
		if !strings.Contains(loc, hashHex) {
			t.Errorf("verify[%d/%d] seq=%d: Location missing hash hex", i, len(results), seq)
			continue
		}

		// Transparency-log invariant: Location MUST be a credential-
		// free URL — no V4-signature query params, no presign tokens.
		// The architecture has only one read path (RFC 9162,
		// c2sp.org/tlog-tiles); this assertion catches any regression
		// that re-introduces credentialed URLs (presign, SigV4, etc.).
		switch {
		case strings.Contains(loc, "X-Goog-Signature="):
			t.Errorf("verify[%d/%d] seq=%d: Location carries GCS V4-signature (transparency-log architecture forbids credentialed URLs): %s",
				i, len(results), seq, loc)
			continue
		case strings.Contains(loc, "X-Amz-Signature="):
			t.Errorf("verify[%d/%d] seq=%d: Location carries S3 V4-signature (transparency-log architecture forbids credentialed URLs): %s",
				i, len(results), seq, loc)
			continue
		}

		// Step 3: follow the 302 with NO Authorization header, NO
		// credentials. The bucket must serve the bytes anonymously.
		r2, err := follow.Get(loc)
		if err != nil {
			t.Errorf("verify[%d/%d] seq=%d: follow: %v", i, len(results), seq, err)
			continue
		}
		body, readErr := io.ReadAll(r2.Body)
		r2.Body.Close()
		if readErr != nil {
			t.Errorf("verify[%d/%d] seq=%d: read body: %v",
				i, len(results), seq, readErr)
			continue
		}
		if r2.StatusCode != http.StatusOK {
			t.Errorf("verify[%d/%d] seq=%d: follow status=%d",
				i, len(results), seq, r2.StatusCode)
			continue
		}

		// Step 4: cryptographic round-trip. SHA-256 the bytes the
		// bucket served and assert they hash to the canonical_hash
		// the SCT promised. A storage corruption that returns the
		// wrong bytes for the right key would land 200 OK above
		// and pass the count + URL-shape checks; this is the only
		// step that catches it.
		got := sha256.Sum256(body)
		if got != r.hash {
			t.Errorf("verify[%d/%d] seq=%d: SHA-256(body)=%x != canonical=%x (%d-byte body)",
				i, len(results), seq, got[:8], r.hash[:8], len(body))
			continue
		}
		verified++
	}
	if verified == len(results) {
		t.Logf("soak verify: %d/%d sampled entries verified via hash→seq→302 path (total submitted=%d)",
			verified, len(results), submitted.Load())
	} else {
		t.Logf("soak verify: %d/%d sampled entries verified — see verify[*] errors above (total submitted=%d)",
			verified, len(results), submitted.Load())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// envSampleCount resolves a sample-size env var. Accepts either an
// absolute integer ("100") or a percentage of total ("5%", "0.5%",
// "10.0%"). Returns def when the var is unset or unparseable, or
// when the percentage parses but rounds to <1 against the supplied
// total.
//
// Why both shapes:
//   - Absolute count is intuitive for fixed-size verification budgets
//     (e.g., "always sample 100 entries regardless of N").
//   - Percentage scales coverage with N: at 1M entries a fixed 100
//     samples is 0.01% (statistically poor for catching rare faults),
//     but "1%" gives 10K samples which has ~99.9% chance of catching
//     a 1-in-1000 corruption. Operators choose by run profile.
//
// Trailing % is the percentage discriminator. Whitespace trimmed.
// Negative values fall back to def.
func envSampleCount(name string, def int, total uint64) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	if strings.HasSuffix(v, "%") {
		raw := strings.TrimSpace(strings.TrimSuffix(v, "%"))
		pct, err := strconv.ParseFloat(raw, 64)
		if err != nil || pct <= 0 {
			return def
		}
		// Round half-up. Cap at total — a percent > 100 is allowed
		// here (it just means "verify everything"); the caller is
		// responsible for clamping to the working set if needed.
		n := int(float64(total)*pct/100.0 + 0.5)
		if n < 1 {
			return def
		}
		return n
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// envDuration returns a duration parsed from the named env var, or
// def when the var is unset or unparseable. Accepts any value
// time.ParseDuration accepts ("30s", "10m", "1h", "1h30m", ...).
func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// parseSCTCanonicalHash extracts the canonical_hash from a 202
// Accepted SCT JSON body without constructing a map[string]any per
// call. At 1M entries this matters.
//
// Body shape (api/submission.go writes encoding/json over an
// sdksct.SignedCertificateTimestamp value — see e2e_v1_sct_test.go
// for the canonical decode path):
//
//	{
//	  "version": 1,
//	  "signer_did":      "did:...",
//	  "sig_algo_id":     "ecdsa-secp256k1-sha256",
//	  "log_did":         "did:...",
//	  "canonical_hash":  "<64 hex chars>",
//	  "log_time_micros": <int>,
//	  "log_time":        "<rfc3339>",
//	  "signature":       "<hex>"
//	}
//
// NO sequence_number — sequencing is asynchronous; the soak verify
// pass resolves hash→seq via GET /v1/entries-hash/{hash}.
func parseSCTCanonicalHash(body []byte) (hash [32]byte, ok bool) {
	const hashTag = `"canonical_hash":"`
	hi := bytes.Index(body, []byte(hashTag))
	if hi < 0 {
		return [32]byte{}, false
	}
	hi += len(hashTag)
	if hi+64 > len(body) {
		return [32]byte{}, false
	}
	hashBytes, err := hex.DecodeString(string(body[hi : hi+64]))
	if err != nil {
		return [32]byte{}, false
	}
	copy(hash[:], hashBytes)
	return hash, true
}

// parseHashLookupSeq extracts the sequence_number from a
// /v1/entries-hash/{hash} JSON response. Returns ok=false when the
// response is in the {"state":"pending"} shape (sequencer hasn't
// committed the entry_index row yet).
func parseHashLookupSeq(body []byte) (seq uint64, ok bool) {
	// Pending response carries "state":"pending" and no
	// sequence_number; short-circuit so the caller can retry.
	if bytes.Contains(body, []byte(`"state":"pending"`)) {
		return 0, false
	}
	const seqTag = `"sequence_number":`
	si := bytes.Index(body, []byte(seqTag))
	if si < 0 {
		return 0, false
	}
	si += len(seqTag)
	end := si
	for end < len(body) && body[end] >= '0' && body[end] <= '9' {
		end++
	}
	n, err := strconv.ParseUint(string(body[si:end]), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// resolveSeqByHash polls GET /v1/entries-hash/{hash} until the
// sequencer has committed the entry_index row (state != pending)
// and returns its sequence number. Bounded retry handles the small
// gap between WAL HWM advancing and the sequencer's INSERT
// landing in entry_index — even after WAL drain the soak observed,
// the sequencer's commit lags by milliseconds.
//
// On timeout: emits a diagnostic line summarizing the LAST attempt's
// status/body and the total number of attempts so the verify-stage
// failure mode is visible without re-running with extra logging.
//
// Returns ok=false when the deadline expires; the verify caller
// records the failure.
func resolveSeqByHash(t *testing.T, ctx context.Context, client *http.Client, baseURL string, hash [32]byte) (uint64, bool) {
	hashHex := hex.EncodeToString(hash[:])
	url := baseURL + "/v1/entries-hash/" + hashHex
	deadline := time.Now().Add(5 * time.Second)
	attempts := 0
	var (
		lastStatus int
		lastBody   []byte
		lastErr    error
	)
	for {
		attempts++
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastStatus = resp.StatusCode
			lastBody = body
			lastErr = nil
			if resp.StatusCode == http.StatusOK {
				if seq, ok := parseHashLookupSeq(body); ok {
					return seq, true
				}
			}
		} else {
			lastStatus = 0
			lastBody = nil
			lastErr = err
		}
		if time.Now().After(deadline) {
			const maxBodyBytes = 512
			bodyTrim := lastBody
			if len(bodyTrim) > maxBodyBytes {
				bodyTrim = bodyTrim[:maxBodyBytes]
			}
			t.Logf("resolveSeqByHash TIMEOUT hash=%s url=%s attempts=%d "+
				"lastStatus=%d lastErr=%v lastBody=%q",
				hashHex, url, attempts, lastStatus, lastErr, bodyTrim)
			return 0, false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func drainSubmissions(ch <-chan soakSubmission) []soakSubmission {
	out := make([]soakSubmission, 0, 1024)
	for r := range ch {
		out = append(out, r)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Schema-drift defender — fails at boot if the test's SQL is stale
// ─────────────────────────────────────────────────────────────────────

// assertEntryIndexSchema introspects information_schema.columns and
// asserts every column the soak's query path references actually
// exists in entry_index. Run once at boot, before any reads.
//
// WHY:
//
//	A column rename in a future migration (e.g. sequence_number →
//	leaf_index) would otherwise surface as a SQLSTATE 42703 nineteen
//	seconds into a 100k+ run, after the entire submission + drain
//	cycle has already completed. This check catches the drift in
//	~5ms at boot.
//
// COLUMN SET:
//
//	The asserted columns mirror exactly what verifyEvidence and the
//	drain-loop pg{} log line query: sequence_number (MIN/MAX/SELECT/
//	ORDER BY) and canonical_hash (SELECT/scan). The soak does not
//	read log_time / signer_did / target_root / cosignature_of /
//	schema_ref, so they are not asserted here — their drift-defence
//	belongs to whatever code does read them.
//
// PATTERN:
//
//	Mirrors tests/entry_storage_rule_test.go:TestRule_EntryIndex_
//	HasNoByteColumns at line 38, which uses the same
//	information_schema.columns query for the inverse property
//	("no byte columns"). Same code shape; different assertion.
func assertEntryIndexSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	expected := map[string]bool{
		"sequence_number": false, // MIN/MAX/SELECT/ORDER BY in verifyEvidence
		"canonical_hash":  false, // SELECT/scan in verifyEvidence
	}

	rows, err := pool.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_name = 'entry_index'
		ORDER BY ordinal_position`)
	if err != nil {
		t.Fatalf("assertEntryIndexSchema: query information_schema: %v", err)
	}
	defer rows.Close()

	var seen []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("assertEntryIndexSchema: scan: %v", err)
		}
		seen = append(seen, col)
		if _, ok := expected[col]; ok {
			expected[col] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("assertEntryIndexSchema: rows.Err: %v", err)
	}

	if len(seen) == 0 {
		t.Fatal("assertEntryIndexSchema: entry_index has zero columns " +
			"(table missing or migrations did not run)")
	}

	missing := make([]string, 0, len(expected))
	for col, found := range expected {
		if !found {
			missing = append(missing, col)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("schema drift: entry_index missing columns %v "+
			"(actual columns present: %v)", missing, seen)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Evidence verification — automates what the operator otherwise runs by hand
// ─────────────────────────────────────────────────────────────────────

// verifyEvidence asserts the three end-to-end transparency-log
// invariants that hold after every successful soak:
//
//  1. Postgres entry_index has exactly `submitted` rows.
//  2. The sequence column is contiguous on [0, submitted-1].
//  3. Every (seq, canonical_hash) tuple is fetchable from the
//     production bytestore — Backend.ReadEntry returns non-zero
//     bytes for all N entries.
//
// All three assertions are hard t.Fatalf on mismatch. The fetch
// step is parallelised (verifyEvidenceWorkers goroutines) so the
// 100k → 1M soak doesn't pay 5 ms × N serial latency.
//
// PRINCIPLE COVERAGE:
//   - L3 (SCT-as-SLA): every SCT the ledger handed back is honored
//     by the time this function runs.
//   - L8 (CQRS): proves the read-path bytestore agrees with the
//     write-path WAL → entry_index commitment.
//   - Trust Alignment 6 (Parse, Don't Validate): the test reads
//     bytes directly from the bytestore, never trusting an HTTP
//     response from the ledger to assert their existence.
func verifyEvidence(t *testing.T, op *soakLedger, submitted uint64) {
	t.Helper()
	if submitted == 0 {
		t.Fatal("verifyEvidence: submitted == 0 (caller bug)")
	}
	ctx := context.Background()

	// 1) Postgres row count.
	var rowCount int64
	if err := op.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM entry_index").Scan(&rowCount); err != nil {
		t.Fatalf("verifyEvidence: SELECT COUNT(*) FROM entry_index: %v", err)
	}
	if uint64(rowCount) != submitted {
		t.Fatalf("verifyEvidence: entry_index has %d rows, want %d (submitted)",
			rowCount, submitted)
	}
	t.Logf("verifyEvidence: ✓ entry_index rows = %d (matches submitted)", rowCount)

	// 2) Sequence contiguity — MIN must be 0, MAX must be submitted-1.
	// Column name is `sequence_number`, NOT `sequence`. Confirmed via:
	//   - store/entries.go:Insert SQL uses `sequence_number`
	//   - store.EntryRow.SequenceNumber is the Go-side struct field
	//   - the table CREATE in store/entries.go declares `sequence_number`
	var minSeq, maxSeq sql.NullInt64
	if err := op.Pool.QueryRow(ctx,
		"SELECT MIN(sequence_number), MAX(sequence_number) FROM entry_index",
	).Scan(&minSeq, &maxSeq); err != nil {
		t.Fatalf("verifyEvidence: SELECT MIN/MAX(sequence_number): %v", err)
	}
	if !minSeq.Valid || !maxSeq.Valid {
		t.Fatalf("verifyEvidence: MIN/MAX(sequence_number) returned NULL (no rows?)")
	}
	if minSeq.Int64 != 0 {
		t.Fatalf("verifyEvidence: MIN(sequence_number) = %d, want 0", minSeq.Int64)
	}
	expectedMax := int64(submitted) - 1
	if maxSeq.Int64 != expectedMax {
		t.Fatalf("verifyEvidence: MAX(sequence_number) = %d, want %d (submitted-1)",
			maxSeq.Int64, expectedMax)
	}
	t.Logf("verifyEvidence: ✓ sequence_number space contiguous: [%d, %d]",
		minSeq.Int64, maxSeq.Int64)

	// 3) Every entry must be physically present in the bytestore.
	verifyEvidenceFetchAll(t, ctx, op, submitted)
}

// verifyTreeIntegrity asserts the cryptographic invariants the soak's
// plumbing checks (verifyEvidence) cannot:
//
//  1. /v1/tree/head reports TreeSize >= submitted. Catches the case
//     where Tessera silently stops integrating leaves while the WAL +
//     bytestore + entry_index pipeline keeps working.
//
//  2. N random inclusion proofs verify against that head's root via
//     the canonical RFC-6962 verifier (transparency-dev/merkle/proof).
//     Catches Merkle-tree drift, tile-storage divergence, hash-only
//     leaf-encoding regressions.
//
// Sample size N is ATTESTA_SOAK_TREE_PROOF_SAMPLES (default 100).
// Accepts either an absolute count ("100") or a percentage of
// submitted entries ("5%", "0.5%"). Sampling, not exhaustive: 1M
// proofs × ~5ms each = 80 minutes, which is longer than most soak
// budgets; 100 random samples × ~5ms = ~0.5s and gives ~1-in-10K
// false-negative odds for tree-wide corruption. At 1M+ scale,
// "1%" (10K samples) is a better default for catching sparse
// faults; the operator chooses by run profile.
func verifyTreeIntegrity(t *testing.T, op *soakLedger, submitted uint64) {
	t.Helper()
	if submitted == 0 {
		t.Fatal("verifyTreeIntegrity: submitted == 0 (caller bug)")
	}
	ctx := context.Background()

	// 1) Tree head + TreeSize check.
	headURL := op.BaseURL + "/v1/tree/head"
	resp, err := http.Get(headURL)
	if err != nil {
		t.Fatalf("verifyTreeIntegrity: GET /v1/tree/head: %v", err)
	}
	headBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verifyTreeIntegrity: /v1/tree/head status=%d body=%s", resp.StatusCode, headBody)
	}
	var head struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
	}
	if err := json.Unmarshal(headBody, &head); err != nil {
		t.Fatalf("verifyTreeIntegrity: decode tree head: %v body=%s", err, headBody)
	}
	if head.TreeSize < submitted {
		t.Fatalf("verifyTreeIntegrity: tree_size=%d < submitted=%d (Tessera not integrating)",
			head.TreeSize, submitted)
	}
	root, err := hex.DecodeString(head.RootHash)
	if err != nil || len(root) != 32 {
		t.Fatalf("verifyTreeIntegrity: malformed root_hash=%q (decode err=%v len=%d)",
			head.RootHash, err, len(root))
	}
	t.Logf("verifyTreeIntegrity: ✓ tree_size=%d root=%x… (matches submitted=%d)",
		head.TreeSize, root[:8], submitted)

	// 2) N random inclusion proofs against head.RootHash.
	n := envSampleCount("ATTESTA_SOAK_TREE_PROOF_SAMPLES", 100, submitted)
	if n <= 0 {
		t.Logf("verifyTreeIntegrity: ATTESTA_SOAK_TREE_PROOF_SAMPLES=%d → skipping proof verification", n)
		return
	}
	if uint64(n) > submitted {
		n = int(submitted)
	}
	rng := rand.New(rand.NewSource(int64(submitted)))
	seen := make(map[uint64]struct{}, n)
	verified := 0
	for verified < n {
		seq := uint64(rng.Int63n(int64(submitted)))
		if _, dup := seen[seq]; dup {
			continue
		}
		seen[seq] = struct{}{}

		// Fetch canonical_hash for this sequence from PG.
		var hashCol []byte
		if err := op.Pool.QueryRow(ctx,
			"SELECT canonical_hash FROM entry_index WHERE sequence_number = $1", seq,
		).Scan(&hashCol); err != nil {
			t.Fatalf("verifyTreeIntegrity: SELECT canonical_hash seq=%d: %v", seq, err)
		}
		if len(hashCol) != 32 {
			t.Fatalf("verifyTreeIntegrity: seq=%d canonical_hash bytes=%d, want 32",
				seq, len(hashCol))
		}
		var canonical [32]byte
		copy(canonical[:], hashCol)

		// Fetch inclusion proof.
		inclURL := fmt.Sprintf("%s/v1/tree/inclusion/%d", op.BaseURL, seq)
		ir, err := http.Get(inclURL)
		if err != nil {
			t.Fatalf("verifyTreeIntegrity: GET inclusion seq=%d: %v", seq, err)
		}
		inclBody, _ := io.ReadAll(ir.Body)
		ir.Body.Close()
		if ir.StatusCode != http.StatusOK {
			t.Fatalf("verifyTreeIntegrity: inclusion seq=%d status=%d body=%s",
				seq, ir.StatusCode, inclBody)
		}
		var prf struct {
			LeafIndex uint64   `json:"leaf_index"`
			TreeSize  uint64   `json:"tree_size"`
			Hashes    []string `json:"hashes"`
		}
		if err := json.Unmarshal(inclBody, &prf); err != nil {
			t.Fatalf("verifyTreeIntegrity: decode inclusion seq=%d: %v body=%s",
				seq, err, inclBody)
		}
		if prf.LeafIndex != seq {
			t.Fatalf("verifyTreeIntegrity: seq=%d returned leaf_index=%d", seq, prf.LeafIndex)
		}
		siblings := make([][]byte, len(prf.Hashes))
		for i, h := range prf.Hashes {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatalf("verifyTreeIntegrity: seq=%d sibling[%d] hex: %v", seq, i, err)
			}
			siblings[i] = b
		}

		// RFC-6962 leaf hash + canonical verifier.
		leafHash := rfc6962.DefaultHasher.HashLeaf(canonical[:])
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher,
			seq, prf.TreeSize, leafHash, siblings, root); err != nil {
			t.Fatalf("verifyTreeIntegrity: VerifyInclusion seq=%d: %v", seq, err)
		}
		verified++
	}
	t.Logf("verifyTreeIntegrity: ✓ %d/%d random inclusion proofs verified against tree_size=%d root=%x…",
		verified, n, head.TreeSize, root[:8])
}

// verifySMTConsistency asserts the per-key Sparse Merkle Tree state
// is consistent: pulls the current /v1/smt/root, then for N random
// entries fetches /v1/smt/proof/{key} and runs the SDK's
// smt.VerifyMembershipProof against the live root.
//
// The SMT is the second cryptographic projection alongside the dense
// log Merkle tree (verifyTreeIntegrity). The dense tree binds
// sequence → canonical bytes; the SMT binds (LogDID, sequence) →
// log-position state. A divergence between the two means a builder
// regression silently corrupted state-of-network without breaking
// the dense-tree inclusion proofs.
//
// Sample size N is ATTESTA_SOAK_SMT_PROOF_SAMPLES (default 100).
// Accepts either an absolute count or a percentage, like the
// inclusion-proof sampler.
func verifySMTConsistency(t *testing.T, op *soakLedger, submitted uint64) {
	t.Helper()
	if submitted == 0 {
		t.Fatal("verifySMTConsistency: submitted == 0 (caller bug)")
	}
	ctx := context.Background()

	// 1) Fetch SMT root.
	rootURL := op.BaseURL + "/v1/smt/root"
	resp, err := http.Get(rootURL)
	if err != nil {
		t.Fatalf("verifySMTConsistency: GET /v1/smt/root: %v", err)
	}
	rootBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verifySMTConsistency: /v1/smt/root status=%d body=%s", resp.StatusCode, rootBody)
	}
	var rootResp struct {
		Root      string `json:"root"`
		LeafCount uint64 `json:"leaf_count"`
	}
	if err := json.Unmarshal(rootBody, &rootResp); err != nil {
		t.Fatalf("verifySMTConsistency: decode /v1/smt/root: %v body=%s", err, rootBody)
	}
	rootBytes, err := hex.DecodeString(rootResp.Root)
	if err != nil || len(rootBytes) != 32 {
		t.Fatalf("verifySMTConsistency: malformed root=%q", rootResp.Root)
	}
	var smtRoot [32]byte
	copy(smtRoot[:], rootBytes)
	t.Logf("verifySMTConsistency: ✓ smt_root=%x… leaf_count=%d (submitted=%d)",
		smtRoot[:8], rootResp.LeafCount, submitted)

	// 2) Sample N entries; verify each proof against smtRoot.
	n := envSampleCount("ATTESTA_SOAK_SMT_PROOF_SAMPLES", 100, submitted)
	if n <= 0 {
		t.Logf("verifySMTConsistency: ATTESTA_SOAK_SMT_PROOF_SAMPLES=%d → skipping", n)
		return
	}
	if uint64(n) > submitted {
		n = int(submitted)
	}

	// LogDID is a test constant; the soak server is configured with
	// testLogDID at startSoakLedger.
	logDID := testLogDID
	_ = op // op is not needed for key derivation

	rng := rand.New(rand.NewSource(int64(submitted) * 31))
	seen := make(map[uint64]struct{}, n)
	verified := 0
	for verified < n {
		seq := uint64(rng.Int63n(int64(submitted)))
		if _, dup := seen[seq]; dup {
			continue
		}
		seen[seq] = struct{}{}

		key := smt.DeriveKey(types.LogPosition{LogDID: logDID, Sequence: seq})
		proofURL := fmt.Sprintf("%s/v1/smt/proof/%x", op.BaseURL, key[:])
		pr, err := http.Get(proofURL)
		if err != nil {
			t.Fatalf("verifySMTConsistency: GET smt/proof seq=%d: %v", seq, err)
		}
		body, _ := io.ReadAll(pr.Body)
		pr.Body.Close()
		if pr.StatusCode != http.StatusOK {
			t.Fatalf("verifySMTConsistency: smt/proof seq=%d status=%d body=%s",
				seq, pr.StatusCode, body)
		}

		var wrap struct {
			Type  string         `json:"type"`
			Proof types.SMTProof `json:"proof"`
		}
		if err := json.Unmarshal(body, &wrap); err != nil {
			t.Fatalf("verifySMTConsistency: decode proof seq=%d: %v body=%s", seq, err, body)
		}
		// Membership: the entry's key MUST be present at this state.
		// Non-membership for an entry we know was sequenced is a
		// builder regression and is a hard failure.
		if wrap.Type != "membership" {
			t.Fatalf("verifySMTConsistency: seq=%d expected membership proof, got %q "+
				"(entry was sequenced but SMT reports non-membership)", seq, wrap.Type)
		}
		// The proof's Key MUST equal the derived key — pin the
		// SDK's contract that proof binds to the requested key.
		if wrap.Proof.Key != key {
			t.Fatalf("verifySMTConsistency: seq=%d proof.Key=%x want=%x",
				seq, wrap.Proof.Key[:8], key[:8])
		}
		if err := smt.VerifyMembershipProof(&wrap.Proof, smtRoot); err != nil {
			t.Fatalf("verifySMTConsistency: VerifyMembershipProof seq=%d: %v "+
				"(SMT root or proof corrupted)", seq, err)
		}
		verified++
	}
	_ = ctx
	t.Logf("verifySMTConsistency: ✓ %d/%d random membership proofs verified against smt_root=%x…",
		verified, n, smtRoot[:8])
}

// verifyEvidenceFetchAll pulls (seq, canonical_hash) for every row
// in entry_index and dispatches Backend.ReadEntry across a worker
// pool. Failure on any single entry is fatal — transparency-log
// invariants don't tolerate partial coverage.
func verifyEvidenceFetchAll(t *testing.T, ctx context.Context, op *soakLedger, submitted uint64) {
	t.Helper()

	type ref struct {
		seq  uint64
		hash [32]byte
	}

	rows, err := op.Pool.Query(ctx,
		"SELECT sequence_number, canonical_hash FROM entry_index ORDER BY sequence_number")
	if err != nil {
		t.Fatalf("verifyEvidence: SELECT all entries: %v", err)
	}
	refs := make([]ref, 0, submitted)
	for rows.Next() {
		var seq int64
		var hashBytes []byte
		if err := rows.Scan(&seq, &hashBytes); err != nil {
			rows.Close()
			t.Fatalf("verifyEvidence: scan entry_index: %v", err)
		}
		if len(hashBytes) != 32 {
			rows.Close()
			t.Fatalf("verifyEvidence: canonical_hash bytes = %d, want 32", len(hashBytes))
		}
		var r ref
		r.seq = uint64(seq)
		copy(r.hash[:], hashBytes)
		refs = append(refs, r)
	}
	rows.Close()
	if uint64(len(refs)) != submitted {
		t.Fatalf("verifyEvidence: pulled %d refs from PG, want %d", len(refs), submitted)
	}

	const verifyEvidenceWorkers = 64
	workers := verifyEvidenceWorkers
	if len(refs) < workers {
		workers = len(refs)
	}
	refCh := make(chan ref, workers*4)
	var fetchOK, fetchFail atomic.Uint64
	var firstFailMu sync.Mutex
	var firstFail string

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range refCh {
				bytes, err := op.Backend.ReadEntry(ctx, r.seq, r.hash)
				if err != nil || len(bytes) == 0 {
					fetchFail.Add(1)
					firstFailMu.Lock()
					if firstFail == "" {
						firstFail = fmt.Sprintf("seq=%d hash=%x… err=%v len=%d",
							r.seq, r.hash[:8], err, len(bytes))
					}
					firstFailMu.Unlock()
					continue
				}
				fetchOK.Add(1)
			}
		}()
	}
	start := time.Now()
	for _, r := range refs {
		refCh <- r
	}
	close(refCh)
	wg.Wait()
	elapsed := time.Since(start).Round(time.Millisecond)

	if fetchFail.Load() != 0 {
		t.Fatalf("verifyEvidence: %d/%d entries failed bytestore ReadEntry — first failure: %s",
			fetchFail.Load(), len(refs), firstFail)
	}
	t.Logf("verifyEvidence: ✓ %d/%d entries fetchable from bytestore in %s "+
		"(every committed entry physically present)",
		fetchOK.Load(), len(refs), elapsed)

	// Log a copy-pasteable sample PublicURL so an operator running
	// with ATTESTA_SOAK_KEEP_DATA=1 has an exact URL to curl post-
	// test (the key carries the per-run prefix soak/<unix-nano>
	// which is otherwise invisible from the shell). Sampling the
	// first ref keeps output bounded; the verifyEvidence loop
	// already proved every entry is fetchable.
	if len(refs) > 0 {
		if pu, err := op.Backend.PublicURL(refs[0].seq, refs[0].hash); err == nil {
			t.Logf("verifyEvidence: sample PublicURL for seq=%d: %s",
				refs[0].seq, pu)
		}
	}
}
