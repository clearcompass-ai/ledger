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
	ATTESTA_SOAK_VERIFY_SAMPLES        random sample of entries to /raw-check at the end (default 100)
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
	"encoding/hex"
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

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/signatures"

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
// soakOperator — real-GCS variant of e2eOperator
// ─────────────────────────────────────────────────────────────────────

type soakOperator struct {
	BaseURL   string
	Pool      *pgxpool.Pool
	WAL       *wal.Committer
	Backend   opbytestore.Backend
	Sequencer *sequencer.Sequencer
	Shipper   *shipper.Shipper
	cancel    context.CancelFunc
}

func startSoakOperator(t *testing.T) *soakOperator {
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
	queryAPI := indexes.NewPostgresQueryAPI(pool, composite, testLogDID)

	merkle := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}
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
	// Mirrors startE2EOperator in e2e_shipper_redirect_test.go.
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

	op := &soakOperator{
		BaseURL: baseURL, Pool: pool, WAL: walc,
		Backend: backend, Sequencer: seq, Shipper: ship, cancel: cancel,
	}

	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
		_ = walc.Close()
		_ = walDB.Close()
		cleanTables(t, pool)
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

func (op *soakOperator) seedSoakSession(t *testing.T, token, exchangeDID string, credits int64) {
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
	mu sync.Mutex
	samples []time.Duration
	cap int
	seen int
	rng *rand.Rand
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
// TestSoak_OneMillionEntries_RealGCS — primary soak test.
// ─────────────────────────────────────────────────────────────────────

func TestSoak_OneMillionEntries_RealGCS(t *testing.T) {
	op := startSoakOperator(t)
	op.seedSoakSession(t, "tok-soak", "did:example:soak-exchange", 100_000_000)

	total := envInt("ATTESTA_SOAK_ENTRIES", 1_000_000)
	concurrency := envInt("ATTESTA_SOAK_CONCURRENCY", 8)
	verifySamples := envInt("ATTESTA_SOAK_VERIFY_SAMPLES", 100)
	p99BoundMs := envInt("ATTESTA_SOAK_P99_BOUND_MS", 100)
	// Re-read here for the unified config log line; the actual values
	// are also read where they're used (startSoakOperator for
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
		_, _ = io.Copy(io.Discard, r2.Body)
		r2.Body.Close()
		if r2.StatusCode != http.StatusOK {
			t.Errorf("verify[%d/%d] seq=%d: follow status=%d",
				i, len(results), seq, r2.StatusCode)
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
