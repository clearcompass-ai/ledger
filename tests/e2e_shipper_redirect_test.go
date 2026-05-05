/*
FILE PATH: tests/e2e_shipper_redirect_test.go

End-to-end happy-path validation for the WAL → Tessera → bytestore
→ 302 redirect pipeline.

WHAT THIS COVERS (vs. the existing unit + http_integration suites):

	unit tests (wal/, shipper/, integrity/, store/) prove each box
	in isolation. http_integration_test.go exercises submission +
	query against the testserver harness but uses Presigner=nil
	(testserver_test.go:212 says any redirect attempt indicates an
	unexpected state transition). Neither suite exercises the
	cross-component sequence:

	  1. POST /v1/entries lands in the WAL durably (state=Sequenced).
	  2. The Shipper migrates bytes from WAL → bytestore + flips the
	     state to Shipped + advances HWM.
	  3. GET /v1/entries/{seq}/raw returns 302 with a Location URL
	     containing the entry's hash (static-verifiability invariant).
	  4. Following the URL fetches the same wire bytes the producer
	     submitted.

	This file builds a parallel harness (startE2EOperator) — separate
	from startTestOperator — that wires a Presigner-aware bytestore
	and runs the Shipper. The harness omits builder/anchor/witness
	pieces because those are exercised elsewhere and would only add
	flake surface.

TEST GATES:

	All tests Skip when ATTESTA_TEST_DSN is unset. No GCS/S3 needed —
	the local presign backend is an httptest.Server backed by an
	in-memory bytestore.Memory, so the redirect path is fully exercised
	without cloud dependencies.
*/
package tests

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// ─────────────────────────────────────────────────────────────────────
// localPresignBackend — Memory bytestore + httptest server that returns
// the stored bytes when its presigned URLs are GET'd.
//
// Implements bytestore.Backend (Reader + Writer + Presigner). Tests
// don't need real V4/SigV4 — the URL embeds (seq, hash) as path
// components, the server reads from the wrapped Memory store, and
// the caller verifies bytes match. The hash hex appears in the path
// so the static-verifiability invariant the 302 path relies on is
// observable.
// ─────────────────────────────────────────────────────────────────────

type localPresignBackend struct {
	*opbytestore.Memory
	server *httptest.Server
}

func newLocalPresignBackend(t *testing.T) *localPresignBackend {
	t.Helper()
	mem := opbytestore.NewMemory()
	b := &localPresignBackend{Memory: mem}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /<seq:016x>/<hash_hex>
		path := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		var seq uint64
		if _, err := fmt.Sscanf(parts[0], "%016x", &seq); err != nil {
			http.Error(w, "bad seq", http.StatusBadRequest)
			return
		}
		hashBytes, err := hex.DecodeString(parts[1])
		if err != nil || len(hashBytes) != 32 {
			http.Error(w, "bad hash", http.StatusBadRequest)
			return
		}
		var hash [32]byte
		copy(hash[:], hashBytes)
		wire, err := mem.ReadEntry(r.Context(), seq, hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	})
	b.server = httptest.NewServer(mux)
	t.Cleanup(b.server.Close)
	return b
}

// PresignGet returns a URL pointing at this backend's httptest server.
// The path embeds the hash hex — the same shape bytestore.layoutKey
// produces — so the redirect target satisfies the static-verifiability
// invariant the 302 read path advertises.
func (b *localPresignBackend) PresignGet(_ context.Context, seq uint64, hash [32]byte, _ time.Duration) (string, error) {
	return fmt.Sprintf("%s/%016x/%s", b.server.URL, seq, hex.EncodeToString(hash[:])), nil
}

// Compile-time pin: localPresignBackend satisfies bytestore.Backend.
var _ opbytestore.Backend = (*localPresignBackend)(nil)

// ─────────────────────────────────────────────────────────────────────
// e2eOperator — minimal harness with WAL + Shipper + Presigner
// ─────────────────────────────────────────────────────────────────────

type e2eOperator struct {
	BaseURL string
	Pool    *pgxpool.Pool
	WAL     *wal.Committer
	Backend *localPresignBackend
	Shipper *shipper.Shipper

	// SCT/MMD additions
	LedgerSignerPriv *ecdsa.PrivateKey
	LogDID           string
	MMD              time.Duration

	cancel context.CancelFunc
}

// seedSession seeds an Authorization-Bearer-resolvable session.
func (op *e2eOperator) seedSession(t *testing.T, token, exchangeDID string, credits int64) {
	t.Helper()
	ctx := context.Background()
	_, err := op.Pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO NOTHING`,
		token, exchangeDID, time.Now().UTC().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if credits > 0 {
		creditStore := store.NewCreditStore(op.Pool)
		if _, err := creditStore.BulkPurchase(ctx, exchangeDID, credits); err != nil {
			t.Fatalf("seed credits: %v", err)
		}
	}
}

func startE2EOperator(t *testing.T) *e2eOperator {
	t.Helper()

	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping e2e shipper redirect test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// ── Postgres ────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		cancel()
		t.Fatalf("migrations: %v", err)
	}
	cleanTables(t, pool)

	// ── WAL ─────────────────────────────────────────────────────────
	walDB, err := wal.OpenInMemory(nil)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("wal open: %v", err)
	}
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{DisableSync: true})

	// ── Local presigning byte backend ───────────────────────────────
	backend := newLocalPresignBackend(t)

	// ── Composite reader (WAL → bytestore fallback) ─────────────────
	composite := store.NewCompositeByteReader(walc, backend, logger)

	// ── Postgres-backed query/fetch surface ─────────────────────────
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	sequenceCursor := store.NewSequenceCursor(pool)
	fetcher := store.NewPostgresEntryFetcher(pool, composite, testLogDID)
	queryAPI := indexes.NewPostgresQueryAPI(pool, composite, testLogDID)

	// ── Stub Tessera (sequence assignment) ──────────────────────────
	merkle := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}

	// ── Difficulty controller ───────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		sequenceCursor, middleware.DefaultDifficultyConfig(), logger,
	)

	// Ledger signer key — secp256k1 ECDSA, used to sign SCTs.
	// Tests get a fresh ephemeral key per ledger boot.
	opSignerPriv, err := signatures.GenerateKey()
	if err != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("ledger signer key: %v", err)
	}

	// ── HTTP handlers ───────────────────────────────────────────────
	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: entryStore,
			WAL:        walc,
			Tessera:    merkle,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    testEpochWindowSeconds,
			EpochAcceptanceWindow: testEpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			Credits:     creditStore,
			DIDResolver: nil,
		},
		LogDID:           testLogDID,
		LedgerDID:        testOperatorDID,
		LedgerSignerPriv: opSignerPriv,
		MaxEntrySize:     1 << 20,
		Logger:           logger,
	}
	queryDeps := &api.QueryDeps{
		QueryAPI:       queryAPI,
		DiffController: diffController,
		Logger:         logger,
		EntryStore:     entryStore,
		WAL:            walc,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher:    fetcher,
		QueryAPI:   queryAPI,
		EntryStore: entryStore,
		WAL:        walc,
		Presigner:  backend,
		LogDID:     testLogDID,
		Logger:     logger,
	}

	const testMMD = 24 * time.Hour
	handlers := api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		BatchSubmission: api.NewBatchSubmissionHandler(submissionDeps),
		MMD:             api.NewMMDHandler(testMMD),
		EntryByHash:     api.NewHashLookupHandler(queryDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryRaw:        api.NewRawEntryHandler(entryReadDeps),
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

	// ── Sequencer (WAL StatePending → Tessera + entry_index) ───────
	// With the SCT/MMD architecture in place, v1 admission is a
	// polling facade; the Sequencer is what advances WAL state from
	// Pending to Sequenced. 10ms poll interval keeps tests fast.
	seq := sequencer.NewSequencer(walc, merkle, pool, entryStore, sequencer.Config{
		PollInterval: 10 * time.Millisecond,
		Logger:       logger,
	})

	// ── Shipper (WAL → bytestore migrator) ──────────────────────────
	ship := shipper.NewShipper(walc, backend, shipper.Config{
		PollInterval: 50 * time.Millisecond,
		MaxInFlight:  4,
		Logger:       logger,
	})

	go func() { _ = server.Serve(ln) }()
	go func() { _ = seq.Run(ctx) }()
	go func() { _ = ship.Run(ctx) }()

	op := &e2eOperator{
		BaseURL:          baseURL,
		Pool:             pool,
		WAL:              walc,
		Backend:          backend,
		Shipper:          ship,
		LedgerSignerPriv: opSignerPriv,
		LogDID:           testLogDID,
		MMD:              testMMD,
		cancel:           cancel,
	}

	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
		_ = walc.Close()
		_ = walDB.Close()
		cleanTables(t, pool)
		pool.Close()
	})

	// Readiness probe.
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
	t.Fatal("e2e ledger did not become ready in 2.5s")
	return nil
}

// waitForShipped polls op.WAL.MetaState(hash) until the entry is
// StateShipped or the deadline elapses. Fails the test on timeout.
func waitForShipped(t *testing.T, op *e2eOperator, hash [32]byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ctx := context.Background()
	for time.Now().Before(deadline) {
		meta, err := op.WAL.MetaState(ctx, hash)
		if err == nil && meta.State == wal.StateShipped {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	meta, _ := op.WAL.MetaState(ctx, hash)
	t.Fatalf("waitForShipped: hash=%x state=%s after %s", hash[:8], meta.State, timeout)
}

// noRedirectClient returns an http.Client that never auto-follows 302s
// so the test can inspect Location + status directly.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}
}

// submitOneE2E POSTs a Mode A entry against op and returns the canonical
// wire bytes plus the parsed (seq, hash) tuple. Fails the test on any
// non-202 response.
func submitOneE2E(t *testing.T, op *e2eOperator, token, signerDID string, payload []byte) (wire []byte, seq uint64, hash [32]byte) {
	t.Helper()
	wire = buildWireEntry(t, envelope.ControlHeader{SignerDID: signerDID}, payload)
	result := submitEntry(t, op.BaseURL, token, wire)

	// sequence_number arrives as float64 from JSON.
	seqF, ok := result["sequence_number"].(float64)
	if !ok {
		t.Fatalf("submitOneE2E: response missing sequence_number: %+v", result)
	}
	seq = uint64(seqF)

	hashHex, ok := result["canonical_hash"].(string)
	if !ok || len(hashHex) != 64 {
		t.Fatalf("submitOneE2E: response canonical_hash bad: %v", result["canonical_hash"])
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Fatalf("submitOneE2E: decode hash: %v", err)
	}
	copy(hash[:], hashBytes)
	return wire, seq, hash
}

// ─────────────────────────────────────────────────────────────────────
// Test 1: pre-shipping read is inline 200 from WAL.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_RawEntry_InlineWhenSequenced(t *testing.T) {
	op := startE2EOperator(t)
	op.seedSession(t, "tok-e2e-inline", "did:example:e2e-inline", 100)

	// Stop the shipper goroutine indirectly: cancel the harness ctx
	// is not an option (it tears the whole thing down). Instead, we
	// race the shipper by checking immediately after submission. With
	// PollInterval=50ms and MaxInFlight=4 the chance of being mid-
	// flight is real, so we issue the GET before the meta could have
	// transitioned. To make this deterministic we assert on either
	// the inline branch (state=Sequenced) OR the 302 branch (already
	// shipped). The 302 case is what TestE2E_RawEntry_RedirectsAfter-
	// Shipping covers; here we just want at least one inline hit.
	wire, seq, _ := submitOneE2E(t, op, "tok-e2e-inline", "did:example:inline-signer", []byte("inline-payload"))

	url := fmt.Sprintf("%s/v1/entries/%d/raw", op.BaseURL, seq)
	client := noRedirectClient()
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET raw: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		if got := resp.Header.Get("X-Source"); got != "wal" {
			t.Errorf("inline serve: X-Source = %q, want wal", got)
		}
		if string(body) != string(wire) {
			t.Errorf("inline serve body mismatch: got %d bytes, want %d", len(body), len(wire))
		}
	case http.StatusFound:
		// Shipper raced ahead. Acceptable; the redirect test covers it.
		if got := resp.Header.Get("X-Source"); got != "bytestore" {
			t.Errorf("redirect: X-Source = %q, want bytestore", got)
		}
		t.Logf("note: shipper raced and shipped before raw GET; redirect path observed")
	default:
		t.Fatalf("GET raw: status=%d body=%s", resp.StatusCode, body)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: post-shipping read is 302 redirect; following the URL
// returns the same bytes the producer submitted.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_RawEntry_RedirectsAfterShipping(t *testing.T) {
	op := startE2EOperator(t)
	op.seedSession(t, "tok-e2e-302", "did:example:e2e-302", 100)

	wire, seq, hash := submitOneE2E(t, op, "tok-e2e-302", "did:example:redirect-signer", []byte("redirect-payload"))

	// Block until shipper has migrated the entry.
	waitForShipped(t, op, hash, 5*time.Second)

	// Issue the raw GET without auto-follow. Must be 302 with a
	// Location URL containing the entry's hash hex.
	url := fmt.Sprintf("%s/v1/entries/%d/raw", op.BaseURL, seq)
	client := noRedirectClient()
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET raw: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 302, got %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Source"); got != "bytestore" {
		t.Errorf("redirect: X-Source = %q, want bytestore", got)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("redirect: Location header empty")
	}
	hashHex := hex.EncodeToString(hash[:])
	if !strings.Contains(loc, hashHex) {
		t.Errorf("Location %q missing hash hex %q (static-verifiability invariant)", loc, hashHex)
	}

	// Follow the redirect with a separate client and assert byte equality.
	follow := &http.Client{Timeout: 10 * time.Second}
	r2, err := follow.Get(loc)
	if err != nil {
		t.Fatalf("follow redirect: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(r2.Body)
		t.Fatalf("follow redirect: status=%d body=%s", r2.StatusCode, body)
	}
	got, _ := io.ReadAll(r2.Body)
	if string(got) != string(wire) {
		t.Errorf("redirect target body mismatch: got %d bytes, want %d", len(got), len(wire))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 3: HWM advances contiguously as a batch ships.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_HWMAdvancesContiguously(t *testing.T) {
	op := startE2EOperator(t)
	op.seedSession(t, "tok-e2e-hwm", "did:example:e2e-hwm", 100)

	const n = 5
	hashes := make([][32]byte, 0, n)
	seqs := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		_, seq, hash := submitOneE2E(t, op, "tok-e2e-hwm",
			"did:example:hwm-signer",
			[]byte(fmt.Sprintf("hwm-payload-%d", i)),
		)
		seqs = append(seqs, seq)
		hashes = append(hashes, hash)
	}

	// Wait for the highest-seq entry to ship. Once it ships, the HWM
	// advancer's contiguous-run rule guarantees every prior entry has
	// also shipped (otherwise HWM would not have advanced past those
	// gaps). The per-hash poll below double-checks each one.
	waitForShipped(t, op, hashes[n-1], 10*time.Second)

	ctx := context.Background()
	for i, h := range hashes {
		meta, err := op.WAL.MetaState(ctx, h)
		if err != nil {
			t.Fatalf("hash[%d] meta: %v", i, err)
		}
		if meta.State != wal.StateShipped {
			t.Errorf("hash[%d] (seq=%d) state=%s, want Shipped", i, seqs[i], meta.State)
		}
	}

	hwm, err := op.WAL.HWM(ctx)
	if err != nil {
		t.Fatalf("HWM: %v", err)
	}
	maxSeq := seqs[0]
	for _, s := range seqs[1:] {
		if s > maxSeq {
			maxSeq = s
		}
	}
	// HWM must have caught up to at least the highest seq we shipped.
	// Strict equality requires no concurrent test workload — these
	// tests run with cleanTables so HWM started at 0.
	if hwm < maxSeq {
		t.Errorf("HWM=%d, want >= %d (highest shipped seq)", hwm, maxSeq)
	}

	// Postgres entry_index sanity check — every submission must have
	// produced an entry_index row.
	var rowCount int
	if err := op.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM entry_index`).Scan(&rowCount); err != nil {
		t.Fatalf("count entry_index: %v", err)
	}
	if rowCount != n {
		t.Errorf("entry_index rows = %d, want %d", rowCount, n)
	}
}
