/*
FILE PATH: tests/e2e_graceful_shutdown_test.go

Validates graceful-shutdown semantics for the WAL + Shipper:

	TestE2E_ShutdownDuringShipping_Drains
	  Submits N entries, lets the Shipper start consuming, then
	  cancels ctx mid-flight. After full harness shutdown, the WAL
	  must be in a consistent state:
	    - HWM is some value H ≤ N (monotonic, never overruns).
	    - Every entry with seq ≤ HWM is StateShipped.
	    - Every entry with seq > HWM is StateSequenced (not half-shipped:
	      the Shipper guarantees bytestore.WriteEntry completes BEFORE
	      wal.MarkShipped runs, so a half-state is impossible).

	TestE2E_RestartCompletesShipping
	  Continuation of the same WAL volume + bytestore: spawns a fresh
	  harness pointed at the persisted WAL path and the same Memory
	  backend instance. The new Shipper picks up the leftover
	  Sequenced entries, ships them, and HWM converges to N.

BOTH TESTS USE A FILE-BACKED WAL (t.TempDir()) so the close-and-
reopen path actually exercises Badger persistence. The harness in
e2e_shipper_redirect_test.go uses wal.OpenInMemory which would not
survive the close.
*/
package tests

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/transparency-dev/tessera/storage/posix"
	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"

	"github.com/clearcompass-ai/ledger/api"
	"github.com/clearcompass-ai/ledger/api/middleware"
	"github.com/clearcompass-ai/ledger/sequencer"
	"github.com/clearcompass-ai/ledger/shipper"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/store/indexes"
	optessera "github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Disk-backed harness
//
// Mirrors startE2ELedger's wiring but parameterized on:
//   - walPath: tempdir path to a Badger DB. Reusing the same path
//     across two startShutdownLedger calls models the
//     restart-after-shutdown path.
//   - backend: shared *localPublicURLBackend so the second harness
//     sees objects the first one wrote. If nil, a fresh one is built.
//   - merkle: shared *stubMerkleAppender so the Tessera state (next
//     seq counter) survives the restart, mirroring the production
//     antispam-volume restart path.
//   - cleanFirst: whether to truncate Postgres tables. The first
//     invocation does; the restart invocation must NOT (would lose
//     the entry_index rows the WAL is reconciling against).
// ─────────────────────────────────────────────────────────────────────

type shutdownHarnessOpts struct {
	walPath    string
	backend    *localPublicURLBackend
	tileRoot   string // shared Tessera POSIX dir across restarts; empty → t.TempDir
	cleanFirst bool
}

type shutdownHarness struct {
	BaseURL  string
	Pool     *pgxpool.Pool
	WAL      *wal.Committer
	walDB    walDBCloser
	Backend  *localPublicURLBackend
	TileRoot string // pass to a second startShutdownLedger call for restart fidelity
	Server   *api.Server
	Shipper  *shipper.Shipper
	merkle   *optessera.EmbeddedAppender // for stop() to call Close in the correct order
	cancel   context.CancelFunc
	done     chan struct{}
}

// walDBCloser is a tiny shim — the wal.Open return type lives in
// the badger v4 package. The shutdown test only ever needs Close()
// on it, so we narrow the surface.
type walDBCloser interface{ Close() error }

func startShutdownLedger(t *testing.T, opts shutdownHarnessOpts) *shutdownHarness {
	t.Helper()

	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping graceful-shutdown test")
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
	if opts.cleanFirst {
		cleanTables(t, pool)
	}

	walDB, err := wal.Open(opts.walPath, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("wal.Open(%q): %v", opts.walPath, err)
	}
	// On-disk Badger: real db.Sync() works (no DisableSync).
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{Logger: logger})

	backend := opts.backend
	if backend == nil {
		backend = newLocalPublicURLBackend(t)
	}
	// Real Tessera over a shared POSIX dir. Reusing the dir
	// across restarts is exactly the production restart path:
	// the antispam dedup volume + tile state survive on disk,
	// the new EmbeddedAppender re-opens them on boot.
	tileRoot := opts.tileRoot
	if tileRoot == "" {
		tileRoot = t.TempDir()
	}
	signer, _, sErr := optessera.GenerateEphemeralSigner("test-shutdown")
	if sErr != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("tessera signer: %v", sErr)
	}
	driver, dErr := posix.New(ctx, posix.Config{Path: tileRoot})
	if dErr != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("tessera posix.New: %v", dErr)
	}
	// ANTISPAM (dedup) — load-bearing for the sequencer's drainOnce
	// race tolerance. Without it, drainOnce N+1 re-picks-up a hash
	// whose stage-1 worker from cycle N is still in flight; the
	// re-spawned worker's AppendLeaf gets a FRESH seq (Tessera with
	// nil antispam treats every Add as new), entry_index gets a
	// status=2 ghost row at the fresh seq, and the shipper's
	// hwmAdvancer contiguity invariant breaks at the first ghost.
	//
	// On the phase-2 restart path the on-disk antispam volume is
	// re-opened at the same tileRoot, so the dedup map survives the
	// kill — exactly the production behavior.
	//
	// Reproducer: tessera/antispam_off_reproducer_test.go.
	// Production-shape harness: tests/witnessed_harness_test.go:141.
	antispamPath := filepath.Join(tileRoot, "antispam")
	antispam, asErr := tposixantispam.NewAntispam(ctx, antispamPath, tposixantispam.AntispamOpts{})
	if asErr != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("tposixantispam.NewAntispam(%s): %v", antispamPath, asErr)
	}
	// CTX LIFETIME: Tessera's background goroutines listen to ctx
	// for termination. h.stop() (and the defensive t.Cleanup below)
	// call merkle.Close BEFORE cancelling ctx so Shutdown can poll
	// the checkpoint while the integration loop is still alive.
	// Do NOT wrap with context.WithoutCancel — that leaks the
	// integration goroutine forever (Close doesn't stop it).
	merkle, mErr := optessera.NewEmbeddedAppender(ctx, driver, optessera.AppenderOptions{
		Origin:               testLogDID,
		Signer:               signer,
		CheckpointInterval:   100 * time.Millisecond,
		BatchSize:            4,
		BatchMaxAge:          50 * time.Millisecond,
		PublicCheckpointPath: filepath.Join(tileRoot, "cosigned-checkpoint"),
		Antispam:             antispam,
	}, logger)
	if mErr != nil {
		_ = walc.Close()
		_ = walDB.Close()
		pool.Close()
		cancel()
		t.Fatalf("tessera embedded: %v", mErr)
	}
	// merkle.Close is called by h.stop() in the spec-correct order
	// (see tests/shutdownchain_test.go). The defensive cleanup below
	// only fires if the test forgets to call h.stop() — covers
	// panic / early-return paths so we still drain pending Tessera
	// futures before the test process exits.
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = merkle.Close(closeCtx)
	})

	composite := store.NewCompositeByteReader(walc, backend, logger)
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	sequenceCursor := store.NewSequenceCursor(pool)
	fetcher := store.NewPostgresEntryFetcher(pool, composite, testLogDID)
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, composite, testLogDID)

	diffController := middleware.NewDifficultyController(
		sequenceCursor, middleware.DefaultDifficultyConfig(), logger,
	)

	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: entryStore, WAL: walc, Tessera: merkle,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    testEpochWindowSeconds,
			EpochAcceptanceWindow: testEpochAcceptanceWindow,
		},
		Identity:         api.IdentityDeps{Credits: creditStore},
		LogDID:           testLogDID,
		LedgerDID:        testLedgerDID,
		LedgerSignerPriv: shutdownSignerPriv(t),
		MaxEntrySize:     1 << 20,
		Logger:           logger,
	}
	queryDeps := &api.QueryDeps{
		EntryStore: entryStore, QueryAPI: queryAPI, DiffController: diffController,
		WAL: walc, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI, EntryStore: entryStore,
		WAL: walc, PublicURLer: backend, LogDID: testLogDID, Logger: logger,
	}

	handlers := api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryByHash:     api.NewHashLookupHandler(queryDeps),
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

	// Sequencer first — v1 admission is now a polling facade and
	// needs the sequencer running to advance WAL state.
	seq := sequencer.NewSequencer(walc, merkle, pool, entryStore, sequencer.Config{
		PollInterval: 10 * time.Millisecond,
		Logger:       logger,
	})

	ship := shipper.NewShipper(walc, backend, shipper.Config{
		PollInterval: 50 * time.Millisecond,
		MaxInFlight:  4,
		Logger:       logger,
	})

	done := make(chan struct{}, 3)
	go func() {
		defer func() { done <- struct{}{} }()
		_ = server.Serve(ln)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		_ = seq.Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		_ = ship.Run(ctx)
	}()

	h := &shutdownHarness{
		BaseURL: baseURL, Pool: pool, WAL: walc, walDB: walDB,
		Backend: backend, TileRoot: tileRoot, Server: server, Shipper: ship,
		merkle: merkle,
		cancel: cancel, done: done,
	}

	for i := 0; i < 50; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return h
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("shutdown harness did not become ready in 2.5s")
	return nil
}

// stop simulates graceful shutdown of this harness instance, in the
// spec-correct order (see tests/shutdownchain_test.go):
//
//  1. Server.Shutdown          → refuse new HTTP requests
//  2. merkle.Close             → drain Tessera pending futures —
//                                this also unblocks any in-flight
//                                sequencer AppendLeaf call (its
//                                future resolves with the appender-
//                                shutdown error)
//  3. cancel()                 → signal sequencer / shipper to exit
//  4. wait for goroutines      → in-flight calls already returned
//                                in step 2, so they drain quickly
//  5. WAL / walDB / pool       → release resources
//
// Tables are NOT cleaned — the next harness instance picks up where
// this one left off (that's the whole point of the restart-fidelity
// scenarios this harness exists to test).
func (h *shutdownHarness) stop(t *testing.T) {
	t.Helper()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// 1. HTTP layer first — refuse new submissions before draining.
	if err := h.Server.Shutdown(shutdownCtx); err != nil {
		t.Logf("stop: server.Shutdown: %v", err)
	}

	// 2. Drain Tessera futures. Load-bearing: Close calls upstream
	// Shutdown which polls the checkpoint until it covers the
	// largest issued index. Must run BEFORE step 3's cancel() so
	// the integration goroutine is still alive to publish the
	// checkpoint.
	if h.merkle != nil {
		if err := h.merkle.Close(shutdownCtx); err != nil {
			t.Logf("stop: merkle.Close: %v", err)
		}
	}

	// 3. Signal sequencer / shipper / server-Serve goroutines.
	h.cancel()

	// 4. Wait for the three background goroutines (server.Serve,
	// seq.Run, ship.Run). Their in-flight Tessera calls already
	// returned in step 2, so wg.Wait drains promptly.
	for i := 0; i < cap(h.done); i++ {
		select {
		case <-h.done:
		case <-shutdownCtx.Done():
			t.Fatalf("shutdown harness goroutine %d/%d did not return in budget",
				i+1, cap(h.done))
		}
	}

	// 5. Release resources.
	_ = h.WAL.Close()
	_ = h.walDB.Close()
	h.Pool.Close()
}

func (h *shutdownHarness) seedSession(t *testing.T, token, exchangeDID string, credits int64) {
	t.Helper()
	ctx := context.Background()
	_, err := h.Pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO NOTHING`,
		token, exchangeDID, time.Now().UTC().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if credits > 0 {
		cs := store.NewCreditStore(h.Pool)
		if _, err := cs.BulkPurchase(ctx, exchangeDID, credits); err != nil {
			t.Fatalf("seed credits: %v", err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 1: shutdown mid-flight leaves the WAL consistent.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_ShutdownDuringShipping_Drains(t *testing.T) {
	const n = 50

	walDir := filepath.Join(t.TempDir(), "wal")
	backend := newLocalPublicURLBackend(t)

	// ── Step 1: submit n entries, let some ship, cancel ────────────
	h1 := startShutdownLedger(t, shutdownHarnessOpts{
		walPath:    walDir,
		backend:    backend,
		cleanFirst: true,
	})
	h1.seedSession(t, "tok-shutdown", "did:example:shutdown-exchange", 1000)

	type submitted struct {
		seq  uint64
		hash [32]byte
	}
	all := make([]submitted, 0, n)
	for i := 0; i < n; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:shutdown-signer",
		}, []byte(fmt.Sprintf("shutdown-%03d", i)))
		result := submitEntry(t, h1.BaseURL, "tok-shutdown", wire)
		seq := uint64(result["sequence_number"].(float64))
		hashHex := result["canonical_hash"].(string)
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil {
			t.Fatalf("decode hash[%d]: %v", i, err)
		}
		var hash [32]byte
		copy(hash[:], hashBytes)
		all = append(all, submitted{seq: seq, hash: hash})
	}

	// Wait until at least 3 entries have shipped so the shipper is
	// known to be active. Don't wait for all — the point of the test
	// is to interrupt mid-flight.
	const minShippedBeforeCancel = 3
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hwm, err := h1.WAL.HWM(context.Background())
		if err != nil {
			t.Fatalf("HWM: %v", err)
		}
		if hwm >= minShippedBeforeCancel {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	hwmBeforeCancel, err := h1.WAL.HWM(context.Background())
	if err != nil {
		t.Fatalf("HWM: %v", err)
	}
	t.Logf("phase 1: cancelling with HWM=%d / submitted=%d", hwmBeforeCancel, n)

	h1.stop(t)

	// ── Step 1 assertions: re-open the WAL read-only and inspect ──
	// We have to reopen because the committer is closed; reopening
	// read-only via wal.Open + a fresh committer (no shipper, no
	// admission) gives us a clean introspection surface.
	probeLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	probeDB, err := wal.Open(walDir, probeLogger)
	if err != nil {
		t.Fatalf("reopen WAL for assertions: %v", err)
	}
	probe := wal.NewCommitter(probeDB, wal.CommitterConfig{Logger: probeLogger})

	finalHWM, err := probe.HWM(context.Background())
	if err != nil {
		t.Fatalf("post-shutdown HWM: %v", err)
	}
	if finalHWM < hwmBeforeCancel {
		t.Errorf("HWM regressed: pre-cancel=%d post-cancel=%d", hwmBeforeCancel, finalHWM)
	}
	if finalHWM > uint64(n) {
		t.Errorf("HWM=%d overran submission count %d", finalHWM, n)
	}

	// Every entry's meta state must be either Sequenced or Shipped —
	// there is no half-state. Group by state for the assertion.
	var (
		shipped   int
		sequenced int
		other     int
	)
	ctx := context.Background()
	for _, e := range all {
		meta, err := probe.MetaState(ctx, e.hash)
		if err != nil {
			t.Errorf("seq=%d hash=%x: meta state: %v", e.seq, e.hash[:4], err)
			continue
		}
		switch meta.State {
		case wal.StateShipped:
			shipped++
		case wal.StateSequenced:
			sequenced++
		default:
			other++
			t.Errorf("seq=%d hash=%x: unexpected state %s", e.seq, e.hash[:4], meta.State)
		}
	}
	t.Logf("phase 1 final: HWM=%d shipped=%d sequenced=%d other=%d", finalHWM, shipped, sequenced, other)
	if other > 0 {
		t.Errorf("entries in non-{Sequenced,Shipped} state: %d", other)
	}
	if shipped+sequenced != n {
		t.Errorf("accounting: shipped+sequenced=%d, want %d", shipped+sequenced, n)
	}

	_ = probe.Close()
	_ = probeDB.Close()
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: a fresh harness against the same WAL drains the leftover.
// ─────────────────────────────────────────────────────────────────────

func TestE2E_RestartCompletesShipping(t *testing.T) {
	const n = 30

	walDir := filepath.Join(t.TempDir(), "wal")
	backend := newLocalPublicURLBackend(t)

	// Shared Tessera POSIX dir across both invocations so the
	// second harness re-opens the same on-disk antispam volume +
	// tile state — exactly the production restart path.
	sharedTileRoot := t.TempDir()

	// ── Step 1: submit n, cancel mid-flight ─────────────────────────
	h1 := startShutdownLedger(t, shutdownHarnessOpts{
		walPath:    walDir,
		backend:    backend,
		tileRoot:   sharedTileRoot,
		cleanFirst: true,
	})
	h1.seedSession(t, "tok-restart", "did:example:restart-exchange", 1000)

	hashes := make([][32]byte, 0, n)
	for i := 0; i < n; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:restart-signer",
		}, []byte(fmt.Sprintf("restart-%03d", i)))
		result := submitEntry(t, h1.BaseURL, "tok-restart", wire)
		hashHex := result["canonical_hash"].(string)
		hashBytes, _ := hex.DecodeString(hashHex)
		var hash [32]byte
		copy(hash[:], hashBytes)
		hashes = append(hashes, hash)
	}

	// Wait until something has shipped, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hwm, _ := h1.WAL.HWM(context.Background())
		if hwm >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	hwmAtCancel, _ := h1.WAL.HWM(context.Background())
	t.Logf("phase 1: cancelling with HWM=%d / submitted=%d", hwmAtCancel, n)
	h1.stop(t)

	// ── Step 2: fresh harness with the same WAL + backend + tessera dir ─
	h2 := startShutdownLedger(t, shutdownHarnessOpts{
		walPath:    walDir,
		backend:    backend,
		tileRoot:   sharedTileRoot,
		cleanFirst: false, // keep entry_index rows
	})
	defer h2.stop(t)

	// Wait for the shipper's HWM to converge to n. With Memory backend
	// and small entry count, this should be sub-second; allow 30s for
	// CI variability + sequencer retry budgets on entries that were
	// in-flight when h1 cancelled.
	deadline = time.Now().Add(30 * time.Second)
	var finalHWM uint64
	for time.Now().Before(deadline) {
		hwm, err := h2.WAL.HWM(context.Background())
		if err != nil {
			t.Fatalf("HWM: %v", err)
		}
		finalHWM = hwm
		if hwm >= uint64(n) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if finalHWM < uint64(n) {
		// Don't Fatalf — surface per-hash state below so we can see
		// which entry leaked and in what state.
		t.Errorf("phase 2: HWM=%d did not converge to %d in 30s", finalHWM, n)
	}

	// Every entry must end StateShipped after the second harness drains.
	ctx := context.Background()
	stateCounts := map[wal.EntryState]int{}
	for i, h := range hashes {
		meta, err := h2.WAL.MetaState(ctx, h)
		if err != nil {
			t.Errorf("hash[%d]: meta state: %v", i, err)
			continue
		}
		stateCounts[meta.State]++
		if meta.State != wal.StateShipped {
			t.Errorf("hash[%d]=%x state=%s, want Shipped", i, h[:4], meta.State)
		}
	}
	t.Logf("phase 2: HWM=%d state breakdown=%v", finalHWM, stateCounts)
}

// shutdownSignerPriv generates an ephemeral ECDSA key for the
// shutdown harness's SCT signer. SubmissionDeps.LedgerSignerPriv
// is required (api.NewSubmissionHandler panics on nil); the key
// is per-test ephemeral because no test asserts on the SCT
// signature identity.
func shutdownSignerPriv(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("shutdownSignerPriv: %v", err)
	}
	return priv
}
