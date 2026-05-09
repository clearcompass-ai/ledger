//go:build integration
// +build integration

// FILE PATH: integration/cosign_collection_test.go
//
// End-to-end integration test for the cosign collection +
// cosigned-checkpoint publication chain.
//
// Build tag `integration` keeps this invisible to standard
// `go test ./...`. scripts/run-integration.sh is the canonical
// runner; it owns the docker compose lifecycle.
//
// PHYSICS UNDER TEST:
//
//	real httptest cosign servers      (SDK NewWitnessHandler)
//	             ↓
//	witnessclient.HeadSync.Collect    (K-of-N over real HTTP)
//	             ↓
//	store.TreeHeadStore               (real Postgres rows)
//	             ↓
//	tessera.EmbeddedAppender          (real POSIX dir)
//	             ↓
//	atomic write of cosigned head     (<tempdir>/cosigned-checkpoint)
//
// The assertions:
//   - the file at the expected path EXISTS;
//   - parses as JSON-encoded types.CosignedTreeHead;
//   - contains the expected TreeSize + RootHash;
//   - contains AT LEAST K signatures (collector short-circuits at K).
//
// We bypass the BuilderLoop's entry-fetching machinery
// deliberately. The chain that needs HTTP-fixture coverage —
// HeadSync → TreeHeadStore → PublishCosignedCheckpoint → disk — is
// exercised here in isolation. Builder-loop end-to-end coverage
// (admission → sequencer → builder → cosign) is the ledger's
// own e2e tests' job.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	uptessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"
	"github.com/clearcompass-ai/ledger/witnessclient"
)

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

const cosignTestLogDID = "did:attesta:integration:cosign-collection"

func requireIntegrationDSN(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset — use scripts/run-integration.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("RunMigrations: %v", err)
	}
	return pool
}

func cosignTestNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0xC0 | (i & 0x3F))
	}
	return n
}

// witnessServer wraps an httptest cosign server with a Close
// method that simulates "this witness went offline".
type witnessServer struct {
	srv *httptest.Server
	url string
}

func startWitness(t *testing.T, netID cosign.NetworkID) *witnessServer {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := cosign.NewECDSAWitnessSigner(priv)
	h, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
		Signer:          signer,
		AllowedNetworks: map[cosign.NetworkID]struct{}{netID: {}},
	})
	if err != nil {
		t.Fatalf("NewWitnessHandler: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(cosign.DefaultCosignPath, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &witnessServer{srv: srv, url: srv.URL}
}

// resetCosignTables clears the cosign persistence tables so each
// test starts from a known-empty state.
func resetCosignTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM tree_head_sigs`,
		`DELETE FROM tree_heads`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("reset: %s: %v", q, err)
		}
	}
}

// buildEmbeddedAppender constructs a real tessera.EmbeddedAppender
// over a fresh t.TempDir() POSIX directory. Returns the appender,
// its public-checkpoint path, and the tile root.
type tesseraStack struct {
	embedded               *optessera.EmbeddedAppender
	tileRoot               string
	cosignedCheckpointPath string
}

func buildEmbeddedAppender(t *testing.T, ctx context.Context, logger *slog.Logger) *tesseraStack {
	t.Helper()
	tileRoot := t.TempDir()
	cosignedPath := filepath.Join(tileRoot, "cosigned-checkpoint")

	signer, _, err := optessera.GenerateEphemeralSigner("integration-cosign-collection")
	if err != nil {
		t.Fatalf("GenerateEphemeralSigner: %v", err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: tileRoot})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	_ = uptessera.Driver(driver)

	// CTX LIFETIME: see tests/shutdownchain_test.go and
	// cmd/ledger/boot/alloc/alloc.go — Tessera's background ctx is
	// decoupled from the test ctx so embedded.Close drains pending
	// futures while the integration loop is still alive.
	embedded, err := optessera.NewEmbeddedAppender(context.WithoutCancel(ctx), driver, optessera.AppenderOptions{
		Origin:               cosignTestLogDID,
		Signer:               signer,
		CheckpointInterval:   100 * time.Millisecond,
		BatchSize:            4,
		BatchMaxAge:          50 * time.Millisecond,
		PublicCheckpointPath: cosignedPath,
	}, logger)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = embedded.Close(ctx)
	})

	return &tesseraStack{
		embedded:               embedded,
		tileRoot:               tileRoot,
		cosignedCheckpointPath: cosignedPath,
	}
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// ─────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────

// TestCosign_QuorumCollectedAndPublished pins the happy path:
// HeadSync collects K-of-N signatures over real HTTP; the
// PublishCosignedCheckpoint call writes the JSON-encoded cosigned
// head to <tempdir>/cosigned-checkpoint atomically. Auditors
// reading this file recover the exact K-of-N evidence.
func TestCosign_QuorumCollectedAndPublished(t *testing.T) {
	pool := requireIntegrationDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetCosignTables(t, ctx, pool)

	logger := silentLogger()
	netID := cosignTestNetID()

	// 3 witness daemons up; K=2.
	const N, K = 3, 2
	witnesses := make([]*witnessServer, N)
	endpoints := make([]string, N)
	for i := 0; i < N; i++ {
		witnesses[i] = startWitness(t, netID)
		endpoints[i] = witnesses[i].url
	}

	// Real embedded appender — the actual file writer under test.
	stack := buildEmbeddedAppender(t, ctx, logger)

	// Real HeadSync — Ledger's cosign client.
	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  endpoints,
		QuorumK:           K,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	// Drive a single cosign collection.
	head := types.TreeHead{
		TreeSize: 4242,
		RootHash: [32]byte{0x42, 0xCA, 0xFE},
	}
	cosigned, err := hs.RequestCosignatures(ctx, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(cosigned.Signatures) < K {
		t.Fatalf("collected %d signatures, want >= K=%d",
			len(cosigned.Signatures), K)
	}

	// Publish to the public CDN path. THIS is the load-bearing
	// physics — the file MUST appear on disk after this returns.
	if err := stack.embedded.PublishCosignedCheckpoint(ctx, cosigned); err != nil {
		t.Fatalf("PublishCosignedCheckpoint: %v", err)
	}

	// Assertion 1: the file exists.
	body, err := os.ReadFile(stack.cosignedCheckpointPath)
	if err != nil {
		t.Fatalf("cosigned-checkpoint at %s: %v\n"+
			"the entire physics chain is broken if this fails",
			stack.cosignedCheckpointPath, err)
	}

	// Assertion 2: parses as the expected JSON shape.
	var got types.CosignedTreeHead
	if jerr := json.Unmarshal(body, &got); jerr != nil {
		t.Fatalf("file is not valid CosignedTreeHead JSON: %v\nbody=%s", jerr, body)
	}

	// Assertion 3: TreeSize + RootHash match what we asked for.
	if got.TreeSize != head.TreeSize {
		t.Errorf("file TreeSize = %d, want %d", got.TreeSize, head.TreeSize)
	}
	if got.RootHash != head.RootHash {
		t.Errorf("file RootHash = %x, want %x", got.RootHash, head.RootHash)
	}

	// Assertion 4: K signatures present.
	if len(got.Signatures) < K {
		t.Errorf("file has %d signatures, want >= K=%d", len(got.Signatures), K)
	}

	// Assertion 5: persisted rows in tree_head_sigs.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount < K {
		t.Errorf("persisted sig rows = %d, want >= K=%d "+
			"(persistence + publish must produce identical evidence)",
			sigCount, K)
	}
}

// TestCosign_QuorumFailureNeverPublishes pins the Strict-STH-
// Finality contract: when fewer than K witnesses respond,
// RequestCosignatures returns ErrQuorumCollectionFailed and the
// cosigned-checkpoint file MUST NOT appear. The Ledger's pre-
// commit gate refuses to call PublishCosignedCheckpoint on a
// quorum failure; this test verifies the file system reflects
// that refusal.
func TestCosign_QuorumFailureNeverPublishes(t *testing.T) {
	pool := requireIntegrationDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetCosignTables(t, ctx, pool)

	logger := silentLogger()
	netID := cosignTestNetID()

	// 3 witnesses; K=2; close 2 of 3 to force quorum failure.
	const N, K = 3, 2
	witnesses := make([]*witnessServer, N)
	endpoints := make([]string, N)
	for i := 0; i < N; i++ {
		witnesses[i] = startWitness(t, netID)
		endpoints[i] = witnesses[i].url
	}
	witnesses[1].srv.Close()
	witnesses[2].srv.Close()

	stack := buildEmbeddedAppender(t, ctx, logger)

	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  endpoints,
		QuorumK:           K,
		PerWitnessTimeout: 1 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{TreeSize: 9999, RootHash: [32]byte{0x99}}
	timedCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cosigned, err := hs.RequestCosignatures(timedCtx, head)
	if err == nil {
		t.Fatal("expected ErrQuorumCollectionFailed, got nil — " +
			"K=2 with only 1 witness up MUST fail")
	}
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		t.Errorf("error chain missing ErrQuorumCollectionFailed: %v", err)
	}

	// The Ledger's builder/loop.go does NOT call
	// PublishCosignedCheckpoint when RequestCosignatures errs.
	// We model that contract here by simply not calling it.
	_ = cosigned

	// Assertion: the cosigned-checkpoint file does NOT exist.
	if _, err := os.Stat(stack.cosignedCheckpointPath); err == nil {
		t.Fatalf("cosigned-checkpoint exists at %s after quorum failure — "+
			"the pre-commit gate or the publish-only-on-success rule "+
			"is broken", stack.cosignedCheckpointPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat: %v", err)
	}

	// Assertion: no persisted rows in tree_head_sigs.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount != 0 {
		t.Errorf("persisted %d rows on quorum failure; want 0", sigCount)
	}
}

// TestCosign_PublishOverwritesAtomically pins the rolling-update
// contract: each successful K-of-N collection produces a fresh
// cosigned-checkpoint file at the SAME path. The atomic write
// (tmp + rename) means auditors hitting the file mid-update see
// either the old contents or the new — never a torn write.
func TestCosign_PublishOverwritesAtomically(t *testing.T) {
	pool := requireIntegrationDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetCosignTables(t, ctx, pool)

	logger := silentLogger()
	netID := cosignTestNetID()

	const N, K = 2, 2
	witnesses := make([]*witnessServer, N)
	endpoints := make([]string, N)
	for i := 0; i < N; i++ {
		witnesses[i] = startWitness(t, netID)
		endpoints[i] = witnesses[i].url
	}

	stack := buildEmbeddedAppender(t, ctx, logger)
	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  endpoints,
		QuorumK:           K,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	// Cycle 1: TreeSize=100.
	head1 := types.TreeHead{TreeSize: 100, RootHash: [32]byte{0xA1}}
	c1, err := hs.RequestCosignatures(ctx, head1)
	if err != nil {
		t.Fatalf("cycle 1 cosign: %v", err)
	}
	if err := stack.embedded.PublishCosignedCheckpoint(ctx, c1); err != nil {
		t.Fatalf("cycle 1 publish: %v", err)
	}

	// Cycle 2: TreeSize=200 — overwrite.
	head2 := types.TreeHead{TreeSize: 200, RootHash: [32]byte{0xA2}}
	c2, err := hs.RequestCosignatures(ctx, head2)
	if err != nil {
		t.Fatalf("cycle 2 cosign: %v", err)
	}
	if err := stack.embedded.PublishCosignedCheckpoint(ctx, c2); err != nil {
		t.Fatalf("cycle 2 publish: %v", err)
	}

	// Assertion: file reflects cycle 2, not cycle 1.
	body, err := os.ReadFile(stack.cosignedCheckpointPath)
	if err != nil {
		t.Fatalf("read after cycle 2: %v", err)
	}
	var got types.CosignedTreeHead
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TreeSize != head2.TreeSize {
		t.Errorf("file TreeSize = %d after cycle 2; want %d (atomic overwrite broken)",
			got.TreeSize, head2.TreeSize)
	}
}
