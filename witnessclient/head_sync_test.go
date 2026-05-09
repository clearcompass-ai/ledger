// FILE PATH: witnessclient/head_sync_test.go
//
// Unit tests for the Ledger's cosign client. Splits cleanly into:
//
//   - Constructor tests (no DSN required) — pin the rejection
//     contract for malformed HeadSyncConfig values.
//
//   - End-to-end RequestCosignatures tests (DSN-gated) — pin the
//     happy path (K-of-N collected + persisted) and the
//     quorum-failure error wrapping. Skip cleanly when
//     ATTESTA_TEST_DSN is unset.
//
// PHYSICS, NOT MOCKS:
//
// The DSN-gated tests use real httptest.NewServer running the
// SDK's cosign.NewWitnessHandler. The Ledger's HeadSync POSTs to
// real HTTP and the witness signs with a real ECDSA key. The
// (head, signature) tuple is persisted into a real Postgres
// tree_heads / tree_head_sigs row pair via store.TreeHeadStore.
package witnessclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// silentLogger discards output; tests assert on return values
// + Postgres state, not log content.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testNetID returns a deterministic non-zero NetworkID scoped
// to this test file.
func testNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0x10 | (i & 0x0F))
	}
	return n
}

// requireDSN returns a connected pgxpool.Pool against
// ATTESTA_TEST_DSN. Skips the test if the env var is unset —
// matches the P4 + commitment_fetcher pattern.
func requireDSN(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping HeadSync DB-backed test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("RunMigrations: %v", err)
	}
	return pool
}

// resetTreeHeadTables truncates the two persistence tables so
// each DSN-gated test starts from a known-empty state.
func resetTreeHeadTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DELETE FROM tree_head_sigs`); err != nil {
		t.Fatalf("clear tree_head_sigs: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tree_heads`); err != nil {
		t.Fatalf("clear tree_heads: %v", err)
	}
}

// startWitnessServer spins up an in-process httptest cosign server
// backed by a fresh ECDSA key + the SDK's NewWitnessHandler.
// Cleanup is registered with t.Cleanup.
func startWitnessServer(t *testing.T, netID cosign.NetworkID) *httptest.Server {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("signatures.GenerateKey: %v", err)
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
	return srv
}

// ─────────────────────────────────────────────────────────────────
// Constructor tests (no DSN needed; treeStore can be nil because
// NewHeadSync does not call it).
// ─────────────────────────────────────────────────────────────────

func TestNewHeadSync_RejectsEmptyEndpoints(t *testing.T) {
	_, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  nil,
		QuorumK:           1,
		PerWitnessTimeout: 5 * time.Second,
		NetworkID:         testNetID(),
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("NewHeadSync with empty WitnessEndpoints: expected error")
	}
}

func TestNewHeadSync_RejectsNonPositiveQuorum(t *testing.T) {
	_, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  []string{"http://w1"},
		QuorumK:           0,
		PerWitnessTimeout: 5 * time.Second,
		NetworkID:         testNetID(),
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("NewHeadSync with QuorumK=0: expected error")
	}
}

func TestNewHeadSync_RejectsQuorumGreaterThanN(t *testing.T) {
	// SDK's NewWitnessCollector rejects K > N — the Ledger-side
	// builder relies on this for early-fail semantics. Pin the
	// rejection so a refactor that swaps the collector for one
	// that silently accepts impossible quora can't slip past.
	_, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  []string{"http://w1", "http://w2"}, // N=2
		QuorumK:           3,                                  // K=3 > N
		PerWitnessTimeout: 5 * time.Second,
		NetworkID:         testNetID(),
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("NewHeadSync with QuorumK > N: expected error")
	}
}

func TestNewHeadSync_DefaultsPerWitnessTimeout(t *testing.T) {
	hs, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  []string{"http://w1"},
		QuorumK:           1,
		PerWitnessTimeout: 0, // ← zero
		NetworkID:         testNetID(),
	}, nil, silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}
	if hs == nil {
		t.Fatal("NewHeadSync returned nil HeadSync")
	}
	// PerWitnessTimeout zero is normalized to a default; we
	// can't read the field directly (unexported), but the
	// constructor accepting zero is itself the contract.
}

func TestNewHeadSync_HappyPath(t *testing.T) {
	hs, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  []string{"http://w1", "http://w2", "http://w3"},
		QuorumK:           2,
		PerWitnessTimeout: 5 * time.Second,
		NetworkID:         testNetID(),
	}, nil, silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}
	if hs == nil {
		t.Fatal("NewHeadSync returned nil")
	}
	if hs.Collector() == nil {
		t.Fatal("Collector() is nil; downstream callers (escrow override, rotation) " +
			"depend on this being non-nil for purpose-flexible cosign")
	}
}

func TestRequestCosignatures_NilReceiver(t *testing.T) {
	var hs *HeadSync
	got, err := hs.RequestCosignatures(context.Background(), types.TreeHead{TreeSize: 1})
	if err != nil {
		t.Errorf("nil receiver: got err %v, want nil (per documented no-op contract)", err)
	}
	if got.TreeSize != 0 {
		t.Errorf("nil receiver: expected zero CosignedTreeHead, got TreeSize=%d", got.TreeSize)
	}
}

// ─────────────────────────────────────────────────────────────────
// DSN-gated end-to-end tests
// ─────────────────────────────────────────────────────────────────

func TestRequestCosignatures_HappyPath_K1(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	srv := startWitnessServer(t, netID)

	hs, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  []string{srv.URL},
		QuorumK:           1,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{
		TreeSize: 7777,
		RootHash: [32]byte{0x77},
	}
	cosigned, err := hs.RequestCosignatures(ctx, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if cosigned.TreeSize != head.TreeSize {
		t.Errorf("returned head.TreeSize = %d, want %d", cosigned.TreeSize, head.TreeSize)
	}
	if len(cosigned.Signatures) != 1 {
		t.Errorf("len(Signatures) = %d, want 1 (K=1)", len(cosigned.Signatures))
	}

	// Persistence assertion: the head + signature row are present.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount != 1 {
		t.Errorf("persisted sig rows for tree_size=%d: %d, want 1", head.TreeSize, sigCount)
	}
}

func TestRequestCosignatures_QuorumFailure_WrapsErr(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	// Spin up two servers then close one before driving HeadSync.
	// K=2, N=2, Online=1 → ErrQuorumCollectionFailed.
	srvA := startWitnessServer(t, netID)
	srvB := startWitnessServer(t, netID)
	srvB.Close()

	hs, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  []string{srvA.URL, srvB.URL},
		QuorumK:           2,
		PerWitnessTimeout: 1 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{TreeSize: 8888, RootHash: [32]byte{0x88}}

	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = hs.RequestCosignatures(ctx2, head)
	if err == nil {
		t.Fatal("RequestCosignatures with K-of-N unmet: expected error, got nil")
	}
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		t.Errorf("error chain missing ErrQuorumCollectionFailed: %v", err)
	}

	// No row should be persisted on quorum failure — the head/sig
	// inserts run only after Collect succeeds.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount != 0 {
		t.Errorf("persisted %d sig rows on quorum failure; want 0 "+
			"(persistence must not run when Collect errs)", sigCount)
	}
}

func TestRequestCosignatures_ExactQuorum_3of5(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	const totalN, quorumK, online = 5, 3, 3

	srvs := make([]*httptest.Server, totalN)
	for i := range srvs {
		srvs[i] = startWitnessServer(t, netID)
	}
	for i := online; i < totalN; i++ {
		srvs[i].Close() // bring N-online offline
	}
	endpoints := make([]string, totalN)
	for i, s := range srvs {
		endpoints[i] = s.URL
	}

	hs, err := NewHeadSync(HeadSyncConfig{
		WitnessEndpoints:  endpoints,
		QuorumK:           quorumK,
		PerWitnessTimeout: 1 * time.Second,
		NetworkID:         netID,
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{TreeSize: 9999, RootHash: [32]byte{0x99}}

	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cosigned, err := hs.RequestCosignatures(ctx2, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(cosigned.Signatures) < quorumK {
		t.Errorf("collected %d signatures, want >= K=%d (collector short-circuits at K)",
			len(cosigned.Signatures), quorumK)
	}
	if len(cosigned.Signatures) > totalN {
		t.Errorf("collected %d signatures, want <= N=%d", len(cosigned.Signatures), totalN)
	}
}
