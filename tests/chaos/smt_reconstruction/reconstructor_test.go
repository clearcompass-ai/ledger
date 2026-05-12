// FILE PATH: tests/chaos/smt_reconstruction/reconstructor_test.go
//
// Unit tests for the reconstructor — both the pure-function
// helpers (FormatMismatch) and the end-to-end Reconstruct flow
// against a real Postgres instance. The PG-backed test is
// t.Skip'd when ATTESTA_TEST_DSN is unset, so the package
// still passes `go test ./...` in environments without
// infrastructure.
package smt_reconstruction

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/store"
)

// ─────────────────────────────────────────────────────────────────────
// Pure-function unit tests (no PG required)
// ─────────────────────────────────────────────────────────────────────

func TestResult_FormatMismatch_EmptyOnMatch(t *testing.T) {
	r := Result{
		LeafCount:         100,
		Match:             true,
		ReconstructedRoot: [32]byte{1, 2, 3},
		PersistedRoot:     [32]byte{1, 2, 3},
	}
	if got := r.FormatMismatch(); got != "" {
		t.Errorf("FormatMismatch on Match=true returned %q, want empty", got)
	}
}

func TestResult_FormatMismatch_IncludesAllFields(t *testing.T) {
	r := Result{
		LeafCount:         12345,
		TreeSize:          12344,
		ReconstructedRoot: [32]byte{0xAA, 0xBB},
		PersistedRoot:     [32]byte{0xCC, 0xDD},
		Match:             false,
	}
	got := r.FormatMismatch()
	for _, want := range []string{
		"12345", "12344", "aabb", "ccdd",
		"mismatch", "reconstructed", "persisted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatMismatch missing %q in:\n%s", want, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// PG-backed integration tests
// ─────────────────────────────────────────────────────────────────────

// TestReconstruct_MatchesPersistedRoot is the load-bearing
// integration test: populate a fresh DB with N synthetic leaves
// + the corresponding SMT root (computed via the SDK's
// in-memory tree, written into smt_root_state), then call
// Reconstruct and assert Match=true.
//
// If Reconstruct's column-scan logic, LogPosition deserialization,
// or in-memory tree construction is broken, this test catches
// it without needing a full subprocess chaos run.
func TestReconstruct_MatchesPersistedRoot(t *testing.T) {
	pool, cleanup := openTestPG(t)
	defer cleanup()

	const numLeaves = 50
	leaves := buildSyntheticLeaves(t, numLeaves, "did:attesta:log:test")
	expectedRoot := computeExpectedRoot(t, leaves)
	populateSMTState(t, pool, leaves, expectedRoot, int64(numLeaves-1))

	result, err := Reconstruct(context.Background(), pool)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !result.Match {
		t.Fatalf("expected Match=true; got:\n%s", result.FormatMismatch())
	}
	if result.LeafCount != numLeaves {
		t.Errorf("LeafCount = %d, want %d", result.LeafCount, numLeaves)
	}
	if result.ReconstructedRoot != expectedRoot {
		t.Errorf("ReconstructedRoot mismatch:\n  got:  %x\n  want: %x",
			result.ReconstructedRoot, expectedRoot)
	}
}

// TestReconstruct_DetectsTampering populates the DB with N
// leaves + the CORRECT root, then alters one leaf's
// authority_tip in the smt_leaves table without updating
// smt_root_state. Reconstruct MUST detect the inconsistency —
// the rebuilt root will not match the persisted root.
//
// This validates that the reconstruction is actually
// independent of the persisted state. If Reconstruct were
// silently reading the persisted root and reporting Match=true,
// this test would catch it.
func TestReconstruct_DetectsTampering(t *testing.T) {
	pool, cleanup := openTestPG(t)
	defer cleanup()

	const numLeaves = 30
	leaves := buildSyntheticLeaves(t, numLeaves, "did:attesta:log:tamper")
	expectedRoot := computeExpectedRoot(t, leaves)
	populateSMTState(t, pool, leaves, expectedRoot, int64(numLeaves-1))

	// Tamper: change leaf[5]'s authority_tip by re-serializing
	// with a different LogPosition. Bypass the
	// PostgresLeafStore (which would update the root) and
	// write directly via SQL.
	tamperedAuthTip := store.SerializeLogPosition(types.LogPosition{
		LogDID:   "did:attesta:log:tamper",
		Sequence: 9999, // not what the leaf was generated with
	})
	res, err := pool.Exec(context.Background(),
		`UPDATE smt_leaves SET authority_tip = $1 WHERE leaf_key = $2`,
		tamperedAuthTip, leaves[5].Key[:],
	)
	if err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	if res.RowsAffected() != 1 {
		t.Fatalf("tamper update: rows affected %d, want 1", res.RowsAffected())
	}

	result, err := Reconstruct(context.Background(), pool)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if result.Match {
		t.Fatalf("expected Match=false after tampering leaf[5], got Match=true (Reconstruct is not actually walking the leaves)")
	}
}

// TestReconstruct_EmptyTable returns Match=true when both
// smt_leaves and smt_root_state describe a freshly-bootstrapped
// log (zero leaves, zero root).
func TestReconstruct_EmptyTable(t *testing.T) {
	pool, cleanup := openTestPG(t)
	defer cleanup()

	// Genesis state: zero-root + zero leaves + zero
	// committed_through_seq.
	var zero [32]byte
	populateSMTState(t, pool, nil, zero, 0)

	result, err := Reconstruct(context.Background(), pool)
	if err != nil {
		t.Fatalf("Reconstruct on empty: %v", err)
	}
	if !result.Match {
		t.Fatalf("empty-table Reconstruct should Match (both roots are zero):\n%s",
			result.FormatMismatch())
	}
	if result.LeafCount != 0 {
		t.Errorf("LeafCount = %d on empty table, want 0", result.LeafCount)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────

// openTestPG creates a fresh database for this test and returns
// the pool + a cleanup function. Schema is empty initially; the
// helper applies migrations 0001-0005 so smt_leaves /
// smt_root_state exist.
func openTestPG(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	adminDSN := os.Getenv("ATTESTA_TEST_DSN")
	if adminDSN == "" {
		t.Skip("ATTESTA_TEST_DSN not set — reconstructor PG tests need a Postgres instance")
	}

	dbName := fmt.Sprintf("recon_%s_%d",
		sanitize(t.Name()), time.Now().UnixNano())
	if len(dbName) > 63 {
		dbName = dbName[:63]
	}

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer adminCancel()
	admin, err := pgx.Connect(adminCtx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(adminCtx)
	if _, err := admin.Exec(adminCtx, fmt.Sprintf(`CREATE DATABASE "%s"`, dbName)); err != nil {
		t.Fatalf("CREATE DATABASE: %v", err)
	}

	testDSN := rewriteDSN(adminDSN, dbName)
	poolCtx, poolCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer poolCancel()
	pool, err := pgxpool.New(poolCtx, testDSN)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	// Apply migrations.
	if err := store.RunMigrations(context.Background(), pool); err != nil {
		pool.Close()
		t.Fatalf("RunMigrations: %v", err)
	}

	return pool, func() {
		pool.Close()
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		admin, err := pgx.Connect(dropCtx, adminDSN)
		if err != nil {
			return
		}
		defer admin.Close(dropCtx)
		_, _ = admin.Exec(dropCtx,
			fmt.Sprintf(`DROP DATABASE IF EXISTS "%s" WITH (FORCE)`, dbName))
	}
}

// buildSyntheticLeaves constructs N SMTLeaf records with
// deterministic LogPositions (logDID, seq=0..N-1). Used as
// the populate-side of the PG-backed tests.
func buildSyntheticLeaves(t *testing.T, n int, logDID string) []types.SMTLeaf {
	t.Helper()
	leaves := make([]types.SMTLeaf, n)
	for i := 0; i < n; i++ {
		pos := types.LogPosition{LogDID: logDID, Sequence: uint64(i)}
		leaves[i] = types.SMTLeaf{
			Key:          smt.DeriveKey(pos),
			OriginTip:    pos,
			AuthorityTip: pos,
		}
	}
	return leaves
}

// computeExpectedRoot constructs an in-memory SMT tree from
// leaves and returns its root. This is what Reconstruct should
// produce when walking the same leaves out of smt_leaves.
func computeExpectedRoot(t *testing.T, leaves []types.SMTLeaf) [32]byte {
	t.Helper()
	tree := smt.NewTree(
		smt.NewInMemoryLeafStore(),
		smt.NewInMemoryNodeStore(),
	)
	if err := tree.SetLeaves(context.Background(), leaves); err != nil {
		t.Fatalf("SDK SetLeaves: %v", err)
	}
	root, err := tree.Root(context.Background())
	if err != nil {
		t.Fatalf("SDK Root: %v", err)
	}
	return root
}

// populateSMTState writes the leaves into smt_leaves + the
// root into smt_root_state. The committedThroughSeq value is
// stamped into smt_root_state.committed_through_seq so the
// Reconstruct result's TreeSize matches.
func populateSMTState(t *testing.T, pool *pgxpool.Pool,
	leaves []types.SMTLeaf, root [32]byte, committedThroughSeq int64) {
	t.Helper()
	ctx := context.Background()

	// Insert leaves directly via SQL — bypass the store's
	// PostgresLeafStore so the root is NOT auto-recomputed
	// (we want to control which root lands in
	// smt_root_state independently).
	for _, leaf := range leaves {
		originBytes := store.SerializeLogPosition(leaf.OriginTip)
		authBytes := store.SerializeLogPosition(leaf.AuthorityTip)
		_, err := pool.Exec(ctx, `
			INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip)
			VALUES ($1, $2, $3)
			ON CONFLICT (leaf_key) DO UPDATE
			SET origin_tip = EXCLUDED.origin_tip,
				authority_tip = EXCLUDED.authority_tip
		`, leaf.Key[:], originBytes, authBytes)
		if err != nil {
			t.Fatalf("insert leaf %x: %v", leaf.Key, err)
		}
	}

	// Upsert smt_root_state.
	_, err := pool.Exec(ctx, `
		INSERT INTO smt_root_state (id, current_root, committed_through_seq)
		VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE
		SET current_root = EXCLUDED.current_root,
			committed_through_seq = EXCLUDED.committed_through_seq
	`, root[:], committedThroughSeq)
	if err != nil {
		t.Fatalf("upsert smt_root_state: %v", err)
	}
}

// sanitize converts an arbitrary string to a Postgres-
// identifier-safe form (alphanumerics + underscore only).
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// rewriteDSN swaps the database name in a postgres:// URL.
func rewriteDSN(dsn, dbName string) string {
	// Quick string substitution: the database is the path
	// component after the host. Sufficient for test DSNs.
	idx := strings.LastIndex(dsn, "/")
	q := strings.Index(dsn, "?")
	if idx < 0 {
		return dsn + "/" + dbName
	}
	if q < 0 || q < idx {
		return dsn[:idx+1] + dbName
	}
	return dsn[:idx+1] + dbName + dsn[q:]
}
