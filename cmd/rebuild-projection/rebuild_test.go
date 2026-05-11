/*
FILE PATH: cmd/rebuild-projection/rebuild_test.go

Integration test for §C2 (PG-as-projection rebuild). Skips when
ATTESTA_TEST_DSN is unset; otherwise:

  1. Builds a temp Tessera tile store.
  2. Appends N synthetic envelope entries through the upstream
     Tessera writer (so the tile files on disk are produced by
     the real append-side code, not a mock).
  3. Waits for upstream Tessera to publish a checkpoint reflecting
     all N appends.
  4. Runs Rebuild() against the tile dir + a fresh PG instance.
  5. Snapshots the projection rows.
  6. Wipes the projection tables, resets singleton rows.
  7. Runs Rebuild() a second time.
  8. Asserts the two snapshots are bit-exact equal — same
     entry_index rows, same smt_leaves rows, same smt_root_state
     row, same builder_cursor.

This pins the structural invariant: given the same tile store,
Rebuild produces deterministic PG state. The live builder loop runs
the same SDK derivation (sdkbuilder.ProcessBatch with the same
LogDID), so by SDK determinism (SDK principles §7, §8) the live
state and the rebuild state are also equal byte-for-byte.

This test deliberately stays simple — no HTTP admission, no
sequencer, no builder goroutine. Those layers are validated by the
soak (tests/soak_test.go) and by the unit tests in builder/. The
ONLY axis this test pins is "Rebuild is correct against tile state."
*/
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"
)

const testRebuildLogDID = "did:example:rebuild-projection-test"

func TestRebuild_DeterministicProjectionFromTiles(t *testing.T) {
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping PG-backed rebuild test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// ── PG: open + migrate + reset projection tables.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()
	if err := store.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	resetProjectionTables(t, ctx, pool)

	// ── Tile store: real upstream Tessera POSIX writer.
	tileDir := t.TempDir()
	driver, err := posix.New(ctx, posix.Config{Path: tileDir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	signer, _, err := optessera.GenerateEphemeralSigner("rebuild-test")
	if err != nil {
		t.Fatalf("GenerateEphemeralSigner: %v", err)
	}
	embedded, err := optessera.NewEmbeddedAppender(ctx, driver, optessera.AppenderOptions{
		Origin:             testRebuildLogDID,
		Signer:             signer,
		CheckpointInterval: 100 * time.Millisecond,
		BatchSize:          16,
		BatchMaxAge:        50 * time.Millisecond,
	}, logger)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, cancelShut := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShut()
		_ = embedded.Close(shutCtx)
	})

	// ── Bytestore: holds the canonical envelope bytes the rebuild
	// reads back at (seq, hash). In-memory in tests; production
	// uses S3/GCS. This mirrors the production architecture:
	// tile/entries gives us a hash, bytestore gives us the
	// canonical bytes for that hash.
	bs := bytestore.NewMemory()

	// ── Produce N entries.
	//
	// Each entry has AuthorityPath=&AuthoritySameSigner +
	// TargetRoot=nil so the SDK routes it through the NewLeaf path
	// (mirrors the soak's workload exactly).
	const N = 50
	priv := mustEphemeralPriv(t)
	authorityPath := envelope.AuthoritySameSigner
	for i := 0; i < N; i++ {
		entry := buildTestEntry(t, priv, authorityPath, i)
		canonical, err := envelope.Serialize(entry)
		if err != nil {
			t.Fatalf("entry %d serialize: %v", i, err)
		}
		identity, err := envelope.EntryIdentity(entry)
		if err != nil {
			t.Fatalf("entry %d identity: %v", i, err)
		}
		// Hash-only AppendLeaf: Tessera stores 32 bytes per leaf,
		// matching the ledger's production AppendLeaf contract.
		seq, err := embedded.AppendLeaf(ctx, identity[:])
		if err != nil {
			t.Fatalf("entry %d AppendLeaf: %v", i, err)
		}
		if seq != uint64(i) {
			t.Fatalf("entry %d AppendLeaf returned seq=%d, want %d", i, seq, i)
		}
		// Canonical bytes go to the bytestore at the same (seq,
		// hash) the live shipper writes them to.
		if err := bs.WriteEntry(ctx, seq, identity, canonical); err != nil {
			t.Fatalf("entry %d bytestore WriteEntry: %v", i, err)
		}
	}

	// Upstream Tessera batches + publishes checkpoints
	// asynchronously. Wait until the checkpoint reflects all N
	// entries before we start the rebuild.
	waitForCheckpoint(t, ctx, embedded, uint64(N))

	// ── First Rebuild → populates PG fully.
	stats1, err := Rebuild(ctx, RebuildDeps{
		TileDir:   tileDir,
		Bytestore: bs,
		Pool:      pool,
		LogDID:    testRebuildLogDID,
		BatchSize: 16,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("Rebuild #1: %v", err)
	}
	if stats1.TreeSize != N {
		t.Fatalf("Rebuild #1 stats.TreeSize=%d, want %d", stats1.TreeSize, N)
	}
	if stats1.LeavesWritten == 0 {
		t.Fatalf("Rebuild #1 produced 0 leaves — workload classification regression?")
	}
	t.Logf("Rebuild #1 ✓ tree_size=%d entries=%d leaves=%d root=%x… in %s",
		stats1.TreeSize, stats1.EntriesProcessed, stats1.LeavesWritten,
		stats1.Root[:8], stats1.Duration.Round(time.Millisecond))

	snap1 := snapshotProjection(t, ctx, pool)

	// ── Wipe + rebuild → must produce bit-exact identical snapshot.
	resetProjectionTables(t, ctx, pool)
	stats2, err := Rebuild(ctx, RebuildDeps{
		TileDir:   tileDir,
		Pool:      pool,
		LogDID:    testRebuildLogDID,
		BatchSize: 16,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("Rebuild #2: %v", err)
	}
	snap2 := snapshotProjection(t, ctx, pool)

	// Stats must agree on the tree-level invariants.
	if stats1.TreeSize != stats2.TreeSize ||
		stats1.EntriesProcessed != stats2.EntriesProcessed ||
		stats1.LeavesWritten != stats2.LeavesWritten ||
		stats1.Root != stats2.Root {
		t.Fatalf("Rebuild non-deterministic in summary stats:\n  #1: %+v\n  #2: %+v", stats1, stats2)
	}

	// Snapshots must match bit-exact.
	assertProjectionsEqual(t, snap1, snap2)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

type projectionSnapshot struct {
	entryIndex    map[uint64]entryIndexRow
	smtLeaves     map[[32]byte]smtLeafRow
	smtRoot       [32]byte
	committedSeq  uint64
	builderCursor uint64
}

type entryIndexRow struct {
	canonicalHash [32]byte
	logTimeUnix   int64
	signerDID     string
	targetRoot    []byte
	cosignatureOf []byte
	schemaRef     []byte
}

type smtLeafRow struct {
	originTip    []byte
	authorityTip []byte
}

func snapshotProjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool) projectionSnapshot {
	t.Helper()
	snap := projectionSnapshot{
		entryIndex: make(map[uint64]entryIndexRow),
		smtLeaves:  make(map[[32]byte]smtLeafRow),
	}

	rows, err := pool.Query(ctx, `
		SELECT sequence_number, canonical_hash, log_time, signer_did,
		       target_root, cosignature_of, schema_ref
		FROM entry_index ORDER BY sequence_number ASC`)
	if err != nil {
		t.Fatalf("snapshot entry_index: %v", err)
	}
	for rows.Next() {
		var seq uint64
		var hashB, targetB, cosigB, schemaB []byte
		var signerDID string
		var logTime time.Time
		if err := rows.Scan(&seq, &hashB, &logTime, &signerDID, &targetB, &cosigB, &schemaB); err != nil {
			rows.Close()
			t.Fatalf("scan entry_index: %v", err)
		}
		var hash [32]byte
		copy(hash[:], hashB)
		snap.entryIndex[seq] = entryIndexRow{
			canonicalHash: hash,
			logTimeUnix:   logTime.UnixMicro(),
			signerDID:     signerDID,
			targetRoot:    targetB,
			cosignatureOf: cosigB,
			schemaRef:     schemaB,
		}
	}
	rows.Close()

	rows, err = pool.Query(ctx, `SELECT leaf_key, origin_tip, authority_tip FROM smt_leaves`)
	if err != nil {
		t.Fatalf("snapshot smt_leaves: %v", err)
	}
	for rows.Next() {
		var keyB, originB, authB []byte
		if err := rows.Scan(&keyB, &originB, &authB); err != nil {
			rows.Close()
			t.Fatalf("scan smt_leaves: %v", err)
		}
		var key [32]byte
		copy(key[:], keyB)
		snap.smtLeaves[key] = smtLeafRow{originTip: originB, authorityTip: authB}
	}
	rows.Close()

	var rootB []byte
	var committedSeq int64
	if err := pool.QueryRow(ctx,
		`SELECT current_root, committed_through_seq FROM smt_root_state WHERE id = 1`,
	).Scan(&rootB, &committedSeq); err != nil {
		t.Fatalf("snapshot smt_root_state: %v", err)
	}
	if len(rootB) != 32 {
		t.Fatalf("snapshot smt_root_state: bad root len=%d", len(rootB))
	}
	copy(snap.smtRoot[:], rootB)
	snap.committedSeq = uint64(committedSeq)

	var cursor int64
	if err := pool.QueryRow(ctx,
		`SELECT last_processed_sequence FROM builder_cursor WHERE id = 1`,
	).Scan(&cursor); err != nil {
		t.Fatalf("snapshot builder_cursor: %v", err)
	}
	snap.builderCursor = uint64(cursor)
	return snap
}

func assertProjectionsEqual(t *testing.T, a, b projectionSnapshot) {
	t.Helper()
	if a.smtRoot != b.smtRoot {
		t.Errorf("smt_root differs:\n  #1: %x\n  #2: %x", a.smtRoot, b.smtRoot)
	}
	if a.committedSeq != b.committedSeq {
		t.Errorf("committed_through_seq differs: #1=%d, #2=%d", a.committedSeq, b.committedSeq)
	}
	if a.builderCursor != b.builderCursor {
		t.Errorf("builder_cursor differs: #1=%d, #2=%d", a.builderCursor, b.builderCursor)
	}
	if len(a.entryIndex) != len(b.entryIndex) {
		t.Errorf("entry_index row count differs: #1=%d, #2=%d", len(a.entryIndex), len(b.entryIndex))
	}
	for seq, row1 := range a.entryIndex {
		row2, ok := b.entryIndex[seq]
		if !ok {
			t.Errorf("entry_index seq=%d missing in #2", seq)
			continue
		}
		if row1.canonicalHash != row2.canonicalHash {
			t.Errorf("entry_index seq=%d canonical_hash differs", seq)
		}
		if row1.logTimeUnix != row2.logTimeUnix {
			t.Errorf("entry_index seq=%d log_time differs: %d vs %d", seq, row1.logTimeUnix, row2.logTimeUnix)
		}
		if row1.signerDID != row2.signerDID {
			t.Errorf("entry_index seq=%d signer_did differs: %q vs %q", seq, row1.signerDID, row2.signerDID)
		}
		if !bytes.Equal(row1.targetRoot, row2.targetRoot) {
			t.Errorf("entry_index seq=%d target_root differs", seq)
		}
		if !bytes.Equal(row1.cosignatureOf, row2.cosignatureOf) {
			t.Errorf("entry_index seq=%d cosignature_of differs", seq)
		}
		if !bytes.Equal(row1.schemaRef, row2.schemaRef) {
			t.Errorf("entry_index seq=%d schema_ref differs", seq)
		}
	}
	if len(a.smtLeaves) != len(b.smtLeaves) {
		t.Errorf("smt_leaves row count differs: #1=%d, #2=%d", len(a.smtLeaves), len(b.smtLeaves))
	}
	keys := make([][32]byte, 0, len(a.smtLeaves))
	for k := range a.smtLeaves {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	for _, k := range keys {
		row1 := a.smtLeaves[k]
		row2, ok := b.smtLeaves[k]
		if !ok {
			t.Errorf("smt_leaves key=%x missing in #2", k[:8])
			continue
		}
		if !bytes.Equal(row1.originTip, row2.originTip) {
			t.Errorf("smt_leaves key=%x origin_tip differs", k[:8])
		}
		if !bytes.Equal(row1.authorityTip, row2.authorityTip) {
			t.Errorf("smt_leaves key=%x authority_tip differs", k[:8])
		}
	}
}

// resetProjectionTables wipes the rows but leaves singletons in
// the migration's initial state. Mirrors tests/helpers_test.go
// cleanTables, scoped to the projections this rebuild populates.
func resetProjectionTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"entry_index", "smt_leaves", "smt_nodes"} {
		if _, err := pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("DELETE FROM %s: %v", table, err)
		}
	}
	if _, err := pool.Exec(ctx,
		`UPDATE builder_cursor SET last_processed_sequence = 0 WHERE id = 1`,
	); err != nil {
		t.Fatalf("reset builder_cursor: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE smt_root_state
		SET current_root = decode('876422b7697ae7c337e2ee7727feb3db474adf7be1cf04b6b5857d82d610e88a', 'hex'),
		    committed_through_seq = 0
		WHERE id = 1`,
	); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
}

func waitForCheckpoint(t *testing.T, ctx context.Context, app *optessera.EmbeddedAppender, want uint64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		head, err := app.Head()
		if err == nil && head.TreeSize >= want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waitForCheckpoint: ctx cancelled: %v", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("waitForCheckpoint: tree never reached size %d within 15s", want)
}

func buildTestEntry(t *testing.T, priv *ecdsa.PrivateKey, ap envelope.AuthorityPath, idx int) *envelope.Entry {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:     "did:example:rebuild-signer",
		Destination:   testRebuildLogDID,
		EventTime:     time.Now().UTC().UnixMicro(),
		AuthorityPath: &ap,
	}
	payload := []byte(fmt.Sprintf("rebuild-test-%010d", idx))
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry %d: %v", idx, err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry %d: %v", idx, err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	return entry
}

func mustEphemeralPriv(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// keep types.LogPosition imported even if test path doesn't use it directly elsewhere.
var _ = types.LogPosition{}

// keep filepath imported for future tile-dir asserts.
var _ = filepath.Join
