/*
FILE PATH: store/smt_state_test.go

Coverage tests for PostgresLeafStore — the Postgres-backed satisfier
of the SDK's smt.LeafStore interface.

Tier 1.3 of the v0.2.0 SDK migration lifted ctx onto every method
of smt.LeafStore. These tests pin two contracts:

 1. STRUCTURAL — the SDK interface is satisfied. A compile-time
    assertion (var _ smt.LeafStore = (*PostgresLeafStore)(nil))
    would cover this; we also exercise each method through the
    interface to confirm dispatch.

 2. CTX PROPAGATION — a per-call cancelled ctx aborts the
    in-flight pgx query rather than being silently absorbed.
    This is the load-bearing invariant the P2 fallback used to
    mask, and the migration's main correctness gain.

Both tests require ATTESTA_TEST_DSN and use the same requireDB +
resetFixtures helpers as commitment_fetcher_test.go.
*/
package store

import (
	"context"
	"errors"
	"testing"

	smt "github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
)

// TestPostgresLeafStore_SatisfiesSDKInterface is a structural pin:
// build-time and runtime confirmation that the Tier 1.3 satisfier
// wires correctly through the SDK's smt.LeafStore interface. If the
// SDK changes another method signature later, this test breaks at
// build-time, surfacing the regression before any other call site.
func TestPostgresLeafStore_SatisfiesSDKInterface(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	// Satisfaction via the interface — the assertion compiles iff
	// every method aligns. The interface variable is exercised via
	// each ctx-aware method to confirm runtime dispatch matches.
	var ls smt.LeafStore = NewPostgresLeafStore(pool)

	// Exercise Get on an absent key — should return (nil, nil).
	got, err := ls.Get(ctx, [32]byte{0x01})
	if err != nil {
		t.Fatalf("Get on absent key: %v", err)
	}
	if got != nil {
		t.Errorf("Get on absent key returned %v, want nil", got)
	}

	// Exercise Count on the empty table.
	n, err := ls.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Errorf("Count on empty leaf table = %d, want 0", n)
	}

	// Exercise Set + round-trip Get.
	key := [32]byte{0xAB, 0xCD}
	leaf := types.SMTLeaf{
		Key: key,
		OriginTip: types.LogPosition{
			LogDID: testLogDID, Sequence: 100,
		},
		AuthorityTip: types.LogPosition{
			LogDID: testLogDID, Sequence: 100,
		},
	}
	if err := ls.Set(ctx, key, leaf); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err = ls.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil after Set")
	}
	if got.OriginTip.Sequence != 100 || got.AuthorityTip.Sequence != 100 {
		t.Errorf("Get returned wrong leaf: %+v", got)
	}

	// Exercise Count after one Set.
	n, err = ls.Count(ctx)
	if err != nil {
		t.Fatalf("Count after Set: %v", err)
	}
	if n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}

	// Exercise SetBatch — atomic write of two leaves.
	batch := []types.SMTLeaf{
		{Key: [32]byte{0x01}, OriginTip: types.LogPosition{LogDID: testLogDID, Sequence: 1}, AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 1}},
		{Key: [32]byte{0x02}, OriginTip: types.LogPosition{LogDID: testLogDID, Sequence: 2}, AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 2}},
	}
	if err := ls.SetBatch(ctx, batch); err != nil {
		t.Fatalf("SetBatch: %v", err)
	}
	n, err = ls.Count(ctx)
	if err != nil {
		t.Fatalf("Count after SetBatch: %v", err)
	}
	if n != 3 {
		t.Errorf("Count after SetBatch = %d, want 3", n)
	}

	// Exercise Delete.
	if err := ls.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	n, err = ls.Count(ctx)
	if err != nil {
		t.Fatalf("Count after Delete: %v", err)
	}
	if n != 2 {
		t.Errorf("Count after Delete = %d, want 2", n)
	}
}

// TestPostgresLeafStore_ContextCancelled pins Tier 1.3's
// load-bearing invariant: a cancelled per-call ctx aborts the
// in-flight pgx query. Before the migration the struct-bound ctx
// fallback silently absorbed cancellation; now ctx threads through
// each method to pgxpool.
//
// One test per ctx-taking method because pgx returns subtly
// different error wrappings depending on which call site cancels.
// errors.Is(err, context.Canceled) is the unifying contract.
func TestPostgresLeafStore_ContextCancelled(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	resetFixtures(t, context.Background(), pool)

	ls := NewPostgresLeafStore(pool)

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name string
		fn   func() error
	}{
		{"Get", func() error {
			_, err := ls.Get(cancelledCtx, [32]byte{0x01})
			return err
		}},
		{"Set", func() error {
			leaf := types.SMTLeaf{Key: [32]byte{0x01}}
			return ls.Set(cancelledCtx, [32]byte{0x01}, leaf)
		}},
		{"SetBatch", func() error {
			return ls.SetBatch(cancelledCtx, []types.SMTLeaf{{Key: [32]byte{0x01}}})
		}},
		{"Delete", func() error {
			return ls.Delete(cancelledCtx, [32]byte{0x01})
		}},
		{"Count", func() error {
			_, err := ls.Count(cancelledCtx)
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatalf("%s: expected error from cancelled ctx, got nil", tc.name)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s: expected error chain to contain context.Canceled, got: %v",
					tc.name, err)
			}
		})
	}
}

// TestPostgresLeafStore_SetBatchTx_RoundTrip pins the structural
// contract of the N+1-fix write path: SetBatchTx writes N leaves
// inside a single tx with a single PG round-trip (unnest-based
// multi-row INSERT), and each leaf is readable by key afterwards
// with byte-identical OriginTip / AuthorityTip values.
//
// If the unnest array encoding regresses (e.g., pgx changes how it
// frames bytea[]) this test surfaces the break immediately. If
// someone reverts SetBatchTx to a per-row loop, this test still
// passes — semantics aren't broken; only the throughput would be.
// The throughput contract is enforced via the soak's `commit`
// telemetry, not here; this is the correctness pin.
func TestPostgresLeafStore_SetBatchTx_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	ls := NewPostgresLeafStore(pool)

	// Build N distinct leaves with deterministic keys.
	const N = 16
	leaves := make([]types.SMTLeaf, N)
	for i := 0; i < N; i++ {
		var key [32]byte
		key[0] = byte(i)
		key[1] = 0xAB
		leaves[i] = types.SMTLeaf{
			Key:          key,
			OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: uint64(1000 + i)},
			AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: uint64(2000 + i)},
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rowsAffected, err := ls.SetBatchTx(ctx, tx, leaves)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("SetBatchTx: %v", err)
	}
	if rowsAffected != int64(len(leaves)) {
		_ = tx.Rollback(ctx)
		t.Fatalf("SetBatchTx rows_affected=%d, want %d", rowsAffected, len(leaves))
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	n, err := ls.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != N {
		t.Fatalf("Count after SetBatchTx = %d, want %d", n, N)
	}

	for i, want := range leaves {
		got, err := ls.Get(ctx, want.Key)
		if err != nil {
			t.Fatalf("Get leaf %d: %v", i, err)
		}
		if got == nil {
			t.Fatalf("Get leaf %d: nil (not persisted)", i)
		}
		if got.OriginTip != want.OriginTip {
			t.Errorf("leaf %d: OriginTip got %+v, want %+v", i, got.OriginTip, want.OriginTip)
		}
		if got.AuthorityTip != want.AuthorityTip {
			t.Errorf("leaf %d: AuthorityTip got %+v, want %+v", i, got.AuthorityTip, want.AuthorityTip)
		}
	}
}

// TestPostgresLeafStore_SetBatchTx_Idempotent pins ON CONFLICT DO
// UPDATE behaviour: rerunning a batch with the same keys but DIFFERENT
// values overwrites the row content (last-write-wins on the tip
// fields, leaf_key is the PK). This is the property the builder's
// retry semantics rely on — a re-committed batch must produce the
// same persisted state, not double-counted rows.
func TestPostgresLeafStore_SetBatchTx_Idempotent(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	ls := NewPostgresLeafStore(pool)

	key := [32]byte{0x55, 0x55}
	first := []types.SMTLeaf{{
		Key:          key,
		OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: 10},
		AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 20},
	}}
	second := []types.SMTLeaf{{
		Key:          key,
		OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: 30},
		AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 40},
	}}

	for i, batch := range [][]types.SMTLeaf{first, second} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
		if _, err := ls.SetBatchTx(ctx, tx, batch); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("SetBatchTx %d: %v", i, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}

	n, err := ls.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 1 {
		t.Fatalf("after two SetBatchTx calls with same key: Count = %d, want 1 (DO UPDATE must dedupe by PK)", n)
	}

	got, err := ls.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OriginTip.Sequence != 30 || got.AuthorityTip.Sequence != 40 {
		t.Errorf("DO UPDATE did not overwrite: got %+v, want OriginTip=30, AuthorityTip=40", got)
	}
}

// TestPostgresLeafStore_SetBatchTx_Empty pins the "n=0 is a no-op"
// contract — the builder calls SetBatchTx unconditionally and the
// store must tolerate empty batches without erroring or issuing a
// PG round-trip.
func TestPostgresLeafStore_SetBatchTx_Empty(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	ls := NewPostgresLeafStore(pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if affected, err := ls.SetBatchTx(ctx, tx, nil); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("SetBatchTx(nil): %v", err)
	} else if affected != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("SetBatchTx(nil) affected=%d, want 0", affected)
	}
	if affected, err := ls.SetBatchTx(ctx, tx, []types.SMTLeaf{}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("SetBatchTx(empty): %v", err)
	} else if affected != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("SetBatchTx(empty) affected=%d, want 0", affected)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestPostgresNodeStore_PutBatchTx_RoundTrip pins the same contract
// for the node-store batched write: N nodes in, N Get()s out, each
// returning a byte-identical reconstruction. This includes leaves
// AND branches mixed in one batch (the overlay produces both shapes
// per ProcessBatch).
func TestPostgresNodeStore_PutBatchTx_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	ns := NewPostgresNodeStore(ctx, pool, 1024)

	// Build a mixed set: 8 leaves + 4 branches.
	nodes := make([]smt.Node, 0, 12)
	for i := 0; i < 8; i++ {
		var key [32]byte
		key[0] = byte(i)
		nodes = append(nodes, &smt.LeafNode{
			Value: types.SMTLeaf{
				Key:          key,
				OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: uint64(i)},
				AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: uint64(i)},
			},
		})
	}
	for i := 0; i < 4; i++ {
		var prefix, left, right [32]byte
		prefix[0] = 0xC0
		left[0] = byte(i)
		right[31] = byte(i)
		nodes = append(nodes, &smt.BranchNode{
			BranchDepth: uint16(i + 1),
			Prefix:      prefix,
			LeftHash:    left,
			RightHash:   right,
		})
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rowsAffected, err := ns.PutBatchTx(ctx, tx, nodes)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("PutBatchTx: %v", err)
	}
	// All nodes are fresh (clean table); every input must be
	// inserted, not skipped.
	if rowsAffected != int64(len(nodes)) {
		_ = tx.Rollback(ctx)
		t.Fatalf("PutBatchTx rows_affected=%d, want %d (no nodes should pre-exist)",
			rowsAffected, len(nodes))
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Round-trip via Get on each hash. Skip the LRU by constructing
	// a SECOND NodeStore over the same pool — the new instance has a
	// cold cache, so Get hits Postgres for each lookup.
	cold := NewPostgresNodeStore(ctx, pool, 1024)
	for i, node := range nodes {
		hash := smt.HashNode(node)
		got, err := cold.Get(hash)
		if err != nil {
			t.Fatalf("Get node %d (hash=%x): %v", i, hash[:8], err)
		}
		if got == nil {
			t.Fatalf("Get node %d (hash=%x): nil (not persisted)", i, hash[:8])
		}
		gotHash := smt.HashNode(got)
		if gotHash != hash {
			t.Errorf("node %d: round-trip hash mismatch — wrote %x, got %x", i, hash, gotHash)
		}
	}
}

// TestPostgresNodeStore_PutBatchTx_CachePromotion pins the cache-fill
// invariant: after a batched Put, the LRU contains every node so
// subsequent Get()s on the SAME store instance never hit Postgres.
//
// Why this matters: ProcessBatch's overlay reads a freshly-written
// node during the SAME batch's root computation in some path-update
// scenarios (rare but possible — the SDK's order-invariance
// guarantee requires reads of a just-written-but-not-yet-committed
// node to succeed). Cache promotion in PutBatchTx makes that
// guarantee hold without requiring read-your-write semantics from
// PG within the same tx.
func TestPostgresNodeStore_PutBatchTx_CachePromotion(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	ns := NewPostgresNodeStore(ctx, pool, 1024)
	if ns.Len() != 0 {
		t.Fatalf("fresh node store should be empty, got Len=%d", ns.Len())
	}

	nodes := []smt.Node{
		&smt.LeafNode{Value: types.SMTLeaf{
			Key:          [32]byte{0x01},
			OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: 1},
			AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 1},
		}},
		&smt.LeafNode{Value: types.SMTLeaf{
			Key:          [32]byte{0x02},
			OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: 2},
			AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 2},
		}},
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := ns.PutBatchTx(ctx, tx, nodes); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("PutBatchTx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if ns.Len() != len(nodes) {
		t.Errorf("after PutBatchTx, LRU Len=%d, want %d (cache promotion missed)",
			ns.Len(), len(nodes))
	}
}

// TestPostgresNodeStore_PutBatchTx_NilNode pins the input-validation
// contract: a nil entry in the batch surfaces as an error instead
// of being silently dropped or causing a panic on Serialize. The
// builder never produces nil nodes, but defensive validation here
// makes the error path explicit.
func TestPostgresNodeStore_PutBatchTx_NilNode(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	resetFixtures(t, ctx, pool)

	ns := NewPostgresNodeStore(ctx, pool, 1024)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = ns.PutBatchTx(ctx, tx, []smt.Node{
		&smt.LeafNode{Value: types.SMTLeaf{
			Key:          [32]byte{0xAA},
			OriginTip:    types.LogPosition{LogDID: testLogDID, Sequence: 1},
			AuthorityTip: types.LogPosition{LogDID: testLogDID, Sequence: 1},
		}},
		nil, // intentionally invalid
	})
	if err == nil {
		t.Fatal("PutBatchTx with nil entry: expected error, got nil")
	}
}

// testLogDID is defined in commitment_fetcher_test.go (same
// package) and reused here for fixture parity.
