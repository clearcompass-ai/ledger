/*
FILE PATH: builder/incremental_root_test.go

Regression tests for the BuilderLoop's SMT-root maintenance path under
attesta v0.3.0 (Jellyfish/Patricia trie).

# WHAT THIS PINS

  - The smt_root_state singleton row R/W contract: after migration the
    row holds the SDK's empty-tree root (smt.EmptyHash); SetTx persists
    a new value; subsequent Read returns it.

  - The SDK contract the builder's overlay-commit path relies on:
    Tree.ComputeDirtyRoot(prior, writes) produces the same root that
    Tree.SetLeaves(writes) would on a tree seeded at `prior`. The
    builder uses ComputeDirtyRoot to derive newRoot inside the batch,
    then commits the overlay's leaf + node mutations transactionally;
    the SDK's order-invariance guarantees the persisted graph
    reproduces the computed root byte-for-byte.

  - Batched-insert order invariance: splitting the same leaf set
    across different batch boundaries (or different intra-batch
    orderings) produces the same final root. A regression here would
    cause cross-replica root divergence under different sequencer
    cadences.

# WHY THE V0.2.0 TEST IS GONE

The pre-v0.3.0 version of this file pinned "incremental
ComputeDirtyRoot equals full enumeration via Tree.Root over a
manually-populated LeafStore." That premise no longer holds in
v0.3.0: Tree.Root returns the cached rootHash and does NOT re-derive
from the LeafStore. Leaves inserted directly into the LeafStore
(bypassing Tree.SetLeaf) are invisible to Tree.Root by construction.
The new tests assert the v0.3.0 semantic — Tree.SetLeaves /
ComputeDirtyRoot are the only legitimate ways to advance the root —
and pin properties the builder loop actually depends on.

The PG-backed test still requires ATTESTA_TEST_DSN; without it it
skips, mirroring the rest of the integration suite.
*/
package builder_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// TestSMTRootStateStore_RoundTrip pins the read/write contract on the
// singleton smt_root_state row under v0.3.0:
//   - After migration 0003, Read returns the Jellyfish empty-tree
//     root (smt.EmptyHash = sha256("")).
//   - SetTx persists a new (root, committed_through_seq) pair.
//   - ReadRoot returns the same value via the SMTRootReader interface.
func TestSMTRootStateStore_RoundTrip(t *testing.T) {
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN not set — skipping PG-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()
	if err := store.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	rs := store.NewSMTRootStateStore(pool)

	// Reset to the v0.3.0 Jellyfish empty root, matching what
	// migration 0003 installs. Using smt.EmptyHash binds this test
	// to the SDK's source of truth; if the SDK ever changes its
	// empty-tree constant the test surfaces a clear mismatch.
	emptyRoot := smt.EmptyHash

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := rs.SetTx(ctx, tx, emptyRoot, 0); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("set initial: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit initial: %v", err)
	}

	got, err := rs.Read(ctx)
	if err != nil {
		t.Fatalf("read initial: %v", err)
	}
	if got.CurrentRoot != emptyRoot {
		t.Fatalf("initial root: got %x, want %x (smt.EmptyHash)",
			got.CurrentRoot, emptyRoot)
	}
	if got.CommittedThroughSeq != 0 {
		t.Fatalf("initial committed_through_seq: got %d, want 0", got.CommittedThroughSeq)
	}

	// ReadRoot returns the same value via the SMTRootReader contract.
	r, err := rs.ReadRoot(ctx)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if r != emptyRoot {
		t.Fatalf("ReadRoot: got %x, want %x", r, emptyRoot)
	}

	// Write a non-empty root.
	newRoot := sha256.Sum256([]byte("test-non-empty-root-v0.3.0"))
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin update: %v", err)
	}
	if err := rs.SetTx(ctx, tx, newRoot, 42); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("set new: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit new: %v", err)
	}

	got, err = rs.Read(ctx)
	if err != nil {
		t.Fatalf("read after update: %v", err)
	}
	if got.CurrentRoot != newRoot {
		t.Fatalf("updated root: got %x, want %x", got.CurrentRoot, newRoot)
	}
	if got.CommittedThroughSeq != 42 {
		t.Fatalf("updated committed_through_seq: got %d, want 42", got.CommittedThroughSeq)
	}
}

// TestComputeDirtyRoot_AgreesWithSetLeaves is the SDK-level pin that
// ComputeDirtyRoot(prior, writes) yields the same root that
// SetLeaves(writes) would, starting from the same prior.
//
// This is the mathematical foundation the builder's overlay-commit
// path relies on: the builder computes newRoot via ComputeDirtyRoot
// inside the batch (no commit), then atomically writes the overlay's
// leaf + node mutations via PutTx — the SDK's order-invariance
// guarantees the persisted graph reproduces the computed root.
//
// If this regresses, every batch's persisted root would diverge from
// the value /v1/smt/root reports and consumers would see proof
// verification failures.
//
// No PG required — operates on pure SDK types.
func TestComputeDirtyRoot_AgreesWithSetLeaves(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	leaves := generateLeaves(t, 50)

	// Path A: SetLeaves(all) on a fresh tree → root_A.
	treeA := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	allLeaves := make([]types.SMTLeaf, 0, len(leaves))
	for _, l := range leaves {
		allLeaves = append(allLeaves, l)
	}
	if err := treeA.SetLeaves(ctx, allLeaves); err != nil {
		t.Fatalf("treeA.SetLeaves: %v", err)
	}
	rootA, err := treeA.Root(ctx)
	if err != nil {
		t.Fatalf("treeA.Root: %v", err)
	}

	// Path B: ComputeDirtyRoot(empty, allLeaves) on a fresh tree → root_B.
	// Tree's rootHash is NOT advanced by ComputeDirtyRoot; pass the
	// empty hash explicitly.
	treeB := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	writes := make(map[[32]byte]types.SMTLeaf, len(leaves))
	for k, v := range leaves {
		writes[k] = v
	}
	rootB, err := treeB.ComputeDirtyRoot(ctx, smt.EmptyHash, writes)
	if err != nil {
		t.Fatalf("treeB.ComputeDirtyRoot: %v", err)
	}

	if rootA != rootB {
		t.Fatalf("SetLeaves vs ComputeDirtyRoot diverge:\n  SetLeaves        : %x\n  ComputeDirtyRoot : %x",
			rootA, rootB)
	}

	// Sanity: the post-50-leaf root must differ from the empty-tree
	// root, otherwise the test could pass trivially against a broken
	// SDK that silently produces EmptyHash for every input.
	if rootA == smt.EmptyHash {
		t.Fatalf("50-leaf root equals EmptyHash — SDK regression")
	}
}

// TestSetLeaves_BatchSplit_RootInvariant pins that splitting the same
// leaf set across different batch boundaries produces the same final
// root. The builder commits one batch at a time; the production
// guarantee is that the resulting smt_root_state.current_root is
// independent of where batch boundaries fall, as long as the union of
// committed leaves is identical.
//
// A regression would surface in soak tests as cross-replica root
// divergence under different sequencer cadences.
func TestSetLeaves_BatchSplit_RootInvariant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	leaves := generateLeaves(t, 60)
	all := make([]types.SMTLeaf, 0, len(leaves))
	for _, l := range leaves {
		all = append(all, l)
	}

	// Layout 1: single batch of 60.
	tree1 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	if err := tree1.SetLeaves(ctx, all); err != nil {
		t.Fatalf("tree1.SetLeaves: %v", err)
	}
	root1, _ := tree1.Root(ctx)

	// Layout 2: three batches of 20.
	tree2 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	for i := 0; i < 3; i++ {
		if err := tree2.SetLeaves(ctx, all[i*20:(i+1)*20]); err != nil {
			t.Fatalf("tree2.SetLeaves batch %d: %v", i, err)
		}
	}
	root2, _ := tree2.Root(ctx)

	// Layout 3: six batches of 10.
	tree3 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	for i := 0; i < 6; i++ {
		if err := tree3.SetLeaves(ctx, all[i*10:(i+1)*10]); err != nil {
			t.Fatalf("tree3.SetLeaves batch %d: %v", i, err)
		}
	}
	root3, _ := tree3.Root(ctx)

	if root1 != root2 {
		t.Fatalf("1x60 vs 3x20 root mismatch: %x vs %x", root1, root2)
	}
	if root1 != root3 {
		t.Fatalf("1x60 vs 6x10 root mismatch: %x vs %x", root1, root3)
	}
}

// TestComputeDirtyRoot_ChainsAcrossBatches pins that the builder's
// per-batch sequence root[B_0] → root[B_1] → … → root[B_n] is
// consistent: feeding root[B_i] as `prior` to ComputeDirtyRoot for
// B_{i+1} produces the same root as committing B_0..B_{i+1} in
// sequence via SetLeaves. This is the precise contract the
// rootStore-wired builder loop runs on each cycle.
func TestComputeDirtyRoot_ChainsAcrossBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	leaves := generateLeaves(t, 60)
	all := make([]types.SMTLeaf, 0, len(leaves))
	for _, l := range leaves {
		all = append(all, l)
	}

	// Path A: SetLeaves(all 60) on one tree.
	commitTree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	if err := commitTree.SetLeaves(ctx, all); err != nil {
		t.Fatalf("commitTree.SetLeaves: %v", err)
	}
	wantRoot, _ := commitTree.Root(ctx)

	// Path B: three sequential ComputeDirtyRoot calls chained.
	chainTree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	priorRoot := smt.EmptyHash
	for i := 0; i < 3; i++ {
		batch := make(map[[32]byte]types.SMTLeaf, 20)
		for _, l := range all[i*20 : (i+1)*20] {
			batch[l.Key] = l
		}
		newRoot, err := chainTree.ComputeDirtyRoot(ctx, priorRoot, batch)
		if err != nil {
			t.Fatalf("ComputeDirtyRoot batch %d: %v", i, err)
		}
		priorRoot = newRoot
	}

	if priorRoot != wantRoot {
		t.Fatalf("chained ComputeDirtyRoot diverges from SetLeaves: chain=%x setleaves=%x",
			priorRoot, wantRoot)
	}
}

// TestComputeDirtyRoot_DoesNotAdvanceTreeRoot pins the SDK contract
// that ComputeDirtyRoot is read-only with respect to the tree's
// internal rootHash. The builder relies on this to validate a batch
// before deciding to commit; if ComputeDirtyRoot silently advanced
// the tree's state, an aborted batch would leak.
func TestComputeDirtyRoot_DoesNotAdvanceTreeRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	rootBefore, _ := tree.Root(ctx)
	if rootBefore != smt.EmptyHash {
		t.Fatalf("fresh tree root = %x, want EmptyHash", rootBefore)
	}

	writes := map[[32]byte]types.SMTLeaf{}
	for i, l := range generateLeaves(t, 10) {
		_ = i
		writes[l.Key] = l
	}
	hypotheticalRoot, err := tree.ComputeDirtyRoot(ctx, smt.EmptyHash, writes)
	if err != nil {
		t.Fatalf("ComputeDirtyRoot: %v", err)
	}
	if hypotheticalRoot == smt.EmptyHash {
		t.Fatalf("ComputeDirtyRoot returned EmptyHash on 10 writes")
	}

	rootAfter, _ := tree.Root(ctx)
	if rootAfter != rootBefore {
		t.Fatalf("ComputeDirtyRoot mutated tree.rootHash: before=%x after=%x",
			rootBefore, rootAfter)
	}
}

// generateLeaves returns n random-key SMTLeaves with monotonic
// sequence numbers. Helper for the table-driven tests above.
func generateLeaves(t *testing.T, n int) map[[32]byte]types.SMTLeaf {
	t.Helper()
	out := make(map[[32]byte]types.SMTLeaf, n)
	for i := 0; i < n; i++ {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		// Use deterministic DID + position-derived sequence so two
		// runs produce structurally-identical commitments. Tests that
		// need fully-deterministic keys can derive from a seed; the
		// invariants asserted here only care about key uniqueness.
		out[key] = types.SMTLeaf{
			Key: key,
			OriginTip: types.LogPosition{
				LogDID:   fmt.Sprintf("did:example:test-log"),
				Sequence: uint64(i + 1),
			},
			AuthorityTip: types.LogPosition{
				LogDID:   fmt.Sprintf("did:example:test-log"),
				Sequence: uint64(i + 1),
			},
		}
	}
	return out
}

// sdkbuilder is imported to satisfy `go vet` even if a test doesn't
// reference it directly — its types appear in the builder's surface
// area and keeping the import here pins the dependency.
var _ = sdkbuilder.BatchResult{}
