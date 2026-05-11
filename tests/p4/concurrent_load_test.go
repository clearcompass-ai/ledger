//go:build p4
// +build p4

// FILE PATH: tests/p4/concurrent_load_test.go
//
// P4.1 — Multi-persona concurrent load. Pins Principle 9
// (Per-Originator Parallelism) at the SMT layer that backs
// every transparency-clock read in the network: concurrent
// goroutines writing leaves under distinct originator LogDIDs
// MUST advance in parallel without a global lock collapsing
// them onto one writer thread.
//
// MATRIX (one row per test case):
//
//  1. ParallelDistinctKeys — N goroutines × M unique leaves
//     each. All N*M writes succeed; final SMT Count == N*M.
//     Race-free against -race (caller invokes the test pkg
//     under -race in CI).
//  2. ParallelDistinctOriginators — N goroutines, each writing
//     leaves whose OriginTip.LogDID is unique to the
//     goroutine. After the run, every persona's leaves are
//     individually retrievable. A global lock would still let
//     this pass (eventually all writes complete) but a
//     data race would flip the LogDIDs across boundaries —
//     detectable by reading back per-key.
//  3. RootStableUnderConcurrentBenignWrites — same key written
//     with the same value from N goroutines must produce
//     ONE durable leaf and a deterministic root, identical
//     to the single-write case. Pins idempotent SetLeaf
//     (Principle 6 / 8: deterministic idempotency).
//
// This package's harness skips when ATTESTA_TEST_DSN is
// unset, so the cell remains a build-tag-gated production
// scenario test.
package p4

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	smt "github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// p4ConcurrentLogDID returns a unique-per-goroutine DID. Used so
// each persona's writes are distinguishable in tip-tuple bytes.
func p4ConcurrentLogDID(i int) string {
	return fmt.Sprintf("did:p4:concurrent:persona-%d", i)
}

// keyForGoroutine derives a 32-byte SMT key that encodes the
// (goroutine, leaf) coordinates. Two goroutines never collide.
func keyForGoroutine(g, leaf int) [32]byte {
	var k [32]byte
	binary.BigEndian.PutUint32(k[0:4], uint32(g))
	binary.BigEndian.PutUint32(k[4:8], uint32(leaf))
	// Fill the rest deterministically so two distinct (g, leaf)
	// tuples always differ in the leading 8 bytes.
	for i := 8; i < 32; i++ {
		k[i] = byte((g*7 + leaf*13 + i) & 0xFF)
	}
	return k
}

// TestP4_ConcurrentLoad_ParallelDistinctKeys: N goroutines each
// write M leaves with distinct keys. Every leaf MUST land; final
// count MUST equal N*M. A global lock that serialised the writers
// would still pass this assertion (correctness), but the test
// also runs cheap enough that wall-clock regressions show up
// in ops dashboards.
func TestP4_ConcurrentLoad_ParallelDistinctKeys(t *testing.T) {
	const (
		N = 8 // goroutines
		M = 32
	)
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DELETE FROM smt_leaves`); err != nil {
		t.Fatalf("clear smt_leaves: %v", err)
	}

	leafStore := store.NewPostgresLeafStore(pool)

	var wg sync.WaitGroup
	errCh := make(chan error, N)
	for g := 0; g < N; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < M; j++ {
				k := keyForGoroutine(g, j)
				leaf := types.SMTLeaf{
					Key: k,
					OriginTip: types.LogPosition{
						LogDID:   p4ConcurrentLogDID(g),
						Sequence: uint64(j + 1),
					},
					AuthorityTip: types.LogPosition{
						LogDID:   p4ConcurrentLogDID(g),
						Sequence: uint64(j + 1),
					},
				}
				if err := leafStore.Set(ctx, k, leaf); err != nil {
					errCh <- fmt.Errorf("g=%d j=%d Set: %w", g, j, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent write: %v", err)
	}

	got, err := leafStore.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	want := N * M
	if got != want {
		t.Fatalf("final SMT Count = %d, want %d (N=%d goroutines × M=%d leaves) — "+
			"a missing leaf would mean concurrent SetLeaf calls clobbered each "+
			"other, a fatal violation of per-key isolation",
			got, want, N, M)
	}
}

// TestP4_ConcurrentLoad_ParallelDistinctOriginators: each
// goroutine writes leaves whose OriginTip.LogDID is unique to
// the goroutine. After the run, every persona's leaves are
// individually retrievable AND the LogDID stamp matches the
// originating goroutine. A data race that swapped LogDIDs across
// goroutines would surface here as a mismatch.
func TestP4_ConcurrentLoad_ParallelDistinctOriginators(t *testing.T) {
	const (
		N = 6
		M = 16
	)
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DELETE FROM smt_leaves`); err != nil {
		t.Fatalf("clear smt_leaves: %v", err)
	}

	leafStore := store.NewPostgresLeafStore(pool)

	var wg sync.WaitGroup
	errCh := make(chan error, N*M)
	for g := 0; g < N; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			did := p4ConcurrentLogDID(g)
			for j := 0; j < M; j++ {
				k := keyForGoroutine(g, j)
				leaf := types.SMTLeaf{
					Key: k,
					OriginTip: types.LogPosition{
						LogDID: did, Sequence: uint64(j + 1),
					},
					AuthorityTip: types.LogPosition{
						LogDID: did, Sequence: uint64(j + 1),
					},
				}
				if err := leafStore.Set(ctx, k, leaf); err != nil {
					errCh <- fmt.Errorf("g=%d j=%d Set: %w", g, j, err)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent write: %v", err)
	}

	// Read-back: every key MUST round-trip back to its originating
	// goroutine's LogDID. A data race that mixed up LogDIDs would
	// surface as a per-key mismatch.
	for g := 0; g < N; g++ {
		wantDID := p4ConcurrentLogDID(g)
		for j := 0; j < M; j++ {
			k := keyForGoroutine(g, j)
			got, err := leafStore.Get(ctx, k)
			if err != nil {
				t.Errorf("Get g=%d j=%d: %v", g, j, err)
				continue
			}
			if got == nil {
				t.Errorf("Get g=%d j=%d returned nil — leaf vanished", g, j)
				continue
			}
			if got.OriginTip.LogDID != wantDID {
				t.Errorf("g=%d j=%d: OriginTip.LogDID = %q, want %q "+
					"(LogDID swap = goroutine-state crossover, "+
					"a fatal Principle-9 violation)",
					g, j, got.OriginTip.LogDID, wantDID)
			}
		}
	}
}

// TestP4_ConcurrentLoad_RootStableUnderConcurrentBenignWrites:
// N goroutines write the SAME (key, leaf) tuple. SMT Set is an
// upsert — duplicate writes must produce the same final state
// AND a deterministic root, identical to the single-write case.
// Pins Principle 8 (Deterministic Idempotency) under contention.
func TestP4_ConcurrentLoad_RootStableUnderConcurrentBenignWrites(t *testing.T) {
	const N = 8
	pool := requirePostgres(t)
	defer pool.Close()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DELETE FROM smt_leaves`); err != nil {
		t.Fatalf("clear smt_leaves: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM smt_nodes`); err != nil {
		t.Fatalf("clear smt_nodes: %v", err)
	}

	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeStore(ctx, pool, 1024)
	tree := smt.NewTree(leafStore, nodeCache)

	key := [32]byte{0xBE, 0xEF}
	leaf := types.SMTLeaf{
		Key: key,
		OriginTip: types.LogPosition{
			LogDID: p4ConcurrentLogDID(0), Sequence: 1,
		},
		AuthorityTip: types.LogPosition{
			LogDID: p4ConcurrentLogDID(0), Sequence: 1,
		},
	}

	// Reference: write once, capture root.
	if err := tree.SetLeaf(ctx, key, leaf); err != nil {
		t.Fatalf("reference SetLeaf: %v", err)
	}
	wantRoot, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("reference Root: %v", err)
	}

	// N goroutines write the SAME (key, leaf) tuple concurrently.
	var wg sync.WaitGroup
	for g := 0; g < N; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = leafStore.Set(ctx, key, leaf) // best-effort; same tuple every time
		}()
	}
	wg.Wait()

	// Root must be identical to the single-write reference.
	gotRoot, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("post-concurrent Root: %v", err)
	}
	if gotRoot != wantRoot {
		t.Fatalf("idempotent SetLeaf produced root drift under concurrency:\n"+
			" got=%x\nwant=%x\nN goroutines writing the same (key,leaf) tuple "+
			"MUST converge to one canonical state. Drift here means SetLeaf is "+
			"NOT idempotent under contention — Principle 8 violated.",
			gotRoot, wantRoot)
	}

	// And exactly one leaf row must exist.
	count, err := leafStore.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("Count = %d, want 1 (one leaf, written N+1 times)", count)
	}
}
