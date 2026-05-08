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

// testLogDID is defined in commitment_fetcher_test.go (same
// package) and reused here for fixture parity.
