/*
FILE PATH: tests/chaos/smt_reconstruction/reconstructor.go

Pure-function SMT root reconstruction from durable Postgres
tables. Validates the disaster-recovery claim: "given only
entry_index + smt_leaves + smt_root_state, an auditor can rebuild
the live SMT root and confirm it matches the persisted value."

WHY THIS EXISTS

The soak's verifySMTConsistency() validates the SMT root via the
API — fetches /v1/smt/root, samples N entries, runs membership
proofs against the live root. That tests the LIVE pipeline; it
does NOT test that the live root could be REBUILT from durable
state alone. Two different invariants:

  (A) "The live root is internally consistent" — soak covers.
  (B) "The live root is reconstructible from durable tables" —
      this file covers.

The Reasserter package was deleted earlier in the project (per
integrity/integrity_test.go's notes). This file replaces the
disaster-recovery validation it used to provide, scoped to
chaos tests instead of boot-time runtime reconciliation.

DESIGN

  - No mutation: pure read against PG. Safe to run against live
    PG even during traffic (with a snapshot serializable txn so
    leaves + root are read coherently).
  - SDK in-memory stores: build a fresh tree from
    smt.NewInMemoryLeafStore + smt.NewInMemoryNodeStore, push
    leaves via tree.SetLeaves, read tree.Root. The SDK's stores
    are correct by construction; if the reconstructed root
    matches the persisted root, the durable state is
    cryptographically self-consistent.
  - Bounded memory: the reconstruction loads ALL leaves into
    memory. At 100K leaves x ~256 bytes per leaf record ≈ 25 MB.
    At 10M ≈ 2.5 GB. For the soak's typical workload (100K-1M)
    this is fine; for production-scale audits a streaming
    variant would be needed.

USE FROM TESTS

  // After a kill-restart cycle, validate the cryptographic
  // invariant survives:
  result, err := smt_reconstruction.Reconstruct(ctx, pool)
  if err != nil { t.Fatal(err) }
  if !result.Match {
      t.Fatalf("SMT root mismatch after restart:\n"+
               "  reconstructed: %x\n  persisted:     %x\n  leaves: %d",
          result.ReconstructedRoot, result.PersistedRoot,
          result.LeafCount)
  }
*/
package smt_reconstruction

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
)

// Result is the outcome of a reconstruction attempt. The two
// fields the caller asserts are Match (boolean) and the two
// root values; the LeafCount + TreeSize fields are informational
// and useful for failure messages.
type Result struct {
	// LeafCount is the number of rows in smt_leaves that
	// contributed to the reconstructed tree.
	LeafCount int

	// TreeSize is committed_through_seq from smt_root_state — the
	// last seq the builder said it has integrated. Compared
	// against LeafCount to surface a mismatch between the leaf
	// table and the builder's claimed progress (different from
	// the root mismatch — this is the "did the builder LIE about
	// its progress" check).
	TreeSize uint64

	// ReconstructedRoot is the root we computed by walking
	// smt_leaves and pushing every leaf through an in-memory
	// tree.
	ReconstructedRoot [32]byte

	// PersistedRoot is smt_root_state.current_root — what the
	// live system claims the root is.
	PersistedRoot [32]byte

	// Match is true iff ReconstructedRoot == PersistedRoot.
	// The load-bearing assertion.
	Match bool
}

// Reconstruct walks the durable SMT state in pool and rebuilds
// the SMT root using the SDK's in-memory tree. Reads are inside
// a single serializable snapshot so smt_leaves and
// smt_root_state are observed coherently — without that, a
// concurrent builder commit could shift smt_leaves between the
// two reads and produce a false-positive mismatch.
//
// Returns a Result with Match=true iff the reconstructed root
// matches the persisted root. Caller decides how to react
// (test t.Fatal, audit log, etc.).
func Reconstruct(ctx context.Context, pool *pgxpool.Pool) (Result, error) {
	var result Result
	err := store.WithSerializableTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		// Step 1: load the persisted root + tree size.
		var persistedRoot []byte
		var committedThrough int64
		err := tx.QueryRow(ctx,
			`SELECT current_root, committed_through_seq FROM smt_root_state WHERE id = 1`,
		).Scan(&persistedRoot, &committedThrough)
		if err != nil {
			return fmt.Errorf("read smt_root_state: %w", err)
		}
		if len(persistedRoot) != 32 {
			return fmt.Errorf("smt_root_state.current_root has %d bytes, want 32",
				len(persistedRoot))
		}
		copy(result.PersistedRoot[:], persistedRoot)
		if committedThrough >= 0 {
			result.TreeSize = uint64(committedThrough)
		}

		// Step 2: load every leaf. Order doesn't matter for
		// correctness (the SDK's tree commits leaves
		// order-invariantly per builder/incremental_root_test.go's
		// pin) but we order by leaf_key for deterministic test
		// output if a mismatch occurs.
		leaves, err := loadLeaves(ctx, tx)
		if err != nil {
			return fmt.Errorf("load smt_leaves: %w", err)
		}
		result.LeafCount = len(leaves)

		// Step 3: build a fresh tree from in-memory stores and
		// push every leaf through SetLeaves. The SDK's tree
		// computes the new root incrementally; after the call
		// completes, tree.Root() returns the rebuilt root.
		tree := smt.NewTree(
			smt.NewInMemoryLeafStore(),
			smt.NewInMemoryNodeStore(),
		)
		if err := tree.SetLeaves(ctx, leaves); err != nil {
			return fmt.Errorf("SDK SetLeaves (n=%d): %w", len(leaves), err)
		}
		root, err := tree.Root(ctx)
		if err != nil {
			return fmt.Errorf("SDK tree.Root: %w", err)
		}
		result.ReconstructedRoot = root
		result.Match = result.ReconstructedRoot == result.PersistedRoot
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// loadLeaves reads every row from smt_leaves inside tx and
// returns the leaves as []types.SMTLeaf. Decodes origin_tip and
// authority_tip via store.DeserializeLogPosition — the same
// codec the builder uses to write them, so this is correct
// by construction as long as the codec is stable.
func loadLeaves(ctx context.Context, tx pgx.Tx) ([]types.SMTLeaf, error) {
	rows, err := tx.Query(ctx,
		`SELECT leaf_key, origin_tip, authority_tip
		 FROM smt_leaves
		 ORDER BY leaf_key`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []types.SMTLeaf
	for rows.Next() {
		var leafKeyBytes []byte
		var originBytes []byte
		var authBytes []byte
		if err := rows.Scan(&leafKeyBytes, &originBytes, &authBytes); err != nil {
			return nil, fmt.Errorf("scan smt_leaves row: %w", err)
		}
		if len(leafKeyBytes) != 32 {
			return nil, fmt.Errorf("smt_leaves.leaf_key has %d bytes, want 32",
				len(leafKeyBytes))
		}
		originTip, err := store.DeserializeLogPosition(originBytes)
		if err != nil {
			return nil, fmt.Errorf("deserialize origin_tip: %w", err)
		}
		authTip, err := store.DeserializeLogPosition(authBytes)
		if err != nil {
			return nil, fmt.Errorf("deserialize authority_tip: %w", err)
		}
		var leafKey [32]byte
		copy(leafKey[:], leafKeyBytes)
		out = append(out, types.SMTLeaf{
			Key:          leafKey,
			OriginTip:    originTip,
			AuthorityTip: authTip,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate smt_leaves: %w", err)
	}
	return out, nil
}

// FormatMismatch returns a human-readable diagnostic string for
// a non-matching Result. Useful for t.Fatalf / log.Error.
// Returns empty string when Match is true.
func (r Result) FormatMismatch() string {
	if r.Match {
		return ""
	}
	return fmt.Sprintf(
		"SMT root mismatch:\n"+
			"  leaves loaded:     %d\n"+
			"  committed_through: %d\n"+
			"  reconstructed:     %x\n"+
			"  persisted:         %x",
		r.LeafCount, r.TreeSize,
		r.ReconstructedRoot, r.PersistedRoot,
	)
}
