-- =============================================================================
-- Migration 0002 — smt_root_state singleton table
-- =============================================================================
--
-- Purpose: maintain the SMT root incrementally so /v1/smt/root and the
-- builder's atomic-commit pipeline don't have to materialize the full
-- leaf set on every read.
--
-- Why this is required:
--
--   The SDK's smt.Tree.Root() walks all leaves via collectLeafHashes
--   (attesta/core/smt/tree.go), which only enumerates the concrete
--   *InMemoryLeafStore and *OverlayLeafStore types. *PostgresLeafStore
--   falls through the typed switch and Tree.Root short-circuits to
--   defaultHashes[TreeDepth] — the empty-tree root — regardless of
--   how many leaves are committed.
--
--   The materialization workaround in api/proofs.go (liveTree +
--   PostgresLeafStore.MaterializeToInMemory) is O(N) per request. At
--   N = 10⁹ leaves it's unusable.
--
--   This table holds the authoritative current root, computed
--   incrementally by the builder via Tree.ComputeDirtyRoot(priorRoot,
--   mutations) inside the same atomic commit transaction that writes
--   the leaves. /v1/smt/root reads this row directly — O(1).
--
-- Singleton pattern (id = 1 + CHECK constraint):
--
--   Mirrors builder_cursor — one row, never DELETEd, only UPDATEd.
--   The CHECK constraint plus DEFAULT 1 makes accidental multi-row
--   inserts impossible. The migration INSERTs the empty-tree default
--   root + committed_through_seq = 0 so reads always succeed.
--
-- This migration seeds the row with the legacy depth-256 empty-tree
-- root for backward-compatibility with the migration ordering. Migration
-- 0003 (Jellyfish/Patricia SMT) overwrites this with the new empty-tree
-- root sha256("") = e3b0c4…b855 immediately after. New deployments
-- observe only the post-0003 value.

CREATE TABLE IF NOT EXISTS smt_root_state (
    id                      SMALLINT PRIMARY KEY DEFAULT 1
        CONSTRAINT smt_root_state_singleton CHECK (id = 1),
    current_root            BYTEA NOT NULL
        CONSTRAINT smt_root_state_root_size CHECK (octet_length(current_root) = 32),
    committed_through_seq   BIGINT NOT NULL DEFAULT 0,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO smt_root_state (id, current_root, committed_through_seq)
VALUES (
    1,
    -- defaultHashes[256] for the SDK's SMT — see
    -- attesta/core/smt/tree.go:defaultHashes initialization.
    decode('876422b7697ae7c337e2ee7727feb3db474adf7be1cf04b6b5857d82d610e88a', 'hex'),
    0
)
ON CONFLICT (id) DO NOTHING;
