-- =============================================================================
-- Migration 0003 — Jellyfish/Patricia SMT replaces depth-256 sparse SMT
-- =============================================================================
--
-- Purpose: replace the depth-256 sparse Merkle tree with a path-compressed
-- (Jellyfish/Patricia) tree. The depth-256 tree wrote 256 cache.Set rows
-- per leaf insertion regardless of tree size, producing a per-batch write
-- amplification of 256× that capped sustained throughput at the 100K-leaf
-- soak and would have crossed PG's UPSERT ceiling around N=10M.
--
-- The Jellyfish tree writes O(log N) nodes per insertion. For N=10B, that
-- is ~33 writes per leaf vs 256 previously — a 7.8× reduction in steady
-- state, and orders of magnitude less in total stored node count
-- (exactly 2N-1 internal nodes vs ~N×(d - log₂N) ≈ N×223 for d=256).
--
-- Cryptographic shape change → root hash changes → smt_root_state's
-- empty-tree constant must move from the depth-256 `876422b7…10e88a` value
-- to `sha256("") = e3b0c4…b855` (the canonical Jellyfish empty root).
--
-- This migration is destructive: the depth-256 `smt_nodes` table is
-- dropped wholesale. There is no migration path from the old shape to
-- the new — they are different cryptographic objects. With zero
-- production users (clean slate), the migration is safe to apply.
--
-- Storage model:
--   - Content-addressed: node_hash (PK) = sha256(payload).
--   - Structurally immortal: in a content-addressed Merkle DAG, a node
--     created on Day 1 representing an inactive segment is still
--     mathematically linked to the live root years later. Time-based
--     eviction (e.g. "DELETE WHERE created_at < N days ago") would tear
--     load-bearing nodes out of the live tree and instantly corrupt
--     every subsequent proof — there is no created_at column for that
--     reason, and there must never be one.
--   - No GC in the initial implementation. The Jellyfish trie's node
--     count is bounded at 2N-1 for N leaves (~20 B rows at 10 B leaves);
--     PG handles that volume natively. If pruning is ever needed it
--     MUST be a Mark-and-Sweep walk rooted at the live tree heads, never
--     a time predicate.
--   - payload is the canonical serialization of a leaf or branch node
--     (tag byte + fields). The SDK's smt.NodeStore reads and writes
--     these rows; the ledger never inspects payload contents.

DROP TABLE IF EXISTS smt_nodes;

CREATE TABLE IF NOT EXISTS jellyfish_nodes (
    node_hash  BYTEA PRIMARY KEY
        CONSTRAINT jellyfish_nodes_hash_size CHECK (octet_length(node_hash) = 32),
    payload    BYTEA NOT NULL
);

-- Reset the singleton root to the Jellyfish empty-tree hash.
-- sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
UPDATE smt_root_state
SET current_root = decode('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'),
    committed_through_seq = 0,
    updated_at = NOW()
WHERE id = 1;
