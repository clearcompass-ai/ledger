-- ──────────────────────────────────────────────────────────────────────
-- Migration 0006 — Ghost leaf admission via partial unique index
-- ──────────────────────────────────────────────────────────────────────
--
-- WHY THIS MIGRATION EXISTS
--
-- The pre-0006 schema enforced `entry_index.canonical_hash UNIQUE`
-- globally. Under the pre_commit_post_pg crash window — where the
-- ledger SIGKILLs between a successful PG batch commit and the
-- post-commit WAL.Sequence call — Tessera's in-memory antispam
-- cache can lose the (hash → seq) mapping for the in-flight batch.
-- On restart, Tessera blindly assigns a FRESH seq to the same hash,
-- producing a duplicate Tessera leaf. The committer's INSERT into
-- entry_index then collides on canonical_hash and the entire batch
-- fails — the committer cannot make forward progress until an
-- operator intervenes.
--
-- A bare `ON CONFLICT DO NOTHING` would silently skip the duplicate
-- INSERT but would leave a GAP in entry_index at the duplicate seq.
-- Tessera's Static-CT tile permanently publishes a leaf at the
-- duplicate seq; an external auditor downloading the tile would see
-- a leaf at index N and call GET /v1/entries/N/raw. With a gap the
-- ledger returns 404 — a Transparency Log that publishes a Merkle
-- leaf and then refuses to serve its bytes is cryptographically
-- indistinguishable from a malicious operator destroying evidence.
-- That's a fatal liability under the SDK's Principle 8 (Deterministic
-- Idempotency).
--
-- THE FIX — PARTIAL UNIQUE INDEX + GHOST STATUS
--
-- (1) Drop the blanket UNIQUE(canonical_hash) constraint.
--
-- (2) Add a new status value: 2 = ghost-leaf. A ghost row says
--     "Tessera assigned this seq to a hash that already lives at a
--     PRIMARY seq; serve the bytes via redirect to the primary."
--
-- (3) Replace the blanket uniqueness with a PARTIAL UNIQUE INDEX on
--     canonical_hash WHERE status <> 2. The primary (live or
--     tombstone) row at the canonical seq stays uniquely indexed;
--     the ghost row at the duplicate Tessera seq is outside the
--     unique partition, so it coexists with the primary row.
--
-- (4) Application-level commit path: on PG `ON CONFLICT (canonical_hash)
--     DO NOTHING` skip, the committer issues a second INSERT for the
--     skipped row with status=2. The partial index passes it through;
--     entry_index has rows for EVERY Tessera seq, no gaps.
--
-- (5) API resolution: a request for GET /v1/entries/{seq}/raw whose
--     row has status=2 looks up the primary row by canonical_hash and
--     redirects (or proxies) to the bytestore path under the
--     primary's seq. The Tessera leaf at the duplicate seq is honored
--     publicly; the bytes are deterministically routed to the canonical
--     storage location.
--
-- CRYPTOGRAPHIC INVARIANT PRESERVED
--
-- Tessera's tree is unchanged: every leaf the auditor sees is
-- reachable. entry_index becomes a routable projection — for any seq
-- the tree publishes, the API returns either the bytes directly
-- (status<>2) or a deterministic redirect (status=2). The 1:1 parity
-- between Tessera's public tree and the routable API is restored.
--
-- COST DISCIPLINE
--
-- Fast path (no crash, no collision): identical to pre-0006. The
-- partial index covers the same rows the old blanket constraint
-- covered, with the same B-tree shape. INSERT cost is unchanged.
--
-- Crash-recovery path (rare): one extra INSERT roundtrip per ghost
-- leaf, scoped to the collision recovery only. Bounded by the
-- maximum in-flight batch at kill time.

-- ── Step 1 — drop the blanket UNIQUE(canonical_hash) constraint ───────
--
-- Pre-0006 schema (migration 0001) defined:
--   canonical_hash BYTEA NOT NULL UNIQUE
-- That UNIQUE creates an implicit constraint named
-- entry_index_canonical_hash_key. We drop it before adding the
-- replacement partial index. IF EXISTS makes this idempotent in
-- case the migration is re-run after a partial apply.
ALTER TABLE entry_index
    DROP CONSTRAINT IF EXISTS entry_index_canonical_hash_key;

-- ── Step 2 — relax the status CHECK to admit ghost (2) ────────────────
--
-- Migration 0005 pinned status IN (0, 1). Add 2 (ghost-leaf) to the
-- allowed set so the committer can INSERT ghost rows. Existing rows
-- with status=0 or status=1 still satisfy the new check.
ALTER TABLE entry_index
    DROP CONSTRAINT IF EXISTS entry_index_status_check;
ALTER TABLE entry_index
    ADD CONSTRAINT entry_index_status_check CHECK (status IN (0, 1, 2));

-- ── Step 3 — partial unique index on canonical_hash for non-ghost rows─
--
-- The new uniqueness rule:
--
--   For any canonical_hash, at most ONE row in entry_index has
--   status <> 2 (i.e., one Live OR Tombstone row per hash).
--   Multiple status=2 (ghost) rows may share the canonical_hash,
--   each at its own Tessera-assigned sequence_number.
--
-- This is exactly the constraint set the Ghost Leaf recovery model
-- requires. Postgres's `ON CONFLICT (canonical_hash) DO NOTHING`
-- clause references this index by column; the partial WHERE clause
-- is implicit.
CREATE UNIQUE INDEX IF NOT EXISTS entry_index_canonical_hash_primary_idx
    ON entry_index (canonical_hash)
    WHERE status <> 2;

-- ── Step 4 — supporting index for ghost-to-primary lookup ─────────────
--
-- The API's ghost-redirect path queries:
--   SELECT sequence_number FROM entry_index
--   WHERE canonical_hash = $1 AND status <> 2
-- to resolve a ghost row's primary seq. The partial unique index
-- above (entry_index_canonical_hash_primary_idx) covers this query
-- directly — Postgres uses it for the lookup, returning the unique
-- non-ghost row's seq.
--
-- For the inverse direction — listing all ghost rows for a given
-- canonical_hash (audit / SRE) — add a small partial index keyed on
-- canonical_hash WHERE status = 2. Bounded to ghost rows so it's
-- cheap even when ghosts are rare.
CREATE INDEX IF NOT EXISTS entry_index_canonical_hash_ghost_idx
    ON entry_index (canonical_hash)
    WHERE status = 2;
