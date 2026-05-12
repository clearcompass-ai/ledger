-- migrate:no-transaction
--
-- This directive MUST appear as the first non-empty line of the
-- file. The migration runner (store/migrations.go) detects it and
-- applies the file via autocommit instead of the default
-- BEGIN/COMMIT wrapper. Required because Phase 3 below uses
-- `CREATE INDEX CONCURRENTLY`, which PostgreSQL refuses to run
-- inside an explicit transaction block.
--
-- DISCIPLINE: every statement in this file is IDEMPOTENT
-- (IF EXISTS / IF NOT EXISTS / DO NOTHING). On replay the file is
-- a no-op against an already-migrated schema. The runner records
-- the version in schema_migrations in a SEPARATE small
-- transaction after all statements succeed; if that record fails,
-- the next boot replays this file safely because every statement
-- short-circuits when already applied.
--
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
-- That's a fatal liability under SDK Principle 8 (Deterministic
-- Idempotency).
--
-- THE FIX — PARTIAL UNIQUE INDEX + GHOST STATUS
--
-- (1) Add status=2 (StatusGhostLeaf) to the entry_index_status_check
--     enum.
--
-- (2) Replace the blanket UNIQUE(canonical_hash) with a PARTIAL
--     UNIQUE INDEX scoped to status <> 2. Primary (live or
--     tombstone) rows stay uniquely indexed; ghost rows at status=2
--     are outside the unique partition and coexist with the primary
--     row carrying the same canonical_hash.
--
-- (3) Application-level commit path (sequencer/committer.go): on
--     `ON CONFLICT (canonical_hash) DO NOTHING` skip, the committer
--     issues a second INSERT for the skipped row with status=2.
--     The partial index passes it through; entry_index has rows
--     for EVERY Tessera seq, no gaps.
--
-- (4) API resolution: a request for GET /v1/entries/{seq}/raw whose
--     row has status=2 looks up the primary row by canonical_hash
--     and 308-redirects to the bytestore path under the primary's
--     seq. The Tessera leaf at the duplicate seq is honored
--     publicly; the bytes are deterministically routed to the
--     canonical storage location.
--
-- ORDER OF STATEMENTS
--
-- Phases 1 + 2 (CHECK + new partial index) run first so the new
-- shape exists before we drop the old constraint. Phase 3 drops
-- the old blanket UNIQUE constraint. Phase 4 adds a supporting
-- index for the ghost-to-primary lookup path. All four are
-- idempotent.
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

-- ── Phase 1 — extend the status enum to admit ghost (2) ────────────────
ALTER TABLE entry_index
    DROP CONSTRAINT IF EXISTS entry_index_status_check;
ALTER TABLE entry_index
    ADD CONSTRAINT entry_index_status_check CHECK (status IN (0, 1, 2));

-- ── Phase 2 — build the new partial unique index ───────────────────────
--
-- CONCURRENTLY is REQUIRED here. It allows ongoing INSERTs/UPDATEs
-- on entry_index while the index builds. Today the table is empty
-- (zero users), so this is instant; once we have production data
-- this is the difference between a maintenance-window operation and
-- an online migration. Disciplined now, paid forward.
--
-- The IF NOT EXISTS clause keeps the statement idempotent on replay.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS
    entry_index_canonical_hash_primary_idx
    ON entry_index (canonical_hash)
    WHERE status <> 2;

-- ── Phase 3 — drop the old blanket UNIQUE constraint ───────────────────
--
-- The pre-0006 schema (migration 0001) defined:
--   canonical_hash BYTEA NOT NULL UNIQUE
-- That UNIQUE creates an implicit constraint named
-- entry_index_canonical_hash_key. Dropping it is fast (catalog-only
-- change), and the new partial index from Phase 2 already covers
-- the same uniqueness rule for non-ghost rows — so during the
-- moment between the new index existing and the old constraint
-- dropping, both rules are enforced (more strictly than needed,
-- never less).
ALTER TABLE entry_index
    DROP CONSTRAINT IF EXISTS entry_index_canonical_hash_key;

-- ── Phase 4 — supporting partial index for ghost-row audit ─────────────
--
-- The API's ghost-redirect path queries by canonical_hash with
-- status <> 2; Phase 2's index covers that exactly. The INVERSE
-- (listing all ghosts for one canonical_hash, for SRE audit) needs
-- its own index scoped to status = 2. Bounded to ghost rows so the
-- index is tiny in steady state.
CREATE INDEX CONCURRENTLY IF NOT EXISTS
    entry_index_canonical_hash_ghost_idx
    ON entry_index (canonical_hash)
    WHERE status = 2;
