-- =============================================================================
-- 0001_initial.sql — initial schema for the Attesta ledger.
--
-- Replaces the historical inline schemaDDL[] in store/postgres.go.
-- Every subsequent change to the schema lands as a NEW numbered file
-- in this directory (0002_*.sql, 0003_*.sql, ...). Existing files
-- are NEVER modified after they ship — the schema_migrations table
-- records what's been applied by version number.
--
-- Discipline:
--   - Additive only. Never DROP or RENAME a column or table here.
--   - Use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
--     so re-running an already-applied file is harmless.
--   - One transaction per file. The applier wraps each file in a
--     single tx; partial application of a single file is impossible.
--
-- See store/migrations/README.md for the full policy.
-- =============================================================================

-- ──────────────────────────────────────────────────────────────────────
-- schema_migrations — applied-version registry. Read by the applier.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     BIGINT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT NOT NULL
);

-- ──────────────────────────────────────────────────────────────────────
-- entry_index — Postgres is an index, not byte storage.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS entry_index (
    sequence_number BIGINT PRIMARY KEY,
    canonical_hash  BYTEA NOT NULL UNIQUE,
    log_time        TIMESTAMPTZ NOT NULL,
    signer_did      TEXT NOT NULL CHECK (signer_did <> ''),
    target_root     BYTEA,
    cosignature_of  BYTEA,
    schema_ref      BYTEA
);

CREATE INDEX IF NOT EXISTS idx_signer_did
    ON entry_index (signer_did);
CREATE INDEX IF NOT EXISTS idx_target_root
    ON entry_index (target_root) WHERE target_root IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cosignature_of
    ON entry_index (cosignature_of) WHERE cosignature_of IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_schema_ref
    ON entry_index (schema_ref) WHERE schema_ref IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────
-- SMT state.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS smt_leaves (
    leaf_key      BYTEA PRIMARY KEY,
    origin_tip    BYTEA NOT NULL,
    authority_tip BYTEA NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS smt_nodes (
    path_key   BYTEA PRIMARY KEY,
    hash       BYTEA NOT NULL,
    depth      INT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Credits.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS credits (
    exchange_did    TEXT PRIMARY KEY,
    balance         BIGINT NOT NULL DEFAULT 0,
    total_purchased BIGINT NOT NULL DEFAULT 0,
    total_consumed  BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Tree heads (normalised: one row per attestation).
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tree_heads (
    tree_size  BIGINT NOT NULL,
    root_hash  BYTEA NOT NULL,
    hash_algo  SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tree_size, hash_algo)
);

CREATE TABLE IF NOT EXISTS tree_head_sigs (
    tree_size  BIGINT NOT NULL,
    hash_algo  SMALLINT NOT NULL DEFAULT 1,
    signer     TEXT NOT NULL,
    sig_algo   SMALLINT NOT NULL,
    signature  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tree_size, hash_algo, signer, sig_algo),
    FOREIGN KEY (tree_size, hash_algo) REFERENCES tree_heads (tree_size, hash_algo)
);

-- ──────────────────────────────────────────────────────────────────────
-- Delta buffer.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS delta_window_buffers (
    leaf_key    BYTEA PRIMARY KEY,
    tip_history BYTEA NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Builder cursor (CT-native log-tailing follower).
--
-- One-row table holding the highest sequence number the builder has
-- fully processed. The cursor reader (builder/cursor_reader.go) tails
-- entry_index by sequence_number > cursor. Admission writes only
-- entry_index — the log itself is the queue.
--
-- At 10B+ scale this avoids per-entry MVCC thrash entirely: cursor
-- mutation is a single-row UPDATE per builder batch inside the
-- builder's atomic commit transaction, so dead-tuple pressure is
-- bounded by batches/sec, not entries/sec.
--
-- id = 1 invariant: the table holds exactly one row. INSERT...ON
-- CONFLICT(id) DO NOTHING keeps it idempotent on bootstrap.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS builder_cursor (
    id                      SMALLINT PRIMARY KEY DEFAULT 1
        CONSTRAINT builder_cursor_singleton CHECK (id = 1),
    last_processed_sequence BIGINT NOT NULL DEFAULT 0,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO builder_cursor (id, last_processed_sequence)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────────────
-- Witness sets.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS witness_sets (
    version    SERIAL PRIMARY KEY,
    set_hash   BYTEA NOT NULL,
    keys_json  BYTEA NOT NULL,
    scheme_tag SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Equivocation proofs (tree-head fork).
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS equivocation_proofs (
    id          SERIAL PRIMARY KEY,
    head_a      BYTEA NOT NULL,
    head_b      BYTEA NOT NULL,
    tree_size   BIGINT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Sessions.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT PRIMARY KEY,
    exchange_did TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Derivation commitments (fraud proof lookup index).
-- Post-commit persistence: crash between atomic commit and this insert
-- loses the row. Acceptable — reconstructable from entries. See
-- store/derivation_commitments.go for full crash recovery semantics.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS derivation_commitments (
    id              SERIAL PRIMARY KEY,
    range_start_seq BIGINT NOT NULL,
    range_end_seq   BIGINT NOT NULL,
    prior_smt_root  BYTEA NOT NULL,
    post_smt_root   BYTEA NOT NULL,
    mutations_json  BYTEA NOT NULL,
    commentary_seq  BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_commitment_range
    ON derivation_commitments (range_start_seq, range_end_seq);

-- ──────────────────────────────────────────────────────────────────────
-- Commitment SplitID index.
--
-- Maps the 32-byte SplitID embedded in pre-grant-commitment-v1 and
-- escrow-split-commitment-v1 entry payloads to the entry's sequence
-- number, enabling the SDK lookup primitives FetchPREGrantCommitment
-- and FetchEscrowSplitCommitment.
--
-- Equivocation evidence preservation: the (schema_id, split_id) index
-- is BTREE, NOT UNIQUE. A malicious dealer publishing two distinct
-- commitment entries under the same SplitID produces two rows here
-- under the same key tuple; both MUST persist so the SDK can return
-- *CommitmentEquivocationError to verifiers. Rejecting the second row
-- on a UNIQUE constraint would silently destroy the cryptographic
-- evidence the SDK's equivocation detection depends on.
--
-- PRIMARY KEY on sequence_number is correct — two equivocating entries
-- have distinct sequence numbers (each has its own admission) and the
-- (schema_id, split_id) tuple is the lookup key, not the uniqueness key.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS commitment_split_id (
    sequence_number BIGINT NOT NULL,
    schema_id       TEXT NOT NULL,
    split_id        BYTEA NOT NULL,
    PRIMARY KEY (sequence_number),
    FOREIGN KEY (sequence_number) REFERENCES entry_index (sequence_number)
);

CREATE INDEX IF NOT EXISTS idx_commitment_split_id
    ON commitment_split_id (schema_id, split_id);

-- =============================================================================
-- Notes:
--
-- - Equivocation evidence persistence lives in the gossipstore BadgerDB
--   projection (prefix 0x0B). Detection runs in
--   gossipnet.EquivocationScanner (independent goroutine subscribed to
--   the splitid index 0x0A); verified findings are persisted as
--   KindEntryCommitmentEquivocation gossip events + projected to 0x0B
--   for O(1) /by-binding lookup. No Postgres surface owns equivocation
--   evidence anymore.
--
-- - Sequence numbers are assigned by the embedded Tessera library (the
--   c2sp.org/tlog-tiles integrator), not by Postgres. The entry_sequence
--   SEQUENCE that lived here in v1 was dropped in the WAL-first
--   admission migration: admission now blocks on wal.Submit (durable
--   bytes), then tessera.AppendLeaf (Tessera-assigned seq), then INSERTs
--   the resulting (seq, hash, ...) row into entry_index. Postgres only
--   records what Tessera already committed to.
-- =============================================================================
