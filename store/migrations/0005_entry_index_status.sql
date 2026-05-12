-- ──────────────────────────────────────────────────────────────────────
-- Migration 0005 — entry_index.status (tombstone marker)
-- ──────────────────────────────────────────────────────────────────────
--
-- The sequencer's new staged-commit architecture (introduced alongside
-- this migration) enforces gap-free entry_index visibility via a
-- singleton committer goroutine drained from a min-heap keyed by seq.
-- That architecture relies on the invariant:
--
--   For every seq that Tessera has assigned, entry_index has a row.
--
-- Tessera.AppendLeaf is irrevocable: once it returns seq=N for a hash,
-- N exists in the cryptographic log permanently. If the entry
-- referenced by seq=N then fails to project (e.g., a permanent
-- batch-commit error after Tessera success, or a future post-AppendLeaf
-- failure mode), the committer MUST still insert a row at seq=N or:
--
--   1. The committer's heap stalls waiting for seq=N, which will never
--      arrive — the entire pipeline deadlocks.
--   2. External auditors querying /v1/entries/{seq=N} would receive a
--      permanent 404 for a seq that exists in Tessera, breaking the
--      log-projection consistency contract.
--
-- A TOMBSTONE row (status=1) preserves the seq slot:
--
--   - canonical_hash: the real hash (we have it — the wire bytes are
--                     stored in WAL under that hash, even if their
--                     deserialization fails)
--   - log_time:       wall-clock at tombstone time
--   - signer_did:     the literal 'system:tombstone' (passes the
--                     CHECK (signer_did <> '') constraint)
--   - target_root,
--     cosignature_of,
--     schema_ref:     NULL
--   - status:         1
--
-- Builder-side: BeginBatch skips tombstones when assembling its work
-- list, but still advances the cursor past them so they don't block
-- progress. See builder/cursor_reader.go for the filter logic.
--
-- ── Schema change ─────────────────────────────────────────────────────
--
-- ALTER TABLE … ADD COLUMN … DEFAULT 0 is fast in PG 11+: the catalog
-- records a "fast default" and existing rows are NOT rewritten. All
-- pre-existing rows logically have status=0 (live) without touching
-- their on-disk representation.
--
-- The CHECK constraint pins the column to {0=live, 1=tombstone}; any
-- third value rejected at insert time. Application code must use the
-- StatusLive / StatusTombstone constants in store/entries.go.
--
-- The partial index on status<>0 makes "list tombstones for audit"
-- queries cheap without indexing the bulk-live partition.

ALTER TABLE entry_index
    ADD COLUMN IF NOT EXISTS status SMALLINT NOT NULL DEFAULT 0
    CONSTRAINT entry_index_status_check CHECK (status IN (0, 1));

CREATE INDEX IF NOT EXISTS idx_entry_index_status
    ON entry_index (status) WHERE status <> 0;
