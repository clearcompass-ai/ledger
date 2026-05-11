-- =============================================================================
-- Migration 0004 — cursor signed-sentinel fix for seq=0 bootstrap
-- =============================================================================
--
-- Purpose: fix a pre-existing off-by-one in the builder's cursor reader
-- that permanently skipped sequence 0 on fresh installs.
--
-- BEFORE
-- ──────
-- store/sequence_cursor.go::Next runs
--     SELECT sequence_number FROM entry_index WHERE sequence_number > $1 ...
-- The cursor starts at 0 (migration 0001 INSERT). On the builder's
-- first BeginBatch the query is `WHERE seq > 0`, which excludes seq=0.
-- The batch returns [1..N]; the cursor advances to N; seq=0 has no
-- second chance.
--
-- EVIDENCE
-- ────────
-- A 100-entry soak with the v0.3.0 builder reached terminal state with
-- entry_index = [0..95] but smt_leaves having 95 rows, and
-- dumpSMTDiagnostics line (E) reported "missing seqs in smt_leaves:
-- first=[0]" — proving exactly one missing sequence and proving it is
-- seq=0. The cursor was at 95.
--
-- v0.2.0 had the same SQL bug; the v0.2.0 soak's larger 48 K-entry
-- backlog masked the off-by-one (51856 < 100000 vs the off-by-one
-- 99999/100000 that would otherwise have shown up).
--
-- FIX
-- ───
-- Use -1 as the "no sequences processed yet" sentinel. builder_cursor.
-- last_processed_sequence is BIGINT (signed in PG); the column type
-- supports -1 without ALTER. The Go cursor reader changes Read/Next
-- to int64 in the same commit; `WHERE seq > -1` then correctly
-- includes seq=0.
--
-- We only flip a row that is still in the fresh-install state: cursor
-- at exactly 0 AND smt_leaves empty. Any install that has already
-- processed entries (cursor > 0, or smt_leaves non-empty) is left
-- alone — its cursor accurately reflects committed work, and seq=0
-- has already been processed (or accepted as permanently lost, which
-- is itself a v0.2.0 production deployment fact that this migration
-- does not retroactively recover).

UPDATE builder_cursor
SET last_processed_sequence = -1,
    updated_at = NOW()
WHERE id = 1
  AND last_processed_sequence = 0
  AND NOT EXISTS (SELECT 1 FROM smt_leaves LIMIT 1);
