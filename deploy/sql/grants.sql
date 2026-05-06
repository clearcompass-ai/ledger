-- =============================================================================
-- FILE PATH:
--     deploy/sql/grants.sql
--
-- DESCRIPTION:
--     Append-only enforcement at the DB role level. Defense-in-depth on top
--     of the application-level invariant ("the ledger never UPDATEs or
--     DELETEs from the append-only tables"): even a SQL injection bug or a
--     misbehaving ORM can't mutate the log because the role lacks the grant.
--
--     The ledger application connects as role <ledger_app>. After
--     RunMigrations creates the schema, run THIS file once as a Postgres
--     superuser (or as the role that owns the schema) to revoke mutation
--     privileges on the append-only tables.
--
--     Mutation is still permitted on the cursor / counter / cache tables
--     that genuinely need it (builder_cursor, credits, smt_leaves,
--     smt_nodes, sessions, delta_window_buffers).
--
-- WHEN TO RUN:
--     Once, at deploy time, AFTER `cmd/ledger` has booted at least once
--     (so RunMigrations has populated the schema). Subsequent runs are
--     idempotent: REVOKE on a privilege the role doesn't have is a no-op.
--
-- HOW TO RUN:
--     psql "$LEDGER_DATABASE_URL_ADMIN" -v ON_ERROR_STOP=1 \
--          -v ledger_app=ledger_app \
--          -f deploy/sql/grants.sql
--
--     Replace `ledger_app` above with whatever role your ledger connects
--     as. The :ledger_app psql variable is referenced below; if you don't
--     pass `-v ledger_app=...` psql will prompt.
--
-- WHAT THIS PROTECTS:
--     entry_index             — the canonical sequence-number → entry
--                               index. Append-only by spec.
--     commitment_split_id     — the (schema_id, split_id) → seq lookup.
--                               BTREE not UNIQUE because equivocation
--                               evidence requires two rows; mutating
--                               either after admission destroys evidence.
--     derivation_commitments  — the SMT-batch derivation pins. Each row
--                               anchors a fraud proof; mutating it
--                               retroactively invalidates the chain.
--     tree_heads              — the signed-checkpoint history. Mutation
--                               would let an operator forge a different
--                               root for an already-published tree size.
--     tree_head_sigs          — co-signatures over tree_heads. Same.
--     equivocation_proofs     — frozen detected-fork records. Mutation
--                               erases evidence of a past fault.
--
-- WHAT STAYS MUTABLE (intentionally):
--     builder_cursor          — single-row counter, must UPDATE on each
--                               builder batch.
--     credits                 — exchange-DID balance, decrements on use.
--     smt_leaves / smt_nodes  — projected SMT state, rebuilt from entries.
--     delta_window_buffers    — projection cache, recomputable.
--     sessions                — auth sessions, expire + delete.
--     witness_sets            — current witness keyset; new versions
--                               appended, but old rows remain immutable
--                               in practice (REVOKE optional here).
-- =============================================================================

\set ON_ERROR_STOP on

BEGIN;

-- entry_index — the canonical log
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE entry_index FROM :ledger_app;

-- commitment_split_id — equivocation evidence
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE commitment_split_id FROM :ledger_app;

-- derivation_commitments — SMT-batch fraud-proof anchors
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE derivation_commitments FROM :ledger_app;

-- tree_heads — signed checkpoints
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE tree_heads FROM :ledger_app;

-- tree_head_sigs — witness co-signatures
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE tree_head_sigs FROM :ledger_app;

-- equivocation_proofs — detected-fork records
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE equivocation_proofs FROM :ledger_app;

-- INSERT, SELECT, REFERENCES remain granted. The role can still append
-- new rows and read existing ones; only mutation of historical rows is
-- denied.

COMMIT;

-- Verification query (run separately to confirm grants):
--
--   SELECT table_name,
--          string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privs
--   FROM information_schema.table_privileges
--   WHERE grantee = :'ledger_app'
--     AND table_name IN ('entry_index', 'commitment_split_id',
--                        'derivation_commitments', 'tree_heads',
--                        'tree_head_sigs', 'equivocation_proofs')
--   GROUP BY table_name
--   ORDER BY table_name;
--
-- Expected: each table shows only INSERT, SELECT (and REFERENCES if
-- granted at schema level). UPDATE / DELETE / TRUNCATE must NOT appear.
