-- FILE PATH: store/migrations/0007_tree_heads_smt_root.sql
--
-- Adds the SMTRoot column to tree_heads so the witness-cosigned
-- payload's full 72-byte state commitment (RootHash || SMTRoot ||
-- TreeSize) persists in full. Pairs with attesta SDK v0.8.0's
-- types.TreeHead.SMTRoot field addition.
--
-- # WHY THIS EXISTS
--
-- Pre-v0.8.0 the cosigned head was 40 bytes: RootHash[32] ||
-- TreeSize[8]. Light clients consuming /v1/smt/root had no
-- cryptographic link between the SMT root they fetched and the
-- witness-cosigned head; an adversary in the read path could
-- swap a forged SMT root and produce membership proofs against
-- it that pass every check except the one the SDK forgot to
-- include. v0.8.0 binds the SMT root INTO the witness signature,
-- closing the forgery vector. This migration persists the bound
-- value for replay + audit.
--
-- # DEFAULT FOR EXISTING ROWS
--
-- Pre-existing rows pre-date the binding. We backfill with
-- 32 zero bytes (the same default types.TreeHead{} would carry).
-- New rows written by SDK v0.8.0+ ledgers will carry the actual
-- SMT root. Auditors comparing historical heads recognise the
-- zero array as "no projection bound" and treat it as pre-v0.8.0
-- semantics.
--
-- The DEFAULT is REMOVED after the column add so that every new
-- row MUST explicitly carry the smt_root. The store layer enforces
-- this at the Insert call site (store/tree_heads.go::InsertHead
-- takes an explicit smtRoot [32]byte arg; the migration default
-- exists only for the backfill window).

ALTER TABLE tree_heads
    ADD COLUMN smt_root BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::BYTEA;

-- Drop the default so future inserts must supply the value
-- explicitly. The column remains NOT NULL.
ALTER TABLE tree_heads
    ALTER COLUMN smt_root DROP DEFAULT;
