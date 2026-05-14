-- FILE PATH: store/migrations/0008_delegate_did.sql
--
-- Adds the delegate_did column to entry_index for PR-J: the
-- ledger-backed delegation.EntrySource adapter that the SDK's
-- attestation policy verifier (v1.4+ Stage 6, v1.5
-- AdmissionEnforced) walks during constraint evaluation
-- (DelegationOriginDID / RequiredScopes).
--
-- # WHAT
--
-- entry_index.delegate_did TEXT — the on-log delegate DID this
-- entry establishes a delegation for. Mirrors the existing
-- target_root / cosignature_of / schema_ref projection: extracted
-- by the sequencer at insert time from
-- ControlHeader.DelegateDID (envelope-level field), nullable on
-- non-delegation entries.
--
-- idx_delegate_did_latest — partial compound index on
-- (delegate_did, sequence_number DESC) WHERE delegate_did IS NOT
-- NULL. Supports the dominant query "the LATEST on-log
-- delegation for this DID" in a single index seek (the DESC half
-- collapses the lookup to one row without a sort). The partial
-- predicate keeps the index size proportional to delegation
-- entries, not the entire log.
--
-- # COMPATIBILITY
--
-- Additive. Pre-migration rows have delegate_did=NULL. The
-- sequencer's INSERT site bumped in the same release populates
-- the column on new rows; historical rows can be backfilled by
-- the rebuild-projection tool if needed (not required for the
-- delegation gate — historical delegations are uncommon, and the
-- gate fail-opens when the lookup returns ErrUnknownDelegate per
-- delegation.EntrySource's documented contract).

ALTER TABLE entry_index
    ADD COLUMN IF NOT EXISTS delegate_did TEXT;

CREATE INDEX IF NOT EXISTS idx_delegate_did_latest
    ON entry_index (delegate_did, sequence_number DESC)
    WHERE delegate_did IS NOT NULL;
