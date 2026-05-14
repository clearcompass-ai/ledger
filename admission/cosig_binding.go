/*
FILE PATH:

	admission/cosig_binding.go

DESCRIPTION:

	PR-D gate 2 — CosignatureOf binding check.

	Today an entry can submit Header.CosignatureOf pointing at any
	log position whatsoever and admission accepts it. Downstream
	consumers (judicial-network, schema readers) MAY route through
	attestation.IsAttestation when they evaluate the entry, but the
	ledger itself takes no position on whether the binding target
	actually exists.

	VerifyCosignatureBinding closes the on-log half of that gap:

	  - CosignatureOf nil           → no-op (entry is not an attestation)
	  - CosignatureOf.LogDID == ours → target sequence MUST exist
	  - CosignatureOf.LogDID foreign → no-op at admission; cross-log
	                                    verification is the job of the
	                                    async reconciliation pipeline
	                                    (KindCrossLogInclusion); see
	                                    decision #6 in issue #75 for
	                                    why admission DOES NOT block on
	                                    peer-log fetches (liveness
	                                    regression at 100-150 admit/s).

	Default flag OFF (LEDGER_ADMISSION_COSIG_BINDING_ENABLE) per the
	canary discipline from PR-A. Multi-sig (PR-C) closes a silent
	cryptographic gap; this gate closes a silent structural gap.
	Both are well-tested locally; both want one canary cycle on the
	SLA dashboard before becoming the default.

KEY ARCHITECTURAL DECISIONS:

  - The function routes the canonical SDK predicate
    attestation.IsAttestation(entry, *entry.Header.CosignatureOf)
    EVEN THOUGH the result is tautologically true (the position
    being checked IS the entry's own CosignatureOf). The call
    documents the intent (this is the attestation-binding gate)
    and stays compatible with the SDK's cmd/lint-binding AST
    linter, which whitelists IsAttestation as the canonical home
    of CosignatureOf checks.

  - TargetEntryFetcher is a single-method interface, narrower than
    the existing api.EntryStore so the admission package depends
    only on the smallest surface it needs (interface segregation).
    *store.EntryStore satisfies it structurally via FetchHashBySeq;
    test code wires a stub.
*/
package admission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
)

// ErrCosignatureTargetNotFound is surfaced when an entry asserts
// it cosigns a position on THIS log that no sequenced entry
// occupies. Today this is the high-value catch: an attacker
// attaching CosignatureOf to a non-existent position is now
// rejected at admission rather than passing silently.
var ErrCosignatureTargetNotFound = errors.New("admission: CosignatureOf target does not exist on this log")

// ErrCosignatureBindingMismatch is surfaced when attestation.IsAttestation
// returns false — the entry's CosignatureOf does not match the
// target position the gate evaluated. Today this is structurally
// impossible (the position checked IS the entry's own CosignatureOf)
// but documenting the sentinel lets future PRs extend the gate
// (e.g., binding against an external expectedPos from a calling
// workflow) without introducing a new error class.
var ErrCosignatureBindingMismatch = errors.New("admission: CosignatureOf binding mismatch")

// TargetEntryFetcher is the minimal interface admission needs to
// confirm that a sequence number on THIS log resolves to a
// sequenced entry. *store.EntryStore satisfies it via
// FetchHashBySeq; test code wires stubs.
//
// The return values:
//   - found=true: an entry exists at seq (canonical_hash is the
//     entry's hash; not used by the binding gate itself).
//   - found=false: no row at seq.
//   - err non-nil: transport / decode failure (route to 500).
//
// The simplification (no isGhost flag, no logTime) keeps the
// interface narrow — admission cares only "did this seq sequence?"
type TargetEntryFetcher interface {
	FetchHashBySeq(ctx context.Context, seq uint64) (hash [32]byte, logTime time.Time, isGhost bool, found bool, err error)
}

// VerifyCosignatureBinding implements PR-D gate 2. See package
// docstring for behavior. The function is a no-op when the entry
// is not an attestation (CosignatureOf nil) or when the target
// position is on a foreign log.
//
// Parameters:
//   - entry: the candidate envelope arriving at admission. Must
//            be non-nil.
//   - logDID: the ledger's own LogDID (SubmissionDeps.LogDID).
//             Used to distinguish local vs. foreign positions.
//   - fetcher: a TargetEntryFetcher. May be nil for tests in
//              degraded modes — when nil and CosignatureOf is
//              local, the function fails-closed with a programmer-
//              error sentinel rather than rubber-stamping the
//              binding.
//
// Returns nil on success. Returns wrapped sentinels on failure;
// each is enrolled in admission/error_mapping.go for HTTP routing.
func VerifyCosignatureBinding(
	ctx context.Context,
	entry *envelope.Entry,
	logDID string,
	fetcher TargetEntryFetcher,
) error {
	if entry == nil {
		return fmt.Errorf("admission: VerifyCosignatureBinding called with nil entry")
	}
	if entry.Header.CosignatureOf == nil {
		// Not an attestation entry — gate 2 is a no-op.
		return nil
	}
	pos := *entry.Header.CosignatureOf

	if pos.LogDID != logDID {
		// Cross-log: defer to async reconciliation per decision
		// #6 (hard no on cross-log admission blocking). Returning
		// nil here lets the entry through; downstream pipelines
		// (KindCrossLogInclusion machinery) reconcile it
		// asynchronously.
		return nil
	}

	if fetcher == nil {
		return fmt.Errorf(
			"admission: VerifyCosignatureBinding called with nil fetcher for local CosignatureOf=%s",
			pos.String())
	}
	_, _, _, found, err := fetcher.FetchHashBySeq(ctx, pos.Sequence)
	if err != nil {
		return fmt.Errorf("admission: target fetch failed: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: %s", ErrCosignatureTargetNotFound, pos.String())
	}

	// Tautologically true here (we pass the entry's own
	// CosignatureOf), but the call documents the binding and
	// keeps cmd/lint-binding happy: every consumer of
	// CosignatureOf routes through IsAttestation.
	if !attestation.IsAttestation(entry, pos) {
		return fmt.Errorf("%w: pos=%s", ErrCosignatureBindingMismatch, pos.String())
	}
	return nil
}
