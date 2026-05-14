/*
FILE PATH:

	admission/evidence_chain_verifier.go

DESCRIPTION:

	PR-F gate 4 — surgical evidence-chain walk.

	verifier.VerifyEvidenceChain (SDK) is a generic depth-first
	walker over an entry's EvidencePointers DAG. Calling it on
	EVERY admitted entry would be the wrong cost shape: the ledger
	admits 100-150 entries/sec; most have zero or shallow evidence
	chains; per-entry chain walks would either (a) saturate the
	entry-fetcher with reads or (b) silently degrade SLA. The walk
	belongs at admission ONLY when the entry's structure declares
	the chain is load-bearing for its admission decision.

	The "surgical" predicate (ShouldWalkEvidenceChain) gates the
	walk to two cases today:

	  1. Path C entries (AuthorityPath == AuthorityScopeAuthority).
	     A scope-authority entry's whole point is that its signer
	     is in the scope's Authority_Set; the chain from the entry
	     back through the authority snapshot is the structural
	     proof, and admission MUST verify the chain shape (no
	     cycles, no broken hops, depth bounded) before letting the
	     entry into the log.

	  2. Future: policy-declared DelegationOriginDID constraints.
	     When a schema policy (PR-E) requires a specific delegation
	     origin, the chain walk validates the origin chain exists.
	     Wired in when the policy resolver lands; today the
	     predicate's second arm is a documented placeholder.

	Default flag OFF (LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE).
	Even when enabled, the surgical predicate keeps the cost shape
	bounded — entries that don't qualify simply skip the walk.

KEY ARCHITECTURAL DECISIONS:

  - The predicate (ShouldWalkEvidenceChain) is exported so test
    code and operator tooling can inspect it. Pure function of
    the entry's header — no I/O, no allocations beyond the input.

  - The walk uses AbortOnError=true. At admission, the FIRST
    structural rejection (cycle, broken hop, unbounded depth)
    is sufficient grounds to reject the entry. The full per-hop
    walk is meaningful for offline auditing, not admission.

  - MaxDepth defaults to verifier.DefaultMaxEvidenceChainDepth
    (1000). Tighter caps could be set per-deployment via env;
    deferred until production data shows the typical depth.

  - The walker's structural sentinels (ErrChainCycle,
    ErrMaxDepthExceeded, ErrHopFetchFailed, ErrHopDeserialize,
    ErrRootFetchFailed, ErrNilFetcher) are already enrolled in
    admission/error_mapping.go so api/submission.go's MapSDKError
    branch routes them automatically.
*/
package admission

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// ShouldWalkEvidenceChain reports whether the surgical predicate
// is true for entry. Today the predicate fires on Path C
// (scope-authority) entries. Future work extends it to entries
// whose resolved policy declares a DelegationOriginDID
// constraint.
//
// nil entry: false (defensive). Path A / Path B / commentary
// entries return false.
func ShouldWalkEvidenceChain(entry *envelope.Entry) bool {
	if entry == nil {
		return false
	}
	if entry.Header.AuthorityPath == nil {
		return false
	}
	if *entry.Header.AuthorityPath == envelope.AuthorityScopeAuthority {
		return true
	}
	return false
}

// VerifyEvidenceChainSurgical implements PR-F gate 4. See package
// docstring for the surgical-walk rationale.
//
// Three-arm dispatch:
//   - ShouldWalkEvidenceChain(entry) == false → no-op
//   - fetcher == nil                         → programmer error
//   - else                                   → SDK walker with
//                                              AbortOnError
//
// The walker's structural sentinels propagate to the caller via
// errors.Is; admission/error_mapping.go enrols each one for HTTP
// routing.
//
// Performance: the walker fetches at most MaxDepth entries before
// terminating; depth is bounded by verifier.DefaultMaxEvidenceChainDepth.
// At admission, AbortOnError=true so the typical reject case
// stops at the first broken hop — a small constant.
func VerifyEvidenceChainSurgical(
	ctx context.Context,
	entry *envelope.Entry,
	logDID string,
	fetcher types.EntryFetcher,
) (*verifier.EvidenceChainReport, error) {
	if entry == nil {
		return nil, fmt.Errorf("admission: VerifyEvidenceChainSurgical called with nil entry")
	}
	if !ShouldWalkEvidenceChain(entry) {
		return nil, nil
	}
	if fetcher == nil {
		return nil, fmt.Errorf("admission: VerifyEvidenceChainSurgical called with nil fetcher for surgical entry")
	}

	// The surgical walk's root is the entry's ScopePointer (Path
	// C entries reference the governing scope; the chain runs
	// from the entry back through the scope's authority snapshot
	// to the genesis authority entry). For entries without a
	// ScopePointer the predicate cannot fire — this is the
	// belt-and-braces guard.
	if entry.Header.ScopePointer == nil {
		return nil, fmt.Errorf("admission: Path C entry without ScopePointer")
	}
	root := *entry.Header.ScopePointer
	if root.LogDID != logDID {
		// Cross-log scope pointer — defer to async reconciliation
		// per decision #6 (the same shape as PR-D's foreign-log
		// CosignatureOf branch). Returning nil here lets the
		// entry through; the async pipeline reconciles.
		return nil, nil
	}

	report, err := verifier.VerifyEvidenceChain(ctx, root, fetcher, verifier.WalkParams{
		AbortOnError: true,
	})
	if err != nil {
		// Envelope-level failure (nil fetcher caught above; root
		// fetch failure surfaces ErrRootFetchFailed). Propagate
		// as-is; the SDK sentinels are enrolled in error_mapping.go.
		return report, err
	}
	if report.HasErrors() {
		// AbortOnError=true populates the FIRST failed hop's Err
		// in the report. Propagate that Err to the caller so
		// MapSDKError routes it.
		for i := range report.Hops {
			if hopErr := report.Hops[i].Err; hopErr != nil {
				return report, hopErr
			}
		}
	}
	return report, nil
}
