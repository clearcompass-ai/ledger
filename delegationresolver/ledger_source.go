/*
FILE PATH:

	delegationresolver/ledger_source.go

DESCRIPTION:

	Concrete delegation.EntrySource backed by the ledger's
	entry_index projection (idx_delegate_did_latest, migration
	0008). Wraps a DelegationFetcher (typed shim around
	*store.PostgresEntryFetcher) and a domain extractor that
	parses the on-log entry's payload into the SDK's
	delegation.DelegationEntry shape.

	Together with delegationresolver.Cached (PR-B), this is the
	full ledger-side substrate the SDK's policy verifier needs
	for constraint evaluation (DelegationOriginDID /
	RequiredScopes per attestation.Constraint).

	Usage (production wire path):

	    fetcher := store.NewPostgresEntryFetcher(pool, byteReader, logDID)
	    src := delegationresolver.NewLedgerEntrySource(fetcher, scopeExtractor)
	    cached, _ := delegationresolver.NewCached(src, capacity, metrics)
	    sdkResolver := delegationresolver.NewSDKResolver(cached)
	    // sdkResolver satisfies attestation.DelegationResolver

KEY ARCHITECTURAL DECISIONS:

  - DelegationFetcher is a narrow interface (one method,
    FetchLatestDelegationByDID). *store.PostgresEntryFetcher
    satisfies it structurally. Lets the package depend on the
    minimum surface and stay testable with fakes.

  - ScopeExtractor lifts the DOMAIN-DECLARED scope set out of
    the on-log delegation entry's payload. The SDK does NOT
    parse domain payloads; the ledger DOES NOT understand domain
    semantics either — so the extractor is supplied by the
    consumer (e.g., judicial-network passes its scope-parser; the
    ortholog-artifact-store passes a different one). Empty
    extractor result (or nil extractor) yields Scopes=nil; the
    SDK treats nil Scopes as "no scope filter" — same as the
    InMemorySource default.

  - Revocation: a successor delegation entry on the log
    supersedes prior ones at admission time. The fetcher returns
    the newest live row. An explicit revocation entry (when the
    domain ships one) is admitted as a successor entry with
    Live=false in its payload — the extractor reads that into
    the DelegationEntry, and the SDK's constraint evaluator
    treats Live=false as ErrConstraintChainRevoked.
*/
package delegationresolver

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/delegation"
	"github.com/clearcompass-ai/attesta/types"
)

// DelegationFetcher is the narrow store-side surface
// LedgerEntrySource depends on. *store.PostgresEntryFetcher
// satisfies it structurally via its FetchLatestDelegationByDID
// method.
//
// Returns (nil, nil) when no live delegation exists for the DID;
// (entry, nil) on hit; (nil, err) on transport / parse failure.
type DelegationFetcher interface {
	FetchLatestDelegationByDID(ctx context.Context, delegateDID string) (*types.EntryWithMetadata, error)
}

// ScopeExtractor lifts the domain-declared scope set + liveness
// flag out of an admitted delegation entry's payload. The SDK
// does not parse domain payloads; consumers supply this.
//
// Returns (scopes, live, nil) on success. A nil ScopeExtractor
// (or nil function return) yields Scopes=nil + Live=true, which
// the SDK treats as "no scope filter, currently active".
//
// extractor.Extract MUST NOT mutate `entry`.
type ScopeExtractor interface {
	Extract(entry *envelope.Entry) (scopes []string, live bool, err error)
}

// NoOpScopeExtractor is a ScopeExtractor that always returns
// (nil, true, nil). Used by callers that don't yet ship a domain
// parser: the resolved delegation carries no scope filter and is
// always treated as live. Equivalent to InMemorySource's defaults.
type NoOpScopeExtractor struct{}

// Extract implements ScopeExtractor.
func (NoOpScopeExtractor) Extract(*envelope.Entry) ([]string, bool, error) {
	return nil, true, nil
}

// LedgerEntrySource implements delegation.EntrySource against
// the ledger's entry_index projection.
type LedgerEntrySource struct {
	Fetcher   DelegationFetcher
	Extractor ScopeExtractor
}

// NewLedgerEntrySource constructs a source against fetcher and
// extractor. nil fetcher panics (programming error — production
// wiring MUST supply one). nil extractor falls back to the
// no-op extractor.
func NewLedgerEntrySource(fetcher DelegationFetcher, extractor ScopeExtractor) *LedgerEntrySource {
	if fetcher == nil {
		panic("delegationresolver: NewLedgerEntrySource: nil fetcher")
	}
	if extractor == nil {
		extractor = NoOpScopeExtractor{}
	}
	return &LedgerEntrySource{Fetcher: fetcher, Extractor: extractor}
}

// DelegationOf implements delegation.EntrySource. Looks up the
// latest live on-log delegation entry for delegateDID, parses out
// the delegate / delegator / scopes / liveness fields, and
// returns the SDK's DelegationEntry shape.
//
// Returns attestation.ErrUnknownDelegate when no on-log
// delegation exists (the SDK's signal for "chain reached its
// root; stop walking").
func (s *LedgerEntrySource) DelegationOf(
	ctx context.Context,
	delegateDID string,
) (delegation.DelegationEntry, error) {
	if delegateDID == "" {
		return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
	}
	meta, err := s.Fetcher.FetchLatestDelegationByDID(ctx, delegateDID)
	if err != nil {
		return delegation.DelegationEntry{},
			fmt.Errorf("delegationresolver: ledger fetch %q: %w", delegateDID, err)
	}
	if meta == nil {
		return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
	}

	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return delegation.DelegationEntry{},
			fmt.Errorf("delegationresolver: deserialize delegation entry for %q at %v: %w",
				delegateDID, meta.Position, err)
	}
	if entry.Header.DelegateDID == nil || *entry.Header.DelegateDID != delegateDID {
		// Index-vs-payload mismatch: the projection said this
		// entry's DelegateDID matched, but the canonical bytes
		// say otherwise. This is a CORRUPTION signal, not a
		// silent skip — surface as an error so ops see the
		// projection drift.
		return delegation.DelegationEntry{}, fmt.Errorf(
			"delegationresolver: projection drift at %v: index says delegate=%q, entry payload says %v",
			meta.Position, delegateDID, entry.Header.DelegateDID)
	}

	scopes, live, err := s.Extractor.Extract(entry)
	if err != nil {
		return delegation.DelegationEntry{}, fmt.Errorf(
			"delegationresolver: scope extract for %q at %v: %w",
			delegateDID, meta.Position, err)
	}

	return delegation.DelegationEntry{
		DelegateDID:  delegateDID,
		DelegatorDID: entry.Header.SignerDID,
		Scopes:       scopes,
		Live:         live,
	}, nil
}
