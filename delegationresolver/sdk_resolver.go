/*
FILE PATH:

	delegationresolver/sdk_resolver.go

DESCRIPTION:

	Construction shim that wires a delegation.Resolver around a
	delegation.EntrySource (typically *Cached, the LRU wrapper
	from cache.go, which itself wraps *LedgerEntrySource from
	ledger_source.go).

	*delegation.Resolver already satisfies
	attestation.DelegationResolver via its ResolveChain method —
	no adapter type needed. This file exists to:

	  - Centralise the construction shape so ledger boot code
	    doesn't have to assemble delegation.NewResolver(...) by
	    hand at every wire site.
	  - Apply the ledger's default WithMaxDepth (mirrors the
	    SDK's verifier/evidence-chain default for consistency).
	  - Provide a compile-time assertion that the resulting
	    *delegation.Resolver satisfies the
	    attestation.DelegationResolver interface — drifts surface
	    at build time.
*/
package delegationresolver

import (
	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/delegation"
)

// DefaultMaxDelegationChainDepth bounds the chain walker against
// pathological / malicious chains. Mirrors
// verifier.DefaultMaxEvidenceChainDepth (1000) so the depth
// budget is uniform across the verifier surfaces. Operators
// override per-deployment via the Resolver's WithMaxDepth Option
// at construction time.
const DefaultMaxDelegationChainDepth = 1000

// NewSDKResolver wraps source in a *delegation.Resolver bounded
// by DefaultMaxDelegationChainDepth. The returned value
// structurally satisfies attestation.DelegationResolver — pass
// directly to attestation.VerifyEntryAttestationPolicy /
// verifier.VerifyComplete Stage 6's PolicyStageParams.
//
// source may be *Cached (production hot-path), the bare
// *LedgerEntrySource (when caching is undesirable, e.g., audit
// tools), or any custom delegation.EntrySource (test fakes).
//
// nil source panics — production wiring MUST supply a backing
// source.
func NewSDKResolver(source delegation.EntrySource) *delegation.Resolver {
	if source == nil {
		panic("delegationresolver: NewSDKResolver: nil source")
	}
	return delegation.NewResolver(source,
		delegation.WithMaxDepth(DefaultMaxDelegationChainDepth),
	)
}

// Compile-time assertion: *delegation.Resolver satisfies
// attestation.DelegationResolver. A drift in either side
// surfaces here at build time.
var _ attestation.DelegationResolver = (*delegation.Resolver)(nil)
