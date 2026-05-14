/*
FILE PATH:

	admission/ledger_policy_resolver.go

DESCRIPTION:

	PR-I — concrete admission.PolicyResolver that consumes the v1.5
	AttestationPolicy.AdmissionEnforced field to gate Stage 6 at
	admission. The resolver walks the schema-on-log projection
	(Header.SchemaRef → SchemaParameters → FindAttestationPolicy),
	respects the policy's evaluation-point declaration, and
	materialises the primary + candidates the SDK's policy
	verifier consumes.

# Wiring shape

	registry := schemareg.BuildLedgerSchemaRegistry()
	fetcher  := store.NewPostgresEntryFetcher(pool, byteReader, logDID)
	candidateFetcher := fetcher // satisfies CandidateFetcher via FetchByCosignatureOf

	resolver := admission.NewLedgerPolicyResolver(admission.LedgerPolicyResolverConfig{
	    Schemas:    registry,
	    Fetcher:    fetcher,
	    Candidates: candidateFetcher,
	})

	deps.PolicyContext = &admission.PolicyContext{
	    Resolver:           resolver,
	    SigVerifier:        sigVerifierAdapter,
	    DelegationResolver: delegationResolverAdapter,
	}

# Self-gate semantics (the load-bearing property)

	The resolver returns found=true ONLY when ALL of the following
	are true:

	  1. entry.Header.SchemaRef        != nil
	  2. entry.Header.AttestationPolicyName != nil
	  3. The schema entry resolves cleanly via Fetcher.Fetch +
	     SchemaParameters extraction.
	  4. The named policy exists on the schema
	     (SchemaParameters.FindAttestationPolicy).
	  5. policy.AdmissionEnforced == true (v1.5 schema-declared
	     evaluation point).
	  6. entry.Header.TargetRoot      != nil AND points at a
	     position on THIS log. The primary the SDK verifier
	     evaluates is the entry at TargetRoot — the pre-existing
	     position the candidates' CosignatureOf bind to.

	Any miss returns found=false, letting VerifyEntryPolicy fall
	through to a no-op (admission accepts; read-time consumers
	enforce).

# Why TargetRoot as the primary anchor

	At admission, the entry being admitted has no Position (not
	yet sequenced). The SDK's VerifyCollection matches candidates'
	CosignatureOf against primary.Position. The ONLY position the
	resolver can supply that is BOTH known and meaningfully
	anchored to the candidates is the entry's TargetRoot —
	the on-log entity the entry being admitted is CLOSING ON.

	For the canonical atomic-policy use case (Board cosignature on
	a Dean delegation): a delegation-proposal entry is admitted
	first (gets position P_proposal); Board members cosign it
	(cosignatures bind to P_proposal); the Dean's final delegation
	entry references P_proposal via TargetRoot; admission at the
	final entry runs the policy verifier against
	(primary=proposal_entry_at_P_proposal, candidates=Board_cosignatures).

# What's deferred

	- Cross-log TargetRoot. If TargetRoot.LogDID != logDID, the
	  resolver returns found=false. Cross-log policy verification
	  is the multi-network shim's responsibility (each network
	  builds its own projection per the matrix-of-consumers
	  design).
	- Constraint walks. The SDK's policy verifier may call back
	  into a DelegationResolver for DelegationOriginDID /
	  RequiredScopes constraints. The DelegationResolver is wired
	  separately on the PolicyContext (PR-J's
	  delegationresolver.NewSDKResolver).
*/
package admission

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
)

// EntryFetcher fetches an entry by LogPosition. Narrower than
// types.EntryFetcher (this admission package doesn't need the
// full SDK interface) — *store.PostgresEntryFetcher satisfies
// both shapes.
type EntryFetcher interface {
	Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// CandidateFetcher materialises the SDK's expected candidate
// shape ([]EntryWithMetadata) from the on-log cosignature index.
// *store.PostgresEntryFetcher satisfies it via
// FetchByCosignatureOf.
type CandidateFetcher interface {
	FetchByCosignatureOf(ctx context.Context, primary types.LogPosition) ([]types.EntryWithMetadata, error)
}

// SchemaParametersExtractor resolves an entry-schema reference
// into its declared SchemaParameters (v1.3+ on-log governance
// shape that carries AttestationPolicies). *schema.Registry from
// the SDK satisfies this.
type SchemaParametersExtractor interface {
	ExtractParameters(id sdkschema.SchemaID, schemaEntry *envelope.Entry) (*types.SchemaParameters, error)
}

// LedgerPolicyResolverConfig bundles the three dependencies the
// resolver needs. All required; nil values panic in
// NewLedgerPolicyResolver.
type LedgerPolicyResolverConfig struct {
	Fetcher    EntryFetcher
	Candidates CandidateFetcher
	Schemas    SchemaParametersExtractor
	// LogDID is THIS ledger's LogDID. Used to short-circuit
	// cross-log TargetRoot anchors (we cannot enforce a policy
	// at admission against a foreign log's entry).
	LogDID string
}

// LedgerPolicyResolver implements PolicyResolver against the
// ledger's storage + schema registry. Returns the v1.5
// AdmissionEnforced gate's decision.
type LedgerPolicyResolver struct {
	cfg LedgerPolicyResolverConfig
}

// NewLedgerPolicyResolver constructs the resolver. Panics on
// any nil dependency or empty LogDID — production wiring MUST
// supply all four.
func NewLedgerPolicyResolver(cfg LedgerPolicyResolverConfig) *LedgerPolicyResolver {
	switch {
	case cfg.Fetcher == nil:
		panic("admission: NewLedgerPolicyResolver: nil Fetcher")
	case cfg.Candidates == nil:
		panic("admission: NewLedgerPolicyResolver: nil Candidates")
	case cfg.Schemas == nil:
		panic("admission: NewLedgerPolicyResolver: nil Schemas")
	case cfg.LogDID == "":
		panic("admission: NewLedgerPolicyResolver: empty LogDID")
	}
	return &LedgerPolicyResolver{cfg: cfg}
}

// resolverSchemaPeek is the same minimum-fields shape
// entry_schema_verifier.go uses to extract a SchemaID from a
// schema entry's DomainPayload.
type resolverSchemaPeek struct {
	SchemaID string `json:"schema_id"`
}

// ResolvePolicy implements PolicyResolver. See file docstring
// for the six conditions the self-gate evaluates.
func (r *LedgerPolicyResolver) ResolvePolicy(
	ctx context.Context,
	entry *envelope.Entry,
) (attestation.Policy, types.EntryWithMetadata, []types.EntryWithMetadata, bool, error) {
	if entry == nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: LedgerPolicyResolver: nil entry")
	}

	// (1) + (2) entry self-declares a policy by name + schema ref
	if entry.Header.SchemaRef == nil || entry.Header.AttestationPolicyName == nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}

	// (3) resolve the schema entry on-log
	schemaMeta, err := r.cfg.Fetcher.Fetch(ctx, *entry.Header.SchemaRef)
	if err != nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: schema fetch at %v: %w", *entry.Header.SchemaRef, err)
	}
	if schemaMeta == nil {
		// Schema not on THIS log (or foreign-log SchemaRef). Defer
		// to read-time; admission cannot run the gate without the
		// schema parameters.
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}
	schemaEntry, err := envelope.Deserialize(schemaMeta.CanonicalBytes)
	if err != nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: schema deserialize at %v: %w", *entry.Header.SchemaRef, err)
	}
	// Extract the schema's SchemaID from its DomainPayload
	// (mirrors the existing entry_schema_verifier.go peek).
	var peek resolverSchemaPeek
	if len(schemaEntry.DomainPayload) == 0 {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}
	if err := json.Unmarshal(schemaEntry.DomainPayload, &peek); err != nil {
		// Schema entry isn't a JSON commitment schema we recognise.
		// Defer to read-time.
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}
	if peek.SchemaID == "" {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}
	params, err := r.cfg.Schemas.ExtractParameters(sdkschema.SchemaID(peek.SchemaID), schemaEntry)
	if err != nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: ExtractParameters %q: %w", peek.SchemaID, err)
	}
	if params == nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}

	// (4) policy declared by name
	policy, ok := params.FindAttestationPolicy(*entry.Header.AttestationPolicyName)
	if !ok {
		// Schema doesn't declare the named policy. Defer to
		// read-time (consumer-side may reject independently; the
		// ledger's job is structural admission only).
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}

	// (5) v1.5 AdmissionEnforced self-gate. The load-bearing
	// branch: if the schema author declared this policy as
	// read-time-only, admission is a no-op even though every
	// other arm matched. Use the SDK's IsAtomic() helper
	// (v1.5+) — semantic alias for AdmissionEnforced=true.
	if !policy.IsAtomic() {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}

	// (6) primary anchor + candidates
	if entry.Header.TargetRoot == nil {
		// AdmissionEnforced policy on an entry with no TargetRoot:
		// we cannot anchor the policy verifier without a position
		// the candidates bind to. Defer to read-time.
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}
	if entry.Header.TargetRoot.LogDID != r.cfg.LogDID {
		// Cross-log primary; the multi-network shim handles it.
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false, nil
	}
	primaryMeta, err := r.cfg.Fetcher.Fetch(ctx, *entry.Header.TargetRoot)
	if err != nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: primary fetch at %v: %w", *entry.Header.TargetRoot, err)
	}
	if primaryMeta == nil {
		// The TargetRoot doesn't resolve. This is a structural
		// problem — the entry references a position that doesn't
		// exist on the log. Bubble up as an error so admission
		// surfaces it via MapSDKError (the verifier wraps with
		// ErrAttestationPolicyNotMet downstream when the chain
		// breaks).
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: TargetRoot %v not found on log %q",
				*entry.Header.TargetRoot, r.cfg.LogDID)
	}

	candidates, err := r.cfg.Candidates.FetchByCosignatureOf(ctx, *entry.Header.TargetRoot)
	if err != nil {
		return attestation.Policy{}, types.EntryWithMetadata{}, nil, false,
			fmt.Errorf("admission: candidate fetch: %w", err)
	}

	return policy, *primaryMeta, candidates, true, nil
}
