/*
FILE PATH:

	admission/policy_verifier.go

DESCRIPTION:

	PR-E gate 3 — schema-declared attestation-policy enforcement.

	Self-gating semantics:

	  - entry.Header.AttestationPolicyName == nil → no-op
	  - PolicyResolver returns "no policy declared" → no-op
	  - PolicyResolver returns a policy → call
	    attestation.VerifyEntryAttestationPolicy and reject on
	    ErrAttestationPolicyNotMet (when policy.Required=true)

	The "self-gating" property is load-bearing for the rollout:
	schemas without AttestationPolicies are unaffected; schemas
	with policies + entries that don't reference them are
	unaffected. The gate fires only when BOTH halves opt in. This
	lets the code land in production (#75 plan) BEFORE the
	judicial-network starts emitting AttestationPolicyName values
	on its decision entries — value lights up automatically when
	the consumer side starts emitting.

	Default flag OFF (LEDGER_ADMISSION_POLICY_ENABLE) — even with
	the gate code merged, no policy is enforced unless an operator
	explicitly opts in.

KEY ARCHITECTURAL DECISIONS:

  - PolicyContext is a single interface bundling the four
    dependencies the SDK verifier needs: PolicyResolver,
    CandidateFetcher, attestation.SignatureVerifier,
    attestation.DelegationResolver. Bundling avoids a five-arg
    function signature and lets production wire one composite
    object.

  - PolicyResolver returns (Policy, []EntryWithMetadata, ok, err).
    Returning the candidates alongside the policy lets the
    resolver own the lookup strategy (schema → policies → search
    log for cosignature entries → candidates). Admission stays
    the dispatcher, not the strategist.

  - A nil PolicyContext or any nil sub-dependency makes
    VerifyEntryPolicy a no-op. Production deployments that haven't
    wired the resolver yet keep the gate effectively off; the
    feature flag is the *intent* to gate, the resolver is the
    *capability*.

  - The function returns the SDK's (PolicyReport, error) shape
    untouched so admission tests can assert against the exact
    structured report (which attestor failed which constraint).
*/
package admission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

// PolicyResolver answers, for an entry being admitted: does this
// entry's schema declare an attestation policy this entry adopts,
// is that policy marked AdmissionEnforced=true, and if so, what
// primary + candidates does the SDK's policy verifier need?
//
// Returns (policy, primary, candidates, true, nil) when ALL of:
//
//   - entry references a policy via Header.AttestationPolicyName
//   - the schema (resolved via Header.SchemaRef) declares that
//     policy by name
//   - policy.AdmissionEnforced == true (the v1.5 self-gate)
//   - the resolver can materialise the primary entry the
//     candidates cosign (typically the entry at
//     Header.TargetRoot) and its candidate set
//
// Returns (Policy{}, EntryWithMetadata{}, nil, false, nil) when
// the gate is a no-op for any of these reasons. Returns
// (..., err) on transport / parse failure (route to 500).
//
// PRIMARY MODEL: at admission, the entry being admitted does NOT
// have a Position yet. The SDK verifier matches candidates'
// CosignatureOf against primary.Position, so the "primary" the
// resolver returns is the entry at Header.TargetRoot — the
// pre-existing position the candidates bind to. The entry being
// admitted is the CLOSURE on the target (e.g., the Dean's
// delegation that ratifies a Board-cosigned proposal); admission
// gate 3 asks "is the target's policy now met?"
type PolicyResolver interface {
	ResolvePolicy(
		ctx context.Context,
		entry *envelope.Entry,
	) (policy attestation.Policy, primary types.EntryWithMetadata, candidates []types.EntryWithMetadata, found bool, err error)
}

// PolicyContext bundles the four dependencies the policy gate
// needs. Each field may be nil; nil any of them turns the gate
// into a no-op (fail-open). Production wires all four; tests wire
// stubs.
type PolicyContext struct {
	Resolver           PolicyResolver
	SigVerifier        attestation.SignatureVerifier
	DelegationResolver attestation.DelegationResolver
	// Logger is optional; nil falls back to slog.Default()
	// inside the SDK verifier.
	Logger any // for forward-compat; today the SDK uses its own internal slog
}

// VerifyEntryPolicy implements PR-E gate 3. See package docstring
// for self-gating semantics.
//
// nil entry: programmer-error sentinel.
// nil ctx fields: no-op (fail-open). Production opts INTO the gate
//   by wiring all four dependencies.
//
// On reject: returns (report, ErrAttestationPolicyNotMet) — same
// (PolicyReport, error) shape the SDK verifier returns. The
// existing admission/error_mapping.go enrolls every relevant
// SDK sentinel; api/submission.go's branch routes through the
// shared MapSDKError switch.
func VerifyEntryPolicy(
	ctx context.Context,
	entry *envelope.Entry,
	logTime time.Time,
	policyCtx *PolicyContext,
) (*attestation.PolicyReport, error) {
	if entry == nil {
		return nil, fmt.Errorf("admission: VerifyEntryPolicy called with nil entry")
	}
	// Fail-open on missing dependencies. The feature flag turns
	// the gate code path on; the dependency wiring turns the
	// capability on. Both must be present for the gate to fire.
	if policyCtx == nil || policyCtx.Resolver == nil {
		return nil, nil
	}
	if entry.Header.AttestationPolicyName == nil {
		// Entry does not adopt a policy → gate is no-op (one
		// of the two self-gating halves).
		return nil, nil
	}

	policy, primary, candidates, found, err := policyCtx.Resolver.ResolvePolicy(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("admission: policy resolution failed: %w", err)
	}
	if !found {
		// Self-gate misses: the entry doesn't adopt a policy,
		// the schema doesn't declare the named policy, the
		// policy is read-time only (AdmissionEnforced=false),
		// or the resolver couldn't materialise the primary.
		// Defer enforcement to read-time consumers.
		return nil, nil
	}

	_ = logTime // primary.LogTime is the load-bearing time field;
	// `logTime` (the entry-being-admitted's wall-clock) is no
	// longer used in the primary's metadata. Kept in the function
	// signature for forward-compat (future PR may surface entry-
	// being-admitted's timestamp through the report).

	// Required guards: the SDK verifier needs a non-nil
	// SigVerifier. DelegationResolver is needed only when the
	// policy's constraint requires a chain walk; we always pass
	// what we have and let the SDK validate.
	if policyCtx.SigVerifier == nil {
		return nil, fmt.Errorf("admission: PolicyContext.SigVerifier nil but resolver returned policy %q", policy.Name)
	}

	report, err := attestation.VerifyEntryAttestationPolicy(
		ctx, primary, policy, candidates,
		policyCtx.SigVerifier, policyCtx.DelegationResolver,
	)
	if err != nil {
		// Wrap with the named policy for diagnostic context.
		// errors.Is preserves match against ErrAttestationPolicyNotMet
		// + the constraint sentinels enrolled in error_mapping.go.
		if errors.Is(err, attestation.ErrAttestationPolicyNotMet) {
			return report, fmt.Errorf("admission: policy %q not met: %w", policy.Name, err)
		}
		return report, fmt.Errorf("admission: policy %q verification failed: %w", policy.Name, err)
	}
	return report, nil
}
