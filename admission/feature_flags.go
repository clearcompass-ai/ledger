/*
FILE PATH:

	admission/feature_flags.go

DESCRIPTION:

	Per-gate feature flags for the SDK uniform-verify rollout
	(issue #75). Each admission gate is guarded by exactly one
	boolean here, populated from one environment variable.

	Defaults reflect the ledger's role as the structural-correctness
	trust boundary:

	  - Gates 1 (multi-sig) and 2 (CosignatureOf binding) default
	    ON. They close silent admission gaps every downstream
	    consumer (judicial-network, witnesses, monitors) benefits
	    from. The ledger is the enforcement point; consumers
	    inherit the protection.

	  - Gates 3 (schema policy) and 4 (surgical evidence-chain
	    walk) default OFF. Both depend on production wiring
	    (PolicyContext resolver, EntryFetcher) that lands as a
	    follow-up; flipping ON before wiring is harmless (gates
	    fail-open on missing capability) but the env var stays the
	    explicit opt-in for ops clarity.

	Operators flip any gate OFF for a canary cycle by setting the
	corresponding env var to "false" (or "0" / "no" / "off"). The
	var is the override knob, not a master-enable switch.

WHY ONE-FLAG-PER-GATE:

	Composite kill-switches force "all on / all off" decisions.
	Independent flags let ops respond to a per-gate regression by
	flipping that gate alone — the other gates stay armed, the
	rollback surface is minimal, and the dashboard signal that
	triggered the rollback stays attributable.

ENVIRONMENT VARIABLES (override the per-gate default; case-
insensitive "true"/"1"/"yes"/"on" enables, "false"/"0"/"no"/"off"
disables; unset means "use the default"):

  - LEDGER_ADMISSION_MULTISIG_ENABLE       — PR-C gate 1 (default ON)
  - LEDGER_ADMISSION_COSIG_BINDING_ENABLE  — PR-D gate 2 (default ON)
  - LEDGER_ADMISSION_POLICY_ENABLE         — PR-E gate 3 (default OFF)
  - LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE — PR-F gate 4 (default OFF)

USAGE:

	gates := admission.LoadGatesFromEnv()
	if gates.MultiSig {
	    // PR-C: attestation.VerifyEntrySignatures path
	} else {
	    // legacy single-sig path (signatures.VerifyEntry)
	}

	The Gates struct is also constructible by tests
	(admission.Gates{MultiSig: true}) without env munging.
*/
package admission

import (
	"os"
	"strings"
)

// Gates groups the four per-gate booleans that the admission path
// consults at request time. Pass by value; the struct is small and
// immutable after construction.
type Gates struct {
	// MultiSig enables PR-C: replace signatures.VerifyEntry with
	// attestation.VerifyEntrySignatures so every Signatures[i] is
	// verified, not only Signatures[0]. Default ON — closes the
	// silent multi-sig gap at the ledger trust boundary. Override
	// to false via LEDGER_ADMISSION_MULTISIG_ENABLE=false for a
	// canary disable.
	MultiSig bool

	// CosigBinding enables PR-D: when entry.Header.CosignatureOf
	// is non-nil, look up the target locally and call
	// attestation.IsAttestation to confirm the binding before
	// admission. Default ON — closes the silent "CosignatureOf =
	// random position" gap at the ledger trust boundary.
	CosigBinding bool

	// Policy enables PR-E: when the entry's schema declares
	// AttestationPolicies AND the entry references one by name,
	// call attestation.VerifyEntryAttestationPolicy. Self-gating
	// — schemas without policies are unaffected. Default OFF
	// (depends on PolicyContext wiring that lands as a follow-up;
	// fail-open until wired).
	Policy bool

	// EvidenceChain enables PR-F: surgical
	// verifier.VerifyEvidenceChain walk for Path C / scope-authority
	// entries OR policies declaring DelegationOriginDID. NOT a
	// universal walk on every admission. Default OFF (depends on
	// EvidenceChainFetcher wiring; fail-open until wired).
	EvidenceChain bool
}

// envFlagWithDefault returns the truthy/falsy interpretation of
// name's env value, falling back to def when unset. Case-
// insensitive. Recognised truthy: "true"/"1"/"yes"/"on". Recognised
// falsy: "false"/"0"/"no"/"off". Unrecognised non-empty values
// fall back to def (operator clearly meant SOMETHING but didn't
// match the vocabulary — preserve the default rather than guess).
//
// Centralised here so all four gates use identical parsing.
func envFlagWithDefault(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// LoadGatesFromEnv reads the four LEDGER_ADMISSION_*_ENABLE
// environment variables and returns the populated Gates struct
// with per-gate defaults applied for unset variables. Called once
// at boot from cmd/ledger/boot/wire and threaded through
// SubmissionDeps; never re-read at request time.
func LoadGatesFromEnv() Gates {
	return Gates{
		MultiSig:      envFlagWithDefault("LEDGER_ADMISSION_MULTISIG_ENABLE", true),
		CosigBinding:  envFlagWithDefault("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", true),
		Policy:        envFlagWithDefault("LEDGER_ADMISSION_POLICY_ENABLE", false),
		EvidenceChain: envFlagWithDefault("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", false),
	}
}
