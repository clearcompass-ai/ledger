/*
FILE PATH:

	admission/feature_flags.go

DESCRIPTION:

	Per-gate feature flags for the SDK uniform-verify rollout
	(issue #75). Each new admission gate added in PR-C through PR-F
	is guarded by exactly one boolean here, populated from one
	environment variable. All flags default OFF — the foundations
	land first (PR-A), each gate flips on individually after canary
	telemetry confirms it doesn't regress the SLA pinned by the
	bench harness.

WHY ONE-FLAG-PER-GATE:

	Composite kill-switches force "all on / all off" decisions.
	Independent flags let ops respond to a per-gate regression by
	flipping that gate alone — the other gates stay armed, the
	rollback surface is minimal, and the dashboard signal that
	triggered the rollback stays attributable.

ENVIRONMENT VARIABLES (all default false; case-insensitive
"true"/"1"/"yes"/"on" enables):

  - LEDGER_ADMISSION_MULTISIG_ENABLE       — PR-C gate 1
  - LEDGER_ADMISSION_COSIG_BINDING_ENABLE  — PR-D gate 2
  - LEDGER_ADMISSION_POLICY_ENABLE         — PR-E gate 3
  - LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE — PR-F gate 4

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
	// verified, not only Signatures[0]. Default OFF until canary
	// telemetry on the PR-A SLA dashboard confirms no regression.
	MultiSig bool

	// CosigBinding enables PR-D: when entry.Header.CosignatureOf
	// is non-nil, look up the target locally and call
	// attestation.IsAttestation to confirm the binding before
	// admission. Default OFF.
	CosigBinding bool

	// Policy enables PR-E: when the entry's schema declares
	// AttestationPolicies AND the entry references one by name,
	// call attestation.VerifyEntryAttestationPolicy. Self-gating
	// — schemas without policies are unaffected. Default OFF
	// (explicit opt-in during rollout).
	Policy bool

	// EvidenceChain enables PR-F: surgical
	// verifier.VerifyEvidenceChain walk for Path C / scope-authority
	// entries OR policies declaring DelegationOriginDID. NOT a
	// universal walk on every admission. Default OFF.
	EvidenceChain bool
}

// envFlag returns true when the environment variable contains a
// recognized truthy value. Case-insensitive. "true", "1", "yes",
// "on" are accepted; everything else (including empty/unset) is
// false. Centralized here so all four gates use identical parsing.
func envFlag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// LoadGatesFromEnv reads the four LEDGER_ADMISSION_*_ENABLE
// environment variables and returns the populated Gates struct.
// Called once at boot from cmd/ledger/boot/wire and threaded
// through SubmissionDeps; never re-read at request time.
func LoadGatesFromEnv() Gates {
	return Gates{
		MultiSig:      envFlag("LEDGER_ADMISSION_MULTISIG_ENABLE"),
		CosigBinding:  envFlag("LEDGER_ADMISSION_COSIG_BINDING_ENABLE"),
		Policy:        envFlag("LEDGER_ADMISSION_POLICY_ENABLE"),
		EvidenceChain: envFlag("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE"),
	}
}
