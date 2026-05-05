/*
FILE PATH: apitypes/error_class_test.go

Tests for the typed ErrorClass taxonomy (PT-6 — A10 + P10):

  - Every defined ErrorClass constant has a non-empty, kebab-case
    String() (the OTel attribute value).
  - Distinct constants produce distinct strings (cardinality
    invariant — collisions would silently merge metric series).
  - The zero value (ErrorClassUnknown) emits "unknown" — flags
    a writeError site that didn't pass an explicit class.
  - Out-of-range values emit "unknown" rather than panic.
*/
package apitypes_test

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-operator/apitypes"
)

// allErrorClasses enumerates every ErrorClass constant defined in
// apitypes/apitypes.go. New additions MUST be added here too —
// the cardinality test below depends on this list staying in sync.
var allErrorClasses = []apitypes.ErrorClass{
	apitypes.ErrorClassUnknown,

	apitypes.ErrorClassMalformedBody,
	apitypes.ErrorClassMalformedJSON,
	apitypes.ErrorClassBodyTooLarge,
	apitypes.ErrorClassBadHexEncoding,
	apitypes.ErrorClassBadHexLength,
	apitypes.ErrorClassMissingPathParam,
	apitypes.ErrorClassMissingQueryParam,
	apitypes.ErrorClassInvalidQueryParam,
	apitypes.ErrorClassUnsupportedSchema,
	apitypes.ErrorClassBatchTooLarge,
	apitypes.ErrorClassEmptyBatch,

	apitypes.ErrorClassInsufficientCredits,
	apitypes.ErrorClassDuplicateEntry,
	apitypes.ErrorClassInvalidSession,
	apitypes.ErrorClassExpiredSession,

	apitypes.ErrorClassSignatureInvalid,
	apitypes.ErrorClassEnvelopeRejected,
	apitypes.ErrorClassFreshnessExpired,
	apitypes.ErrorClassDestinationMismatch,
	apitypes.ErrorClassAdmissionProofInvalid,
	apitypes.ErrorClassDifficultyTooLow,

	apitypes.ErrorClassNotFound,

	apitypes.ErrorClassWALBackpressure,
	apitypes.ErrorClassWALPersistFailed,
	apitypes.ErrorClassSCTSigningFailed,
	apitypes.ErrorClassDBQueryFailed,
	apitypes.ErrorClassReadProjectionFailed,
	apitypes.ErrorClassFetcherFailed,
	apitypes.ErrorClassProofGenFailed,
	apitypes.ErrorClassCreditDeductFailed,
	apitypes.ErrorClassEscrowOverrideFailed,
}

func TestErrorClass_StringNonEmpty(t *testing.T) {
	for _, c := range allErrorClasses {
		got := c.String()
		if got == "" {
			t.Errorf("class %d: empty String()", c)
		}
		// Kebab-case attribute value: lowercase ASCII letters,
		// digits, underscores. Distinguishes from CamelCase
		// constants and the wider Prometheus convention.
		for _, r := range got {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
			if !ok {
				t.Errorf("class %d (%q): non-kebab-case rune %q",
					c, got, r)
			}
		}
	}
}

func TestErrorClass_DistinctStrings(t *testing.T) {
	seen := make(map[string]apitypes.ErrorClass, len(allErrorClasses))
	for _, c := range allErrorClasses {
		s := c.String()
		if prior, ok := seen[s]; ok && prior != c {
			t.Errorf("string collision: classes %d and %d both stringify to %q",
				prior, c, s)
		}
		seen[s] = c
	}
	if len(seen) != len(allErrorClasses) {
		t.Errorf("distinct strings = %d, want %d (catalog drift?)",
			len(seen), len(allErrorClasses))
	}
}

func TestErrorClass_UnknownZeroValue(t *testing.T) {
	var zero apitypes.ErrorClass
	if got := zero.String(); got != "unknown" {
		t.Errorf("zero value String() = %q, want %q", got, "unknown")
	}
}

func TestErrorClass_OutOfRangeFallsBackToUnknown(t *testing.T) {
	bogus := apitypes.ErrorClass(9999)
	got := bogus.String()
	if got != "unknown" {
		t.Errorf("out-of-range String() = %q, want %q (no panic, default)",
			got, "unknown")
	}
}

func TestErrorClass_HostileNamesAreDistinct(t *testing.T) {
	// Hostile-flavor classes (the ones SREs alert on) must NOT
	// collide with network-noise classes. This list guards the
	// PT-6 contract: SREs distinguish active attacks from
	// caller bugs without parsing log lines.
	hostile := []apitypes.ErrorClass{
		apitypes.ErrorClassSignatureInvalid,
		apitypes.ErrorClassEnvelopeRejected,
		apitypes.ErrorClassFreshnessExpired,
		apitypes.ErrorClassDestinationMismatch,
		apitypes.ErrorClassAdmissionProofInvalid,
	}
	noise := []apitypes.ErrorClass{
		apitypes.ErrorClassMalformedBody,
		apitypes.ErrorClassMalformedJSON,
		apitypes.ErrorClassBadHexEncoding,
		apitypes.ErrorClassBadHexLength,
		apitypes.ErrorClassMissingPathParam,
		apitypes.ErrorClassMissingQueryParam,
		apitypes.ErrorClassInvalidQueryParam,
	}
	hostileStrs := make(map[string]struct{})
	for _, c := range hostile {
		hostileStrs[c.String()] = struct{}{}
	}
	for _, c := range noise {
		if _, collision := hostileStrs[c.String()]; collision {
			t.Errorf("noise class %d (%q) collides with a hostile class",
				c, c.String())
		}
	}
	// Sanity: hostile names contain hostile-flavor substrings.
	for _, c := range hostile {
		s := c.String()
		hostile5xxKeyword := strings.Contains(s, "invalid") ||
			strings.Contains(s, "rejected") ||
			strings.Contains(s, "expired") ||
			strings.Contains(s, "mismatch")
		if !hostile5xxKeyword {
			t.Errorf("hostile class %q lacks hostile-flavor keyword (review naming)", s)
		}
	}
}
