/*
FILE PATH:

	admission/nfc_check.go

DESCRIPTION:

	Defensive NFC normalization assertion at the ledger's trust
	boundary. The SDK's caller-normalizes contract (Decision 52)
	places NFC normalization at the caller boundary; the ledger
	asserts the caller honored that contract and rejects mismatches.

	The ledger never normalizes on the caller's behalf. Silent
	normalization at admission would diverge the bytes the caller
	signed over from the bytes the ledger stored, breaking the
	canonical-hash invariant downstream consumers depend on.

KEY ARCHITECTURAL DECISIONS:

  - Defensive only. CheckNFC is a structural assertion, not a
    transformation. If `norm.NFC.String(s) != s`, the entry is
    rejected; the ledger does not rewrite `s`.
  - All DID-shaped header fields covered: SignerDID, Destination,
    DelegateDID (when non-nil), and every key in AuthoritySet.
    These are the four places where Unicode normalization mismatches
    can produce divergent SplitIDs or scope-membership lookups
    downstream.
  - Empty strings pass through. envelope.Entry.Validate() catches
    empty-DID violations; this stage's job is normalization
    discipline, not non-emptiness.

KEY DEPENDENCIES:

  - golang.org/x/text/unicode/norm: NFC normalization primitive.
  - github.com/clearcompass-ai/attesta/core/envelope: Entry,
    ControlHeader (read-only).
*/
package admission

import (
	"errors"
	"fmt"

	"golang.org/x/text/unicode/norm"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// ErrIngressNotNFC is returned by CheckNFC when a DID-shaped header
// field is not in NFC normalization form. The error message names
// the offending field so the caller can locate the input that
// needs normalization upstream.
//
// HTTP mapping: 422 Unprocessable Entity. The submission is
// structurally well-formed but violates the caller-normalizes
// contract.
var ErrIngressNotNFC = errors.New("admission: header field not in NFC normalization form")

// CheckNFC asserts NFC form on every DID-shaped field in the entry's
// control header. Returns ErrIngressNotNFC (wrapped with the offending
// field name) on the first mismatch.
//
// Fields checked:
//   - SignerDID (always required by Validate, so always non-empty here)
//   - Destination (always required by Validate)
//   - DelegateDID (only when non-nil — present only on delegation entries)
//   - AuthoritySet keys (only when non-empty — scope creation/amendment)
//
// Empty strings are skipped: envelope.Entry.Validate() handles
// non-emptiness; this function handles normalization discipline.
func CheckNFC(entry *envelope.Entry) error {
	if entry == nil {
		return fmt.Errorf("admission: CheckNFC called with nil entry")
	}
	h := &entry.Header

	if err := assertNFC("SignerDID", h.SignerDID); err != nil {
		return err
	}
	if err := assertNFC("Destination", h.Destination); err != nil {
		return err
	}
	if h.DelegateDID != nil {
		if err := assertNFC("DelegateDID", *h.DelegateDID); err != nil {
			return err
		}
	}
	for did := range h.AuthoritySet {
		if err := assertNFC("AuthoritySet", did); err != nil {
			return err
		}
	}
	return nil
}

// assertNFC returns ErrIngressNotNFC wrapped with the field name when
// `s` is non-empty and not equal to its NFC-normalized form. Empty
// strings are accepted because non-emptiness is policed elsewhere
// (envelope.Entry.Validate, scope-membership rules).
func assertNFC(field, s string) error {
	if s == "" {
		return nil
	}
	if norm.NFC.String(s) != s {
		return fmt.Errorf("%w: field %q", ErrIngressNotNFC, field)
	}
	return nil
}
