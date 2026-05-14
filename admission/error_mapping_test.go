/*
FILE PATH:

	admission/error_mapping_test.go

DESCRIPTION:

	Pin two load-bearing properties of the SDK-sentinel mapping table:

	1. EVERY sentinel listed in sdkErrorTable maps to a non-zero
	   HTTPStatus and a non-Unknown ErrorClass. A row that maps to
	   ErrorClassUnknown defeats the dashboard wiring; a row with
	   HTTPStatus=0 produces a malformed HTTP response. Both are
	   regressions worth failing CI on.

	2. errors.Is matches CORRECTLY through wrap chains so the
	   handler can call MapSDKError on a fmt.Errorf("%w", ...)
	   and still get the right mapping. This is the property that
	   lets every admission-time call site wrap freely (for
	   diagnostic context) without breaking the table.

	A third property — that the table COVERS every sentinel any of
	the gates surfaces — is enforced by the per-gate verifier tests
	in PR-C/D/E/F (each gate must round-trip its own sentinels
	through MapSDKError as part of acceptance).
*/
package admission

import (
	"errors"
	"fmt"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/ledger/apitypes"
)

func TestSDKErrorTable_NoZeroFields(t *testing.T) {
	t.Parallel()

	for i, m := range SDKErrorTable() {
		if m.Sentinel == nil {
			t.Errorf("row %d: nil Sentinel", i)
		}
		if m.HTTPStatus == 0 {
			t.Errorf("row %d (%v): HTTPStatus=0; would produce malformed HTTP response", i, m.Sentinel)
		}
		if m.Class == apitypes.ErrorClassUnknown {
			t.Errorf("row %d (%v): Class=Unknown; defeats dashboard wiring", i, m.Sentinel)
		}
	}
}

func TestMapSDKError_NilReturnsMissNotPanic(t *testing.T) {
	t.Parallel()

	matched, status, class := MapSDKError(nil)
	if matched {
		t.Error("MapSDKError(nil) returned matched=true; expected miss")
	}
	if status != 0 || class != apitypes.ErrorClassUnknown {
		t.Errorf("MapSDKError(nil) returned (status=%d, class=%v); expected (0, Unknown)", status, class)
	}
}

func TestMapSDKError_UnknownErrorReturnsMiss(t *testing.T) {
	t.Parallel()

	bogus := errors.New("not enrolled in the table")
	matched, _, _ := MapSDKError(bogus)
	if matched {
		t.Error("MapSDKError matched an error not in the table")
	}
}

func TestMapSDKError_MatchesEachEnrolledSentinelDirectly(t *testing.T) {
	t.Parallel()

	// Every row of the table MUST be reachable via direct match —
	// otherwise the row is dead code.
	for i, m := range SDKErrorTable() {
		matched, status, class := MapSDKError(m.Sentinel)
		if !matched {
			t.Errorf("row %d (%v): direct match failed", i, m.Sentinel)
			continue
		}
		if status != m.HTTPStatus {
			t.Errorf("row %d: status=%d, want %d", i, status, m.HTTPStatus)
		}
		if class != m.Class {
			t.Errorf("row %d: class=%v, want %v", i, class, m.Class)
		}
	}
}

func TestMapSDKError_MatchesThroughWrapChain(t *testing.T) {
	t.Parallel()

	// The handler wraps SDK errors with fmt.Errorf("%w: ctx", err)
	// for diagnostic richness. The table MUST still match through
	// the wrap. This pins the contract that callers can wrap freely.
	cases := []struct {
		name     string
		raw      error
		wantStat int
		wantCls  apitypes.ErrorClass
	}{
		{
			name:     "gate1 ErrEmptySignatures",
			raw:      attestation.ErrEmptySignatures,
			wantStat: 401,
			wantCls:  apitypes.ErrorClassSignatureInvalid,
		},
		{
			name:     "gate2 ErrBindingMismatch",
			raw:      attestation.ErrBindingMismatch,
			wantStat: 422,
			wantCls:  apitypes.ErrorClassCosignatureBindingMismatch,
		},
		{
			name:     "gate3 ErrAttestationPolicyNotMet",
			raw:      attestation.ErrAttestationPolicyNotMet,
			wantStat: 422,
			wantCls:  apitypes.ErrorClassAttestationPolicyNotMet,
		},
		{
			name:     "gate4 ErrChainCycle",
			raw:      verifier.ErrChainCycle,
			wantStat: 422,
			wantCls:  apitypes.ErrorClassEvidenceChainBroken,
		},
		{
			name:     "gate4 ErrRootFetchFailed (fetcher fault → 500)",
			raw:      verifier.ErrRootFetchFailed,
			wantStat: 500,
			wantCls:  apitypes.ErrorClassEvidenceChainUnavailable,
		},
		{
			name:     "ledger sentinel ErrSignatureInvalid",
			raw:      ErrSignatureInvalid,
			wantStat: 401,
			wantCls:  apitypes.ErrorClassSignatureInvalid,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Single wrap.
			wrapped1 := fmt.Errorf("admission context: %w", tc.raw)
			matched, status, class := MapSDKError(wrapped1)
			if !matched || status != tc.wantStat || class != tc.wantCls {
				t.Errorf("single-wrap: matched=%v status=%d class=%v; want (true, %d, %v)",
					matched, status, class, tc.wantStat, tc.wantCls)
			}

			// Double wrap (handler → submission helper → caller).
			wrapped2 := fmt.Errorf("submission: %w", wrapped1)
			matched, status, class = MapSDKError(wrapped2)
			if !matched || status != tc.wantStat || class != tc.wantCls {
				t.Errorf("double-wrap: matched=%v status=%d class=%v; want (true, %d, %v)",
					matched, status, class, tc.wantStat, tc.wantCls)
			}
		})
	}
}

func TestSDKErrorTable_EveryGateRepresented(t *testing.T) {
	t.Parallel()

	// PR-A's acceptance criterion: the table MUST cover the
	// sentinels that PR-C/D/E/F will surface. Sample one from
	// each gate so a regression that drops the row for an entire
	// gate is caught here, not in the gate's own PR.
	mustBeMapped := []error{
		attestation.ErrEmptySignatures,            // gate 1
		attestation.ErrBindingMismatch,            // gate 2
		attestation.ErrAttestationPolicyNotMet,    // gate 3
		verifier.ErrChainCycle,                    // gate 4 (structural)
		verifier.ErrRootFetchFailed,               // gate 4 (fetcher)
	}

	for _, sentinel := range mustBeMapped {
		matched, _, _ := MapSDKError(sentinel)
		if !matched {
			t.Errorf("gate sentinel %v not enrolled in sdkErrorTable; PR-A acceptance violated", sentinel)
		}
	}
}

func TestSDKErrorTable_DefensiveCopy(t *testing.T) {
	t.Parallel()

	// SDKErrorTable() must return a copy so external mutation
	// cannot poison the production table.
	c1 := SDKErrorTable()
	c1Len := len(c1)
	c1[0].HTTPStatus = 999
	c2 := SDKErrorTable()
	if len(c2) != c1Len {
		t.Errorf("table length changed: got %d, want %d", len(c2), c1Len)
	}
	if c2[0].HTTPStatus == 999 {
		t.Error("external mutation poisoned sdkErrorTable")
	}
}
