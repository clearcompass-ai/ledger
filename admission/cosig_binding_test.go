/*
FILE PATH:

	admission/cosig_binding_test.go

DESCRIPTION:

	Binding tests for PR-D gate 2 — admission.VerifyCosignatureBinding.

	Pins the load-bearing property: an entry asserting it cosigns
	a position on OUR log MUST point at a real, sequenced entry.
	Today (gate OFF) such entries pass admission; gate ON closes
	the structural gap.

	Cross-log positions are explicitly NOT validated at admission
	per decision #6 ("hard no on cross-log admission blocking" —
	defer to async reconciliation). Pinned here so a regression that
	starts blocking on peer fetches surfaces in CI.
*/
package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

const testLogDID = "did:web:bench.log"

// stubFetcher implements TargetEntryFetcher with a configured
// outcome. Used to pin gate behavior across the (found / not-found
// / error) result space.
type stubFetcher struct {
	found bool
	hash  [32]byte
	logT  time.Time
	ghost bool
	err   error
	calls int
}

func (s *stubFetcher) FetchHashBySeq(_ context.Context, _ uint64) ([32]byte, time.Time, bool, bool, error) {
	s.calls++
	return s.hash, s.logT, s.ghost, s.found, s.err
}

func cosigEntry(pos *types.LogPosition) *envelope.Entry {
	return &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:      "did:web:cosigner",
		Destination:    testLogDID,
		CosignatureOf:  pos,
	}}
}

func TestVerifyCosignatureBinding_NilEntryRejects(t *testing.T) {
	t.Parallel()

	err := VerifyCosignatureBinding(context.Background(), nil, testLogDID, &stubFetcher{})
	if err == nil {
		t.Error("nil entry accepted")
	}
}

func TestVerifyCosignatureBinding_NonAttestationEntryNoop(t *testing.T) {
	t.Parallel()

	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:     "did:web:alice",
		Destination:   testLogDID,
		CosignatureOf: nil, // not an attestation
	}}
	fetcher := &stubFetcher{}
	if err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, fetcher); err != nil {
		t.Errorf("non-attestation entry rejected: %v", err)
	}
	if fetcher.calls != 0 {
		t.Errorf("fetcher called %d times for non-attestation entry; want 0", fetcher.calls)
	}
}

func TestVerifyCosignatureBinding_LocalPosFoundAccepts(t *testing.T) {
	t.Parallel()

	pos := types.LogPosition{LogDID: testLogDID, Sequence: 42}
	entry := cosigEntry(&pos)
	fetcher := &stubFetcher{found: true}
	if err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, fetcher); err != nil {
		t.Errorf("valid binding rejected: %v", err)
	}
	if fetcher.calls != 1 {
		t.Errorf("fetcher called %d times; want 1", fetcher.calls)
	}
}

func TestVerifyCosignatureBinding_LocalPosNotFoundRejects(t *testing.T) {
	t.Parallel()

	// The load-bearing property: entry asserting CosignatureOf on
	// OUR log MUST resolve to a real sequenced entry.
	pos := types.LogPosition{LogDID: testLogDID, Sequence: 99999}
	entry := cosigEntry(&pos)
	fetcher := &stubFetcher{found: false}
	err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, fetcher)
	if !errors.Is(err, ErrCosignatureTargetNotFound) {
		t.Errorf("err=%v, want ErrCosignatureTargetNotFound", err)
	}
}

func TestVerifyCosignatureBinding_LocalPosFetchErrorSurfaces(t *testing.T) {
	t.Parallel()

	pos := types.LogPosition{LogDID: testLogDID, Sequence: 7}
	entry := cosigEntry(&pos)
	fetchErr := errors.New("transient db unreachable")
	fetcher := &stubFetcher{err: fetchErr}
	err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, fetcher)
	if !errors.Is(err, fetchErr) {
		t.Errorf("err=%v, want wrapping of %v", err, fetchErr)
	}
}

func TestVerifyCosignatureBinding_ForeignPosNoop_DeferredToAsync(t *testing.T) {
	t.Parallel()

	// Decision #6: cross-log peer attestations DO NOT block at
	// admission. Liveness regression at 100-150 admit/s if we
	// blocked on peer-ledger fetches. The async reconciliation
	// pipeline (KindCrossLogInclusion) handles it instead.
	//
	// This test pins that property: foreign-log CosignatureOf
	// passes admission WITHOUT consulting the local fetcher.
	pos := types.LogPosition{LogDID: "did:web:peer-log", Sequence: 1}
	entry := cosigEntry(&pos)
	fetcher := &stubFetcher{found: false}
	if err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, fetcher); err != nil {
		t.Errorf("foreign-log attestation rejected at admission; decision #6 violated: %v", err)
	}
	if fetcher.calls != 0 {
		t.Errorf("local fetcher called %d times for foreign-log attestation; want 0", fetcher.calls)
	}
}

func TestVerifyCosignatureBinding_NilFetcherForLocalPosRejects(t *testing.T) {
	t.Parallel()

	// Programmer error: production wiring MUST supply a fetcher
	// when the gate is enabled. Fail-closed rather than rubber-
	// stamping the binding.
	pos := types.LogPosition{LogDID: testLogDID, Sequence: 1}
	entry := cosigEntry(&pos)
	err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, nil)
	if err == nil {
		t.Error("nil fetcher accepted; want programmer-error rejection")
	}
}

func TestVerifyCosignatureBinding_NilFetcherForForeignPosOK(t *testing.T) {
	t.Parallel()

	// Foreign-log entries DO NOT consult the fetcher, so a nil
	// fetcher is fine for them. Pinning this property keeps the
	// gate cheap for deployments that don't wire the fetcher at
	// all (test fixtures).
	pos := types.LogPosition{LogDID: "did:web:peer-log", Sequence: 1}
	entry := cosigEntry(&pos)
	if err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, nil); err != nil {
		t.Errorf("foreign-log + nil fetcher rejected: %v", err)
	}
}

func TestVerifyCosignatureBinding_RejectsRouteThroughErrorMapping(t *testing.T) {
	t.Parallel()

	// PR-A acceptance: every gate's sentinels MUST round-trip
	// through MapSDKError.
	pos := types.LogPosition{LogDID: testLogDID, Sequence: 1}
	entry := cosigEntry(&pos)
	err := VerifyCosignatureBinding(context.Background(), entry, testLogDID, &stubFetcher{found: false})
	if err == nil {
		t.Fatal("expected ErrCosignatureTargetNotFound, got nil")
	}
	matched, status, _ := MapSDKError(err)
	if !matched {
		t.Error("MapSDKError did not match ErrCosignatureTargetNotFound; wiring violated")
	}
	if status != 422 {
		t.Errorf("status=%d, want 422", status)
	}
}
