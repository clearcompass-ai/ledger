// FILE PATH: sequencer/ghost_event_validate_test.go
//
// Unit tests for sequencer.GhostLeafEvent.Validate.
//
// The local Validate mirrors the SDK constructor's invariants
// (attesta/gossip/findings/ghost_leaf.go::Validate, v0.5.0).
// Defense-in-depth: the committer ALWAYS populates every field
// correctly today, but a future refactor that drops a field
// would surface as an SDK-side rejection deep in cosign.Sign —
// the local Validate catches the misuse one stack frame off the
// committer call site so the failure is attributable.
//
// Sentinel pinning: tests use errors.Is against the four
// exported-as-values sentinels (errGhostLeafEventEmptyLogDID,
// etc.) — this is the same shape the emitter's failure-mode
// logging will eventually filter on for dimensional metrics.
package sequencer

import (
	"errors"
	"strings"
	"testing"
)

// validEvent returns a populated GhostLeafEvent whose every field
// satisfies the Validate invariants. Tests mutate one field at a
// time off this baseline to exercise individual rejection paths.
func validEvent() GhostLeafEvent {
	return GhostLeafEvent{
		GhostSeq:           16,
		CanonicalSeq:       8,
		CanonicalHash:      [32]byte{0xab, 0xcd, 0xef},
		LogDID:             "did:example:ledger",
		ObservedAtUnixNano: 1_700_000_000_000_000_000,
	}
}

func TestGhostLeafEvent_Validate_HappyPath(t *testing.T) {
	ev := validEvent()
	if err := ev.Validate(); err != nil {
		t.Fatalf("happy-path Validate() = %v, want nil", err)
	}
}

func TestGhostLeafEvent_Validate_EmptyLogDID(t *testing.T) {
	ev := validEvent()
	ev.LogDID = ""
	err := ev.Validate()
	if err == nil {
		t.Fatal("empty LogDID must be rejected")
	}
	if !errors.Is(err, errGhostLeafEventEmptyLogDID) {
		t.Errorf("error = %v, want errGhostLeafEventEmptyLogDID", err)
	}
	// Sentinel message must contain "log_did" so log greps work.
	if !strings.Contains(err.Error(), "log_did") {
		t.Errorf("error message = %q, want substring 'log_did'", err.Error())
	}
}

func TestGhostLeafEvent_Validate_ZeroHash(t *testing.T) {
	ev := validEvent()
	ev.CanonicalHash = [32]byte{}
	err := ev.Validate()
	if err == nil {
		t.Fatal("zero CanonicalHash must be rejected")
	}
	if !errors.Is(err, errGhostLeafEventZeroHash) {
		t.Errorf("error = %v, want errGhostLeafEventZeroHash", err)
	}
}

func TestGhostLeafEvent_Validate_SeqOrderEqual(t *testing.T) {
	ev := validEvent()
	ev.GhostSeq = ev.CanonicalSeq // equal — not strictly greater
	err := ev.Validate()
	if err == nil {
		t.Fatal("ghost_seq == canonical_seq must be rejected (must be strictly greater)")
	}
	if !errors.Is(err, errGhostLeafEventSeqOrder) {
		t.Errorf("error = %v, want errGhostLeafEventSeqOrder", err)
	}
}

func TestGhostLeafEvent_Validate_SeqOrderInverted(t *testing.T) {
	ev := validEvent()
	ev.GhostSeq, ev.CanonicalSeq = 8, 16 // ghost predates canonical
	err := ev.Validate()
	if err == nil {
		t.Fatal("ghost_seq < canonical_seq must be rejected (Tessera monotonic)")
	}
	if !errors.Is(err, errGhostLeafEventSeqOrder) {
		t.Errorf("error = %v, want errGhostLeafEventSeqOrder", err)
	}
}

func TestGhostLeafEvent_Validate_ZeroObservedAt(t *testing.T) {
	ev := validEvent()
	ev.ObservedAtUnixNano = 0
	err := ev.Validate()
	if err == nil {
		t.Fatal("ObservedAtUnixNano=0 must be rejected (uninitialized sentinel)")
	}
	if !errors.Is(err, errGhostLeafEventZeroObservedAt) {
		t.Errorf("error = %v, want errGhostLeafEventZeroObservedAt", err)
	}
}

// TestGhostLeafEvent_Validate_MatchesSDKContract pins the
// invariants in the same order the SDK enforces (attesta v0.5.0
// gossip/findings/ghost_leaf.go:Validate). If the SDK's order
// changes, both sides should evolve together — the test serves
// as the audit hint.
func TestGhostLeafEvent_Validate_MatchesSDKContract(t *testing.T) {
	// First invariant — log_did.
	ev := GhostLeafEvent{
		// All other fields zero too; Validate must trip on
		// log_did FIRST (matches SDK).
	}
	err := ev.Validate()
	if !errors.Is(err, errGhostLeafEventEmptyLogDID) {
		t.Errorf("with all-zero event, want first failure on log_did, got %v", err)
	}
}
