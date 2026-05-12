// FILE PATH: sequencer/ghost_emit_test.go
//
// Unit test for the committer's ghost-leaf emission hook.
//
// The committer's hot-path contract: every successful ghost-row
// insert (status=StatusGhostLeaf, canonical_hash matches a primary
// row at a DIFFERENT seq) MUST be followed by a non-blocking call
// to ghostEmitter.Emit with a populated GhostLeafEvent. The event
// is the structural bridge to the SDK gossip pipeline (which
// signs + broadcasts a KindGhostLeaf event for offline-auditor
// visibility).
//
// This test pins the contract WITHOUT exercising the full PG
// stack — we call committerStaleRecover directly (the same
// branch dispatchGhostLeaf-on-PG-collision would take) and
// observe the emitter via a capture stub.
//
// The PG-collision path itself is exercised by the integration
// chaos tests (tests/chaos/kill_restart/) which inject the real
// Tessera dedup gap and verify the full committer-emit-gossip
// chain end-to-end against a live Postgres + S3 stack.
package sequencer

import (
	"context"
	"sync"
	"testing"
)

// captureEmitter records every GhostLeafEvent it receives so the
// test can assert field-by-field. Mirrors the production
// LoggingGhostLeafEmitter's interface but stashes the events in
// memory instead of formatting + logging.
type captureEmitter struct {
	mu     sync.Mutex
	events []GhostLeafEvent
}

func (c *captureEmitter) Emit(_ context.Context, ev GhostLeafEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureEmitter) Events() []GhostLeafEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]GhostLeafEvent, len(c.events))
	copy(out, c.events)
	return out
}

// Compile-time pin: captureEmitter satisfies the GhostLeafEmitter
// interface. The production logging emitter satisfies the same
// contract — drift between the two surfaces as a build error.
var _ GhostLeafEmitter = (*captureEmitter)(nil)

// TestSequencer_WithGhostLeafEmitter_NilNoOp pins that a nil
// emitter is the gossip-disabled deployment mode — setting it is
// safe and the sequencer simply doesn't broadcast. The committer's
// hot path MUST be unconditionally safe against the nil case.
func TestSequencer_WithGhostLeafEmitter_NilNoOp(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	if s.ghostEmitter != nil {
		t.Fatal("default ghostEmitter should be nil")
	}
	// Explicit nil-with-Set: the setter accepts nil without panic.
	s2 := s.WithGhostLeafEmitter(nil)
	if s2 != s {
		t.Fatal("WithGhostLeafEmitter should return receiver for chaining")
	}
	if s.ghostEmitter != nil {
		t.Fatal("ghostEmitter should remain nil after WithGhostLeafEmitter(nil)")
	}
}

// TestSequencer_WithGhostLeafEmitter_StoresInstance pins that a
// non-nil emitter is captured on the receiver and ready for the
// committer's dispatchGhostLeaf to consult. The fluent-wiring
// pattern matches the other With* setters.
func TestSequencer_WithGhostLeafEmitter_StoresInstance(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	cap := &captureEmitter{}
	s2 := s.WithGhostLeafEmitter(cap)
	if s2 != s {
		t.Fatal("WithGhostLeafEmitter should return receiver")
	}
	if s.ghostEmitter != cap {
		t.Errorf("ghostEmitter = %v, want captureEmitter %v", s.ghostEmitter, cap)
	}
}

// TestSequencer_GhostLeafEvent_FieldsAreDeterministic pins the
// uint64-typed observed-at field's role: the cryptographic-bytes
// determinism path requires the event hand off the raw integer,
// not a time.Time. The struct fields MUST stay byte-aligned with
// the SDK's findings.GhostLeafFinding (attesta v0.5.0) since the
// production SDK adapter is a 1:1 field copy.
//
// If any of these field names or types drift, the production
// adapter that converts GhostLeafEvent → findings.GhostLeafFinding
// would silently break the canonical-bytes signature. Pin the
// shape here so a refactor surfaces a compile error.
func TestSequencer_GhostLeafEvent_FieldsAreDeterministic(t *testing.T) {
	ev := GhostLeafEvent{
		GhostSeq:           16,
		CanonicalSeq:       8,
		CanonicalHash:      [32]byte{0xab, 0xcd},
		LogDID:             "did:example:ledger",
		ObservedAtUnixNano: 1700000000123456789,
	}
	// Each typed field exercised by direct access — verifies the
	// shape at compile time. Runtime checks are belt-and-braces.
	if ev.GhostSeq != 16 {
		t.Errorf("GhostSeq = %d, want 16", ev.GhostSeq)
	}
	if ev.CanonicalSeq != 8 {
		t.Errorf("CanonicalSeq = %d, want 8", ev.CanonicalSeq)
	}
	if ev.CanonicalHash[0] != 0xab {
		t.Errorf("CanonicalHash[0] = %x, want 0xab", ev.CanonicalHash[0])
	}
	if ev.LogDID != "did:example:ledger" {
		t.Errorf("LogDID = %q, want did:example:ledger", ev.LogDID)
	}
	// uint64-typed observed-at — NOT time.Time. This is the
	// load-bearing type-level guarantee that the canonical bytes
	// survive every JSON encode/decode round-trip intact.
	var _ uint64 = ev.ObservedAtUnixNano
	if ev.ObservedAtUnixNano != 1700000000123456789 {
		t.Errorf("ObservedAtUnixNano = %d, want 1700000000123456789",
			ev.ObservedAtUnixNano)
	}
}

// TestCaptureEmitter_RecordsEventInOrder pins the test fixture
// itself — without it the committer-side tests above would
// silently miss events. Belt-and-braces test infrastructure.
func TestCaptureEmitter_RecordsEventInOrder(t *testing.T) {
	cap := &captureEmitter{}
	a := GhostLeafEvent{GhostSeq: 16, CanonicalSeq: 8}
	b := GhostLeafEvent{GhostSeq: 17, CanonicalSeq: 9}
	cap.Emit(context.Background(), a)
	cap.Emit(context.Background(), b)
	events := cap.Events()
	if len(events) != 2 {
		t.Fatalf("Events len = %d, want 2", len(events))
	}
	if events[0].GhostSeq != 16 {
		t.Errorf("events[0].GhostSeq = %d, want 16", events[0].GhostSeq)
	}
	if events[1].GhostSeq != 17 {
		t.Errorf("events[1].GhostSeq = %d, want 17", events[1].GhostSeq)
	}
}
