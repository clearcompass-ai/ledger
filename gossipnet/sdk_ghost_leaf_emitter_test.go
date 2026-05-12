// FILE PATH: gossipnet/sdk_ghost_leaf_emitter_test.go
//
// Unit tests for SDKGossipGhostLeafEmitter — the production
// adapter that signs+appends+broadcasts via attesta SDK v0.5.0.
//
// Test surface covered:
//
//   (1) Constructor — every missing-required-field path returns
//       a non-nil error with the documented prefix.
//
//   (2) Compile-time pin — *SDKGossipGhostLeafEmitter satisfies
//       sequencer.GhostLeafEmitter structurally. Drift surfaces
//       at build time, not in production.
//
//   (3) End-to-end happy path — a valid event lands as a signed
//       SignedEvent in the in-memory GossipStore + flows through
//       the Sink. Snapshot reports Succeeded=1.
//
//   (4) Validate rejection — the local Validate fires before any
//       SDK call. Sink + Store receive zero events.
//
//   (5) Sink failure path — Append succeeds, Broadcast fails;
//       Snapshot reports AppendOnly=1. The local audit record
//       remains; peers catch up via anti-entropy.
//
// Test fixtures use the SDK's reference InMemoryStore + a tiny
// captureSink. The Signer is constructed from a fresh ECDSA key
// (cosign.NewECDSAWitnessSigner) so the signature actually
// verifies — this is end-to-end, not mocked.
package gossipnet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdkdid "github.com/clearcompass-ai/attesta/did"
	sdkgossip "github.com/clearcompass-ai/attesta/gossip"

	"github.com/clearcompass-ai/ledger/sequencer"
)

// Compile-time pin — see file docstring (2).
var _ sequencer.GhostLeafEmitter = (*SDKGossipGhostLeafEmitter)(nil)

// captureSink records every Broadcast call. Optionally fails the
// first N broadcasts to exercise the AppendOnly path. Implements
// sdkgossip.Sink which embeds Closeable — Close is a no-op for
// this in-memory fixture.
type captureSink struct {
	mu         sync.Mutex
	events     []sdkgossip.SignedEvent
	failFirstN int
	failErr    error
}

func (s *captureSink) Broadcast(_ context.Context, ev sdkgossip.SignedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFirstN > 0 {
		s.failFirstN--
		return s.failErr
	}
	s.events = append(s.events, ev)
	return nil
}

func (s *captureSink) Close(_ context.Context) error { return nil }

func (s *captureSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// validEmitterConfig returns a fully-populated config. Tests
// shallow-copy + nil-out one field at a time to exercise the
// missing-field constructor branches.
func validEmitterConfig(t *testing.T) (SDKGossipGhostLeafEmitterConfig, *sdkgossip.InMemoryStore, *captureSink) {
	t.Helper()
	// SDK helper that returns matched (DID, PrivateKey). Using
	// the SDK constructor keeps the originator + the signer
	// consistent — Sign reads the originator's DID and the
	// signer's private key from the same provenance.
	kp, err := sdkdid.GenerateDIDKeyP256()
	if err != nil {
		t.Fatalf("GenerateDIDKeyP256: %v", err)
	}
	store := sdkgossip.NewInMemoryStore()
	sink := &captureSink{}
	cfg := SDKGossipGhostLeafEmitterConfig{
		GossipStore: store,
		Sink:        sink,
		Signer:      cosign.NewECDSAWitnessSigner(kp.PrivateKey),
		NetworkID:   cosign.NetworkID{0xab, 0xcd, 0xef}, // arbitrary non-zero
		Originator:  kp.DID,
		Logger:      nil, // fall back to default
	}
	return cfg, store, sink
}

// validEventForEmitter returns a valid sequencer.GhostLeafEvent
// matching the originator in validEmitterConfig.
func validEventForEmitter(originator string) sequencer.GhostLeafEvent {
	return sequencer.GhostLeafEvent{
		GhostSeq:           16,
		CanonicalSeq:       8,
		CanonicalHash:      [32]byte{0xfe, 0xed, 0xfa, 0xce},
		LogDID:             originator,
		ObservedAtUnixNano: 1_700_000_000_000_000_000,
	}
}

// ─────────────────────────────────────────────────────────────────────
// (1) Constructor — missing required fields
// ─────────────────────────────────────────────────────────────────────

func TestSDKGhostEmitter_Constructor_RejectsMissingStore(t *testing.T) {
	cfg, _, _ := validEmitterConfig(t)
	cfg.GossipStore = nil
	if _, err := NewSDKGossipGhostLeafEmitter(cfg); err == nil ||
		!strings.Contains(err.Error(), "GossipStore") {
		t.Errorf("nil GossipStore: err=%v, want substring 'GossipStore'", err)
	}
}

func TestSDKGhostEmitter_Constructor_RejectsMissingSink(t *testing.T) {
	cfg, _, _ := validEmitterConfig(t)
	cfg.Sink = nil
	if _, err := NewSDKGossipGhostLeafEmitter(cfg); err == nil ||
		!strings.Contains(err.Error(), "Sink") {
		t.Errorf("nil Sink: err=%v, want substring 'Sink'", err)
	}
}

func TestSDKGhostEmitter_Constructor_RejectsMissingSigner(t *testing.T) {
	cfg, _, _ := validEmitterConfig(t)
	cfg.Signer = nil
	if _, err := NewSDKGossipGhostLeafEmitter(cfg); err == nil ||
		!strings.Contains(err.Error(), "Signer") {
		t.Errorf("nil Signer: err=%v, want substring 'Signer'", err)
	}
}

func TestSDKGhostEmitter_Constructor_RejectsZeroNetworkID(t *testing.T) {
	cfg, _, _ := validEmitterConfig(t)
	cfg.NetworkID = cosign.NetworkID{} // zero
	if _, err := NewSDKGossipGhostLeafEmitter(cfg); err == nil ||
		!strings.Contains(err.Error(), "NetworkID") {
		t.Errorf("zero NetworkID: err=%v, want substring 'NetworkID'", err)
	}
}

func TestSDKGhostEmitter_Constructor_RejectsEmptyOriginator(t *testing.T) {
	cfg, _, _ := validEmitterConfig(t)
	cfg.Originator = ""
	if _, err := NewSDKGossipGhostLeafEmitter(cfg); err == nil ||
		!strings.Contains(err.Error(), "Originator") {
		t.Errorf("empty Originator: err=%v, want substring 'Originator'", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (3) Happy path — Sign → Append → Broadcast all succeed
// ─────────────────────────────────────────────────────────────────────

func TestSDKGhostEmitter_HappyPath_AppendsAndBroadcasts(t *testing.T) {
	cfg, store, sink := validEmitterConfig(t)
	e, err := NewSDKGossipGhostLeafEmitter(cfg)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	ev := validEventForEmitter(cfg.Originator)

	e.Emit(context.Background(), ev)

	snap := e.Snapshot()
	if snap.Succeeded != 1 {
		t.Errorf("Snapshot.Succeeded = %d, want 1 (full Sign→Append→Broadcast path); snap=%+v",
			snap.Succeeded, snap)
	}
	if snap.SignFailed != 0 || snap.ValidateFailed != 0 || snap.AppendOnly != 0 {
		t.Errorf("expected no failure counters; got %+v", snap)
	}
	// Sink received the signed event.
	if got := sink.Count(); got != 1 {
		t.Errorf("sink.Count = %d, want 1", got)
	}
	// Store recorded the event — check via the originator's head.
	prev, lamport, herr := store.Head(context.Background(), cfg.Originator)
	if herr != nil {
		t.Fatalf("store.Head: %v", herr)
	}
	var zero [32]byte
	if prev == zero {
		t.Error("store.Head.prev = zero — Append did not land")
	}
	if lamport != 1 {
		t.Errorf("store.Head.lamport = %d, want 1 (first event in chain)", lamport)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (4) Validate rejection — Sink + Store untouched
// ─────────────────────────────────────────────────────────────────────

func TestSDKGhostEmitter_RejectsInvalidEvent(t *testing.T) {
	cfg, store, sink := validEmitterConfig(t)
	e, err := NewSDKGossipGhostLeafEmitter(cfg)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	// Zero ObservedAtUnixNano triggers Validate rejection.
	ev := validEventForEmitter(cfg.Originator)
	ev.ObservedAtUnixNano = 0

	e.Emit(context.Background(), ev)

	snap := e.Snapshot()
	if snap.ValidateFailed != 1 {
		t.Errorf("Snapshot.ValidateFailed = %d, want 1; snap=%+v",
			snap.ValidateFailed, snap)
	}
	if snap.Succeeded != 0 {
		t.Errorf("Snapshot.Succeeded = %d, want 0 (Validate must short-circuit before Sign)",
			snap.Succeeded)
	}
	if got := sink.Count(); got != 0 {
		t.Errorf("sink.Count = %d, want 0 (Validate rejection must not Broadcast)", got)
	}
	// Store head must remain zero — no Append ran.
	_, lamport, herr := store.Head(context.Background(), cfg.Originator)
	if herr != nil {
		t.Fatalf("store.Head: %v", herr)
	}
	if lamport != 0 {
		t.Errorf("store lamport = %d, want 0 (no Append should have fired)", lamport)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (5) Sink-failure path — AppendOnly bucket increments
// ─────────────────────────────────────────────────────────────────────

func TestSDKGhostEmitter_SinkFailure_RecordsAppendOnly(t *testing.T) {
	cfg, store, sink := validEmitterConfig(t)
	// First Broadcast fails. Append should still land.
	sinkFailErr := errors.New("simulated peer-broadcast failure")
	sink.failFirstN = 1
	sink.failErr = sinkFailErr

	e, err := NewSDKGossipGhostLeafEmitter(cfg)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	ev := validEventForEmitter(cfg.Originator)
	e.Emit(context.Background(), ev)

	snap := e.Snapshot()
	if snap.AppendOnly != 1 {
		t.Errorf("Snapshot.AppendOnly = %d, want 1 (Append landed; Broadcast failed); snap=%+v",
			snap.AppendOnly, snap)
	}
	if snap.Succeeded != 0 {
		t.Errorf("Snapshot.Succeeded = %d, want 0 (Broadcast failed)", snap.Succeeded)
	}
	// Store DID receive the event — local audit log is durable
	// even when peers can't be reached.
	_, lamport, herr := store.Head(context.Background(), cfg.Originator)
	if herr != nil {
		t.Fatalf("store.Head: %v", herr)
	}
	if lamport != 1 {
		t.Errorf("store lamport = %d, want 1 (Append must land regardless of Broadcast)", lamport)
	}
}
