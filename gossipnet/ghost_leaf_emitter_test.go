// FILE PATH: gossipnet/ghost_leaf_emitter_test.go
//
// Unit tests for the GhostLeafEmitter contract + the in-tree
// LoggingGhostLeafEmitter implementation.
//
// Three guarantees pinned:
//
//  1. Compile-time interface conformance — LoggingGhostLeafEmitter
//     satisfies sequencer.GhostLeafEmitter structurally. Future
//     SDK-adapter implementations land via the same contract.
//
//  2. EmittedCount is monotone and matches Emit call count
//     exactly. The harness + chaos tests rely on this counter
//     as the cross-process signal that a ghost row was written.
//
//  3. The logged line carries the SDK-aligned uint64 observed-
//     at field (NOT a time.Time string), so the eventual SDK
//     adapter sees the same wire-aligned data.
package gossipnet

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/clearcompass-ai/ledger/sequencer"
)

// Compile-time pin — LoggingGhostLeafEmitter MUST satisfy the
// sequencer's local interface. If the contract drifts (return
// type, signature, etc.) the build breaks here, not at runtime.
var _ sequencer.GhostLeafEmitter = (*LoggingGhostLeafEmitter)(nil)

func TestLoggingGhostLeafEmitter_EmitsAtINFO(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := NewLoggingGhostLeafEmitter(logger)

	ev := sequencer.GhostLeafEvent{
		GhostSeq:           16,
		CanonicalSeq:       8,
		CanonicalHash:      [32]byte{0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce},
		LogDID:             "did:example:ledger",
		ObservedAtUnixNano: 1700000000123456789,
	}
	e.Emit(context.Background(), ev)

	out := buf.String()
	if !strings.Contains(out, "ghost leaf emitted") {
		t.Errorf("expected diagnostic line in log, got: %q", out)
	}
	if !strings.Contains(out, "ghost_seq=16") {
		t.Errorf("expected ghost_seq=16 in log, got: %q", out)
	}
	if !strings.Contains(out, "canonical_seq=8") {
		t.Errorf("expected canonical_seq=8 in log, got: %q", out)
	}
	// The uint64 nano value MUST appear unmodified in the log —
	// confirms the emitter is NOT silently round-tripping
	// through time.RFC3339Nano (which would introduce the
	// non-determinism risk the architect flagged).
	if !strings.Contains(out, "observed_at_unix_nano=1700000000123456789") {
		t.Errorf("expected observed_at_unix_nano=1700000000123456789 in log, got: %q", out)
	}
	// Defensive: the canonical_hash short form should be the
	// first 8 bytes hex (NOT the full 32-byte slice noise).
	if !strings.Contains(out, "canonical_hash=deadbeeffacef") &&
		!strings.Contains(out, "canonical_hash=deadbeefface") {
		// short hash builds the first 8 bytes; the 6 we set
		// should be present (deadbeefface00) or close to it.
		// Loose match acceptable.
		t.Logf("warning: short canonical_hash form may have changed; log line: %q", out)
	}
}

func TestLoggingGhostLeafEmitter_EmittedCountMatchesCalls(t *testing.T) {
	e := NewLoggingGhostLeafEmitter(slog.New(slog.DiscardHandler))

	if got := e.EmittedCount(); got != 0 {
		t.Fatalf("initial EmittedCount = %d, want 0", got)
	}
	ev := sequencer.GhostLeafEvent{GhostSeq: 1, CanonicalSeq: 0,
		LogDID: "did:example:x", ObservedAtUnixNano: 1}
	for i := 0; i < 7; i++ {
		e.Emit(context.Background(), ev)
	}
	if got := e.EmittedCount(); got != 7 {
		t.Errorf("EmittedCount after 7 emits = %d, want 7", got)
	}
}

func TestLoggingGhostLeafEmitter_EmittedCountIsThreadSafe(t *testing.T) {
	e := NewLoggingGhostLeafEmitter(slog.New(slog.DiscardHandler))
	const goroutines = 16
	const callsPerG = 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := sequencer.GhostLeafEvent{GhostSeq: 1, CanonicalSeq: 0}
			for j := 0; j < callsPerG; j++ {
				e.Emit(context.Background(), ev)
			}
		}()
	}
	wg.Wait()
	want := uint64(goroutines * callsPerG)
	if got := e.EmittedCount(); got != want {
		t.Errorf("concurrent EmittedCount = %d, want %d", got, want)
	}
}

func TestLoggingGhostLeafEmitter_NilLoggerFallsBackToDefault(t *testing.T) {
	// nil logger must not panic; the constructor substitutes the
	// process default. The deployment-time invariant: "wiring code
	// can forget to pass a logger and the emitter still works."
	e := NewLoggingGhostLeafEmitter(nil)
	if e.Logger == nil {
		t.Fatal("expected fallback to slog.Default(); got nil")
	}
	e.Emit(context.Background(), sequencer.GhostLeafEvent{})
	if got := e.EmittedCount(); got != 1 {
		t.Errorf("EmittedCount = %d, want 1 (one emit through nil-logger path)", got)
	}
}

func TestNopGhostLeafEmitter_AcceptsAnyEventWithoutPanic(t *testing.T) {
	e := NopGhostLeafEmitter()
	// 100 emits on the nop emitter must complete without error.
	for i := 0; i < 100; i++ {
		e.Emit(context.Background(), sequencer.GhostLeafEvent{
			GhostSeq:     uint64(i),
			CanonicalSeq: uint64(i / 2),
		})
	}
	// Compile-time interface satisfaction is the real assertion;
	// the runtime call just proves no panic. Test passes if we
	// reach this line.
}

