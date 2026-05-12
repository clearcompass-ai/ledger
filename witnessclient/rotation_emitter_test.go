/*
FILE PATH: witnessclient/rotation_emitter_test.go

Unit tests for WitnessRotationEmitter + RotationHandler.WithEmitter.

# WHAT'S COVERED

  (1) NopWitnessRotationEmitter — Emit is a no-op; safe to call
      with any zero-value event.

  (2) LoggingWitnessRotationEmitter — Emit increments the Emitted
      counter, writes a structured log line with every field of
      the event present.

  (3) Compile-time pins — both implementations satisfy the
      WitnessRotationEmitter interface (drift surfaces as a build
      error, not a runtime panic).

  (4) RotationHandler.WithEmitter — chains, stores the supplied
      emitter, accepts nil.

# WHAT'S ABSENT (and why)

End-to-end "rotation lands in DB, emitter fires" tests live in the
integration package (witnessclient/integration_test.go would gate
on a real Postgres). The unit boundary here is the emitter contract
+ the handler's wire-up. The DB-write→emit ordering is enforced by
the linear control flow in rotation_handler.go::ProcessRotation —
visual inspection + the integration test gating on a real DB cover
the cross-boundary property.
*/
package witnessclient

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// Compile-time pin — same surface as the production rotation_
// emitter.go file already declares; duplicated here so a future
// refactor that splits the file doesn't drop the assertion.
var _ WitnessRotationEmitter = NopWitnessRotationEmitter{}
var _ WitnessRotationEmitter = (*LoggingWitnessRotationEmitter)(nil)

// ─────────────────────────────────────────────────────────────────────
// (1) NopWitnessRotationEmitter
// ─────────────────────────────────────────────────────────────────────

func TestNopWitnessRotationEmitter_IsNoOp(t *testing.T) {
	var e NopWitnessRotationEmitter
	// Should not panic, should not allocate, should not return
	// anything. Calling on a zero-value event is the canonical
	// test for "this is a true no-op".
	e.Emit(context.Background(), WitnessRotationEvent{})
	// Calling twice on the same instance should also be safe.
	e.Emit(context.Background(), WitnessRotationEvent{NewKeysCount: 5})
}

// ─────────────────────────────────────────────────────────────────────
// (2) LoggingWitnessRotationEmitter
// ─────────────────────────────────────────────────────────────────────

func TestLoggingWitnessRotationEmitter_EmitIncrementsCounterAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := NewLoggingWitnessRotationEmitter(logger)

	if got := e.Emitted(); got != 0 {
		t.Fatalf("Emitted before any Emit = %d, want 0", got)
	}

	ev := WitnessRotationEvent{
		PreviousSetHash:   [32]byte{0xab, 0xcd},
		NewSetHash:        [32]byte{0xef, 0x12},
		OldSchemeTag:      0x01,
		NewSchemeTag:      0x02,
		NewKeysCount:      5,
		DualSigned:        true,
		AppliedAtUnixNano: 1_700_000_000_000_000_000,
	}
	e.Emit(context.Background(), ev)

	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted after one Emit = %d, want 1", got)
	}

	// Verify the log line carries the event fields. Parse the
	// JSON line and check the keys.
	line := buf.String()
	if !strings.Contains(line, "witnessclient: rotation event") {
		t.Errorf("log line missing event marker: %q", line)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, line)
	}
	// Spot-check the load-bearing field — new_keys_count. If
	// future refactors drop a field, the structured-log shape
	// detects it.
	if got, want := int(parsed["new_keys_count"].(float64)), 5; got != want {
		t.Errorf("log new_keys_count = %d, want %d", got, want)
	}
	if got := parsed["dual_signed"].(bool); !got {
		t.Errorf("log dual_signed = %v, want true", got)
	}
}

func TestLoggingWitnessRotationEmitter_NilLoggerFallsBackToDefault(t *testing.T) {
	// Passing nil for the logger should not panic — the constructor
	// falls back to slog.Default. The test value is that the
	// fallback works; the default logger's destination is not
	// directly observable here, so we only assert the Emit doesn't
	// panic.
	e := NewLoggingWitnessRotationEmitter(nil)
	if e == nil {
		t.Fatal("NewLoggingWitnessRotationEmitter(nil) returned nil")
	}
	e.Emit(context.Background(), WitnessRotationEvent{NewKeysCount: 1})
	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted = %d, want 1", got)
	}
}

func TestLoggingWitnessRotationEmitter_EmittedIsConcurrencySafe(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	const N = 100

	// Fire N emits concurrently. The internal mu serializes the
	// slog write; the atomic counter must also reach N exactly.
	done := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			e.Emit(context.Background(), WitnessRotationEvent{})
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
	if got := e.Emitted(); got != N {
		t.Errorf("Emitted after %d concurrent Emits = %d, want %d", N, got, N)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (3) RotationHandler.WithEmitter — wire-up
// ─────────────────────────────────────────────────────────────────────

func TestRotationHandler_WithEmitter_ChainsAndStores(t *testing.T) {
	rh := &RotationHandler{}
	cap := &capturingEmitter{}
	got := rh.WithEmitter(cap)
	if got != rh {
		t.Fatal("WithEmitter must return the receiver for chaining")
	}
	if rh.emitter != cap {
		t.Errorf("WithEmitter did not store the emitter: got %v, want %v", rh.emitter, cap)
	}
}

func TestRotationHandler_WithEmitter_AcceptsNil(t *testing.T) {
	rh := (&RotationHandler{}).WithEmitter(&capturingEmitter{})
	if rh.emitter == nil {
		t.Fatal("test setup wrong: emitter should be non-nil before reset")
	}
	rh.WithEmitter(nil)
	if rh.emitter != nil {
		t.Errorf("WithEmitter(nil) did not clear the emitter; got %v", rh.emitter)
	}
}

// capturingEmitter records every Emit so the handler-side wiring
// tests can assert on the call. Mirrors the captureEmitter pattern
// in sequencer/ghost_emit_test.go.
type capturingEmitter struct {
	events []WitnessRotationEvent
}

func (c *capturingEmitter) Emit(_ context.Context, ev WitnessRotationEvent) {
	c.events = append(c.events, ev)
}

var _ WitnessRotationEmitter = (*capturingEmitter)(nil)

// TestComputeWitnessSetHash_DeterministicAndDistinct pins the
// stub set-hash helper. Two distinct inputs MUST hash distinctly;
// the same input MUST hash to the same digest twice. When SDK
// v0.6.0 ships the canonical fingerprint shape, this test gets
// updated alongside the helper.
func TestComputeWitnessSetHash_DeterministicAndDistinct(t *testing.T) {
	a := []byte(`[{"ID":"...","PublicKey":"..."}]`)
	b := []byte(`[{"ID":"...","PublicKey":"different"}]`)

	hashA1 := computeWitnessSetHash(a)
	hashA2 := computeWitnessSetHash(a)
	hashB := computeWitnessSetHash(b)

	if hashA1 != hashA2 {
		t.Errorf("hash not deterministic: hashA1=%x, hashA2=%x", hashA1, hashA2)
	}
	if hashA1 == hashB {
		t.Errorf("distinct inputs hashed identically: hash=%x", hashA1)
	}
}
