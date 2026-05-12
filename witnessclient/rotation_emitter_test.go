/*
FILE PATH: witnessclient/rotation_emitter_test.go

Unit tests for WitnessRotationEmitter + RotationHandler.WithEmitter.

# WHAT'S COVERED

  (1) NopWitnessRotationEmitter — Emit is a no-op; safe with nil
      finding too.

  (2) LoggingWitnessRotationEmitter — Emit increments the Emitted
      counter and writes a structured log line carrying the
      load-bearing fields of the finding.

  (3) Compile-time pins — both implementations satisfy the
      WitnessRotationEmitter interface (drift surfaces as a build
      error, not a runtime panic).

  (4) RotationHandler.WithEmitter — chains, stores the supplied
      emitter, accepts nil.

# WHAT'S ABSENT (and why)

End-to-end "rotation lands in DB, emitter fires" tests live in the
witnessclient/rotation_cross_network_test.go and the integration
package (which gates on a real Postgres). The unit boundary here
is the emitter contract + the handler's wire-up. The DB-write→emit
ordering is enforced by the linear control flow in
rotation_handler.go::ProcessRotation — visual inspection +
integration tests cover the cross-boundary property.
*/
package witnessclient

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// Compile-time pins — same surface as the production rotation_
// emitter.go file already declares; duplicated here so a future
// refactor that splits the file doesn't drop the assertion.
var (
	_ WitnessRotationEmitter = NopWitnessRotationEmitter{}
	_ WitnessRotationEmitter = (*LoggingWitnessRotationEmitter)(nil)
)

// fixtureFinding returns a structurally-valid (but NOT
// cryptographically-verifiable) WitnessRotationFinding suitable
// for emitter-surface tests. Construction goes through
// findings.NewWitnessRotationFinding so the SDK's Validate fires
// — if Validate rejects, the test fixture is broken, not the
// emitter contract.
func fixtureFinding(t *testing.T) *findings.WitnessRotationFinding {
	t.Helper()
	rotation := types.WitnessRotation{
		CurrentSetHash: [32]byte{0xab, 0xcd, 0xef},
		NewSet: []types.WitnessPublicKey{
			{
				ID:        [32]byte{0x01},
				PublicKey: []byte{0x04, 0x01, 0x02, 0x03}, // structurally-valid; not crypto-verified
			},
		},
		SchemeTagOld:      0x01,
		CurrentSignatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: []byte{0xAA}}},
		SchemeTagNew:      0x01,
		NewSignatures:     []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: []byte{0xBB}}},
	}
	f, err := findings.NewWitnessRotationFinding(rotation, "https://ledger.example/")
	if err != nil {
		t.Fatalf("fixture finding rejected by SDK Validate: %v", err)
	}
	return f
}

// ─────────────────────────────────────────────────────────────────────
// (1) NopWitnessRotationEmitter
// ─────────────────────────────────────────────────────────────────────

func TestNopWitnessRotationEmitter_IsNoOp(t *testing.T) {
	var e NopWitnessRotationEmitter
	// Should not panic on nil finding (defense-in-depth).
	e.Emit(context.Background(), nil)
	// Should not panic on a real finding.
	e.Emit(context.Background(), fixtureFinding(t))
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

	f := fixtureFinding(t)
	e.Emit(context.Background(), f)

	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted after one Emit = %d, want 1", got)
	}

	line := buf.String()
	if !strings.Contains(line, "witnessclient: rotation event") {
		t.Errorf("log line missing event marker: %q", line)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, line)
	}
	// Spot-check the load-bearing field — new_set_size. If a
	// future refactor drops a field, the structured-log shape
	// detects it.
	if got, want := int(parsed["new_set_size"].(float64)), 1; got != want {
		t.Errorf("log new_set_size = %d, want %d", got, want)
	}
	if got, want := parsed["ledger_endpoint"].(string), "https://ledger.example/"; got != want {
		t.Errorf("log ledger_endpoint = %q, want %q", got, want)
	}
}

func TestLoggingWitnessRotationEmitter_NilFindingIsNoOp(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	e.Emit(context.Background(), nil) // must not panic
	if got := e.Emitted(); got != 0 {
		t.Errorf("nil-finding Emit incremented counter: got %d, want 0", got)
	}
}

func TestLoggingWitnessRotationEmitter_NilLoggerFallsBackToDefault(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(nil)
	if e == nil {
		t.Fatal("NewLoggingWitnessRotationEmitter(nil) returned nil")
	}
	e.Emit(context.Background(), fixtureFinding(t))
	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted = %d, want 1", got)
	}
}

func TestLoggingWitnessRotationEmitter_EmittedIsConcurrencySafe(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	f := fixtureFinding(t)
	const N = 100

	done := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			e.Emit(context.Background(), f)
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
	findings []*findings.WitnessRotationFinding
}

func (c *capturingEmitter) Emit(_ context.Context, f *findings.WitnessRotationFinding) {
	c.findings = append(c.findings, f)
}

var _ WitnessRotationEmitter = (*capturingEmitter)(nil)
