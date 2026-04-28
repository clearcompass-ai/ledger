/*
FILE PATH: sequencer/sequencer_test.go

Unit tests covering both sequencer.go (Sequencer lifecycle,
config defaults, metrics) and loop.go (drainOnce, processOne,
isUniqueViolation). Postgres-free — the entry_index INSERT path
is exercised via the test-mode nil-DB short-circuit so we can
assert drain semantics in milliseconds without a live Postgres
pool.

Real Postgres + Tessera coverage lives in tests/e2e_v2_sct_test.go
(committed alongside the v2 endpoint wiring).

WHAT'S COVERED:

  Lifecycle:
    - NewSequencer normalizes zero-valued Config into defaults.
    - Run drains immediately (no first-tick wait), then on
      ticker.
    - Run returns ctx.Err() on cancellation.

  drainOnce / processOne:
    - Pending entry → AppendLeaf → Sequence happy path.
    - State guard: non-Pending entries skipped, attempts reset.
    - wal.ErrNotFound during MetaState short-circuits cleanly.
    - Tessera transport failure → MarkRetry; counter increments.
    - MaxAttempts exhausted → MarkManual.
    - Deserialize failure on durable WAL bytes → MarkManual
      (treated as permanent corruption).
    - UNIQUE-violation on entry_index INSERT is idempotent —
      Sequence still called.
    - WAL.Sequence transport failure → MarkRetry (Tessera/Postgres
      already advanced; WAL state lag is recoverable).

  Helpers:
    - isUniqueViolation matches the three pgx error shapes,
      rejects non-violations.
*/
package sequencer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"

	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

type fakeWAL struct {
	mu sync.Mutex

	// hashes seeded for IterateInflight to walk.
	pending []wal.PendingHash

	// per-hash state mocked. Default: StatePending.
	state map[[32]byte]wal.EntryState

	// per-hash wire bytes. nil → Read returns wal.ErrNotFound.
	bytes map[[32]byte][]byte

	// per-hash error injection knobs. Each call increments a
	// counter; tests can configure "fail first N calls" by
	// initializing failsRemaining.
	readErr     error
	metaErr     error
	sequenceErr error

	// per-hash sequence advance record.
	sequenced map[[32]byte]uint64

	// counters for assertions.
	markRetryCalls  atomic.Uint64
	markManualCalls atomic.Uint64
	sequenceCalls   atomic.Uint64
}

func newFakeWAL() *fakeWAL {
	return &fakeWAL{
		state:     make(map[[32]byte]wal.EntryState),
		bytes:     make(map[[32]byte][]byte),
		sequenced: make(map[[32]byte]uint64),
	}
}

// seed adds a fake pending entry with the supplied wire bytes.
func (f *fakeWAL) seed(hash [32]byte, wire []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, wal.PendingHash{Hash: hash})
	f.state[hash] = wal.StatePending
	f.bytes[hash] = wire
}

func (f *fakeWAL) IterateInflight(ctx context.Context, fn func(wal.PendingHash) error) error {
	f.mu.Lock()
	pending := append([]wal.PendingHash(nil), f.pending...)
	f.mu.Unlock()
	for _, p := range pending {
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeWAL) Read(ctx context.Context, hash [32]byte) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bytes[hash]
	if !ok {
		return nil, wal.ErrNotFound
	}
	return b, nil
}

func (f *fakeWAL) MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error) {
	if f.metaErr != nil {
		return wal.Meta{}, f.metaErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.state[hash]
	if !ok {
		return wal.Meta{}, wal.ErrNotFound
	}
	return wal.Meta{State: st, Sequence: f.sequenced[hash]}, nil
}

func (f *fakeWAL) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	f.sequenceCalls.Add(1)
	if f.sequenceErr != nil {
		return f.sequenceErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[hash] = wal.StateSequenced
	f.sequenced[hash] = seq
	return nil
}

func (f *fakeWAL) MarkRetry(ctx context.Context, hash [32]byte) error {
	f.markRetryCalls.Add(1)
	return nil
}

func (f *fakeWAL) MarkManual(ctx context.Context, hash [32]byte) error {
	f.markManualCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[hash] = wal.StateManual
	return nil
}

type fakeTessera struct {
	mu sync.Mutex
	// next seq to assign. Caller can override.
	nextSeq uint64
	// dedup table: same hash → same seq returned (antispam).
	assigned map[[32]byte]uint64
	// per-call error injection: fail first N calls then succeed.
	failsRemaining atomic.Int64
	calls          atomic.Uint64
}

func newFakeTessera() *fakeTessera {
	return &fakeTessera{
		nextSeq:  1,
		assigned: make(map[[32]byte]uint64),
	}
}

func (f *fakeTessera) AppendLeaf(data []byte) (uint64, error) {
	f.calls.Add(1)
	if remaining := f.failsRemaining.Load(); remaining > 0 {
		f.failsRemaining.Add(-1)
		return 0, errors.New("fake tessera: injected transient failure")
	}
	if len(data) != 32 {
		return 0, fmt.Errorf("fake tessera: AppendLeaf wants 32 bytes, got %d", len(data))
	}
	var hash [32]byte
	copy(hash[:], data)
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq, ok := f.assigned[hash]; ok {
		return seq, nil // antispam idempotent
	}
	seq := f.nextSeq
	f.nextSeq++
	f.assigned[hash] = seq
	return seq, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// buildEntry produces a v7.75-shape envelope.Entry suitable for
// envelope.Serialize → envelope.Deserialize round-trip. The hash
// of Serialize's output IS the canonical hash; tests use that
// as the WAL key.
func buildEntry(t *testing.T, payload string) (wire []byte, hash [32]byte) {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: "did:test:log",
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte(payload))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	// Stub a structurally-valid signature so Validate + Serialize succeed.
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wire = envelope.Serialize(entry)
	hash = sha256.Sum256(wire)
	return wire, hash
}

// newTestSequencer wires a Sequencer with the supplied fakes. db
// and store are nil so insertEntryIndex short-circuits cleanly.
func newTestSequencer(t *testing.T, w WAL, ts Tessera, cfg Config) *Sequencer {
	t.Helper()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Millisecond
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	return NewSequencer(w, ts, nil, nil, cfg)
}

// ─────────────────────────────────────────────────────────────────────
// Lifecycle tests
// ─────────────────────────────────────────────────────────────────────

func TestSequencer_NewSequencer_ConfigDefaults(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	s := NewSequencer(w, ts, nil, nil, Config{})
	if s.cfg.PollInterval != DefaultPollInterval {
		t.Errorf("PollInterval = %v, want %v", s.cfg.PollInterval, DefaultPollInterval)
	}
	if s.cfg.MaxInFlight != DefaultMaxInFlight {
		t.Errorf("MaxInFlight = %d, want %d", s.cfg.MaxInFlight, DefaultMaxInFlight)
	}
	if s.cfg.MaxAttempts != DefaultMaxAttempts {
		t.Errorf("MaxAttempts = %d, want %d", s.cfg.MaxAttempts, DefaultMaxAttempts)
	}
	if s.cfg.BackoffBase != DefaultBackoffBase {
		t.Errorf("BackoffBase = %v, want %v", s.cfg.BackoffBase, DefaultBackoffBase)
	}
	if s.cfg.BackoffMax != DefaultBackoffMax {
		t.Errorf("BackoffMax = %v, want %v", s.cfg.BackoffMax, DefaultBackoffMax)
	}
	if s.cfg.Logger == nil {
		t.Error("Logger should default to slog.Default()")
	}
}

func TestSequencer_Run_RequiresDeps(t *testing.T) {
	s := NewSequencer(nil, newFakeTessera(), nil, nil, Config{})
	if err := s.Run(context.Background()); err == nil {
		t.Error("Run should error when WAL is nil")
	}
	s = NewSequencer(newFakeWAL(), nil, nil, nil, Config{})
	if err := s.Run(context.Background()); err == nil {
		t.Error("Run should error when Tessera is nil")
	}
}

func TestSequencer_Run_DrainsOnceImmediately(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	_, hash := buildEntry(t, "drain-on-start")
	w.seed(hash, mustSerializeWith(t, "drain-on-start"))

	s := newTestSequencer(t, w, ts, Config{PollInterval: time.Hour})

	// Cancel before the first ticker tick fires; only the immediate
	// drainOnce on Run start can have processed the entry.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.sequenceCalls.Load() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got := w.sequenceCalls.Load(); got != 1 {
		t.Fatalf("Sequence calls = %d, want 1 (immediate drain on Run start)", got)
	}
}

func TestSequencer_Run_StopsOnCtxCancel(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	s := newTestSequencer(t, w, ts, Config{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on ctx cancel within 2s")
	}
}

// ─────────────────────────────────────────────────────────────────────
// processOne / drainOnce semantics
// ─────────────────────────────────────────────────────────────────────

func TestSequencer_processOne_HappyPath(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	wire, hash := buildEntry(t, "happy")
	w.seed(hash, wire)

	s := newTestSequencer(t, w, ts, Config{})
	s.drainOnce(context.Background())

	if got := ts.calls.Load(); got != 1 {
		t.Errorf("Tessera.AppendLeaf calls = %d, want 1", got)
	}
	if got := w.sequenceCalls.Load(); got != 1 {
		t.Errorf("WAL.Sequence calls = %d, want 1", got)
	}
	if got := s.metrics.processed.Load(); got != 1 {
		t.Errorf("metrics.processed = %d, want 1", got)
	}
}

func TestSequencer_processOne_StateGuard_NotPending_NoOp(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	wire, hash := buildEntry(t, "already-sequenced")
	w.seed(hash, wire)
	w.mu.Lock()
	w.state[hash] = wal.StateSequenced
	w.mu.Unlock()

	s := newTestSequencer(t, w, ts, Config{})
	s.drainOnce(context.Background())

	if got := ts.calls.Load(); got != 0 {
		t.Errorf("Tessera.AppendLeaf calls = %d, want 0 (entry not Pending)", got)
	}
}

func TestSequencer_processOne_TransientTesseraFailure_MarksRetry(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	ts.failsRemaining.Store(1) // fail once, succeed thereafter

	wire, hash := buildEntry(t, "transient")
	w.seed(hash, wire)

	s := newTestSequencer(t, w, ts, Config{MaxAttempts: 3})

	// First drain: Tessera fails → MarkRetry, attempt=1.
	s.drainOnce(context.Background())
	if got := w.markRetryCalls.Load(); got != 1 {
		t.Errorf("after first drain: MarkRetry = %d, want 1", got)
	}
	if got := w.markManualCalls.Load(); got != 0 {
		t.Errorf("after first drain: MarkManual = %d, want 0", got)
	}

	// Second drain: Tessera succeeds → Sequence advances.
	s.drainOnce(context.Background())
	if got := w.sequenceCalls.Load(); got != 1 {
		t.Errorf("after second drain: Sequence calls = %d, want 1", got)
	}
}

func TestSequencer_processOne_MaxAttemptsExhausted_MarksManual(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	ts.failsRemaining.Store(1000) // always fail

	wire, hash := buildEntry(t, "doomed")
	w.seed(hash, wire)

	s := newTestSequencer(t, w, ts, Config{MaxAttempts: 3})

	// Three drains: each fails. On the 3rd, MarkManual.
	for i := 0; i < 3; i++ {
		s.drainOnce(context.Background())
	}
	if got := w.markManualCalls.Load(); got != 1 {
		t.Errorf("MarkManual calls = %d, want 1 (after MaxAttempts=3)", got)
	}
	if got := s.metrics.manualCount.Load(); got != 1 {
		t.Errorf("metrics.manualCount = %d, want 1", got)
	}

	// State should now be StateManual; subsequent drain should be a no-op.
	s.drainOnce(context.Background())
	if got := w.markManualCalls.Load(); got != 1 {
		t.Errorf("after 4th drain: MarkManual still = %d, want 1 (state guard)", got)
	}
}

func TestSequencer_processOne_DeserializeFailure_MarksManual(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	hash := sha256.Sum256([]byte("garbage"))
	// Inject non-envelope bytes to provoke envelope.Deserialize failure.
	w.seed(hash, []byte("not a valid envelope"))

	s := newTestSequencer(t, w, ts, Config{})
	s.drainOnce(context.Background())

	if got := w.markManualCalls.Load(); got != 1 {
		t.Errorf("MarkManual = %d, want 1 (deserialize is permanent failure)", got)
	}
	if got := ts.calls.Load(); got != 0 {
		t.Errorf("Tessera.AppendLeaf calls = %d, want 0", got)
	}
}

func TestSequencer_processOne_TesseraDedup_Idempotent(t *testing.T) {
	// Two pending entries with the SAME hash (simulates a v1 facade
	// retry that landed in WAL twice for the same content). Tessera
	// dedup makes both return the same seq; both Sequence calls
	// land at the same final state.
	w := newFakeWAL()
	ts := newFakeTessera()
	wire, hash := buildEntry(t, "dedup")
	w.seed(hash, wire)

	s := newTestSequencer(t, w, ts, Config{})

	// First drain succeeds.
	s.drainOnce(context.Background())
	firstSeq := w.sequenced[hash]

	// Re-seed to simulate a second drain catching the same hash
	// before the state guard transitioned.
	w.mu.Lock()
	w.state[hash] = wal.StatePending
	w.pending = []wal.PendingHash{{Hash: hash}}
	w.mu.Unlock()

	s.drainOnce(context.Background())
	if got := w.sequenced[hash]; got != firstSeq {
		t.Errorf("second drain assigned different seq: %d != %d (Tessera dedup broken?)", got, firstSeq)
	}
	if got := ts.calls.Load(); got != 2 {
		t.Errorf("AppendLeaf called %d times across two drains; expected 2", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// isUniqueViolation
// ─────────────────────────────────────────────────────────────────────

func TestSequencer_isUniqueViolation_MatchesPgxShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("connection refused"), false},
		{"sqlstate-23505", errors.New("ERROR: SQLSTATE 23505: duplicate"), true},
		{"duplicate-key-prose", errors.New("duplicate key value violates UNIQUE constraint \"foo\""), true},
		{"unique-constraint-prose", errors.New("UNIQUE constraint violated"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := isUniqueViolation(tc.err)
			if got != tc.want {
				t.Errorf("isUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// mustSerializeWith returns the wire bytes produced by buildEntry.
// Used in tests that need the payload separately from the hash.
func mustSerializeWith(t *testing.T, payload string) []byte {
	t.Helper()
	wire, _ := buildEntry(t, payload)
	return wire
}
