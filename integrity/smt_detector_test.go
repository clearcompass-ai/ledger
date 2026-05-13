/*
FILE PATH: integrity/smt_detector_test.go

Tests for the SMT-root divergence detector.

# WHAT'S COVERED

  (1) Tick happy path        — root + cosigned head match → samplesVerified++
  (2) Tick mismatch          — root differs from head.SMTRoot → ErrSMTRootDiverged
  (3) Tick pre-batch         — committed_through_seq == 0 → samplesSkipped++
  (4) Tick no-cosigned-yet   — head not yet at current seq → samplesSkipped++
  (5) Tick infra error       — state read fails → wrapped error (not skip)
  (6) Loop cancel            — ctx cancelled → ctx.Canceled
  (7) Loop divergence stops  — first mismatch → loop exits with ErrSMTRootDiverged
  (8) Counter monotonicity   — samples accumulate correctly across ticks
*/
package integrity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

type fakeSMTRootState struct {
	mu   sync.Mutex
	snap SMTRootSnapshot
	err  error
}

func (f *fakeSMTRootState) Read(_ context.Context) (SMTRootSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return SMTRootSnapshot{}, f.err
	}
	return f.snap, nil
}

func (f *fakeSMTRootState) set(root [32]byte, seq uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap = SMTRootSnapshot{CurrentRoot: root, CommittedThroughSeq: seq}
}

type fakeHeadStore struct {
	mu      sync.Mutex
	bySize  map[uint64]*apitypes.CosignedTreeHead
	readErr error
}

func newFakeHeadStore() *fakeHeadStore {
	return &fakeHeadStore{bySize: make(map[uint64]*apitypes.CosignedTreeHead)}
}

func (f *fakeHeadStore) GetBySize(_ context.Context, size uint64) (*apitypes.CosignedTreeHead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.bySize[size], nil
}

func (f *fakeHeadStore) put(size uint64, smtRoot [32]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bySize[size] = &apitypes.CosignedTreeHead{
		TreeSize: size,
		SMTRoot:  smtRoot,
	}
}

func discardLoggerSMT() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ─────────────────────────────────────────────────────────────────────
// (1) Happy path
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Tick_AlignedRoot(t *testing.T) {
	state := &fakeSMTRootState{}
	heads := newFakeHeadStore()
	root := [32]byte{0xAB, 0xCD, 0xEF}

	state.set(root, 100)
	heads.put(100, root)

	d := NewSMTDetector(state, heads, SMTDetectorConfig{Logger: discardLoggerSMT()})
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("aligned-root Tick: %v", err)
	}
	if got := d.SamplesVerified(); got != 1 {
		t.Errorf("SamplesVerified = %d, want 1", got)
	}
	if got := d.SamplesSkipped(); got != 0 {
		t.Errorf("SamplesSkipped = %d, want 0", got)
	}
	if got := d.InvariantFailures(); got != 0 {
		t.Errorf("InvariantFailures = %d, want 0", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (2) Mismatch — the load-bearing alarm
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Tick_MismatchedRoot_ReturnsErrSMTRootDiverged(t *testing.T) {
	state := &fakeSMTRootState{}
	heads := newFakeHeadStore()
	stateRoot := [32]byte{0xAA, 0xBB}
	headRoot := [32]byte{0xCC, 0xDD} // DIFFERENT

	state.set(stateRoot, 42)
	heads.put(42, headRoot)

	d := NewSMTDetector(state, heads, SMTDetectorConfig{Logger: discardLoggerSMT()})
	err := d.Tick(context.Background())
	if err == nil {
		t.Fatal("Tick: expected ErrSMTRootDiverged on root mismatch")
	}
	if !errors.Is(err, ErrSMTRootDiverged) {
		t.Errorf("err = %v, want errors.Is(.., ErrSMTRootDiverged)", err)
	}
	if got := d.InvariantFailures(); got != 1 {
		t.Errorf("InvariantFailures = %d, want 1", got)
	}
	if got := d.SamplesVerified(); got != 0 {
		t.Errorf("SamplesVerified = %d, want 0", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (3) Pre-batch — committed_through_seq=0 is a clean skip, not a panic
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Tick_PreFirstBatch_Skips(t *testing.T) {
	state := &fakeSMTRootState{}
	heads := newFakeHeadStore()
	state.set([32]byte{}, 0) // zero seq → pre-first-batch

	d := NewSMTDetector(state, heads, SMTDetectorConfig{Logger: discardLoggerSMT()})
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("pre-first-batch Tick must skip cleanly, got: %v", err)
	}
	if got := d.SamplesSkipped(); got != 1 {
		t.Errorf("SamplesSkipped = %d, want 1", got)
	}
	if got := d.SamplesVerified(); got != 0 {
		t.Errorf("SamplesVerified = %d, want 0", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (4) Witness lag — state advanced, head not yet cosigned at this seq
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Tick_NoCosignedHeadYet_Skips(t *testing.T) {
	state := &fakeSMTRootState{}
	heads := newFakeHeadStore()
	state.set([32]byte{0xFF}, 50)
	// heads has nothing at size=50 — witness collection lags

	d := NewSMTDetector(state, heads, SMTDetectorConfig{Logger: discardLoggerSMT()})
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("witness-lag Tick must skip cleanly, got: %v", err)
	}
	if got := d.SamplesSkipped(); got != 1 {
		t.Errorf("SamplesSkipped = %d, want 1", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (5) Infra error — DB read failure surfaces as wrapped, not skip
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Tick_StateReadError_PropagatesWrapped(t *testing.T) {
	state := &fakeSMTRootState{err: errors.New("connection refused")}
	heads := newFakeHeadStore()

	d := NewSMTDetector(state, heads, SMTDetectorConfig{Logger: discardLoggerSMT()})
	err := d.Tick(context.Background())
	if err == nil {
		t.Fatal("DB read error must propagate, not skip")
	}
	if errors.Is(err, ErrSMTRootDiverged) {
		t.Errorf("DB error misclassified as divergence: %v", err)
	}
	// Counter unchanged: not a verify, not a skip, not a divergence.
	if got := d.SamplesVerified() + d.SamplesSkipped() + d.InvariantFailures(); got != 0 {
		t.Errorf("infra error must not increment any counter; got total=%d", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (6) Loop respects ctx
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Loop_ContextCancelReturnsCancelErr(t *testing.T) {
	d := NewSMTDetector(
		&fakeSMTRootState{},
		newFakeHeadStore(),
		SMTDetectorConfig{
			SampleInterval: 50 * time.Millisecond,
			Logger:         discardLoggerSMT(),
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Loop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Loop on cancelled ctx: %v, want context.Canceled", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (7) Loop exits on first divergence
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Loop_DivergenceStopsLoop(t *testing.T) {
	state := &fakeSMTRootState{}
	heads := newFakeHeadStore()
	state.set([32]byte{0x01}, 7)
	heads.put(7, [32]byte{0x02}) // mismatch

	d := NewSMTDetector(state, heads, SMTDetectorConfig{
		SampleInterval: 5 * time.Millisecond,
		Logger:         discardLoggerSMT(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := d.Loop(ctx)
	if !errors.Is(err, ErrSMTRootDiverged) {
		t.Fatalf("Loop did not surface ErrSMTRootDiverged: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (8) Counter monotonicity across mixed-outcome ticks
// ─────────────────────────────────────────────────────────────────────

func TestSMTDetector_Tick_CountersAccumulateAcrossMixedOutcomes(t *testing.T) {
	state := &fakeSMTRootState{}
	heads := newFakeHeadStore()
	d := NewSMTDetector(state, heads, SMTDetectorConfig{Logger: discardLoggerSMT()})

	// Cycle 1: skip (pre-first-batch)
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}

	// Cycle 2: skip (state advanced, no cosigned head yet)
	state.set([32]byte{0xAA}, 10)
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}

	// Cycle 3: verify (head lands matching the state)
	heads.put(10, [32]byte{0xAA})
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("cycle 3: %v", err)
	}

	// Cycle 4: verify again at the same seq (idempotent)
	if err := d.Tick(context.Background()); err != nil {
		t.Fatalf("cycle 4: %v", err)
	}

	if got := d.SamplesSkipped(); got != 2 {
		t.Errorf("SamplesSkipped = %d, want 2", got)
	}
	if got := d.SamplesVerified(); got != 2 {
		t.Errorf("SamplesVerified = %d, want 2", got)
	}
	if got := d.InvariantFailures(); got != 0 {
		t.Errorf("InvariantFailures = %d, want 0", got)
	}
}
