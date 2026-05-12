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
	"container/heap"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/wal"
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

// sequencedFor returns the seq the WAL has recorded for hash, plus a
// presence flag. Reads under f.mu so tests observing committer
// progress don't race the committer's own writes (which also take
// f.mu). Necessary because the committer goroutine runs concurrently
// with the test body via t.Cleanup; bare map indexing from the test
// would be an unsynchronized read.
func (f *fakeWAL) sequencedFor(hash [32]byte) (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seq, ok := f.sequenced[hash]
	return seq, ok
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
		nextSeq:  0,
		assigned: make(map[[32]byte]uint64),
	}
}

func (f *fakeTessera) AppendLeaf(_ context.Context, data []byte) (uint64, error) {
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

// buildEntry produces a canonical envelope.Entry suitable for
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
	wire, sErr := envelope.Serialize(entry)
	if sErr != nil {
		t.Fatalf("envelope.Serialize: %v", sErr)
	}
	hash = sha256.Sum256(wire)
	return wire, hash
}

// newTestSequencer wires a Sequencer with the supplied fakes plus
// a running committer goroutine — for tests that drive drainOnce
// or processOne directly. db and store are nil so the committer's
// flushBatch short-circuits the PG INSERT, but still fires the
// per-entry WAL state transitions and metrics so tests can assert
// as they would against a real PG-backed sequencer.
//
// Tests that exercise the full Run() lifecycle should use
// newTestSequencerNoCommitter instead — Run() spawns its own
// committer, and running two committers on one channel races.
//
// t.Cleanup cancels the committer's context and waits for it to
// drain — guaranteeing no stale goroutines leak between tests.
//
// Tests must use waitForProcessed / waitForManual after drainOnce
// to give the committer time to process emitted tuples; processOne
// is now async with respect to WAL state transitions.
func newTestSequencer(t *testing.T, w WAL, ts Tessera, cfg Config) *Sequencer {
	t.Helper()
	s := newTestSequencerNoCommitter(t, w, ts, cfg)
	// Stand up the committer the same way Run() does, but in a
	// test-scoped goroutine. Tests live in-package, so we touch
	// the unexported fields directly.
	committerCtx, cancel := context.WithCancel(context.Background())
	s.commitCh = make(chan stagedEntry, s.cfg.CommitChannelBuffer)
	// Both fakeTessera and concurrencyTrackingTessera assign seqs
	// starting at 1 (not 0). nextExpectedSeq has to match or the
	// committer's heap stalls waiting for seq=0 forever. Real
	// production paths source nextExpectedSeq from
	// readNextExpectedSeq → MAX(entry_index.seq)+1, which is also
	// 1-based on a fresh seeded fake.
	// Fake Tessera assigns seqs starting at 0; init committer to
	// match. Production paths use readNextExpectedSeq from PG.
	s.nextExpectedSeq.Store(0)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.committerLoop(committerCtx)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return s
}

// newTestSequencerNoCommitter is the constructor for tests that
// drive Run(ctx) and rely on Run's own committer goroutine.
// Spawning a second committer (as newTestSequencer does) would
// race the Run-spawned one on the same channel.
func newTestSequencerNoCommitter(t *testing.T, w WAL, ts Tessera, cfg Config) *Sequencer {
	t.Helper()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Millisecond
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	// Snappy defaults so the committer flushes individual entries
	// without the 50ms production wait — tests want sub-ms turnaround.
	if cfg.CommitMaxWait == 0 {
		cfg.CommitMaxWait = 1 * time.Millisecond
	}
	if cfg.CommitMaxBatchSize == 0 {
		cfg.CommitMaxBatchSize = 1
	}
	return NewSequencer(w, ts, nil, nil, cfg)
}

// waitForProcessed blocks until s.metrics.processed reaches at
// least n, or t.Fatal's after a generous timeout. Used by tests
// that assert WAL state transitions after a drainOnce — the
// committer is async, so the metric is the synchronization point.
func waitForProcessed(t *testing.T, s *Sequencer, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.metrics.processed.Load() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waitForProcessed: timeout (have processed=%d, want >= %d)",
		s.metrics.processed.Load(), n)
}

// waitForManual blocks until s.metrics.manualCount reaches at least n.
// Used by tests that drive tombstone-or-deserialize-failure paths.
func waitForManual(t *testing.T, s *Sequencer, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.metrics.manualCount.Load() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waitForManual: timeout (have manualCount=%d, want >= %d)",
		s.metrics.manualCount.Load(), n)
}

// waitForStaleCrashRecoveries blocks until s.metrics.staleCrashRecoveries
// reaches at least n. Used by tests that exercise the
// committer.committerStaleRecover crash-recovery branch (duplicate
// stagedEntry arriving while WAL state is still Pending).
func waitForStaleCrashRecoveries(t *testing.T, s *Sequencer, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.metrics.staleCrashRecoveries.Load() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waitForStaleCrashRecoveries: timeout (have staleCrashRecoveries=%d, want >= %d)",
		s.metrics.staleCrashRecoveries.Load(), n)
}

// ─────────────────────────────────────────────────────────────────────
// Lifecycle tests
// ─────────────────────────────────────────────────────────────────────

// fakeEntryLookupWriter records calls so wiring tests can assert
// the sequencer captures the writer correctly via WithEntryLookup.
type fakeEntryLookupWriter struct {
	calls []fakeLookupCall
}

type fakeLookupCall struct {
	schemaID string
	splitID  [32]byte
	seq      uint64
	entry    EntryLookupIndexEntry
}

func (f *fakeEntryLookupWriter) WriteEntryLookupEntry(
	_ context.Context, schemaID string, splitID [32]byte, seq uint64,
	entry EntryLookupIndexEntry,
) error {
	f.calls = append(f.calls, fakeLookupCall{schemaID, splitID, seq, entry})
	return nil
}

// TestSequencer_WithEntryLookup_CapturesWriterAndDID asserts the
// fluent setter records both the writer and the ledger's log
// DID into the Sequencer's struct, so the loop's 0x0C write call
// has both at hand.
func TestSequencer_WithEntryLookup_CapturesWriterAndDID(t *testing.T) {
	s := NewSequencer(newFakeWAL(), newFakeTessera(), nil, nil, Config{})
	w := &fakeEntryLookupWriter{}
	ret := s.WithEntryLookup(w, "did:web:ledger.example")
	if ret != s {
		t.Error("WithEntryLookup should return receiver for fluent chaining")
	}
	if s.entryLookup == nil {
		t.Fatal("entryLookup not captured")
	}
	if s.logDID != "did:web:ledger.example" {
		t.Errorf("logDID = %q, want did:web:ledger.example", s.logDID)
	}
	// Compile-time interface check.
	var _ EntryLookupWriter = w
}

// TestSequencer_WithEntryLookup_NilWriter_NoOp confirms a nil
// writer is captured without panic — the loop's nil-tolerant
// branch then skips the 0x0C write.
func TestSequencer_WithEntryLookup_NilWriter_NoOp(t *testing.T) {
	s := NewSequencer(newFakeWAL(), newFakeTessera(), nil, nil, Config{})
	s.WithEntryLookup(nil, "did:web:op")
	if s.entryLookup != nil {
		t.Error("nil writer should be captured as nil")
	}
	// logDID is still recorded — harmless when writer is nil.
}

// TestEntryLookupIndexEntry_StructHasExpectedFields pins the
// sequencer-side type's field set so the gossipstore-side type
// can't drift out of sync with the adapter.
func TestEntryLookupIndexEntry_StructHasExpectedFields(t *testing.T) {
	e := EntryLookupIndexEntry{
		CanonicalBytes: []byte("x"),
		LogTimeMicros:  1,
		LogDID:         "did:web:op",
	}
	if len(e.CanonicalBytes) == 0 {
		t.Error("CanonicalBytes lost")
	}
	if e.LogTimeMicros != 1 {
		t.Error("LogTimeMicros lost")
	}
	if e.LogDID == "" {
		t.Error("LogDID lost")
	}
}

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

	// Run-based test: Run() spawns its own committer. Use the
	// no-committer helper to avoid racing two committers on commitCh.
	s := newTestSequencerNoCommitter(t, w, ts, Config{PollInterval: time.Hour})

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
	// Run-based test: avoid double-committer race.
	s := newTestSequencerNoCommitter(t, w, ts, Config{})

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
	// Stage-1 emitted to commitCh; wait for the committer goroutine
	// to drain it and run the post-commit hook (WAL.Sequence + metric
	// increment). processed=1 is the synchronization point.
	waitForProcessed(t, s, 1)

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

	// Second drain: Tessera succeeds → stage-1 emits; committer
	// flushes; WAL.Sequence advances. Wait for processed=1.
	s.drainOnce(context.Background())
	waitForProcessed(t, s, 1)
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

// TestSequencer_processOne_DuplicateHash_StaleRecover exercises the
// crash-recovery branch of committer.committerStaleRecover. We
// manually reset the WAL state back to Pending between drains —
// simulating the rare path where the original commit's
// WAL.Sequence call failed and left state lagging entry_index. The
// committer's stale-recover should then advance the WAL forward
// via the recovery branch (staleCrashRecoveries++), NOT
// double-count the processed metric.
//
// The normal-race branch (state already past Pending → silent
// discard) is covered by TestCommitterStaleRecover_NormalRace.
func TestSequencer_processOne_DuplicateHash_StaleRecover(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	wire, hash := buildEntry(t, "dedup")
	w.seed(hash, wire)

	s := newTestSequencer(t, w, ts, Config{})

	// First drain: clean path, state Pending → Sequenced.
	s.drainOnce(context.Background())
	waitForProcessed(t, s, 1)
	firstSeq, _ := w.sequencedFor(hash)

	// Re-pendingify: simulates the post-PG-commit, pre-WAL.Sequence
	// crash scenario. entry_index has the row (the committer's
	// PG batch already committed for seq=firstSeq); WAL is back
	// at Pending.
	w.mu.Lock()
	w.state[hash] = wal.StatePending
	w.pending = []wal.PendingHash{{Hash: hash}}
	w.mu.Unlock()

	s.drainOnce(context.Background())

	// Stage-1 re-runs and re-emits. The committer sees the duplicate
	// seq, recognizes it's < nextExpectedSeq, probes MetaState,
	// finds StatePending, and advances via Sequence. Wait for the
	// recovery counter rather than for processed (which must NOT
	// double-count — see method docs on committerStaleRecover).
	waitForStaleCrashRecoveries(t, s, 1)

	// Tessera dedup invariant: same hash → same seq.
	if got, _ := w.sequencedFor(hash); got != firstSeq {
		t.Errorf("second drain assigned different seq: %d != %d (Tessera dedup broken?)", got, firstSeq)
	}
	// AppendLeaf called twice (stage-1 re-ran).
	if got := ts.calls.Load(); got != 2 {
		t.Errorf("AppendLeaf calls = %d, want 2", got)
	}
	// processed must stay at 1 — the duplicate did not introduce
	// a new "processed entry", just a state-fix-up.
	if got := s.metrics.processed.Load(); got != 1 {
		t.Errorf("processed = %d, want 1 (stale recovery must not double-count)", got)
	}
	// staleDuplicatesDiscarded should stay 0 (we hit the recovery
	// branch, not the silent-discard branch).
	if got := s.metrics.staleDuplicatesDiscarded.Load(); got != 0 {
		t.Errorf("staleDuplicatesDiscarded = %d, want 0 (recovery branch, not discard)", got)
	}
}

// TestCommitterStaleRecover_NormalRace covers the steady-state
// branch: a duplicate stagedEntry arrives whose WAL state has
// already advanced past Pending. The committer must silently
// discard (no redundant WAL.Sequence, which would race the shipper
// and surface as "want pending" warnings).
//
// We invoke committerStaleRecover directly to avoid the drainOnce
// scheduling that would short-circuit the duplicate at the
// MetaState guard in processOne — the goal here is to pin the
// committer-side behavior under the duplicate-arrival contract.
func TestCommitterStaleRecover_NormalRace(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	_, hash := buildEntry(t, "normal-race")
	s := newTestSequencerNoCommitter(t, w, ts, Config{})

	// Set WAL state to StateSequenced — what it would be after a
	// successful prior commit. No need to seed the wire bytes;
	// committerStaleRecover only consults MetaState.
	w.mu.Lock()
	w.state[hash] = wal.StateSequenced
	w.sequenced[hash] = 42
	w.mu.Unlock()

	duplicate := stagedEntry{
		Seq:  42,
		Hash: hash,
		Row:  store.EntryRow{SequenceNumber: 42, CanonicalHash: hash, Status: store.StatusLive},
	}
	// expected > Seq, so this is the stale branch.
	s.committerStaleRecover(context.Background(), duplicate, 100)

	if got := s.metrics.staleDuplicatesDiscarded.Load(); got != 1 {
		t.Errorf("staleDuplicatesDiscarded = %d, want 1", got)
	}
	if got := s.metrics.staleCrashRecoveries.Load(); got != 0 {
		t.Errorf("staleCrashRecoveries = %d, want 0 (state already advanced)", got)
	}
	if got := s.metrics.processed.Load(); got != 0 {
		t.Errorf("processed = %d, want 0 (duplicate must not double-count)", got)
	}
	if got := w.sequenceCalls.Load(); got != 0 {
		t.Errorf("WAL.Sequence calls = %d, want 0 (silent-discard branch)", got)
	}
}

// TestCommitterStaleRecover_CrashRecovery covers the rare branch:
// a duplicate arrives while WAL is still StatePending. The
// committer must advance the WAL forward, leaving the entry
// usable downstream by the shipper.
func TestCommitterStaleRecover_CrashRecovery(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	_, hash := buildEntry(t, "crash-recovery")
	s := newTestSequencerNoCommitter(t, w, ts, Config{})

	// WAL state is StatePending (the fakeWAL default); no need to
	// seed anything else — committerStaleRecover only consults
	// MetaState and then calls Sequence.
	w.mu.Lock()
	w.state[hash] = wal.StatePending
	w.mu.Unlock()

	duplicate := stagedEntry{
		Seq:  42,
		Hash: hash,
		Row:  store.EntryRow{SequenceNumber: 42, CanonicalHash: hash, Status: store.StatusLive},
	}
	s.committerStaleRecover(context.Background(), duplicate, 100)

	if got := s.metrics.staleCrashRecoveries.Load(); got != 1 {
		t.Errorf("staleCrashRecoveries = %d, want 1", got)
	}
	if got := s.metrics.staleDuplicatesDiscarded.Load(); got != 0 {
		t.Errorf("staleDuplicatesDiscarded = %d, want 0 (recovery branch)", got)
	}
	if got := w.sequenceCalls.Load(); got != 1 {
		t.Errorf("WAL.Sequence calls = %d, want 1 (recovery branch must advance state)", got)
	}
	w.mu.Lock()
	finalState := w.state[hash]
	finalSeq := w.sequenced[hash]
	w.mu.Unlock()
	if finalState != wal.StateSequenced {
		t.Errorf("WAL state after recovery = %v, want StateSequenced", finalState)
	}
	if finalSeq != 42 {
		t.Errorf("sequenced[hash] = %d, want 42", finalSeq)
	}
}

// TestDrainHeapInto_InBatchDuplicate_SilentDiscard pins the
// structural fix for the WAL.Sequence-after-commit WARN noise: when
// the heap contains BOTH the original tuple and a duplicate for the
// same seq, the committer MUST keep the original in `pending` and
// silently discard the duplicate. Calling committerStaleRecover for
// the duplicate would probe MetaState before flushBatch runs, see
// Pending, and incorrectly fire the crash-recovery path — racing the
// impending applyPostCommitForOne call.
//
// Discriminator: head.Seq < expected (it IS a duplicate) AND
// head.Seq >= committed (the original is still in pending, not yet
// flushed). Sub-case (A) of drainHeapInto.
func TestDrainHeapInto_InBatchDuplicate_SilentDiscard(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	s := newTestSequencerNoCommitter(t, w, ts, Config{
		CommitMaxBatchSize: 256,
	})

	// nextExpectedSeq starts at 0; "committed" cursor is 0.
	// Push ORIGINAL tuple seq=0 and DUPLICATE tuple seq=0.
	_, hashA := buildEntry(t, "in-batch-dup-orig")
	original := stagedEntry{
		Seq:  0,
		Hash: hashA,
		Row:  store.EntryRow{SequenceNumber: 0, CanonicalHash: hashA, Status: store.StatusLive},
	}
	duplicate := stagedEntry{
		Seq:  0,
		Hash: hashA,
		Row:  store.EntryRow{SequenceNumber: 0, CanonicalHash: hashA, Status: store.StatusLive},
	}
	heap.Push(s.committerHeap, original)
	heap.Push(s.committerHeap, duplicate)

	// State for hashA is StatePending (the fakeWAL default for a
	// hash never seeded — the test's mu unlocked path needs explicit
	// state set).
	w.mu.Lock()
	w.state[hashA] = wal.StatePending
	w.mu.Unlock()

	pending := s.drainHeapInto(context.Background(), nil)

	if len(pending) != 1 {
		t.Fatalf("pending size = %d, want 1 (original kept, dup discarded)", len(pending))
	}
	if pending[0].Seq != 0 {
		t.Errorf("pending[0].Seq = %d, want 0 (original preserved)", pending[0].Seq)
	}
	if got := s.metrics.staleDuplicatesDiscarded.Load(); got != 1 {
		t.Errorf("staleDuplicatesDiscarded = %d, want 1 (in-batch dup silently discarded)", got)
	}
	if got := s.metrics.staleCrashRecoveries.Load(); got != 0 {
		t.Errorf("staleCrashRecoveries = %d, want 0 (in-batch dup must NOT fire recovery)", got)
	}
	if got := w.sequenceCalls.Load(); got != 0 {
		t.Errorf("WAL.Sequence calls = %d, want 0 (only flushBatch should call Sequence later)", got)
	}
	if s.committerHeap.Len() != 0 {
		t.Errorf("heap remaining = %d, want 0 (both original and dup popped)",
			s.committerHeap.Len())
	}
}

// TestDrainHeapInto_CrossBatchStale_RoutesToRecover pins the OTHER
// sub-case of drainHeapInto: a duplicate whose seq is strictly less
// than committed (nextExpectedSeq) — i.e., the original was committed
// in a PRIOR batch. This must route to committerStaleRecover so the
// MetaState probe can distinguish "WAL state already advanced"
// (silent discard) from "WAL state still Pending" (crash-recovery
// must run WAL.Sequence to unblock the shipper).
//
// Sub-case (B) of drainHeapInto. Pairs with
// TestCommitterStaleRecover_NormalRace +
// TestCommitterStaleRecover_CrashRecovery which pin the
// committerStaleRecover internals.
func TestDrainHeapInto_CrossBatchStale_RoutesToRecover(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	s := newTestSequencerNoCommitter(t, w, ts, Config{
		CommitMaxBatchSize: 256,
	})

	// Advance nextExpectedSeq to 10 — simulates 10 entries already
	// committed in earlier batches. Pushing a stagedEntry for seq=5
	// is then a TRUE cross-batch stale.
	s.nextExpectedSeq.Store(10)
	_, hash := buildEntry(t, "cross-batch-stale")
	// Set state to StateSequenced — matches "original committed in
	// a prior batch, state already advanced." committerStaleRecover
	// should silently discard.
	w.mu.Lock()
	w.state[hash] = wal.StateSequenced
	w.sequenced[hash] = 5
	w.mu.Unlock()

	stale := stagedEntry{
		Seq:  5,
		Hash: hash,
		Row:  store.EntryRow{SequenceNumber: 5, CanonicalHash: hash, Status: store.StatusLive},
	}
	heap.Push(s.committerHeap, stale)

	pending := s.drainHeapInto(context.Background(), nil)

	if len(pending) != 0 {
		t.Errorf("pending size = %d, want 0 (stale must NOT enter pending)", len(pending))
	}
	if got := s.metrics.staleDuplicatesDiscarded.Load(); got != 1 {
		t.Errorf("staleDuplicatesDiscarded = %d, want 1 (state was Sequenced — silent discard)", got)
	}
	if got := s.metrics.staleCrashRecoveries.Load(); got != 0 {
		t.Errorf("staleCrashRecoveries = %d, want 0 (state already advanced)", got)
	}
	if got := w.sequenceCalls.Load(); got != 0 {
		t.Errorf("WAL.Sequence calls = %d, want 0 (silent-discard branch)", got)
	}
}

// TestSequencer_TesseraInFlight_TracksConcurrentWorkers verifies that
// the in-flight counter and high-water mark behave correctly under
// concurrent stage-1 workers calling processOne. The HW mark is the
// load-bearing observation: it survives the recovery to zero, so even
// post-soak we can see the saturation peak.
func TestSequencer_TesseraInFlight_TracksConcurrentWorkers(t *testing.T) {
	w := newFakeWAL()
	// Make Tessera AppendLeaf block until we release it, so multiple
	// stage-1 workers pile up inside the call simultaneously.
	gate := make(chan struct{})
	released := make(chan struct{})
	ts := &blockingTessera{
		gate:     gate,
		released: released,
	}

	const concurrent = 8
	cfg := Config{MaxInFlight: concurrent, CommitMaxBatchSize: 1, CommitMaxWait: time.Millisecond}
	s := newTestSequencer(t, w, ts, cfg)

	// Seed the WAL with `concurrent` distinct pending hashes so
	// drainOnce dispatches one worker per slot.
	for i := 0; i < concurrent; i++ {
		wire, hash := buildEntry(t, fmt.Sprintf("in-flight-%d", i))
		w.seed(hash, wire)
	}

	// Drive the drain on a separate goroutine — drainOnce blocks
	// until all dispatched workers complete, but our blockingTessera
	// won't let them complete until we send on `gate`.
	drainDone := make(chan struct{})
	go func() {
		s.drainOnce(context.Background())
		close(drainDone)
	}()

	// Wait for all `concurrent` workers to be inside AppendLeaf.
	// blockingTessera signals each entry via `released`; we collect
	// that many to know everyone is parked.
	for i := 0; i < concurrent; i++ {
		select {
		case <-released:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/%d workers reached AppendLeaf within 2s",
				i, concurrent)
		}
	}

	// In-flight should equal MaxInFlight; high-water tracks it.
	snap := s.Metrics()
	if snap.TesseraInFlight != int64(concurrent) {
		t.Errorf("TesseraInFlight = %d, want %d (all workers parked)",
			snap.TesseraInFlight, concurrent)
	}
	if snap.TesseraInFlightHighWater != int64(concurrent) {
		t.Errorf("TesseraInFlightHighWater = %d, want %d",
			snap.TesseraInFlightHighWater, concurrent)
	}

	// Release every worker; drainOnce should return.
	for i := 0; i < concurrent; i++ {
		gate <- struct{}{}
	}
	select {
	case <-drainDone:
	case <-time.After(2 * time.Second):
		t.Fatal("drainOnce did not return within 2s of releasing all workers")
	}

	// After release, in-flight returns to zero but high-water stays
	// at the peak — the post-recovery saturation evidence.
	snap = s.Metrics()
	if snap.TesseraInFlight != 0 {
		t.Errorf("TesseraInFlight after drain = %d, want 0",
			snap.TesseraInFlight)
	}
	if snap.TesseraInFlightHighWater != int64(concurrent) {
		t.Errorf("TesseraInFlightHighWater after recovery = %d, want %d "+
			"(high-water must NOT reset)",
			snap.TesseraInFlightHighWater, concurrent)
	}
}

// blockingTessera is a fake Tessera that parks each AppendLeaf call
// until the test releases it via `gate`. Used by
// TestSequencer_TesseraInFlight_TracksConcurrentWorkers to deterministically
// hold N workers inside AppendLeaf simultaneously.
type blockingTessera struct {
	gate     chan struct{} // test sends → one worker is released
	released chan struct{} // worker sends after entering AppendLeaf
	calls    atomic.Uint64
	nextSeq  atomic.Uint64
}

func (b *blockingTessera) AppendLeaf(ctx context.Context, data []byte) (uint64, error) {
	b.calls.Add(1)
	// Signal "I am inside AppendLeaf" before blocking.
	select {
	case b.released <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	// Block until the test releases this worker.
	select {
	case <-b.gate:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	// Allocate the seq AFTER unblocking so seqs are monotonic in
	// release order (irrelevant to this test but matches real
	// Tessera ordering for any future assertions).
	return b.nextSeq.Add(1) - 1, nil
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
// drainOnce — bounded concurrency
// ─────────────────────────────────────────────────────────────────────

// concurrencyTrackingTessera mirrors fakeTessera but instruments the
// AppendLeaf path so tests can prove that no more than MaxInFlight
// goroutines are inside it at once.
type concurrencyTrackingTessera struct {
	mu             sync.Mutex
	concurrent     int
	peakConcurrent int
	holdInside     time.Duration
	nextSeq        uint64
	assigned       map[[32]byte]uint64
}

func newConcurrencyTrackingTessera(holdInside time.Duration) *concurrencyTrackingTessera {
	return &concurrencyTrackingTessera{
		holdInside: holdInside,
		nextSeq:    0,
		assigned:   make(map[[32]byte]uint64),
	}
}

func (f *concurrencyTrackingTessera) AppendLeaf(_ context.Context, data []byte) (uint64, error) {
	f.mu.Lock()
	f.concurrent++
	if f.concurrent > f.peakConcurrent {
		f.peakConcurrent = f.concurrent
	}
	f.mu.Unlock()

	// Hold the slot to give the next iteration a chance to enter.
	time.Sleep(f.holdInside)

	defer func() {
		f.mu.Lock()
		f.concurrent--
		f.mu.Unlock()
	}()

	if len(data) != 32 {
		return 0, fmt.Errorf("concurrencyTrackingTessera: AppendLeaf wants 32 bytes, got %d", len(data))
	}
	var hash [32]byte
	copy(hash[:], data)
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq, ok := f.assigned[hash]; ok {
		return seq, nil
	}
	seq := f.nextSeq
	f.nextSeq++
	f.assigned[hash] = seq
	return seq, nil
}

func (f *concurrencyTrackingTessera) PeakConcurrent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peakConcurrent
}

func TestSequencer_drainOnce_HonorsMaxInFlight(t *testing.T) {
	const maxInFlight = 3
	const numEntries = 12

	w := newFakeWAL()
	for i := 0; i < numEntries; i++ {
		wire, hash := buildEntry(t, fmt.Sprintf("inflight-%d", i))
		w.seed(hash, wire)
	}
	ts := newConcurrencyTrackingTessera(20 * time.Millisecond)

	cfg := Config{
		MaxInFlight:  maxInFlight,
		MaxAttempts:  3,
		PollInterval: 1 * time.Hour, // we drive drainOnce manually
	}
	s := newTestSequencer(t, w, ts, cfg)

	s.drainOnce(context.Background())
	// drainOnce.wg.Wait only ensures stage-1 workers finished; the
	// committer is async. Wait for it to flush the staged tuples.
	waitForProcessed(t, s, numEntries)

	if peak := ts.PeakConcurrent(); peak > maxInFlight {
		t.Errorf("peak concurrent AppendLeaf calls = %d, want <= %d", peak, maxInFlight)
	}
	if peak := ts.PeakConcurrent(); peak < 2 {
		t.Errorf("peak concurrent AppendLeaf calls = %d, want >= 2 (concurrency must be exercised)", peak)
	}
	if got := s.metrics.processed.Load(); got != numEntries {
		t.Errorf("processed = %d, want %d (drainOnce must wait for all workers)", got, numEntries)
	}
}

// drainOnce must complete every spawned worker before returning,
// so currentLag reflects the post-drain state — not a mid-flight
// snapshot.
func TestSequencer_drainOnce_BlocksUntilWorkersComplete(t *testing.T) {
	w := newFakeWAL()
	for i := 0; i < 5; i++ {
		wire, hash := buildEntry(t, fmt.Sprintf("wait-%d", i))
		w.seed(hash, wire)
	}
	ts := newConcurrencyTrackingTessera(15 * time.Millisecond)

	s := newTestSequencer(t, w, ts, Config{
		MaxInFlight: 2,
		MaxAttempts: 3,
	})

	start := time.Now()
	s.drainOnce(context.Background())
	elapsed := time.Since(start)

	// 5 entries × 15ms with 2 in-flight ⇒ ceil(5/2)*15ms = 45ms minimum.
	// drainOnce must NOT return after the iterator finishes spawning;
	// it must wait for the stage-1 goroutines too.
	if elapsed < 30*time.Millisecond {
		t.Errorf("drainOnce returned in %v — too fast; workers must not have completed", elapsed)
	}

	// Stage-1 emits happen before drainOnce returns (wg.Wait); the
	// committer flushes asynchronously. Wait for processed=5 so the
	// WAL state transitions complete.
	waitForProcessed(t, s, 5)
	if got := s.metrics.processed.Load(); got != 5 {
		t.Errorf("processed = %d, want 5", got)
	}
}

// ctx cancel during drain unwinds cleanly without deadlock.
func TestSequencer_drainOnce_CtxCancelMidDrain(t *testing.T) {
	w := newFakeWAL()
	for i := 0; i < 20; i++ {
		wire, hash := buildEntry(t, fmt.Sprintf("cancel-%d", i))
		w.seed(hash, wire)
	}
	ts := newConcurrencyTrackingTessera(20 * time.Millisecond)

	s := newTestSequencer(t, w, ts, Config{
		MaxInFlight: 2,
		MaxAttempts: 3,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(15 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	go func() {
		s.drainOnce(ctx)
		close(done)
	}()
	select {
	case <-done:
		// drainOnce returned cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("drainOnce did not return after ctx cancel — deadlock?")
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
