/*
FILE PATH: sequencer/replay_test.go

Unit-level coverage for the sequencer.Replayer (PT-4):

  - NewReplayer config validation: every required field is checked.
  - BatchSize defaults to DefaultReplayBatchSize when zero.
  - applyOne reads canonical bytes from the supplied bytestore.Reader,
    deserializes the entry, and writes both 0x0A + 0x0C with the
    correct field mapping.
  - applyOne propagates per-step errors with descriptive context.
  - Run-time wiring (Sequencer.WithReplayer + Run goroutine drain on
    ctx cancellation) is covered in sequencer_test.go.

The full SELECT loop (fetchBatch) is covered by an integration
test in integration/replay_test.go (requires ATTESTA_TEST_DSN).
This file uses fakes so the suite stays Postgres-free.
*/
package sequencer

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/ledger/bytestore"
)

// ─────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────

// fakeBytestoreReader satisfies bytestore.Reader for replay tests.
type fakeBytestoreReader struct {
	bytesByHash map[[32]byte][]byte
	readErr     error
}

func (f *fakeBytestoreReader) ReadEntry(_ context.Context, _ uint64, hash [32]byte) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	b, ok := f.bytesByHash[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

func (f *fakeBytestoreReader) ReadEntryBatch(_ context.Context, refs []bytestore.EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		b, err := f.ReadEntry(nil, r.Seq, r.Hash)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// fakeSplitIDWriter records calls.
type fakeSplitIDWriter struct {
	calls   []splitWriteCall
	failErr error
}

type splitWriteCall struct {
	schemaID string
	splitID  [32]byte
	seq      uint64
	entry    SplitIDIndexEntry
}

func (f *fakeSplitIDWriter) WriteSplitIDIndexEntry(
	_ context.Context, schemaID string, splitID [32]byte, seq uint64,
	entry SplitIDIndexEntry,
) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.calls = append(f.calls, splitWriteCall{schemaID, splitID, seq, entry})
	return nil
}

// fakeLookupWriter records calls.
type fakeLookupWriter struct {
	calls   []lookupWriteCall
	failErr error
}

type lookupWriteCall struct {
	schemaID string
	splitID  [32]byte
	seq      uint64
	entry    EntryLookupIndexEntry
}

func (f *fakeLookupWriter) WriteEntryLookupEntry(
	_ context.Context, schemaID string, splitID [32]byte, seq uint64,
	entry EntryLookupIndexEntry,
) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.calls = append(f.calls, lookupWriteCall{schemaID, splitID, seq, entry})
	return nil
}

// fakeReplayCursor implements SplitIDReplayCursor.
type fakeReplayCursor struct {
	hwm    uint64
	getErr error
	setErr error
}

func (f *fakeReplayCursor) SplitIDReplayHWM(_ context.Context) (uint64, error) {
	return f.hwm, f.getErr
}

func (f *fakeReplayCursor) SetSplitIDReplayHWM(_ context.Context, seq uint64) error {
	if f.setErr != nil {
		return f.setErr
	}
	if seq > f.hwm {
		f.hwm = seq
	}
	return nil
}

func discardReplayLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// buildReplayEntry produces a v7.75-shape envelope, returns the
// canonical wire bytes + the SHA-256 hash, suitable for stuffing
// into a fake bytestore for applyOne tests.
func buildReplayEntry(t *testing.T, payload string) (wire []byte, hash [32]byte) {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:operator",
		Destination: "did:test:log",
		EventTime:   1714659120_000000,
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte(payload))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     []byte("ecdsa-sig-stub"),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wire = envelope.Serialize(entry)
	hash = sha256.Sum256(wire)
	return wire, hash
}

// ─────────────────────────────────────────────────────────────────────
// NewReplayer config validation
// ─────────────────────────────────────────────────────────────────────

// stubPool is the zero-value *pgxpool.Pool. NewReplayer's nil-check
// only tests for nil pointers; the field's internal state is never
// dereferenced in NewReplayer. Sufficient for validating the OTHER
// required-field errors.
func stubPool() *pgxpool.Pool { return &pgxpool.Pool{} }

func TestNewReplayer_RejectsMissingDeps(t *testing.T) {
	good := ReplayConfig{
		DB:           stubPool(),
		Reader:       &fakeBytestoreReader{},
		SplitIDIndex: &fakeSplitIDWriter{},
		EntryLookup:  &fakeLookupWriter{},
		Cursor:       &fakeReplayCursor{},
		LogDID:       "did:web:op",
	}

	cases := []struct {
		name    string
		mutate  func(*ReplayConfig)
		wantErr string
	}{
		{"missing DB", func(c *ReplayConfig) { c.DB = nil }, "DB required"},
		{"missing Reader", func(c *ReplayConfig) { c.Reader = nil }, "Reader required"},
		{"missing SplitIDIndex", func(c *ReplayConfig) { c.SplitIDIndex = nil }, "SplitIDIndex required"},
		{"missing EntryLookup", func(c *ReplayConfig) { c.EntryLookup = nil }, "EntryLookup required"},
		{"missing Cursor", func(c *ReplayConfig) { c.Cursor = nil }, "Cursor required"},
		{"empty LogDID", func(c *ReplayConfig) { c.LogDID = "" }, "LogDID required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.mutate(&cfg)
			_, err := NewReplayer(cfg)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if got := err.Error(); !contains(got, tc.wantErr) {
				t.Errorf("error %q does not mention %q", got, tc.wantErr)
			}
		})
	}
}

func TestNewReplayer_DefaultsBatchSize(t *testing.T) {
	cfg := ReplayConfig{
		DB:           stubPool(),
		Reader:       &fakeBytestoreReader{},
		SplitIDIndex: &fakeSplitIDWriter{},
		EntryLookup:  &fakeLookupWriter{},
		Cursor:       &fakeReplayCursor{},
		LogDID:       "did:web:op",
		BatchSize:    0,
	}
	r, err := NewReplayer(cfg)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if r.cfg.BatchSize != DefaultReplayBatchSize {
		t.Errorf("BatchSize = %d, want %d (default)",
			r.cfg.BatchSize, DefaultReplayBatchSize)
	}
}

func TestNewReplayer_HonorsExplicitBatchSize(t *testing.T) {
	cfg := ReplayConfig{
		DB:           stubPool(),
		Reader:       &fakeBytestoreReader{},
		SplitIDIndex: &fakeSplitIDWriter{},
		EntryLookup:  &fakeLookupWriter{},
		Cursor:       &fakeReplayCursor{},
		LogDID:       "did:web:op",
		BatchSize:    50,
	}
	r, err := NewReplayer(cfg)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if r.cfg.BatchSize != 50 {
		t.Errorf("BatchSize = %d, want 50", r.cfg.BatchSize)
	}
}

func TestNewReplayer_DefaultsLogger(t *testing.T) {
	cfg := ReplayConfig{
		DB:           stubPool(),
		Reader:       &fakeBytestoreReader{},
		SplitIDIndex: &fakeSplitIDWriter{},
		EntryLookup:  &fakeLookupWriter{},
		Cursor:       &fakeReplayCursor{},
		LogDID:       "did:web:op",
	}
	r, err := NewReplayer(cfg)
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if r.logger == nil {
		t.Error("Logger should default to slog.Default()")
	}
}

// ─────────────────────────────────────────────────────────────────────
// applyOne happy path + error propagation
// ─────────────────────────────────────────────────────────────────────

func TestReplayer_applyOne_HappyPath(t *testing.T) {
	wire, hash := buildReplayEntry(t, "replay-payload")
	reader := &fakeBytestoreReader{
		bytesByHash: map[[32]byte][]byte{hash: wire},
	}
	splitW := &fakeSplitIDWriter{}
	lookupW := &fakeLookupWriter{}

	r := &Replayer{
		cfg: ReplayConfig{
			Reader:       reader,
			SplitIDIndex: splitW,
			EntryLookup:  lookupW,
			LogDID:       "did:web:operator",
		},
		logger: discardReplayLog(),
	}

	row := replayRow{
		seq:      42,
		schemaID: "schema-x",
		splitID:  [32]byte{0xab, 0xcd},
		signer:   "did:test:operator",
		hash:     hash,
		logTime:  1714659120_000000,
	}

	if err := r.applyOne(context.Background(), row); err != nil {
		t.Fatalf("applyOne: %v", err)
	}

	if len(splitW.calls) != 1 {
		t.Fatalf("split writes = %d, want 1", len(splitW.calls))
	}
	c := splitW.calls[0]
	if c.schemaID != row.schemaID {
		t.Errorf("split schemaID = %q", c.schemaID)
	}
	if c.splitID != row.splitID {
		t.Errorf("split splitID drift")
	}
	if c.seq != row.seq {
		t.Errorf("split seq = %d", c.seq)
	}
	if c.entry.EquivocatorDID != row.signer {
		t.Errorf("EquivocatorDID = %q", c.entry.EquivocatorDID)
	}
	if c.entry.CanonicalHash != row.hash {
		t.Errorf("CanonicalHash drift")
	}
	if string(c.entry.SigBytes) != "ecdsa-sig-stub" {
		t.Errorf("SigBytes drift: %x", c.entry.SigBytes)
	}

	if len(lookupW.calls) != 1 {
		t.Fatalf("lookup writes = %d, want 1", len(lookupW.calls))
	}
	l := lookupW.calls[0]
	if l.schemaID != row.schemaID {
		t.Errorf("lookup schemaID = %q", l.schemaID)
	}
	if string(l.entry.CanonicalBytes) != string(wire) {
		t.Errorf("CanonicalBytes drift")
	}
	if l.entry.LogTimeMicros != row.logTime {
		t.Errorf("LogTimeMicros = %d, want %d", l.entry.LogTimeMicros, row.logTime)
	}
	if l.entry.LogDID != "did:web:operator" {
		t.Errorf("LogDID = %q, want did:web:operator", l.entry.LogDID)
	}
}

func TestReplayer_applyOne_BytestoreError(t *testing.T) {
	r := &Replayer{
		cfg: ReplayConfig{
			Reader:       &fakeBytestoreReader{readErr: errors.New("boom")},
			SplitIDIndex: &fakeSplitIDWriter{},
			EntryLookup:  &fakeLookupWriter{},
			LogDID:       "did:web:op",
		},
		logger: discardReplayLog(),
	}
	err := r.applyOne(context.Background(), replayRow{seq: 1, hash: [32]byte{0x01}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "bytestore read") {
		t.Errorf("error %q does not mention bytestore", err)
	}
}

func TestReplayer_applyOne_DeserializeError(t *testing.T) {
	r := &Replayer{
		cfg: ReplayConfig{
			Reader: &fakeBytestoreReader{
				bytesByHash: map[[32]byte][]byte{
					{0x01}: []byte("not-an-envelope"),
				},
			},
			SplitIDIndex: &fakeSplitIDWriter{},
			EntryLookup:  &fakeLookupWriter{},
			LogDID:       "did:web:op",
		},
		logger: discardReplayLog(),
	}
	err := r.applyOne(context.Background(), replayRow{seq: 1, hash: [32]byte{0x01}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "deserialize") {
		t.Errorf("error %q does not mention deserialize", err)
	}
}

func TestReplayer_applyOne_SplitIDWriteError(t *testing.T) {
	wire, hash := buildReplayEntry(t, "p")
	r := &Replayer{
		cfg: ReplayConfig{
			Reader: &fakeBytestoreReader{
				bytesByHash: map[[32]byte][]byte{hash: wire},
			},
			SplitIDIndex: &fakeSplitIDWriter{failErr: errors.New("badger oom")},
			EntryLookup:  &fakeLookupWriter{},
			LogDID:       "did:web:op",
		},
		logger: discardReplayLog(),
	}
	err := r.applyOne(context.Background(), replayRow{seq: 1, hash: hash})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "0x0A write") {
		t.Errorf("error %q does not mention 0x0A", err)
	}
}

func TestReplayer_applyOne_LookupWriteError(t *testing.T) {
	wire, hash := buildReplayEntry(t, "p")
	r := &Replayer{
		cfg: ReplayConfig{
			Reader: &fakeBytestoreReader{
				bytesByHash: map[[32]byte][]byte{hash: wire},
			},
			SplitIDIndex: &fakeSplitIDWriter{},
			EntryLookup:  &fakeLookupWriter{failErr: errors.New("badger fsync")},
			LogDID:       "did:web:op",
		},
		logger: discardReplayLog(),
	}
	err := r.applyOne(context.Background(), replayRow{seq: 1, hash: hash})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "0x0C write") {
		t.Errorf("error %q does not mention 0x0C", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Sequencer.Run wiring + WaitGroup drain on ctx cancellation
// ─────────────────────────────────────────────────────────────────────

func TestSequencer_WithReplayer_CapturesReplayer(t *testing.T) {
	s := NewSequencer(newFakeWAL(), newFakeTessera(), nil, nil, Config{})
	r := &Replayer{logger: discardReplayLog()}
	ret := s.WithReplayer(r)
	if ret != s {
		t.Error("WithReplayer should return receiver")
	}
	if s.replayer != r {
		t.Error("replayer not captured")
	}
}

func TestSequencer_WithReplayer_NilIsNoOp(t *testing.T) {
	s := NewSequencer(newFakeWAL(), newFakeTessera(), nil, nil, Config{})
	s.WithReplayer(nil)
	if s.replayer != nil {
		t.Error("nil replayer should remain nil")
	}
}

// blockingReplayCursor's HWM read blocks until ctx cancels, then
// returns ctx.Err(). Lets the WaitGroup-drain test prove the
// goroutine is in flight when ctx cancels (via the parked
// goroutine count) without ever hitting the DB query path.
type blockingReplayCursor struct {
	started chan struct{} // closed once HWM read parks
}

func (b *blockingReplayCursor) SplitIDReplayHWM(ctx context.Context) (uint64, error) {
	close(b.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

func (b *blockingReplayCursor) SetSplitIDReplayHWM(_ context.Context, _ uint64) error {
	return nil
}

// TestSequencer_Run_DrainsReplayerOnCtxCancel pins the WaitGroup
// discipline (P11): the replayer goroutine must complete before
// Run returns. The blocking cursor parks the replayer in
// SplitIDReplayHWM until ctx cancels — at that point Replay
// returns, and Run.wg.Wait drains it before returning.
func TestSequencer_Run_DrainsReplayerOnCtxCancel(t *testing.T) {
	cursor := &blockingReplayCursor{started: make(chan struct{})}

	// Construct Replayer directly (skip NewReplayer's DB-required
	// check; we never reach the DB because the cursor blocks).
	r := &Replayer{
		cfg: ReplayConfig{
			Reader:       &fakeBytestoreReader{},
			SplitIDIndex: &fakeSplitIDWriter{},
			EntryLookup:  &fakeLookupWriter{},
			Cursor:       cursor,
			LogDID:       "did:web:op",
			BatchSize:    DefaultReplayBatchSize,
		},
		logger: discardReplayLog(),
	}

	s := newTestSequencer(t, newFakeWAL(), newFakeTessera(),
		Config{PollInterval: time.Hour})
	s.WithReplayer(r)

	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()

	// Wait for the replay goroutine to park inside the cursor.
	select {
	case <-cursor.started:
	case <-time.After(1 * time.Second):
		t.Fatal("replay goroutine did not start within 1s")
	}

	// Cancel — Replay should return ctx.Err(); Run.wg.Wait
	// must drain it before returning.
	cancel()

	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run did not return within 2s of ctx cancel — replayer goroutine leaked?")
	}
}

// TestSequencer_Run_NoReplayer_StillStarts pins that a nil
// replayer is harmless: Run starts the drain loop and returns
// on ctx cancel without spawning a child goroutine.
func TestSequencer_Run_NoReplayer_StillStarts(t *testing.T) {
	s := newTestSequencer(t, newFakeWAL(), newFakeTessera(),
		Config{PollInterval: time.Hour})
	// no WithReplayer call

	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run did not return within 2s of ctx cancel")
	}
}

// ─────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
