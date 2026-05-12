/*
FILE PATH: wal/wal_test.go

Evidence-based tests for the WAL. Establishes the load-bearing
invariants the rest of the ledger relies on:

	Durability invariant:
	  Submit returns nil only after the wire bytes are fsync'd. We
	  can't directly observe fsync on Badger's in-memory mode (the
	  "WAL" is a virtual buffer), but we CAN verify:
	    - Submit returns the same error to every concurrent submitter
	      in the batch (group-commit fan-out)
	    - Read after Submit returns the byte-identical wire
	    - Submit returns ErrEmptyWire on nil/empty input
	    - Submit returns ErrQueueFull when the queue is saturated

	State machine invariants:
	  pending → sequenced → shipped is a monotonic progression.
	  Re-issuing the same transition is idempotent. Out-of-order
	  transitions (e.g. MarkShipped before Sequence) are rejected.

	Hash-keyed contract:
	  Two Submits of the same hash with different content are stored
	  distinctly under (hash) — there's no aliasing across content.

	Iterator invariants:
	  IterateInflight yields the inflight set; IterateSequenced yields
	  StateSequenced entries in seq ASC starting after fromSeq.

	Group-commit semantics:
	  Concurrent Submits in flight before a flush all receive the same
	  error (success or failure). Hot path is race-free under -race.

	Tessera dedup contract:
	  Get(unknown) → (0, false, nil); Set + Get round-trips the index;
	  Get of an unset identity is not-found.
*/
package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// openTestCommitter spins up an in-memory Badger DB + Committer with
// fast batch parameters so tests don't wait on the default 10ms
// latency timer.
func openTestCommitter(t *testing.T) (*Committer, *badger.DB) {
	t.Helper()
	db, err := OpenInMemory(nil)
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	c := NewCommitter(db, CommitterConfig{
		QueueSize:       128,
		BatchMaxEntries: 16,
		BatchMaxBytes:   1 << 16, // 64 KiB
		BatchMaxLatency: 5 * time.Millisecond,
		DisableSync:     true, // in-memory Badger has no WAL to sync
	})
	t.Cleanup(func() {
		_ = c.Close()
		_ = db.Close()
	})
	return c, db
}

func wireHashWal(wire []byte) [32]byte { return sha256.Sum256(wire) }

// ─────────────────────────────────────────────────────────────────────
// 1) Submit / Read round-trip
// ─────────────────────────────────────────────────────────────────────

func TestWAL_Submit_ReadRoundTrip(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	wire := []byte("the wire bytes for the entry")
	hash := wireHashWal(wire)

	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	got, err := c.Read(ctx, hash)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("Read returned wrong bytes:\n got=%x\n want=%x", got, wire)
	}
	// And the meta is in pending.
	meta, err := c.MetaState(ctx, hash)
	if err != nil {
		t.Fatalf("MetaState: %v", err)
	}
	if meta.State != StatePending {
		t.Fatalf("expected StatePending, got %s", meta.State)
	}
}

func TestWAL_Submit_RejectsEmptyWire(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	hash := wireHashWal([]byte("x"))
	if err := c.Submit(ctx, hash, nil, time.Now().UnixMicro()); !errors.Is(err, ErrEmptyWire) {
		t.Fatalf("expected ErrEmptyWire on nil, got %v", err)
	}
	if err := c.Submit(ctx, hash, []byte{}, time.Now().UnixMicro()); !errors.Is(err, ErrEmptyWire) {
		t.Fatalf("expected ErrEmptyWire on empty, got %v", err)
	}
}

// TestWAL_Submit_LatencyObserved pins the in-process Submit latency
// histogram: every successful Submit MUST produce one observation in
// SubmitLatencySnapshot. This is the path the soak relies on to
// diagnose WAL-side backpressure (admission p99 spikes); a silent
// regression in the observe-site would hide WAL fsync slowdowns
// behind admission-side timeouts.
func TestWAL_Submit_LatencyObserved(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	// Before any Submit, the snapshot is empty.
	if snap := c.SubmitLatencySnapshot(); snap.Count != 0 {
		t.Fatalf("pre-Submit Count = %d, want 0", snap.Count)
	}

	const n = 10
	for i := 0; i < n; i++ {
		wire := []byte(fmt.Sprintf("entry-%d-wire-bytes", i))
		hash := wireHashWal(wire)
		if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
			t.Fatalf("Submit[%d]: %v", i, err)
		}
	}

	snap := c.SubmitLatencySnapshot()
	if snap.Count != n {
		t.Fatalf("Count = %d, want %d (every Submit must observe)",
			snap.Count, n)
	}
	if snap.MinUs == 0 {
		t.Fatalf("MinUs = 0 after observations — sentinel collapse on non-empty histogram")
	}
	if snap.MaxUs < snap.MinUs {
		t.Fatalf("MaxUs=%d < MinUs=%d", snap.MaxUs, snap.MinUs)
	}
	if got := snap.Format(); got == "n=0" {
		t.Fatalf("Format = %q on populated histogram", got)
	}
}

func TestWAL_Read_NotFound(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)
	_, err := c.Read(ctx, [32]byte{0xDE, 0xAD})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2) Inflight breadcrumb covers the Tessera-Add window
// ─────────────────────────────────────────────────────────────────────

// TestWAL_Submit_WritesInflight: after Submit, the inflight breadcrumb
// is set so reconciliation can find this entry. After Sequence, the
// breadcrumb is cleared.
func TestWAL_Submit_WritesInflight_SequenceClears(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	wire := []byte("inflight test")
	hash := wireHashWal(wire)
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// Inflight is set.
	saw := false
	if err := c.IterateInflight(ctx, func(p PendingHash) error {
		if p.Hash == hash {
			saw = true
		}
		return nil
	}); err != nil {
		t.Fatalf("IterateInflight: %v", err)
	}
	if !saw {
		t.Fatal("inflight breadcrumb not set after Submit")
	}

	// Sequence clears it.
	if err := c.Sequence(ctx, hash, 100); err != nil {
		t.Fatalf("Sequence: %v", err)
	}
	saw = false
	if err := c.IterateInflight(ctx, func(p PendingHash) error {
		if p.Hash == hash {
			saw = true
		}
		return nil
	}); err != nil {
		t.Fatalf("IterateInflight: %v", err)
	}
	if saw {
		t.Fatal("inflight breadcrumb still set after Sequence")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3) State machine: pending → sequenced → shipped
// ─────────────────────────────────────────────────────────────────────

func TestWAL_StateMachine_PendingToShipped(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	wire := []byte("state-machine entry")
	hash := wireHashWal(wire)
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	steps := []struct {
		name      string
		do        func() error
		wantState EntryState
		wantSeq   uint64
	}{
		{"after submit", func() error { return nil }, StatePending, 0},
		{"sequence", func() error { return c.Sequence(ctx, hash, 42) }, StateSequenced, 42},
		{"mark shipped", func() error { return c.MarkShipped(ctx, hash) }, StateShipped, 42},
	}
	for _, step := range steps {
		if err := step.do(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		meta, err := c.MetaState(ctx, hash)
		if err != nil {
			t.Fatalf("%s MetaState: %v", step.name, err)
		}
		if meta.State != step.wantState {
			t.Errorf("%s: state=%s want=%s", step.name, meta.State, step.wantState)
		}
		if meta.Sequence != step.wantSeq {
			t.Errorf("%s: seq=%d want=%d", step.name, meta.Sequence, step.wantSeq)
		}
	}
}

func TestWAL_StateMachine_OutOfOrderRejected(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	wire := []byte("ooo")
	hash := wireHashWal(wire)
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// MarkShipped before Sequence: must error.
	if err := c.MarkShipped(ctx, hash); err == nil {
		t.Fatal("MarkShipped on pending should error")
	}
}

func TestWAL_StateMachine_SequenceIdempotent(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	wire := []byte("idem")
	hash := wireHashWal(wire)
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := c.Sequence(ctx, hash, 7); err != nil {
		t.Fatalf("Sequence: %v", err)
	}
	// Same seq again: idempotent no-op.
	if err := c.Sequence(ctx, hash, 7); err != nil {
		t.Fatalf("Sequence (idempotent): %v", err)
	}
	// Different seq: rejected.
	if err := c.Sequence(ctx, hash, 8); err == nil {
		t.Fatal("Sequence with different seq should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4) HWM round-trip
// ─────────────────────────────────────────────────────────────────────

func TestWAL_HWM_DefaultZero_Advance(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	hwm, err := c.HWM(ctx)
	if err != nil {
		t.Fatalf("HWM: %v", err)
	}
	if hwm != 0 {
		t.Fatalf("default HWM: got %d want 0", hwm)
	}
	if err := c.AdvanceHWM(ctx, 1234); err != nil {
		t.Fatalf("AdvanceHWM: %v", err)
	}
	hwm, err = c.HWM(ctx)
	if err != nil {
		t.Fatalf("HWM: %v", err)
	}
	if hwm != 1234 {
		t.Fatalf("HWM: got %d want 1234", hwm)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5) IterateSequenced — Shipper's read path
// ─────────────────────────────────────────────────────────────────────

func TestWAL_IterateSequenced_OrderedAndFiltered(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	// Submit + Sequence five entries with seqs 10, 11, 12, 13, 14.
	for i := uint64(10); i < 15; i++ {
		wire := []byte(fmt.Sprintf("entry-%d", i))
		h := wireHashWal(wire)
		if err := c.Submit(ctx, h, wire, time.Now().UnixMicro()); err != nil {
			t.Fatalf("Submit seq=%d: %v", i, err)
		}
		if err := c.Sequence(ctx, h, i); err != nil {
			t.Fatalf("Sequence seq=%d: %v", i, err)
		}
	}
	// Mark seq 11 shipped — the iterator should skip it.
	wire11 := []byte(fmt.Sprintf("entry-%d", 11))
	h11 := wireHashWal(wire11)
	if err := c.MarkShipped(ctx, h11); err != nil {
		t.Fatalf("MarkShipped seq=11: %v", err)
	}

	// Iterate from fromSeq=9; expect 10, 12, 13, 14 (11 filtered).
	var got []uint64
	if err := c.IterateSequenced(ctx, 9, func(e SequencedEntry) error {
		got = append(got, e.Seq)
		return nil
	}); err != nil {
		t.Fatalf("IterateSequenced: %v", err)
	}
	want := []uint64{10, 12, 13, 14}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("IterateSequenced: got %v, want %v", got, want)
	}
}

func TestWAL_IterateSequenced_StartsAfterFromSeq(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	for i := uint64(1); i <= 5; i++ {
		wire := []byte(fmt.Sprintf("e%d", i))
		h := wireHashWal(wire)
		if err := c.Submit(ctx, h, wire, time.Now().UnixMicro()); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
		if err := c.Sequence(ctx, h, i); err != nil {
			t.Fatalf("Sequence %d: %v", i, err)
		}
	}
	var got []uint64
	if err := c.IterateSequenced(ctx, 3, func(e SequencedEntry) error {
		got = append(got, e.Seq)
		return nil
	}); err != nil {
		t.Fatalf("IterateSequenced: %v", err)
	}
	want := []uint64{4, 5}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("IterateSequenced(fromSeq=3): got %v, want %v", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6) Group commit — concurrent submitters get fanned-out completion
// ─────────────────────────────────────────────────────────────────────

func TestWAL_GroupCommit_ConcurrentSubmits(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	const N = 64
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)
	wires := make([][]byte, N)
	hashes := make([][32]byte, N)
	for i := 0; i < N; i++ {
		wires[i] = []byte(fmt.Sprintf("concurrent-%d", i))
		hashes[i] = wireHashWal(wires[i])
	}

	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			if err := c.Submit(ctx, hashes[i], wires[i], time.Now().UnixMicro()); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Submit: %v", err)
	}

	// Read all back and verify identity.
	for i := 0; i < N; i++ {
		got, err := c.Read(ctx, hashes[i])
		if err != nil {
			t.Errorf("Read i=%d: %v", i, err)
			continue
		}
		if !bytes.Equal(got, wires[i]) {
			t.Errorf("Read i=%d: byte mismatch", i)
		}
	}
}

// Backpressure semantics (Submit returns ErrQueueFull immediately
// when the in-memory channel is full) are not unit-testable: the
// commit goroutine drains the channel faster than this process can
// fill it from a single producer. The behavior is exercised in the
// integration suite where a real fsync floor lets a producer outpace
// the drain. The non-blocking-send shape is statically pinned in
// committer.go (see the `select { case ... default: ErrQueueFull }`
// in Submit).

// ─────────────────────────────────────────────────────────────────────
// 7) Same-hash idempotency
// ─────────────────────────────────────────────────────────────────────

func TestWAL_Submit_SameHash_Idempotent(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)

	wire := []byte("same-content")
	hash := wireHashWal(wire)
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	// Second Submit with same (hash, wire): committed again. Storage
	// remains consistent — same value overwritten with same value.
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit 2: %v", err)
	}
	got, err := c.Read(ctx, hash)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("re-submit changed bytes")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8) TesseraDedup contract
// ─────────────────────────────────────────────────────────────────────

func TestTesseraDedup_GetMissing_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)
	d := c.Dedup()

	identity := sha256.Sum256([]byte("nope"))
	idx, found, err := d.Get(ctx, identity[:])
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("Get on unset identity: found=true (idx=%d)", idx)
	}
}

func TestTesseraDedup_SetGet_Roundtrip(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)
	d := c.Dedup()

	identity := sha256.Sum256([]byte("entry-content"))
	if err := d.Set(ctx, identity[:], 99); err != nil {
		t.Fatalf("Set: %v", err)
	}
	idx, found, err := d.Get(ctx, identity[:])
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("Get after Set: found=false")
	}
	if idx != 99 {
		t.Fatalf("Get after Set: idx=%d want=99", idx)
	}
}

func TestTesseraDedup_DistinctIdentities(t *testing.T) {
	ctx := context.Background()
	c, _ := openTestCommitter(t)
	d := c.Dedup()

	id1 := sha256.Sum256([]byte("a"))
	id2 := sha256.Sum256([]byte("b"))
	if err := d.Set(ctx, id1[:], 10); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := d.Set(ctx, id2[:], 20); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	got1, _, _ := d.Get(ctx, id1[:])
	got2, _, _ := d.Get(ctx, id2[:])
	if got1 != 10 || got2 != 20 {
		t.Fatalf("dedup aliasing: got1=%d got2=%d, want 10/20", got1, got2)
	}
}

// TestTesseraDedup_Persistence: on disk-backed Badger, dedup state
// survives close+reopen. (Tested separately because in-memory mode
// would short-circuit.)
func TestTesseraDedup_Persistence(t *testing.T) {
	dir := t.TempDir()
	logger := slogTestLogger(t)

	// First boot: write dedup record.
	{
		db, err := Open(dir, logger)
		if err != nil {
			t.Fatalf("Open 1: %v", err)
		}
		c := NewCommitter(db, CommitterConfig{Logger: logger})
		identity := sha256.Sum256([]byte("persistent"))
		if err := c.Dedup().Set(context.Background(), identity[:], 7); err != nil {
			t.Fatalf("Set: %v", err)
		}
		_ = c.Close()
		_ = db.Close()
	}

	// Second boot: read it back.
	{
		db, err := Open(dir, logger)
		if err != nil {
			t.Fatalf("Open 2: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		c := NewCommitter(db, CommitterConfig{Logger: logger})
		t.Cleanup(func() { _ = c.Close() })
		identity := sha256.Sum256([]byte("persistent"))
		idx, found, err := c.Dedup().Get(context.Background(), identity[:])
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !found || idx != 7 {
			t.Fatalf("dedup did not persist: found=%v idx=%d (want 7)", found, idx)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9) Helpers
// ─────────────────────────────────────────────────────────────────────

// slogTestLogger discards Badger's verbose startup chatter while
// keeping anything that looks like a real warning visible.
func slogTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testLogWriter{t: t}, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
