/*
FILE PATH: tessera/embedded_appender_test.go

End-to-end tests for EmbeddedAppender against a tmpdir-backed
upstream Tessera POSIX driver. Self-contained — no docker, no
Postgres, no network. Always runs.

Coverage:
  - Constructor validation (nil driver, nil signer).
  - GenerateEphemeralSigner round-trip.
  - Boot → Add hash → Head reads checkpoint → Close.
  - AppendLeaf rejects non-32-byte input.
  - Head returns os.ErrNotExist before first checkpoint.
  - Multiple Add calls return monotonically-increasing indices.
  - Close is idempotent (safe to call twice).
  - Round-trip: AppendLeaf → wait for integration → Head.TreeSize > 0.

The end-to-end test exercises the full Tessera library boot
sequence against a real POSIX driver, so any future upstream
breakage surfaces here at build/test time rather than in
production.
*/
package tessera

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	uptessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
)

// newTestEmbeddedAppender wires a tmpdir-backed POSIX Tessera and
// returns the appender. Registers Close + signer-name +
// storage-dir cleanup with t.Cleanup. Returns the appender, the
// raw storage directory (for direct file inspection), and the
// signer's verifier key (for round-trip identification in logs).
func newTestEmbeddedAppender(t *testing.T) (*EmbeddedAppender, string, string) {
	t.Helper()

	dir := t.TempDir()
	ctx := context.Background()

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New(%s): %v", dir, err)
	}

	signer, vkey, err := GenerateEphemeralSigner("test-embedded")
	if err != nil {
		t.Fatalf("GenerateEphemeralSigner: %v", err)
	}

	app, err := NewEmbeddedAppender(ctx, driver, AppenderOptions{
		Origin:             "test-embedded",
		Signer:             signer,
		CheckpointInterval: 100 * time.Millisecond, // fast checkpoint for test speed
		BatchSize:          16,
		BatchMaxAge:        50 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := app.Close(shutdownCtx); err != nil {
			t.Logf("Close (cleanup): %v", err)
		}
	})

	return app, dir, vkey
}

// ─────────────────────────────────────────────────────────────────
// Constructor validation
// ─────────────────────────────────────────────────────────────────

func TestEmbeddedAppender_New_RejectsNilDriver(t *testing.T) {
	signer, _, _ := GenerateEphemeralSigner("test")
	_, err := NewEmbeddedAppender(context.Background(), nil, AppenderOptions{Signer: signer}, nil)
	if err == nil {
		t.Fatal("expected error on nil driver")
	}
}

func TestEmbeddedAppender_New_RejectsNilSigner(t *testing.T) {
	dir := t.TempDir()
	driver, err := posix.New(context.Background(), posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	_, err = NewEmbeddedAppender(context.Background(), driver, AppenderOptions{}, nil)
	if err == nil {
		t.Fatal("expected error on nil signer")
	}
}

// ─────────────────────────────────────────────────────────────────
// Ephemeral signer helper
// ─────────────────────────────────────────────────────────────────

func TestGenerateEphemeralSigner_HappyPath(t *testing.T) {
	signer, vkey, err := GenerateEphemeralSigner("alpha")
	if err != nil {
		t.Fatalf("GenerateEphemeralSigner: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
	if signer.Name() != "alpha" {
		t.Errorf("signer name: got %q, want %q", signer.Name(), "alpha")
	}
	if vkey == "" {
		t.Error("vkey empty")
	}
}

func TestGenerateEphemeralSigner_DefaultsToAttesta(t *testing.T) {
	signer, _, err := GenerateEphemeralSigner("")
	if err != nil {
		t.Fatalf("GenerateEphemeralSigner: %v", err)
	}
	if signer.Name() != "attesta-local-dev" {
		t.Errorf("default signer name: got %q, want %q",
			signer.Name(), "attesta-local-dev")
	}
}

// ─────────────────────────────────────────────────────────────────
// AppendLeaf input validation
// ─────────────────────────────────────────────────────────────────

func TestEmbeddedAppender_AppendLeaf_RejectsWrongSize(t *testing.T) {
	app, _, _ := newTestEmbeddedAppender(t)

	// 0 bytes
	if _, err := app.AppendLeaf(context.Background(), nil); err == nil {
		t.Error("expected error on nil input")
	}
	// 31 bytes (one short)
	if _, err := app.AppendLeaf(context.Background(), make([]byte, 31)); err == nil {
		t.Error("expected error on 31-byte input")
	}
	// 33 bytes (one over)
	if _, err := app.AppendLeaf(context.Background(), make([]byte, 33)); err == nil {
		t.Error("expected error on 33-byte input")
	}
}

// ─────────────────────────────────────────────────────────────────
// Head before any append
// ─────────────────────────────────────────────────────────────────
//
// Upstream Tessera publishes an initial empty checkpoint
// (tree_size = 0) at boot before any Add. Head returns it
// successfully — there is no os.ErrNotExist window in practice.
// This test pins the empty-tree contract so any future upstream
// change (e.g., a flag that delays the empty checkpoint) surfaces
// here rather than as a startup race.

func TestEmbeddedAppender_Head_BeforeFirstAppend_ReturnsEmptyTree(t *testing.T) {
	app, _, _ := newTestEmbeddedAppender(t)

	// Allow up to 2s for Tessera's initial empty checkpoint to
	// land — first-boot integration cycle includes filesystem
	// init steps.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		head, err := app.Head()
		if err == nil {
			if head.TreeSize != 0 {
				t.Errorf("pre-append tree_size: got %d, want 0", head.TreeSize)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("initial empty checkpoint did not appear within deadline")
}

// ─────────────────────────────────────────────────────────────────
// Full round trip: Add → Head
// ─────────────────────────────────────────────────────────────────

func TestEmbeddedAppender_AppendLeaf_AssignsMonotonicIndices(t *testing.T) {
	app, _, _ := newTestEmbeddedAppender(t)

	// Append three distinct hashes; indices must be 0, 1, 2.
	prev := uint64(0)
	for i := 0; i < 3; i++ {
		var hash [32]byte
		hash[0] = byte(i + 1) // distinct, non-zero
		idx, err := app.AppendLeaf(context.Background(), hash[:])
		if err != nil {
			t.Fatalf("AppendLeaf #%d: %v", i, err)
		}
		if i == 0 {
			if idx != 0 {
				t.Errorf("first index: got %d, want 0", idx)
			}
		} else if idx != prev+1 {
			t.Errorf("index #%d: got %d, want %d (prev+1)", i, idx, prev+1)
		}
		prev = idx
	}
}

func TestEmbeddedAppender_AddThenHead_RoundTrip(t *testing.T) {
	app, dir, _ := newTestEmbeddedAppender(t)

	// Add a single distinct hash.
	var entryHash [32]byte
	if _, err := rand.Read(entryHash[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	idx, err := app.AppendLeaf(context.Background(), entryHash[:])
	if err != nil {
		t.Fatalf("AppendLeaf: %v", err)
	}
	if idx != 0 {
		t.Fatalf("first index: got %d, want 0", idx)
	}

	// Wait for Tessera's batcher to publish a checkpoint.
	// CheckpointInterval is 100ms in newTestEmbeddedAppender;
	// 5 seconds is generous slack for slow CI.
	deadline := time.Now().Add(5 * time.Second)
	gotCheckpoint := false
	var finalSize uint64
	for time.Now().Before(deadline) {
		h, herr := app.Head()
		if herr == nil && h.TreeSize >= 1 {
			gotCheckpoint = true
			finalSize = h.TreeSize
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !gotCheckpoint {
		// Inspect the storage directory for diagnostic context.
		t.Fatalf("Head never returned tree_size >= 1 within deadline; storage dir: %s", dir)
	}
	if finalSize < 1 {
		t.Errorf("expected tree_size >= 1 after one Add, got %d", finalSize)
	}

	// Sanity: a checkpoint file exists at <dir>/checkpoint with
	// the expected three lines (origin, size, hash).
	ckpt, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatalf("read checkpoint file: %v", err)
	}
	if !bytes.Contains(ckpt, []byte("test-embedded\n")) {
		t.Errorf("checkpoint missing origin line; got %q", ckpt[:64])
	}
}

// ─────────────────────────────────────────────────────────────────
// AppendLeaf deduplicates identical hashes
// ─────────────────────────────────────────────────────────────────
//
// Upstream Tessera's antispam (when enabled) deduplicates by
// identity hash. With antispam off (ledger's chosen
// configuration — see the architecture doc's §2 antispam-off
// rationale), the SAME hash submitted twice gets two distinct
// indices. This test pins the ledger's antispam-off contract:
// duplicate hashes appear at distinct positions in the log.

func TestEmbeddedAppender_AppendLeaf_DuplicateHashGetsDistinctIndices(t *testing.T) {
	app, _, _ := newTestEmbeddedAppender(t)

	hash := sha256.Sum256([]byte("identical input"))

	idx1, err := app.AppendLeaf(context.Background(), hash[:])
	if err != nil {
		t.Fatalf("AppendLeaf #1: %v", err)
	}
	idx2, err := app.AppendLeaf(context.Background(), hash[:])
	if err != nil {
		t.Fatalf("AppendLeaf #2: %v", err)
	}

	if idx1 == idx2 {
		t.Errorf("expected distinct indices for duplicate hash with antispam off, got both at %d", idx1)
	}
}

// ─────────────────────────────────────────────────────────────────
// Close idempotency
// ─────────────────────────────────────────────────────────────────

func TestEmbeddedAppender_Close_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	signer, _, _ := GenerateEphemeralSigner("idempotent-test")
	app, err := NewEmbeddedAppender(ctx, driver, AppenderOptions{
		Signer:      signer,
		DrainBudget: -1, // disable drain wait — keeps the test fast
	}, nil)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}

	// First Close: shutdown runs.
	if err := app.Close(ctx); err != nil {
		t.Errorf("first Close: %v", err)
	}

	// Second Close: must NOT panic and must NOT fail.
	if err := app.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestEmbeddedAppender_Close_DoneChannelClosesAfterDrainBudget pins
// the Done() channel contract: closed exactly once, after Close
// completes its drain budget. Tests rely on this to gate t.TempDir
// cleanup until upstream goroutines have observed ctx.Done.
func TestEmbeddedAppender_Close_DoneChannelClosesAfterDrainBudget(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	signer, _, _ := GenerateEphemeralSigner("done-channel-test")
	const drain = 50 * time.Millisecond
	app, err := NewEmbeddedAppender(ctx, driver, AppenderOptions{
		Signer:      signer,
		DrainBudget: drain,
	}, nil)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}

	// Before Close, Done() returns an open channel — select with
	// default branch should hit default, not the channel.
	select {
	case <-app.Done():
		t.Fatal("Done() was closed before Close() ran")
	default:
		// expected
	}

	closeStart := time.Now()
	if err := app.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
	closeElapsed := time.Since(closeStart)

	// Close must have waited at least the drain budget.
	if closeElapsed < drain {
		t.Errorf("Close returned in %s, expected >= drainBudget=%s "+
			"(drain-budget wait skipped?)", closeElapsed, drain)
	}

	// After Close returns, Done() must be closed (immediate receive).
	select {
	case <-app.Done():
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Done() was not closed after Close returned")
	}

	// Idempotent close + Done stays closed.
	if err := app.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
	select {
	case <-app.Done():
		// still closed — expected (channel close is permanent)
	default:
		t.Fatal("Done() is no longer closed after second Close")
	}
}

// TestEmbeddedAppender_Close_HonorsCallerCtxDeadline pins that
// Close returns when the caller's ctx fires, even if the drain
// budget hasn't elapsed. Production shutdown chains rely on this
// to bound shutdown time under a SIGTERM grace window.
func TestEmbeddedAppender_Close_HonorsCallerCtxDeadline(t *testing.T) {
	dir := t.TempDir()
	driver, err := posix.New(context.Background(), posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	signer, _, _ := GenerateEphemeralSigner("ctx-deadline-test")
	// Big drain budget; small caller deadline. Caller deadline wins.
	app, err := NewEmbeddedAppender(context.Background(), driver, AppenderOptions{
		Signer:      signer,
		DrainBudget: 5 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	closeStart := time.Now()
	_ = app.Close(closeCtx)
	closeElapsed := time.Since(closeStart)

	// Caller's 30ms deadline must dominate the 5s drain budget.
	// Slack: 5s drain → 200ms ceiling means caller-deadline was honored.
	if closeElapsed >= 200*time.Millisecond {
		t.Errorf("Close took %s, expected < 200ms (caller ctx deadline "+
			"should have dominated the 5s drain budget)", closeElapsed)
	}
}

// ─────────────────────────────────────────────────────────────────
// Reader() escape hatch
// ─────────────────────────────────────────────────────────────────

func TestEmbeddedAppender_Reader_ReturnsLogReader(t *testing.T) {
	app, _, _ := newTestEmbeddedAppender(t)

	r := app.Reader()
	if r == nil {
		t.Fatal("Reader returned nil")
	}

	// Compile-time pin: r implements LogReader's full surface.
	var _ uptessera.LogReader = r
}

// ─────────────────────────────────────────────────────────────────
// Boundary translation: upstream "appender has been shut down" →
// typed ErrAppenderShutdown sentinel
// ─────────────────────────────────────────────────────────────────

// TestEmbeddedAppender_AppendLeaf_TypedShutdownError pins the
// boundary translation in AppendLeaf. Upstream tessera
// (transparency-dev/tessera@v1.0.2/append_lifecycle.go:491) emits
// a stringly-typed error "appender has been shut down" when
// terminator.stopped is true. Our wrapper translates that single
// signature into ErrAppenderShutdown so sequencer + builder
// consumers can match it via errors.Is and classify as non-retriable.
//
// This test is the canary: if upstream renames their error string
// (e.g., to "appender stopped"), the wrapper's strings.Contains check
// no longer fires, AppendLeaf falls through to the generic
// fmt.Errorf wrap, and the typed sentinel is lost — silently
// re-enabling the retry-storm shutdown pattern. This test fails
// loudly the moment that happens, forcing the operator to update
// the upstreamShutdownSignature constant.
//
// The test path: build an appender, close it (which flips upstream
// terminator.stopped via our e.shutdown call), then attempt
// AppendLeaf. The returned error MUST satisfy
// errors.Is(err, ErrAppenderShutdown).
func TestEmbeddedAppender_AppendLeaf_TypedShutdownError(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	signer, _, _ := GenerateEphemeralSigner("shutdown-sentinel-test")
	app, err := NewEmbeddedAppender(ctx, driver, AppenderOptions{
		Signer:      signer,
		DrainBudget: -1, // disable drain wait — keeps the test fast
	}, nil)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}

	// Flip upstream terminator.stopped via Close. This is the only
	// path that sets the flag; once set, every subsequent Add returns
	// the stringly-typed shutdown error from upstream.
	if err := app.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// AppendLeaf must surface the typed sentinel. errors.Is unwraps
	// the fmt.Errorf("…: %w", ErrAppenderShutdown) chain we emit at
	// the boundary.
	hash := sha256.Sum256([]byte("shutdown-sentinel-test"))
	_, err = app.AppendLeaf(ctx, hash[:])
	if err == nil {
		t.Fatal("AppendLeaf after Close: expected error, got nil")
	}
	if !errors.Is(err, ErrAppenderShutdown) {
		t.Fatalf("AppendLeaf after Close: error does not satisfy "+
			"errors.Is(err, ErrAppenderShutdown). "+
			"Upstream tessera may have renamed its shutdown error "+
			"signature; update upstreamShutdownSignature in "+
			"embedded_appender.go. Got: %v", err)
	}
}
