// Tests for teardown.Register's spec-order contract.
//
// FILE PATH: cmd/ledger/boot/teardown/teardown_test.go
//
// These tests pin the registration-order semantics that teardown
// relies on:
//
//   - http-server registers BEFORE pprof-server (when present),
//     BEFORE background-goroutines.
//   - background-goroutines registers BEFORE alloc closers.
//   - alloc closers register in REVERSE of their AppendCloser order
//     (newest opened first; oldest opened last).
//   - zero-key-material registers AFTER all alloc closers.
//   - TakeClosers is called (closeStack is consumed) so a second
//     Register call is a no-op for the alloc closers.
//
// We don't run the chain — these are registration-order tests, and
// the chain.Run path is exercised by lifecycle/shutdown_test.go.
package teardown

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/cmd/ledger/boot/deps"
	"github.com/clearcompass-ai/ledger/lifecycle"
)

func TestRegister_OrderHTTPThenGoroutinesThenAllocReverse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	d := &deps.AppDeps{Logger: logger}

	// Three alloc closers in registration order: postgres, wal, bytestore.
	d.AppendCloser(deps.NamedCloser{Name: "postgres", Timeout: time.Second, Close: noopClose})
	d.AppendCloser(deps.NamedCloser{Name: "wal", Timeout: time.Second, Close: noopClose})
	d.AppendCloser(deps.NamedCloser{Name: "bytestore", Timeout: time.Second, Close: noopClose})

	chain := lifecycle.NewShutdownChain(logger)
	teardown := Register(chain, d)
	if teardown == nil {
		t.Fatal("Register returned nil")
	}

	got := chainStepNames(chain)
	want := []string{
		"http-server",
		// pprof-server skipped (d.PprofServer == nil)
		"background-goroutines",
		// alloc closers in REVERSE registration order
		"bytestore",
		"wal",
		"postgres",
		"zero-key-material",
	}
	if len(got) != len(want) {
		t.Fatalf("step count = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestRegister_PprofIncludedWhenSet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	d := &deps.AppDeps{
		Logger:      logger,
		PprofServer: stubServer(),
	}

	chain := lifecycle.NewShutdownChain(logger)
	Register(chain, d)

	got := chainStepNames(chain)
	// First three: http-server, pprof-server, background-goroutines.
	want := []string{"http-server", "pprof-server", "background-goroutines"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Errorf("step[%d] = %q, want %q (full=%v)", i, get(got, i), want[i], got)
		}
	}
}

func TestRegister_TakeClosersConsumesStack(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	d := &deps.AppDeps{Logger: logger}
	d.AppendCloser(deps.NamedCloser{Name: "a", Timeout: time.Second, Close: noopClose})
	d.AppendCloser(deps.NamedCloser{Name: "b", Timeout: time.Second, Close: noopClose})

	// First Register reads + drains the stack.
	chain1 := lifecycle.NewShutdownChain(logger)
	Register(chain1, d)
	got1 := chainStepNames(chain1)
	allocCount1 := 0
	for _, n := range got1 {
		if n == "a" || n == "b" {
			allocCount1++
		}
	}
	if allocCount1 != 2 {
		t.Fatalf("first Register saw %d alloc closers, want 2", allocCount1)
	}

	// Second Register should find no alloc closers (stack reset).
	chain2 := lifecycle.NewShutdownChain(logger)
	Register(chain2, d)
	got2 := chainStepNames(chain2)
	for _, n := range got2 {
		if n == "a" || n == "b" {
			t.Errorf("second Register included alloc closer %q; stack should be reset", n)
		}
	}
	// Runtime steps still register: http-server, background-goroutines, zero-key-material.
	if len(got2) != 3 {
		t.Errorf("second Register step count = %d, want 3 (runtime-only) (got=%v)", len(got2), got2)
	}
}

func TestRegister_ZeroKeyMaterialIsLast(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	d := &deps.AppDeps{Logger: logger}
	d.AppendCloser(deps.NamedCloser{Name: "x", Timeout: time.Second, Close: noopClose})

	chain := lifecycle.NewShutdownChain(logger)
	Register(chain, d)
	got := chainStepNames(chain)
	if len(got) == 0 {
		t.Fatal("no steps")
	}
	if last := got[len(got)-1]; last != "zero-key-material" {
		t.Errorf("last step = %q, want zero-key-material", last)
	}
}

func TestWaitGroupBounded_ReturnsOnCtxCancel(t *testing.T) {
	// A WaitGroup that never reaches zero — bounded by ctx.
	d := &deps.AppDeps{}
	d.WG.Add(1)
	defer d.WG.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := waitGroupBounded(ctx, &d.WG)
	if err == nil {
		t.Fatal("waitGroupBounded should have returned ctx.Err on timeout")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %v; want context error", err)
	}
}

// --- helpers ------------------------------------------------------------

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func noopClose(_ context.Context) error { return nil }

func chainStepNames(chain *lifecycle.ShutdownChain) []string {
	summary := chain.Summary()
	out := make([]string, len(summary))
	for i, s := range summary {
		out[i] = s.Name
	}
	return out
}

func get(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return "<oob>"
	}
	return s[i]
}

func stubServer() *http.Server {
	return &http.Server{Addr: "127.0.0.1:0"}
}
