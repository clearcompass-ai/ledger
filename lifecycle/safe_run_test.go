/*
FILE PATH:

	lifecycle/safe_run_test.go

DESCRIPTION:

	Tests for SafeRun + SafeRunInWG. Pins the panic-recovery
	contract: a goroutine that panics MUST surface the panic via
	the fatal channel + slog event, and the recovered error MUST
	wrap ErrPanicRecovered so callers can errors.Is on the
	sentinel.

KEY ARCHITECTURAL DECISIONS:
  - Each test exercises ONE invariant. No table-driven hybrid
    that masks which assertion failed.
  - http.ErrAbortHandler re-panic is exercised explicitly via
    a defer-recover in the test (mirrors the SDK's gossip +
    cosign self-encapsulating recovery test pattern).
  - WaitGroup variant pinned so callers using SafeRunInWG can
    rely on wg.Wait() returning even when the goroutine
    panicked.
*/
package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) SafeRun panic recovery
// -------------------------------------------------------------------------------------------------

// TestSafeRun_PanicRecoveredSurfacesError pins that a goroutine
// that panics surfaces the recovered value (a) via the return
// error wrapping ErrPanicRecovered AND (b) via the fatal channel.
func TestSafeRun_PanicRecoveredSurfacesError(t *testing.T) {
	t.Parallel()
	fatalCh := make(chan error, 1)
	err := SafeRun(context.Background(), "panic-test", nil, fatalCh, func() error {
		panic("synthetic panic")
	})
	if err == nil {
		t.Fatal("expected non-nil error from panicking SafeRun")
	}
	if !errors.Is(err, ErrPanicRecovered) {
		t.Fatalf("err = %v; want errors.Is(.., ErrPanicRecovered)", err)
	}
	select {
	case fatalErr := <-fatalCh:
		if !errors.Is(fatalErr, ErrPanicRecovered) {
			t.Errorf("fatalCh err = %v; want errors.Is(.., ErrPanicRecovered)", fatalErr)
		}
	default:
		t.Error("expected fatalCh to receive the recovered error; got none")
	}
}

// TestSafeRun_NormalReturnPasses pins that a non-panicking
// goroutine simply returns whatever the wrapped function returns.
func TestSafeRun_NormalReturnPasses(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("normal exit")
	fatalCh := make(chan error, 1)
	got := SafeRun(context.Background(), "normal", nil, fatalCh, func() error {
		return wantErr
	})
	if got != wantErr {
		t.Errorf("got = %v; want %v", got, wantErr)
	}
	select {
	case fatalErr := <-fatalCh:
		t.Errorf("fatalCh should be empty on normal return; got %v", fatalErr)
	default:
	}
}

// TestSafeRun_NilFatalChannelIsSafe pins that passing a nil
// fatalCh does not panic — the goroutine still recovers and
// surfaces the wrapped error via the return.
func TestSafeRun_NilFatalChannelIsSafe(t *testing.T) {
	t.Parallel()
	err := SafeRun(context.Background(), "nil-fatal", nil, nil, func() error {
		panic("synthetic panic")
	})
	if err == nil || !errors.Is(err, ErrPanicRecovered) {
		t.Errorf("err = %v; want non-nil wrapping ErrPanicRecovered", err)
	}
}

// TestSafeRun_ErrAbortHandler_ReRaises pins that
// http.ErrAbortHandler is RE-PANICKED rather than recovered, so
// the stdlib's connection-level abort signaling continues to
// work as designed (matches the SDK's gossip + cosign handler
// recovery semantics).
func TestSafeRun_ErrAbortHandler_ReRaises(t *testing.T) {
	t.Parallel()
	rePanicked := false
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					rePanicked = true
				}
			}
		}()
		_ = SafeRun(context.Background(), "abort", nil, nil, func() error {
			panic(http.ErrAbortHandler)
		})
	}()
	if !rePanicked {
		t.Fatal("expected SafeRun to re-panic http.ErrAbortHandler")
	}
}

// -------------------------------------------------------------------------------------------------
// 2) SafeRunInWG (WaitGroup integration)
// -------------------------------------------------------------------------------------------------

// TestSafeRunInWG_WaitReturnsAfterPanic pins that wg.Wait()
// returns even when the wrapped goroutine panics. Without the
// SafeRunInWG wrapper, an unrecovered panic in the goroutine
// would crash the binary; with it, the panic is caught,
// surfaced, and wg.Done is called via the deferred chain.
func TestSafeRunInWG_WaitReturnsAfterPanic(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	fatalCh := make(chan error, 1)
	SafeRunInWG(context.Background(), &wg, "panic-wg", nil, fatalCh, func() error {
		panic("synthetic")
	})
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait did not return within 2s after panic")
	}
	select {
	case <-fatalCh:
	default:
		t.Error("fatalCh should have received the panic")
	}
}

// TestSafeRunInWG_NormalCompletion pins the WaitGroup unwind on
// non-panic return.
func TestSafeRunInWG_NormalCompletion(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	fatalCh := make(chan error, 1)
	SafeRunInWG(context.Background(), &wg, "normal-wg", nil, fatalCh, func() error {
		return nil
	})
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait did not return within 2s after normal exit")
	}
	select {
	case fatalErr := <-fatalCh:
		t.Errorf("fatalCh should be empty on normal exit; got %v", fatalErr)
	default:
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Entry / exit Info logs (E2)
// -------------------------------------------------------------------------------------------------

// TestSafeRun_EmitsStartedAndStoppedLogs pins the E2 contract:
// every wrapped goroutine emits a "goroutine started" line at
// Info on entry AND a matching "goroutine stopped" line on exit.
// Administrators rely on this pair to prove from logs alone that each
// supervisor child launched and terminated cleanly.
func TestSafeRun_EmitsStartedAndStoppedLogs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	_ = SafeRun(context.Background(), "logged-goroutine", logger, nil, func() error {
		return nil
	})
	out := buf.String()
	if !strings.Contains(out, "goroutine started") || !strings.Contains(out, "logged-goroutine") {
		t.Errorf("expected 'goroutine started' + name in log; got %q", out)
	}
	if !strings.Contains(out, "goroutine stopped") {
		t.Errorf("expected 'goroutine stopped' in log; got %q", out)
	}
}

// TestSafeRun_EmitsStoppedLogEvenOnPanic pins the symmetric-pair
// guarantee: a panic still emits the matching "stopped" line so
// `grep started/stopped` pairs up across normal + panic exits.
func TestSafeRun_EmitsStoppedLogEvenOnPanic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	_ = SafeRun(context.Background(), "panic-logged", logger, nil, func() error {
		panic("synthetic")
	})
	out := buf.String()
	if !strings.Contains(out, "goroutine started") {
		t.Errorf("expected 'goroutine started' line even on panic path; got %q", out)
	}
	if !strings.Contains(out, "goroutine stopped") {
		t.Errorf("expected 'goroutine stopped' line on panic path; got %q", out)
	}
	if !strings.Contains(out, "panic recovered") {
		t.Errorf("expected 'panic recovered' line; got %q", out)
	}
}
