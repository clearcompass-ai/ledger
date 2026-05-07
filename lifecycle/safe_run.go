/*
FILE PATH:
    lifecycle/safe_run.go

DESCRIPTION:
    Panic-recovery wrapper for long-running background goroutines.
    Every goroutine spawned by cmd/ledger/main.go (Sequencer, Shipper,
    EquivocationScanner, AntiEntropy, AnchorPublisher, etc.) is
    protected by a defer-recover that captures any panic, captures
    a bounded stack trace, logs it as a structured event, and
    surfaces the panic value via a fatal channel so the supervisor
    can terminate the process cleanly.

KEY ARCHITECTURAL DECISIONS:
    - Mirrors the SDK's gossip + cosign self-encapsulating
      defer-recover pattern (attesta v0.1.2). Where the SDK
      protects HTTP handlers from panics surfaced inside its own
      ServeHTTP, this protects the LEDGER's own background
      goroutines from panics surfaced inside their hot loops.
    - Stack capture is bounded to MaxRecoveredStackBytes (8 KiB)
      to keep panic-storm log volume bounded — a runaway loop
      panicking 1000×/sec must not flood the log shipper.
    - Fatal-channel surfacing ensures a panicked goroutine
      terminates the process via the supervisor's existing
      fatal-channel pathway. Process-level termination is the
      orchestrator's signal (k8s/systemd/bare-metal restart-loops).
    - http.ErrAbortHandler is re-panicked (matches stdlib idiom);
      it's an in-band abort signal used by stdlib's TimeoutHandler,
      not a real panic.
    - Pure function over a Run-shaped goroutine; doesn't introduce
      a framework. The Go-idiomatic wrapper.

OVERVIEW:
    Background goroutine is wrapped:

        wg.Add(1)
        go SafeRun(ctx, "sequencer", logger, fatalCh, func() error {
            return seq.Run(ctx)
        })

    Returns ctx.Err() OR the wrapped function's terminal error OR
    the recovered panic value (wrapped in ErrPanicRecovered). On
    panic the stack trace is logged BEFORE the fatal-channel send
    so debugging artifacts are present in the log stream even if
    the supervisor terminates the process before flushing.

KEY DEPENDENCIES:
    - log/slog: structured logging.
    - runtime/debug: bounded stack capture.
    - errors: typed sentinel for panic-classified errors.
*/
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// MaxRecoveredStackBytes caps stack-trace bytes captured per
// recovered panic. Keeps panic-storm log volume bounded — a
// runaway loop panicking N×/sec stays under the log-shipper's
// per-record budget.
const MaxRecoveredStackBytes = 8 * 1024

// ErrPanicRecovered is the sentinel returned by SafeRun when the
// inner Run function panics. Wraps the recovered value via
// fmt.Errorf("%w: ..., %v", ErrPanicRecovered, rec).
var ErrPanicRecovered = errors.New("lifecycle: goroutine panic recovered")

// -------------------------------------------------------------------------------------------------
// 2) Public API
// -------------------------------------------------------------------------------------------------

// SafeRun runs the supplied function under panic recovery. Returns:
//
//   - whatever the function returns on normal exit;
//   - ErrPanicRecovered (wrapped with the recovered value) on panic;
//   - ctx.Err() if ctx is cancelled before the function returns.
//
// Mandatory parameters:
//
//   - name identifies the goroutine in logs; appears as the
//     "goroutine" structured-log field.
//   - logger receives panic events at slog.LevelError. nil is
//     permitted (panics are still recovered, just unlogged).
//   - fatalCh receives the wrapped panic error AFTER logging. Pass
//     nil to suppress process-level termination (the panic still
//     surfaces via the return value).
//   - run is the wrapped goroutine body.
//
// The standard cmd/ledger/main.go pattern is:
//
//   wg.Add(1)
//   go func() {
//       defer wg.Done()
//       if err := lifecycle.SafeRun(ctx, "shipper", logger, fatal, func() error {
//           return ship.Run(ctx)
//       }); err != nil && !errors.Is(err, context.Canceled) {
//           // err already in fatal channel + logged; nothing to do
//       }
//   }()
func SafeRun(
	ctx context.Context,
	name string,
	logger *slog.Logger,
	fatalCh chan<- error,
	run func() error,
) (retErr error) {
	// Entry log: every wrapped goroutine emits a "goroutine started"
	// line at Info so operators can prove from logs alone that each
	// supervisor child actually launched. The corresponding "stopped"
	// line fires from the deferred branch below — including on panic
	// — so the start/stop pair is symmetric.
	if logger != nil {
		logger.InfoContext(ctx, "goroutine started", "goroutine", name)
	}
	defer func() {
		rec := recover()
		if rec == nil {
			// Normal exit. Log the terminal error class (nil,
			// context.Canceled, or other) so operators can
			// distinguish graceful shutdown from premature exit.
			if logger != nil {
				logger.InfoContext(ctx, "goroutine stopped",
					"goroutine", name,
					"err", retErr,
				)
			}
			return
		}
		// Stdlib idiom: ErrAbortHandler is the in-band abort
		// signal used by stdlib's TimeoutHandler. Re-panic so the
		// stdlib's connection-level recovery handles it.
		if rec == http.ErrAbortHandler {
			panic(rec)
		}
		stack := debug.Stack()
		if len(stack) > MaxRecoveredStackBytes {
			stack = stack[:MaxRecoveredStackBytes]
		}
		err := fmt.Errorf("%w: %s panicked: %v", ErrPanicRecovered, name, rec)
		if logger != nil {
			logger.ErrorContext(ctx,
				"goroutine panic recovered",
				"goroutine", name,
				"panic", fmt.Sprint(rec),
				"stack", string(stack),
			)
			// Symmetric stopped log even on panic so
			// `grep "goroutine stopped"` always pairs with the
			// matching "started" line.
			logger.InfoContext(ctx, "goroutine stopped",
				"goroutine", name,
				"panic", true,
			)
		}
		// Surface to fatal channel so supervisor can terminate
		// the process cleanly. Non-blocking send: if the channel
		// buffer is full or fatalCh is nil, the panic still
		// surfaces via retErr.
		if fatalCh != nil {
			select {
			case fatalCh <- err:
			default:
			}
		}
		retErr = err
	}()
	return run()
}

// -------------------------------------------------------------------------------------------------
// 3) WaitGroup-aware variant
// -------------------------------------------------------------------------------------------------

// SafeRunInWG is a tiny convenience wrapper that combines
// wg.Add(1)/wg.Done discipline with SafeRun. The supplied
// goroutine name is used both for log correlation and for the
// returned-error wrap.
//
// Use this when the caller's goroutine body is shaped like
// `func() error` and there's no other lifecycle to thread. For
// goroutines that need additional cleanup (defer cancel,
// resource close, etc.), call SafeRun directly.
func SafeRunInWG(
	ctx context.Context,
	wg *sync.WaitGroup,
	name string,
	logger *slog.Logger,
	fatalCh chan<- error,
	run func() error,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = SafeRun(ctx, name, logger, fatalCh, run)
	}()
}
