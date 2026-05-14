/*
FILE PATH: tessera/debug_trace.go

DIAGNOSTIC INSTRUMENTATION — TEMPORARY.

Captures the chronology of EmbeddedAppender.Close calls AND
AppendLeaf failures with full stack traces. Designed to produce
indisputable evidence of WHO calls Close before the test's first
AppendLeaf — the root cause of the "appender has been shut down"
errors observed in the tests/ HTTP-integration suite.

# ACTIVATION

Gated behind LEDGER_DEBUG_TESSERA=1. Default disabled; production
runs see no overhead beyond a single os.Getenv lookup per
Close/AppendLeaf call.

# HOW TO USE

	LEDGER_DEBUG_TESSERA=1 go test -count=1 -p 1 -v -timeout=30s \
	    -run TestRule_SubmissionStoresBytesInEntryReader ./tests/ \
	    2>&1 | tee /tmp/tessera-trace.log

	# Extract the chronology:
	grep -E 'DEBUG/tessera:' /tmp/tessera-trace.log
	# Or the stack-bearing events:
	grep -A 25 'DEBUG/tessera:' /tmp/tessera-trace.log | less

# WHAT TO READ

The trace lines carry `t_offset` (nanoseconds since the first
traced event in this process). Three lines fix the story:

  1. "EmbeddedAppender.Close invoked"     — first Close call. Stack
                                            shows the caller.
  2. "AppendLeaf returned shutdown error" — first failure. Stack
                                            shows the sequencer
                                            invocation.
  3. Compare t_offsets.

If (1) precedes (2): the caller at (1)'s stack is the bug. Fix
the offending site so Close doesn't fire during test body.

If (2) appears with NO preceding (1): upstream tessera's
`stopped` flag became true through some other path
(unexpected — would force a deeper look at upstream/v1.0.2's
internals).

# REMOVAL

Delete this file once the offending caller is identified and the
real fix has shipped. The Close + AppendLeaf instrumentation in
embedded_appender.go calls `debugTrace*` functions that no-op
when this file is gone; build will fail loudly, prompting
removal of the call sites too. (See debug_trace_off.go for the
no-op variant if you want to ship-WITH-call-sites and just
disable.)
*/
package tessera

import (
	"log/slog"
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// debugEnvVar is the toggle for this whole file. One value to
// look for in CI logs or local scripts.
const debugEnvVar = "LEDGER_DEBUG_TESSERA"

// debugEnabled is re-read on every call so a long-running test
// process can flip the flag mid-flight (e.g., via os.Setenv from
// a sub-test) without re-init. Cheap — a single syscall.
func debugEnabled() bool { return os.Getenv(debugEnvVar) == "1" }

// debugT0 anchors every traced event to a single time origin.
// The first event captured in this process sets debugT0 (lazy
// init via CompareAndSwap). Subsequent events report
// `now - debugT0` in nanoseconds, making it trivial to read the
// chronology in the log even if absolute clocks drift.
var debugT0 atomic.Int64

// debugRelativeTime returns nanoseconds elapsed since the first
// traced event. Returns 0 for the first call (which is the
// origin).
func debugRelativeTime() time.Duration {
	now := time.Now().UnixNano()
	if debugT0.CompareAndSwap(0, now) {
		return 0
	}
	return time.Duration(now - debugT0.Load())
}

// debugCaptureStack returns the current goroutine's stack as a
// string, truncated to `maxBytes` to keep the log entry bounded.
// 4096 bytes is enough to see ~30 frames; deeper traces are
// rarely informative.
func debugCaptureStack(maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	buf := make([]byte, maxBytes)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// debugTraceClose captures one log entry per Close call when the
// env var is set. Called unconditionally from
// EmbeddedAppender.Close (the env check happens inside).
//
// The stack identifies who invoked Close. In a healthy test run
// there should be EXACTLY ONE Close invocation, fired from
// shutdownChain.Run via t.Cleanup. Any earlier invocation is the
// bug.
func debugTraceClose(logger *slog.Logger) {
	if !debugEnabled() {
		return
	}
	logger.Warn("DEBUG/tessera: EmbeddedAppender.Close invoked",
		"t_offset_ns", debugRelativeTime().Nanoseconds(),
		"stack", debugCaptureStack(4096))
}

// debugTraceAddFailure captures the first (and every subsequent)
// AppendLeaf failure that matches the "appender has been shut
// down" signature. Carries the same stack-capture treatment as
// Close so the sequencer's invocation chain is visible.
//
// The data prefix (first 8 bytes of the leaf) is included for
// per-entry correlation. The error string is logged verbatim so
// changes in upstream tessera's error vocabulary surface here
// immediately.
func debugTraceAddFailure(logger *slog.Logger, data []byte, err error) {
	if !debugEnabled() {
		return
	}
	prefix := data
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	logger.Warn("DEBUG/tessera: AppendLeaf returned shutdown error",
		"t_offset_ns", debugRelativeTime().Nanoseconds(),
		"data_prefix", prefix,
		"err", err.Error(),
		"stack", debugCaptureStack(2048))
}

// debugTraceAppenderConstructed fires exactly once per
// EmbeddedAppender construction, anchoring the t=0 timestamp to
// the post-NewAppender point. Makes it trivial to spot a Close
// that fires AT t=0 (a smoking-gun construction-time race).
func debugTraceAppenderConstructed(logger *slog.Logger) {
	if !debugEnabled() {
		return
	}
	logger.Warn("DEBUG/tessera: EmbeddedAppender constructed",
		"t_offset_ns", debugRelativeTime().Nanoseconds(),
		"stack", debugCaptureStack(2048))
}
