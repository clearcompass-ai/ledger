// FILE PATH: chaos/trigger_chaos.go
//
// Chaos-build Trigger: terminates the process via os.Exit(2) when
// LEDGER_CHAOS_PANIC_AT matches the call-site name. Compiled only
// when -tags=chaos is set. The default (production) build uses
// trigger_default.go.
//
// WHY os.Exit AND NOT panic
//
// The ledger wraps every long-running goroutine (sequencer,
// shipper, anti-entropy, etc.) in lifecycle.SafeRun, which has a
// defer recover() that catches any panic, logs it, and does a
// NON-BLOCKING send to the fatal channel. If the fatal channel is
// full or nil the panic is silently swallowed and the goroutine
// just terminates — the rest of the process keeps running. That
// breaks the chaos contract: we want to simulate SIGKILL, which
// is an unrecoverable termination.
//
// os.Exit(2) bypasses every defer recover() in the goroutine
// chain because it terminates the process at the kernel level
// before any Go unwinding happens. This is exactly the semantic
// chaos tests need: a hard kill at the injection point. We emit a
// stable marker line to stderr BEFORE calling os.Exit so the test
// harness can still grep for the marker to confirm the kill fired
// at the intended injection point.
//
// (The exit code 2 distinguishes chaos kills from normal exits
// (0) and from generic Go panics that escaped to the runtime (2
// is also Go's default for unrecovered panics, but the marker
// line disambiguates).

//go:build chaos
// +build chaos

package chaos

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Trigger terminates the process via os.Exit(2) when name matches
// LEDGER_CHAOS_PANIC_AT. The marker line written to stderr before
// exit lets the harness's stderr capture confirm the trigger
// fired at the intended injection point.
//
// LEDGER_CHAOS_PANIC_AT accepts a single name or a comma-separated
// list; any matching name triggers. The variable is read once per
// call (no caching) so chaos tests can toggle the trigger between
// stages by re-exporting the env var — but for subprocess tests
// (the realistic case), the env var is set at process launch and
// the value never changes within the process lifetime.
//
// LEDGER_CHAOS_PANIC_AFTER_N caps the trigger to fire only on the
// Nth or later match (1-indexed). Without it, the FIRST matching
// call kills — usually what's wanted for "kill mid-AppendLeaf"
// style tests where any matching call is acceptable. For tests
// like "kill on the 100th submission" set it to 100.
func Trigger(name string) {
	matchSet := loadMatchSet()
	if _, ok := matchSet[name]; !ok {
		return
	}

	// Per-name counter: ensures LEDGER_CHAOS_PANIC_AFTER_N gates
	// independently for distinct injection points. A single
	// global counter would couple unrelated points and produce
	// confusing test failures.
	count := nameCounter(name).Add(1)
	if threshold := loadAfterN(); threshold > 0 && count < threshold {
		return
	}

	// Emit the marker line to stderr FIRST. The default emitMarker
	// is a single fmt.Fprint to os.Stderr — one Write syscall to
	// the stderr FD, which the kernel buffers atomically; when the
	// harness wires the subprocess stderr as a pipe the harness
	// reader sees the marker before the SIGCHLD/exit notification.
	emitMarker(fmt.Sprintf("%s name=%s count=%d\n", Marker, name, count))

	// exitFn — bypasses every defer recover() in the goroutine
	// chain. Default is os.Exit(2) (matches SIGKILL semantics:
	// no Go unwinding, no deferred cleanup, no graceful close).
	// Indirected through a variable so in-process unit tests can
	// intercept without terminating the test runner.
	exitFn(2)
}

// exitFn is the process-termination function used by Trigger.
// Production uses os.Exit. Unit tests in this package replace it
// with a panic-on-call shim so they can assert behavior without
// killing the test runner; the shim restores os.Exit on cleanup.
//
// emitMarker writes the chaos marker line to stderr. Tests
// override it with a synchronous buffer writer so the captured
// stderr line is observable immediately after Trigger returns
// (no pipe, no goroutine drain, no scheduling race).
var (
	exitFn     = os.Exit
	emitMarker = func(line string) { fmt.Fprint(os.Stderr, line) }
)

// Marker is the leading substring of every chaos-induced panic
// message. Test harnesses grep stderr for this to assert the
// kill fired at the intended point. Stable across versions; do
// not change without updating every chaos test.
const Marker = "LEDGER_CHAOS_PANIC"

var (
	// matchSet cached on first call. Set once at process start;
	// safe to read concurrently after that. Reset only by tests
	// (via resetForTests).
	matchSetCache atomic.Pointer[map[string]struct{}]
	afterNCache   atomic.Int64
	afterNLoaded  atomic.Bool

	// One Add-only counter per injection-point name. Tracks how
	// many times this name has been seen by Trigger; gated against
	// LEDGER_CHAOS_PANIC_AFTER_N. sync.Map keeps the read path
	// lock-free in the common case (cache hit on existing name).
	counters sync.Map
)

func loadMatchSet() map[string]struct{} {
	if p := matchSetCache.Load(); p != nil {
		return *p
	}
	raw := os.Getenv("LEDGER_CHAOS_PANIC_AT")
	set := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		set[part] = struct{}{}
	}
	matchSetCache.CompareAndSwap(nil, &set)
	return set
}

func loadAfterN() int64 {
	if afterNLoaded.Load() {
		return afterNCache.Load()
	}
	raw := strings.TrimSpace(os.Getenv("LEDGER_CHAOS_PANIC_AFTER_N"))
	if raw == "" {
		afterNLoaded.Store(true)
		return 0
	}
	var n int64
	_, err := fmt.Sscanf(raw, "%d", &n)
	if err != nil || n < 0 {
		n = 0
	}
	afterNCache.Store(n)
	afterNLoaded.Store(true)
	return n
}

func nameCounter(name string) *atomic.Int64 {
	if v, ok := counters.Load(name); ok {
		return v.(*atomic.Int64)
	}
	fresh := &atomic.Int64{}
	actual, _ := counters.LoadOrStore(name, fresh)
	return actual.(*atomic.Int64)
}
