// FILE PATH: chaos/trigger_chaos.go
//
// Chaos-build Trigger: panics when LEDGER_CHAOS_PANIC_AT matches
// the call-site name. Compiled only when -tags=chaos is set.
// The default (production) build uses trigger_default.go.

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

// Trigger panics when name matches LEDGER_CHAOS_PANIC_AT. The
// panic message includes the name + a trace marker so the test
// harness can confirm via stderr capture that the panic fired at
// the intended injection point.
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
// call panics — usually what's wanted for "kill mid-AppendLeaf"
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

	// Panic with a unambiguously-recognizable marker so the
	// harness's stderr scrape can confirm the trigger fired here
	// (and not from some unrelated production panic). The marker
	// is stable and exported via the Marker constant below.
	panic(fmt.Sprintf("%s name=%s count=%d", Marker, name, count))
}

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
