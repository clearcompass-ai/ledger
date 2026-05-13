/*
FILE PATH: tests/tessera_lifecycle_helper_test.go

Test helper that gives Tessera's upstream background goroutines
time to exit before the on-disk tile-root directory vanishes.

# WHY THIS HELPER EXISTS

Upstream tessera.NewAppender (tessera@v1.0.2/append_lifecycle.go:
278-282) spawns three background goroutines using bare `go`, with
no sync.WaitGroup and no completion signal. After ctx.Cancel they
exit asynchronously; the returned shutdown function does NOT wait
for them.

In test scope, t.TempDir() registers its directory removal via
t.Cleanup. Cleanup functions run in LIFO order at the end of the
test function. If the appender's Close runs in an earlier cleanup
(or via deferred shutdownChain), the upstream goroutines may
still be running when t.TempDir's removal fires — they then log
"open .../treeState: no such file or directory" at 10ms cadence
until they observe ctx.Done.

Our optessera.EmbeddedAppender's Close (tessera/embedded_appender.
go) already waits a drainBudget after cancelling its private
bg-ctx. tesseraTempDir is the companion helper at the test side:
it defers the directory removal by an additional drainBudget
window so the goroutines have time to exit even if Close was
called late in the test.

# WHEN UPSTREAM SHIPS A WAIT FUNCTION

Tier-1 of the structural fix plan files an upstream PR adding
NewAppender wait(ctx) function. When that lands, EmbeddedAppender.
Close can do an explicit join and this helper becomes unnecessary
— callers can switch back to t.TempDir().

# USAGE

	tileRoot := tesseraTempDir(t, 200*time.Millisecond)
	// ... build EmbeddedAppender at tileRoot ...
	// On test exit:
	//   1. t.Cleanup fires embedded.Close (registered by harness)
	//   2. Close drains, cancels bg-ctx, waits its OWN drainBudget
	//   3. tesseraTempDir's cleanup waits drainBudget more
	//   4. RemoveAll runs — goroutines have had 2×drainBudget total
*/
package tests

import (
	"os"
	"testing"
	"time"
)

// tesseraTempDir is a t.TempDir() replacement that defers
// directory removal by drainBudget. Use for any test that
// constructs an EmbeddedAppender — the drainBudget gives
// upstream Tessera's background goroutines (which don't have a
// WaitGroup; see file docstring) time to observe ctx.Done and
// exit before the on-disk state vanishes.
//
// Returns an absolute path. Cleanup is automatic via t.Cleanup;
// callers don't need to remove the directory themselves.
//
// drainBudget=0 disables the delay (equivalent to t.TempDir).
// 200ms is the recommended default — see
// tessera.DefaultDrainBudget for the rationale.
func tesseraTempDir(t *testing.T, drainBudget time.Duration) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tessera-test-")
	if err != nil {
		t.Fatalf("tesseraTempDir: os.MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		// Drain window — give upstream goroutines time to observe
		// ctx.Done before the directory they may still be reading
		// from gets removed.
		if drainBudget > 0 {
			time.Sleep(drainBudget)
		}
		if err := os.RemoveAll(dir); err != nil {
			// Best-effort. A failed removal leaves a tmpdir behind;
			// the OS will eventually reap. Log at info so noisy
			// runs are diagnosable but a single failure doesn't
			// fail the test.
			t.Logf("tesseraTempDir: RemoveAll(%s): %v (ignored)", dir, err)
		}
	})
	return dir
}
