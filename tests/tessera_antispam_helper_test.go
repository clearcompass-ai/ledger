/*
FILE PATH: tests/tessera_antispam_helper_test.go

Shared test helper for posix-backed Tessera Antispam allocation.

# WHY THIS HELPER EXISTS

Multiple E2E harnesses (e2e_shipper_redirect, e2e_graceful_shutdown,
testserver_tessera) construct a Tessera EmbeddedAppender. Without
Antispam wired, Tessera assigns a fresh seq to every AppendLeaf
call — even for duplicate hashes — and the sequencer's drainOnce
re-pickup race (committer.go:649-664) inflates ghost-row activations
from "single-digit percent under burst" to ~80%. The
hwmAdvancer then stalls at the first gap.

# WHY POSIX ANTISPAM IS THE CT PATTERN

Production CT logs (Trillian, CTFE / Sectigo, Cloudflare Nimbus,
Let's Encrypt Oak) all rely on a durable hash → seq index that
synchronously dedupes submissions before sequence assignment.
Tessera's Antispam follower IS that primitive: a Badger/POSIX-
backed map populated by an integration follower that catches
duplicate AppendLeaf calls at the Tessera boundary. Production
wires it at cmd/ledger/boot/alloc/alloc.go:418; this helper
mirrors that wiring for tests.

# WHY THE HELPER TAKES AN EXPLICIT PATH

The restart-style test (TestE2E_RestartCompletesShipping in
e2e_graceful_shutdown_test.go) launches two sequencer instances
against the SAME on-disk tile root. The antispam volume must
survive across both invocations so dedup state persists through
the simulated crash. A helper that calls t.TempDir() internally
would create a fresh dir on each call and break that contract.
Callers pass filepath.Join(tileRoot, "antispam") explicitly so
the on-disk lifecycle stays in the harness's control.
*/
package tests

import (
	"context"
	"testing"

	"github.com/transparency-dev/tessera"
	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"
)

// newAntispamForTest constructs a posix-backed Antispam at the
// given on-disk path. Mirrors cmd/ledger/boot/alloc/alloc.go::
// allocateAntispam so harnesses exercise the same dedup primitive
// production runs with.
//
// Callers pass the path explicitly. Typical use:
//
//	filepath.Join(tileRoot, "antispam")
//
// where tileRoot is the harness's t.TempDir() (single-invocation
// tests) or a shared sub-test-scoped directory (restart-style
// tests where antispam state must survive the appender's
// reconstruction).
//
// No t.Cleanup is registered: AntispamStorage's upstream surface
// has no Close method (cmd/ledger/boot/alloc/alloc.go:471 confirms
// the same in production — it registers a no-op closer for chain
// ordering only). The antispam's background goroutines observe
// the supplied ctx and exit when the test's ctx is cancelled; the
// on-disk files are cleaned up by t.TempDir's deferred removal.
//
// Errors are t.Fatal — a failed Antispam allocation is
// unrecoverable for the test.
func newAntispamForTest(t *testing.T, ctx context.Context, antispamPath string) tessera.Antispam {
	t.Helper()
	antispam, err := tposixantispam.NewAntispam(ctx, antispamPath, tposixantispam.AntispamOpts{})
	if err != nil {
		t.Fatalf("newAntispamForTest(%s): %v", antispamPath, err)
	}
	return antispam
}
