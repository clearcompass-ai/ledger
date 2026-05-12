//go:build chaos
// +build chaos

// FILE PATH: tests/chaos/kill_restart/kill_appendleaf_test.go
//
// Variant #1 — SIGKILL during stage-1, just after Tessera
// AppendLeaf returns but before the staged-entry tuple is
// emitted to the committer.
//
// Recovery expectation: on restart, drainOnce re-fetches the
// still-Pending hash, stage-1 re-runs, Tessera's antispam
// dedup returns the SAME seq, the tuple flows through normally.
// No duplicate entry_index rows, no gap in the sequence space.
package kill_restart

import (
	"context"
	"testing"

	"github.com/clearcompass-ai/ledger/tests/chaos/harness"
)

// TestKillRestart_PostAppendLeaf — variant #1.
//
// Variant-specific assertion: Tessera's antispam dedup must
// return the SAME seq for the re-AppendLeaf call after restart.
// If dedup were broken, the post-restart submitter would see
// either (a) a duplicate seq in entry_index (gap or
// double-assignment) or (b) an SCT with a different canonical
// hash than the original submitter saw. Either case fails the
// AssertInvariants step inside killRestartCycle (gaps=0 OR SMT
// reconstruction mismatch).
//
// We capture the same hash being submitted on both sides of the
// kill, then explicitly assert it landed exactly once in
// entry_index. This is the property "Tessera antispam dedup
// composes with our restart" — the load-bearing invariant of
// variant #1.
func TestKillRestart_PostAppendLeaf(t *testing.T) {
	r := killRestartCycle(t, cycleOpts{
		killPoint:          harness.KillPointPostAppendLeaf,
		afterN:             30,
		submitBeforeKill:   100,
		submitAfterRestart: 50,
	})

	// Variant-specific: confirm no canonical-hash collisions
	// in entry_index (Tessera antispam dedup invariant).
	assertNoHashCollisions(context.Background(), t, r.h)
}
