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
	"testing"
)

func TestKillRestart_PostAppendLeaf(t *testing.T) {
	killRestartCycle(t, cycleOpts{
		panicAt:            "post_appendleaf",
		afterN:             30,
		submitBeforeKill:   100,
		submitAfterRestart: 50,
	})
}
