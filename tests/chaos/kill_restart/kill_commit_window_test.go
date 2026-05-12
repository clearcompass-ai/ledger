//go:build chaos
// +build chaos

// FILE PATH: tests/chaos/kill_restart/kill_commit_window_test.go
//
// Variant #2 — SIGKILL between the committer's PG transaction
// commit and the subsequent applyPostCommitForOne call. This
// is the exact window committerStaleRecover was written for:
// entry_index has the row durably, but WAL state never made
// the Pending → Sequenced transition.
//
// Recovery expectation: on restart, drainOnce re-fetches the
// hash (still WAL Pending), stage-1 re-runs, AppendLeaf
// dedupes, the duplicate stagedEntry hits the committer's
// cross-batch stale path, committerStaleRecover advances the
// WAL state, no duplicate entry_index row produced.
//
// This is the integration-level counterpart to the unit test
// TestSequencer_processOne_DuplicateHash_StaleRecover. The
// unit test validates the recovery logic with in-process state
// manipulation; this test validates it under a real SIGKILL.
package kill_restart

import (
	"testing"
)

func TestKillRestart_PreCommitPostPG(t *testing.T) {
	killRestartCycle(t, cycleOpts{
		panicAt:            "pre_commit_post_pg",
		afterN:             3, // panic after the 3rd batch commit
		submitBeforeKill:   200,
		submitAfterRestart: 50,
	})
}
