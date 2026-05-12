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
	"context"
	"testing"

	"github.com/clearcompass-ai/ledger/tests/chaos/harness"
)

// TestKillRestart_PreCommitPostPG — variant #2 (the most
// load-bearing kill point).
//
// Variant-specific assertion: the staleCrashRecoveries metric
// on the restarted sequencer MUST be > 0. That metric only
// increments inside committerStaleRecover when MetaState
// reports StatePending — i.e., the original PG-committed-but-
// WAL-not-advanced state. If the recovery code fired, that
// counter moves. If it's zero, either:
//   (a) the kill didn't actually land between PG commit and
//       WAL.Sequence (false-positive test pass)
//   (b) some other code path advanced the WAL state instead
//       (regression in the recovery logic)
//
// Either case is a failure. This assertion is what
// distinguishes variant #2 from the others — the unit test
// TestSequencer_processOne_DuplicateHash_StaleRecover validates
// the same code with in-process state manipulation; here we
// validate it under real SIGKILL.
func TestKillRestart_PreCommitPostPG(t *testing.T) {
	r := killRestartCycle(t, cycleOpts{
		killPoint:          harness.KillPointPreCommitPostPG,
		afterN:             3, // panic after the 3rd batch commit
		submitBeforeKill:   200,
		submitAfterRestart: 50,
	})

	// Variant-specific: staleCrashRecoveries must have fired.
	// The harness's invariant assertion confirms reconciliation
	// completed; this confirms the SPECIFIC recovery path was
	// the one that completed it.
	assertStaleCrashRecoveriesPositive(context.Background(), t, r.h)
}
