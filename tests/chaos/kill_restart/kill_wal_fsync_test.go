//go:build chaos
// +build chaos

// FILE PATH: tests/chaos/kill_restart/kill_wal_fsync_test.go
//
// Variant #4 — SIGKILL inside the WAL Committer's group-commit
// goroutine, after the Badger transaction commit but BEFORE
// the db.Sync() fsync. This is the most violent kill: it
// kills the process between "in memtable" and "durable on
// disk".
//
// Recovery expectation: Badger's WAL replay surfaces every
// txn committed before the kill, including the just-committed
// batch whose fsync was interrupted. Every submission that
// returned 202 to the client MUST be recoverable.
//
// This is the hardest durability claim the ledger makes. If
// this test green, the Phase 1 Liability Transfer guarantee
// (every 202 is recoverable) holds under abrupt power-loss
// semantics.
package kill_restart

import (
	"context"
	"testing"

	"github.com/clearcompass-ai/ledger/tests/chaos/harness"
)

// TestKillRestart_PreWALFsync — variant #4 (hardest durability
// claim).
//
// Variant-specific assertion: every submission that the
// harness's submitter recorded as 202-accepted MUST be
// recoverable from entry_index after restart. The Badger WAL
// replay on restart surfaces every txn committed before
// SIGKILL, including the batch whose fsync was interrupted.
// This is the "Phase 1 Liability Transfer" durability claim
// the ledger makes to clients: every SCT returned is durable.
//
// The harness's AssertInvariants validates the FINAL count
// matches `expected` (accepted + post-restart-submissions).
// This variant-specific check adds: every canonical_hash the
// submitter saw in a 202 response MUST be present in
// entry_index. Catches the failure mode where the ledger
// returns 202 but the entry is lost on kill.
//
// The cycleOpts.captureHashes flag instructs killRestartCycle
// to record every 202'd canonical_hash for this purpose.
func TestKillRestart_PreWALFsync(t *testing.T) {
	r := killRestartCycle(t, cycleOpts{
		killPoint:          harness.KillPointPreWALFsync,
		afterN:             2,
		submitBeforeKill:   200,
		submitAfterRestart: 50,
		captureHashes:      true,
	})

	// Variant-specific: every 202'd canonical_hash MUST appear
	// in entry_index. Validates the "every SCT is durable"
	// claim under abrupt-power-loss semantics.
	assertHashesPresent(context.Background(), t, r.h, r.acceptedHashes)
}
