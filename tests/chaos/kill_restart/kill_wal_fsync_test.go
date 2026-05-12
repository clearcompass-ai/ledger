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
	"testing"
)

func TestKillRestart_PreWALFsync(t *testing.T) {
	killRestartCycle(t, cycleOpts{
		panicAt:            "pre_wal_fsync",
		afterN:             2, // panic after the 2nd group-commit
		submitBeforeKill:   200,
		submitAfterRestart: 50,
	})
}
