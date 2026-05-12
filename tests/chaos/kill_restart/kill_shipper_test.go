//go:build chaos
// +build chaos

// FILE PATH: tests/chaos/kill_restart/kill_shipper_test.go
//
// Variant #3 — SIGKILL during shipper.shipOne, between the
// WAL bytes read and the bytestore.WriteEntry call.
//
// Recovery expectation: on restart, the seq's WAL state is
// still Sequenced (not Shipped). The shipper's IterateSequenced
// catches it on the first cycle, re-uploads to the bytestore
// (idempotent by seq+hash key), advances WAL state to Shipped.
//
// The bytestore upload is content-addressed by seq + hash, so a
// re-upload of the same entry MUST land at the same URL — the
// invariant assertion confirms every entry from entry_index is
// fetchable from the bytestore at the expected URL.
package kill_restart

import (
	"testing"
)

func TestKillRestart_PreShipperUpload(t *testing.T) {
	killRestartCycle(t, cycleOpts{
		panicAt:            "pre_shipper_upload",
		afterN:             50,
		submitBeforeKill:   200,
		submitAfterRestart: 50,
	})
}
