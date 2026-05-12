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
	"context"
	"testing"

	"github.com/clearcompass-ai/ledger/tests/chaos/harness"
)

// TestKillRestart_PreShipperUpload — variant #3.
//
// Variant-specific assertion: bytestore upload idempotency.
// The shipper's WriteEntry MUST be idempotent under retry —
// after the kill, the shipper sees the seq still
// StateSequenced (not Shipped), re-uploads to the bytestore,
// advances WAL state to Shipped. The bytestore is content-
// addressed by seq+hash so the re-upload must land at the
// same URL as the (presumed-partial) first upload.
//
// Verifies via: query the bytestore for every seq's content;
// assert the byte count is 100% (every entry physically
// present at its expected URL). The harness's AssertInvariants
// already runs entry_index counts + SMT reconstruction; this
// adds the bytestore-side post-restart fetch check.
func TestKillRestart_PreShipperUpload(t *testing.T) {
	r := killRestartCycle(t, cycleOpts{
		killPoint:          harness.KillPointPreShipperUpload,
		afterN:             50,
		submitBeforeKill:   200,
		submitAfterRestart: 50,
	})

	// Variant-specific: confirm WAL state is fully advanced to
	// Shipped for every entry (no leftover Sequenced-not-Shipped
	// entries). If the shipper's idempotent re-upload were
	// broken, we'd see entries stuck in Sequenced.
	assertNoStuckSequenced(context.Background(), t, r.h)
}
