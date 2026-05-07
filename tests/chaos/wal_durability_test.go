//go:build chaos
// +build chaos

/*
FILE PATH:
    tests/chaos/wal_durability_test.go

DESCRIPTION:
    J4 — Chaos test: WAL durability under simulated mid-Submit
    process death. Pins Phase 1 Liability Transfer durability
    (Ledger principle #3 SCT-as-SLA): every Submit that returned
    202 MUST be recoverable from the WAL after restart.

    Mechanism: in-process simulation that uses a real on-disk
    Badger WAL (NOT in-memory) so the test exercises actual
    fsync semantics. Submit N entries; close the Committer
    abruptly (close before draining queue); reopen against the
    same on-disk path; assert N recoverable entries.

KEY ARCHITECTURAL DECISIONS:
    - On-disk Badger via t.TempDir(). Real fsync; real Badger
      replay on reopen.
    - Sequential submits (not concurrent) so the "abrupt close"
      semantics are deterministic. Concurrent + chaos =
      separate test.
    - Doesn't kill the process — Go test framework doesn't
      survive SIGKILL on itself. Instead, simulates via
      Committer.Close() which triggers the same flush path
      the WAL takes on graceful shutdown. A SIGKILL chaos
      test requires a subprocess harness (follow-up).
*/
package chaos

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/wal"
)

// TestChaos_WALDurabilityCloseAndReopen pins: every Submit
// that returned 202 is recoverable after Committer.Close +
// Reopen.
func TestChaos_WALDurabilityCloseAndReopen(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(quietWriter{}, nil))

	// Phase 1: Submit N entries, then close.
	const N = 50
	hashes := make([][32]byte, N)
	wires := make([][]byte, N)

	db1, err := wal.Open(dir, logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	c1 := wal.NewCommitter(db1, wal.CommitterConfig{Logger: logger})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < N; i++ {
		wire := []byte(fmt.Sprintf("durability-test-entry-%d", i))
		hash := sha256.Sum256(wire)
		hashes[i] = hash
		wires[i] = wire
		if err := c1.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}

	// Close the Committer + DB. Real fsync semantics fire; the
	// on-disk Badger WAL is now durable.
	if err := c1.Close(); err != nil {
		t.Fatalf("Committer.Close: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("DB.Close: %v", err)
	}

	// Phase 2: Reopen + verify every entry is recoverable.
	db2, err := wal.Open(dir, logger)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	defer db2.Close()
	c2 := wal.NewCommitter(db2, wal.CommitterConfig{Logger: logger})
	defer c2.Close()

	for i := 0; i < N; i++ {
		got, err := c2.Read(ctx, hashes[i])
		if err != nil {
			t.Errorf("Read %d after reopen: %v", i, err)
			continue
		}
		if string(got) != string(wires[i]) {
			t.Errorf("Read %d: bytes differ after reopen", i)
		}
	}
}
