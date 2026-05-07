/*
FILE PATH:
    wal/fuzz_test.go

DESCRIPTION:
    J1 — Fuzz the WAL Submit → Read round-trip. Property: the
    bytes Read returns are EXACTLY the bytes Submit committed.
    The WAL is the load-bearing durability primitive (Ledger
    principle #3 SCT-as-SLA); any byte-corruption between
    Submit and Read is a critical bug.

    Run via:
        go test -run=^$ -fuzz=^FuzzWALSubmitRead$ \
            -fuzztime=30s ./wal/

KEY ARCHITECTURAL DECISIONS:
    - In-memory Badger so the fuzzer can spawn many WALs
      without touching disk.
    - Hash is SHA-256 of the wire bytes (the canonical-hash
      shape Submit expects). Fuzz inputs that wouldn't form
      a valid envelope are still valid Submit inputs because
      the WAL is byte-faithful to whatever Submit hands it.
    - One WAL per fuzz iteration so we exercise fresh state.
*/
package wal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// FuzzWALSubmitRead asserts: for any non-empty wire bytes, after
// Submit completes, Read returns the same bytes byte-for-byte.
// Catches WAL serialization bugs (truncation, padding, encoding)
// that example tests miss because they use fixed-shape inputs.
func FuzzWALSubmitRead(f *testing.F) {
	// Production-shaped seeds (small + medium + tile-bundle ceiling).
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0xAA}, 1024))
	f.Add(bytes.Repeat([]byte{0xFF}, 32*1024)) // 32 KiB
	// Hostile seeds (0x00 byte content, non-utf8).
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})
	f.Add([]byte{0xC3, 0x28}) // invalid utf-8

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) == 0 {
			// Submit rejects empty; documented contract.
			return
		}
		// Cap to MaxBundleEntrySize-equivalent so we don't OOM
		// the runner on a fuzzer-generated 100MiB input.
		if len(wire) > 65535 {
			wire = wire[:65535]
		}

		db, err := OpenInMemory(slog.Default())
		if err != nil {
			t.Fatalf("OpenInMemory: %v", err)
		}
		defer db.Close()

		c := NewCommitter(db, CommitterConfig{
			Logger:      slog.Default(),
			DisableSync: true, // in-memory Badger has no WAL to sync
		})
		defer c.Close()

		hash := sha256.Sum256(wire)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
			// Submit MAY return ErrQueueFull under heavy fuzz
			// concurrency; that's a backpressure signal, not a
			// correctness violation.
			if errors.Is(err, ErrQueueFull) || errors.Is(err, ErrClosed) {
				return
			}
			t.Fatalf("Submit: %v", err)
		}

		got, err := c.Read(ctx, hash)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if !bytes.Equal(got, wire) {
			t.Errorf("WAL round-trip altered bytes:\n  in  (%d bytes): %x\n  out (%d bytes): %x",
				len(wire), wire[:min(len(wire), 32)],
				len(got), got[:min(len(got), 32)])
		}
	})
}
