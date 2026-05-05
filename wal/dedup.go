/*
FILE PATH: wal/dedup.go

TesseraDedup — a Badger-backed implementation of the upstream
Tessera library's deduplicator interface. Backed by the SAME Badger
DB as the WAL itself (separate keyspace prefix), so dedup state
shares the ledger's single durability medium with the WAL: same
fsync, same backup, same recovery story.

THE TESSERA-DEDUP CONTRACT:

	Tessera invokes Get(identity) before each Add to detect previously
	integrated entries. On a hit, Tessera returns the existing index
	to the caller — no new sequence assigned. On a miss, integration
	proceeds normally and Tessera invokes Set(identity, idx) to record
	the assignment.

	Identity is the SHA-256 of the entry's serialized form
	(envelope.EntryIdentity = sha256(envelope.Serialize(entry))).
	Both Get and Set are called in Tessera's hot path; this adapter
	uses single-row Badger ops with no extra synchronization.

WHY SAME BADGER:

	Reconciliation re-Adds inflight entries on boot (the integrity
	package owns this loop). For Re-Add to be idempotent, Tessera must
	return the previously-assigned index for any hash it has seen.
	That requires the dedup to survive the same crashes the WAL does.
	Sharing the BadgerDB instance ensures this — both go through the
	same fsync, both restore together, no chance of a state-mismatch
	window between two databases.

KEY SHAPE:

	See keyspace.go: tessera_dedup:<identity:32> → <seq:8 bigendian>.
*/
package wal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
)

// TesseraDedup is the Badger-backed deduplicator. Construct via
// Committer.Dedup() so the storage backend stays scoped to the
// committer's lifetime.
type TesseraDedup struct {
	db *badger.DB
}

// Dedup returns the TesseraDedup adapter rooted at the same Badger
// DB as the committer. Wire it into tessera.NewAppender via
// tessera.WithDeduplication(...).
func (c *Committer) Dedup() *TesseraDedup {
	return &TesseraDedup{db: c.db}
}

// Get returns the previously-assigned index for identity, if any.
// (idx, true, nil) on a hit; (0, false, nil) on a miss; non-nil err
// for transport / decode failures.
func (d *TesseraDedup) Get(ctx context.Context, identity []byte) (uint64, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if len(identity) == 0 {
		return 0, false, fmt.Errorf("wal/dedup: empty identity")
	}
	var (
		idx   uint64
		found bool
	)
	err := d.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(tesseraDedupKey(identity))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) != 8 {
				return fmt.Errorf("wal/dedup: bad value length %d, want 8", len(val))
			}
			idx = binary.BigEndian.Uint64(val)
			found = true
			return nil
		})
	})
	if err != nil {
		return 0, false, fmt.Errorf("wal/dedup: get: %w", err)
	}
	return idx, found, nil
}

// Set records identity → idx. Called by Tessera when integration
// of a new entry completes. Last-write-wins: re-Set with a different
// idx for the same identity overwrites (programmer error / equivocation
// scenario; Tessera itself enforces single-assignment in its happy
// path).
func (d *TesseraDedup) Set(ctx context.Context, identity []byte, idx uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(identity) == 0 {
		return fmt.Errorf("wal/dedup: empty identity")
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, idx)
	if err := d.db.Update(func(txn *badger.Txn) error {
		return txn.Set(tesseraDedupKey(identity), buf)
	}); err != nil {
		return fmt.Errorf("wal/dedup: set: %w", err)
	}
	return nil
}
