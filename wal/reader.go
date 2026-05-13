/*
FILE PATH: wal/reader.go

Reader-side methods on Committer: Read, MetaState, HWM, Sequence,
MarkShipped, Pending iteration, Sequenced iteration. Group commit
lives in committer.go; everything that doesn't go through the group
commit hot path lives here.

Read paths use db.View (read-only txn). Write paths use db.Update
(read-write txn). None of these call db.Sync — sequence transitions
and shipped marks are post-202 events; durability of those records
is best-effort (a crash at this layer means reconciliation runs
re-Add against Tessera, which is idempotent through dedup).
*/
package wal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// Read returns the wire bytes for an entry by hash. Returns
// ErrNotFound when no entry exists for hash. Caller receives a copy
// the WAL no longer owns — safe to mutate.
func (c *Committer) Read(ctx context.Context, hash [32]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []byte
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(entryKey(hash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return ErrNotFound
			}
			return err
		}
		return item.Value(func(val []byte) error {
			out = append([]byte(nil), val...)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MetaState returns the current state for an entry. Returns
// ErrNotFound when no meta record exists for hash.
func (c *Committer) MetaState(ctx context.Context, hash [32]byte) (Meta, error) {
	if err := ctx.Err(); err != nil {
		return Meta{}, err
	}
	var meta Meta
	err := c.db.View(func(txn *badger.Txn) error {
		return readMeta(txn, hash, &meta)
	})
	return meta, err
}

func readMeta(txn *badger.Txn, hash [32]byte, out *Meta) error {
	item, err := txn.Get(metaKey(hash))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrNotFound
		}
		return err
	}
	return item.Value(func(val []byte) error {
		m, decErr := decodeMeta(val)
		if decErr != nil {
			return decErr
		}
		*out = m
		return nil
	})
}

// Sequence atomically transitions an entry from StatePending →
// StateSequenced and clears the inflight breadcrumb. Called by
// admission AFTER tessera.Add returns the assigned sequence.
//
// Invariants:
//   - meta:<hash> must exist and be in StatePending.
//   - entry:<hash> must exist (covered by the Submit path's atomic
//     write of entry+meta).
//
// Returns ErrNotFound when hash has no meta record (unsubmitted
// entry — programmer error).
func (c *Committer) Sequence(ctx context.Context, hash [32]byte, seq uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.db.Update(func(txn *badger.Txn) error {
		var meta Meta
		if err := readMeta(txn, hash, &meta); err != nil {
			return err
		}
		// Idempotent: Sequence on an already-sequenced entry with the
		// same seq is a no-op. Callers that retry through ctx-cancel
		// races shouldn't be punished.
		if meta.State == StateSequenced && meta.Sequence == seq {
			return nil
		}
		if meta.State != StatePending {
			return fmt.Errorf("wal/reader: Sequence: hash in state %s, want %s",
				meta.State, StatePending)
		}
		meta.State = StateSequenced
		meta.Sequence = seq
		if err := txn.Set(metaKey(hash), encodeMeta(meta)); err != nil {
			return fmt.Errorf("wal/reader: set meta: %w", err)
		}
		// seq_index:<seq> = hash (Shipper iterates this)
		if err := txn.Set(seqIndexKey(seq), hash[:]); err != nil {
			return fmt.Errorf("wal/reader: set seq_index: %w", err)
		}
		// Clear inflight breadcrumb — entry is now safely sequenced.
		if err := txn.Delete(inflightKey(hash)); err != nil {
			return fmt.Errorf("wal/reader: delete inflight: %w", err)
		}
		return nil
	})
}

// MarkShipped transitions StateSequenced → StateShipped. Called by
// Shipper after the bytestore upload completes. Does NOT advance the
// HWM — that's a separate call by the Shipper after it confirms the
// entry's seq is contiguous from HWM+1.
func (c *Committer) MarkShipped(ctx context.Context, hash [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.db.Update(func(txn *badger.Txn) error {
		var meta Meta
		if err := readMeta(txn, hash, &meta); err != nil {
			return err
		}
		if meta.State == StateShipped {
			return nil // idempotent
		}
		if meta.State != StateSequenced && meta.State != StateManual {
			return fmt.Errorf("wal/reader: MarkShipped: hash in state %s, want %s",
				meta.State, StateSequenced)
		}
		meta.State = StateShipped
		meta.LastErrTs = time.Time{} // clear any retry timestamp
		return txn.Set(metaKey(hash), encodeMeta(meta))
	})
}

// MarkRetry increments the attempts counter and records lastErrTs.
// Used by the Shipper when an upload fails; does not change state.
// After N retries the Shipper transitions the meta to StateManual via
// MarkManual.
func (c *Committer) MarkRetry(ctx context.Context, hash [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.db.Update(func(txn *badger.Txn) error {
		var meta Meta
		if err := readMeta(txn, hash, &meta); err != nil {
			return err
		}
		meta.Attempts++
		meta.LastErrTs = time.Now().UTC()
		return txn.Set(metaKey(hash), encodeMeta(meta))
	})
}

// MarkManual transitions an entry to StateManual after retry exhaustion.
// Bytes stay in the WAL; this is metric/ledger state, not a deletion.
func (c *Committer) MarkManual(ctx context.Context, hash [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.db.Update(func(txn *badger.Txn) error {
		var meta Meta
		if err := readMeta(txn, hash, &meta); err != nil {
			return err
		}
		meta.State = StateManual
		return txn.Set(metaKey(hash), encodeMeta(meta))
	})
}

// HashAt returns the entry's content hash for the given sequence
// number. Returns ErrNotFound when no entry has been Sequence'd at
// seq yet. Used by the integrity Detector for periodic sample
// verification (compare WAL.HashAt vs Tessera.HashAt; mismatch =
// divergence).
func (c *Committer) HashAt(ctx context.Context, seq uint64) ([32]byte, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	var hash [32]byte
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(seqIndexKey(seq))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return ErrNotFound
			}
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) != 32 {
				return fmt.Errorf("wal/reader: bad seq_index value len=%d for seq=%d", len(val), seq)
			}
			copy(hash[:], val)
			return nil
		})
	})
	if err != nil {
		return [32]byte{}, err
	}
	return hash, nil
}

// HWM returns the high-water mark — the highest contiguous SEQUENCE
// NUMBER whose entry has been shipped. HWM is a seq value, not a
// count: under the migration-0004 contract seqs are 0-indexed, so
// N entries occupy seqs 0..N-1 and HWM caps at N-1, not N.
//
// HWM=0 is ambiguous on its face — it can mean either "no entry has
// been shipped yet" OR "seq=0 has been shipped." The system does NOT
// distinguish: shipper/shipper.go:538 absorbs the seq=0 completion
// as a no-op against HWM=0, so HWM advances 0→1→2→…→N-1 rather than
// 0→0→1→…→N-1. Callers needing to distinguish must consult per-hash
// state via MetaState; the WAL has no Bootstrapped bit.
//
// If future work wants HWM-as-count semantics, BOTH this convention
// AND the seq <= hwm no-op at shipper.go:538 have to move together.
func (c *Committer) HWM(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var hwm uint64
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(hwmKey())
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil // hwm = 0
			}
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) != 8 {
				return fmt.Errorf("wal/reader: bad HWM record length %d", len(val))
			}
			hwm = binary.BigEndian.Uint64(val)
			return nil
		})
	})
	return hwm, err
}

// AdvanceHWM sets the high-water mark to newHWM. Caller (Shipper) is
// responsible for ensuring newHWM is contiguous from the previous
// HWM+1 (no gaps in the shipped run). The WAL does NOT enforce
// contiguity here — it's a single-row UPDATE that the Shipper
// invariants must protect.
func (c *Committer) AdvanceHWM(ctx context.Context, newHWM uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, newHWM)
	return c.db.Update(func(txn *badger.Txn) error {
		return txn.Set(hwmKey(), buf)
	})
}

// ReconcileHWM advances the high-water mark through any contiguous
// run of StateShipped entries starting at HWM+1. Called by the
// Shipper at boot to recover from a crash in which entries finished
// shipping (state transitioned to StateShipped on disk) but the
// shipper's in-memory completion-advancer never observed them — so
// AdvanceHWM was never called for those seqs.
//
// Without this reconciliation, an entry that ships but whose
// completion event is lost across a process restart leaves HWM
// permanently behind: subsequent IterateSequenced calls skip the
// already-Shipped entry, and the completion-advancer never receives
// a signal for its seq.
//
// Safe to call repeatedly; idempotent and bounded by the size of the
// contiguous Shipped run above HWM. Returns the new HWM value.
func (c *Committer) ReconcileHWM(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	hwm, err := c.HWM(ctx)
	if err != nil {
		return 0, err
	}
	newHWM := hwm
	err = c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte{prefixSeqIndex}
		it := txn.NewIterator(opts)
		defer it.Close()
		startKey := seqIndexKey(hwm + 1)
		for it.Seek(startKey); it.Valid(); it.Next() {
			seq := seqFromIndexKey(it.Item().KeyCopy(nil))
			if seq != newHWM+1 {
				return nil // gap — stop reconciliation here
			}
			var hash [32]byte
			vErr := it.Item().Value(func(val []byte) error {
				if len(val) != 32 {
					return fmt.Errorf("wal/reader: bad seq_index value len=%d", len(val))
				}
				copy(hash[:], val)
				return nil
			})
			if vErr != nil {
				return vErr
			}
			var meta Meta
			if mErr := readMeta(txn, hash, &meta); mErr != nil {
				return mErr
			}
			if meta.State != StateShipped {
				return nil // not shipped — stop
			}
			newHWM = seq
		}
		return nil
	})
	if err != nil {
		return hwm, err
	}
	if newHWM > hwm {
		if aErr := c.AdvanceHWM(ctx, newHWM); aErr != nil {
			return hwm, aErr
		}
	}
	return newHWM, nil
}

// PendingHash describes one inflight entry — the breadcrumb reconciler
// scans on boot.
type PendingHash struct {
	Hash [32]byte
}

// IterateInflight iterates all inflight breadcrumbs. Used at boot by
// Reconcile. Concurrent writes (more Submits firing) are safe under
// Badger's MVCC — the iterator sees a stable snapshot.
//
// Yields PendingHash entries one at a time via fn. fn returning a
// non-nil error stops iteration and propagates that error.
func (c *Committer) IterateInflight(ctx context.Context, fn func(PendingHash) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte{prefixInflight}
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			h := hashFromInflightKey(it.Item().KeyCopy(nil))
			if err := fn(PendingHash{Hash: h}); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	})
}

// SequencedEntry describes one StateSequenced entry — what the
// Shipper iterates to find work.
type SequencedEntry struct {
	Seq  uint64
	Hash [32]byte
}

// IterateSequenced iterates entries with State==StateSequenced in
// ascending seq order, starting AFTER fromSeq (so the Shipper can
// resume from the last HWM+1).
func (c *Committer) IterateSequenced(ctx context.Context, fromSeq uint64, fn func(SequencedEntry) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte{prefixSeqIndex}
		it := txn.NewIterator(opts)
		defer it.Close()
		// Seek to fromSeq+1 (or 0 if fromSeq is 0).
		startKey := seqIndexKey(fromSeq + 1)
		if fromSeq == 0 {
			startKey = []byte{prefixSeqIndex}
		}
		for it.Seek(startKey); it.Valid(); it.Next() {
			item := it.Item()
			seq := seqFromIndexKey(item.KeyCopy(nil))
			var hash [32]byte
			err := item.Value(func(val []byte) error {
				if len(val) != 32 {
					return fmt.Errorf("wal/reader: bad seq_index value len=%d", len(val))
				}
				copy(hash[:], val)
				return nil
			})
			if err != nil {
				return err
			}
			// Filter by state — seq_index entries persist after MarkShipped
			// so we need to check.
			var meta Meta
			if err := readMeta(txn, hash, &meta); err != nil {
				return err
			}
			if meta.State != StateSequenced {
				continue
			}
			if err := fn(SequencedEntry{Seq: seq, Hash: hash}); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	})
}
