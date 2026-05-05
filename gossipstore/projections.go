/*
FILE PATH: gossipstore/projections.go

Public API for the v0.9.6 sub-prefixes:

  WriteSplitIDIndexEntry — sequencer writes one entry per
                           commitment_split_id INSERT (Phase 2).
                           EquivocationScanner subscribes to
                           the prefix and detects collisions.

  ListSplitIDIndexEntriesAt — scanner / diagnostics: list every
                              entry under a (schema_id, split_id).

  PutEquivProjection / GetEquivProjection — read-side
                                            projection store
                                            (0x0B). O(1) point
                                            access for
                                            /v1/commitments/by-split-id.

# WHY HERE (NOT badger_store.go)

Keeps badger_store.go under the 300-LOC budget and isolates the
v0.9.6-specific projection surface from the gossip-store core.
The Store interface continues to be exactly what gossip.Store
requires; these are operator-internal extensions.
*/
package gossipstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/pb"
)

// WriteSplitIDIndexEntry persists a (schema_id, split_id, seq) →
// SplitIDIndexEntry mapping under prefix 0x0A. Idempotent: writing
// the same key twice produces the same on-disk state.
//
// Called by the sequencer at Phase 2 commit, in the same Postgres
// transaction span as the entry_index INSERT (the splitid index
// write happens AFTER the Postgres commit so a Postgres rollback
// doesn't leave a stale Badger entry).
func (s *BadgerStore) WriteSplitIDIndexEntry(
	ctx context.Context, schemaID string, splitID [32]byte, seq uint64,
	entry SplitIDIndexEntry,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if schemaID == "" {
		return fmt.Errorf("gossipstore: WriteSplitIDIndexEntry: empty schemaID")
	}
	value, err := EncodeSplitIDIndexEntry(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(splitIDIndexKey(schemaID, splitID, seq), value)
	})
}

// SplitIDIndexHit pairs a key's seq with its decoded value for
// scanner consumers.
type SplitIDIndexHit struct {
	EntrySeq uint64
	Entry    SplitIDIndexEntry
}

// ListSplitIDIndexEntriesAt scans the splitid index for the
// supplied (schema_id, split_id) and returns every hit. The
// scanner uses this when its Subscribe handler wakes — if the
// list has ≥ 2 entries, the (schema, split) tuple is equivocated.
//
// Empty schemaID is rejected. A zero splitID is allowed
// (defensive — the scanner may receive zero values during
// subscribe-replay; returns empty).
func (s *BadgerStore) ListSplitIDIndexEntriesAt(
	ctx context.Context, schemaID string, splitID [32]byte,
) ([]SplitIDIndexHit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if schemaID == "" {
		return nil, fmt.Errorf("gossipstore: ListSplitIDIndexEntriesAt: empty schemaID")
	}
	var out []SplitIDIndexHit
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.Prefix = splitIDIndexPrefix(schemaID, splitID)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			_, _, seq, kerr := SplitIDIndexEntryFromKey(item.KeyCopy(nil))
			if kerr != nil {
				return kerr
			}
			var entry SplitIDIndexEntry
			verr := item.Value(func(raw []byte) error {
				var perr error
				entry, perr = DecodeSplitIDIndexEntry(raw)
				return perr
			})
			if verr != nil {
				return verr
			}
			out = append(out, SplitIDIndexHit{EntrySeq: seq, Entry: entry})
		}
		return nil
	})
	return out, err
}

// SubscribeSplitIDIndex registers a callback fired on every PUT
// under the splitid index prefix. Wraps badger.DB.Subscribe so
// the EquivocationScanner doesn't reach into the underlying DB
// directly. Returns ctx.Err() on cancellation; any error from
// fn aborts the subscription.
//
// fn receives the schema_id, split_id, and seq decoded from the
// key. It does NOT receive the value to keep the callback fast;
// the scanner re-loads via ListSplitIDIndexEntriesAt to get a
// fresh, consistent snapshot under one View transaction.
func (s *BadgerStore) SubscribeSplitIDIndex(
	ctx context.Context, fn func(schemaID string, splitID [32]byte, seq uint64) error,
) error {
	if fn == nil {
		return fmt.Errorf("gossipstore: SubscribeSplitIDIndex: nil fn")
	}
	match := []pb.Match{{Prefix: allSplitIDIndexPrefix()}}
	cb := func(kv *badger.KVList) error {
		for _, kvi := range kv.Kv {
			schemaID, splitID, seq, kerr := SplitIDIndexEntryFromKey(kvi.Key)
			if kerr != nil {
				continue
			}
			if err := fn(schemaID, splitID, seq); err != nil {
				return err
			}
		}
		return nil
	}
	return subscribeViaBadger(ctx, s.db, cb, match)
}

// subscribeViaBadger isolates the Badger Subscribe call so unit
// tests can fake the subscription with an in-memory channel.
// Production calls go through here.
func subscribeViaBadger(ctx context.Context, db *badger.DB, cb func(*badger.KVList) error, match []pb.Match) error {
	err := db.Subscribe(ctx, cb, match)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// PutEquivProjection writes (or overwrites) a verified
// equivocation finding into the read-side projection (0x0B)
// keyed by binding hash.
//
// Idempotent: re-receiving the same finding is a no-op
// (identical bytes overwrite identical bytes). This preserves
// the gossip layer's I9 idempotency through the projection.
func (s *BadgerStore) PutEquivProjection(
	ctx context.Context, binding [32]byte, signedEventBytes []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(signedEventBytes) == 0 {
		return fmt.Errorf("gossipstore: PutEquivProjection: empty signedEventBytes")
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(equivProjKey(binding), signedEventBytes)
	})
}

// GetEquivProjection returns the verified equivocation finding
// previously projected under the supplied binding hash, or
// (nil, nil) when no projection exists. Used by
// /v1/commitments/by-split-id to serve O(1) point reads without
// touching Postgres.
func (s *BadgerStore) GetEquivProjection(
	ctx context.Context, binding [32]byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, gerr := txn.Get(equivProjKey(binding))
		if errors.Is(gerr, badger.ErrKeyNotFound) {
			return nil
		}
		if gerr != nil {
			return gerr
		}
		return item.Value(func(raw []byte) error {
			out = append([]byte{}, raw...)
			return nil
		})
	})
	return out, err
}
