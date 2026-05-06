/*
FILE PATH: gossipstore/badger_iter.go

Iterate, IterSince, LatestSTH, and Stats for the BadgerStore.
Split from badger_store.go to keep both files under the
project's 300-line module budget.

# ITERATION PRIMITIVES

Each iteration runs in a Badger View txn that snapshots the LSM
state. Inside the txn we hold an iterator (defer it.Close() —
mandatory; leaking iterators pins memtables and breaks GC).

The chain index (subChain) is the primary scan path. It already
sorts (originator, lamport ASC), so:

  - Iterate(Originator=X)            → prefix scan chainPrefix(X)
  - Iterate(Kind=K, no Originator)   → prefix scan kindIndexPrefix(K)
  - Iterate(neither)                 → prefix scan allChainsPrefix()
  - IterSince mirrors Iterate but seeks past cursor.Lamport.

Both scans dereference the value (eventID) via a second point read
on the byID index (subEvent). One extra LSM hop per result is the
cost of normalized indexes; the alternative (denormalize + rewrite
the SignedEvent into every index) blows up disk usage and amplifies
write traffic by 4x.

# IterSince ORDERING SUBTLETY

The SDK contract says IterSince returns events in ascending
(originator, lamport) order. When cursor.Originator is set we
scan one prefix and ordering is natural. When it is empty, the
chain prefix scans through originators in lex order — also
natural per the contract.

When cursor.Kind is set + cursor.Originator is empty, we scan the
kind index which is ordered (kind, lamport, originator). That
gives lamport-then-originator order, NOT the contract's
originator-then-lamport order. We sort the resulting slice in
memory before truncating. For the ledger's bounded result-set
sizes (limit ≤ DefaultFeedListLimit = 100, MaxFeedListLimit =
1000) this is O(limit log limit) at worst.

# Stats SCALING

EventCount and OriginatorCount are read from the singleton stats
record (O(1)). Heads is populated by scanning the head-pointer
prefix (subHead) — one entry per distinct originator. With
hundreds of originators max in production gossip, this is
sub-millisecond.
*/
package gossipstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/dgraph-io/badger/v4"

	"github.com/clearcompass-ai/attesta/gossip"
)

// Iterate implements gossip.Store.
func (s *BadgerStore) Iterate(
	ctx context.Context, f gossip.Filter, fn func(gossip.SignedEvent) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Filter.Binding takes the binding-index (0x09) fast path when
	// set — point lookup keyed by the 32-byte hash. Other filters
	// (Kind, Originator, SinceLamport) intersect in-memory
	// against the binding result set.
	if f.Binding != nil {
		hits, err := s.collectByBinding(*f.Binding, f)
		if err != nil {
			return err
		}
		for _, ev := range hits {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(ev); err != nil {
				return err
			}
		}
		return nil
	}
	hits, err := s.collect(f.Originator, f.Kind, f.SinceLamport, 0)
	if err != nil {
		return err
	}
	for _, ev := range hits {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
	return nil
}

// collectByBinding scans the binding inverted index (0x09) for
// the supplied 32-byte hash, dereferences each suffix-eventID
// against the byID index (0x01), and applies the residual
// filters (Kind, Originator, SinceLamport) in memory.
//
// Time complexity: O(N_at_binding + log N_total) — point
// lookups on Badger LSM are sub-millisecond regardless of total
// event count.
func (s *BadgerStore) collectByBinding(
	binding [32]byte, f gossip.Filter,
) ([]gossip.SignedEvent, error) {
	var hits []gossip.SignedEvent
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = bindingIndexPrefix(binding)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			eventID, kerr := eventIDFromBindingIndexKey(it.Item().KeyCopy(nil))
			if kerr != nil {
				return kerr
			}
			ev, gerr := getEvent(txn, eventID)
			if gerr != nil {
				return gerr
			}
			if f.Kind != nil && ev.Kind != *f.Kind {
				continue
			}
			if f.Originator != nil && ev.Originator != *f.Originator {
				continue
			}
			if f.SinceLamport > 0 && ev.LamportTime <= f.SinceLamport {
				continue
			}
			hits = append(hits, ev)
		}
		return nil
	})
	return hits, err
}

// IterSince implements gossip.Store.
func (s *BadgerStore) IterSince(
	ctx context.Context, cursor gossip.IterCursor, limit int,
) ([]gossip.SignedEvent, gossip.IterCursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, cursor, err
	}
	if limit <= 0 {
		return nil, cursor, fmt.Errorf("%w: limit must be positive, got %d",
			gossip.ErrInvalidConfig, limit)
	}

	var origPtr *string
	if cursor.Originator != "" {
		o := cursor.Originator
		origPtr = &o
	}
	var kindPtr *gossip.Kind
	if cursor.Kind != "" {
		k := cursor.Kind
		kindPtr = &k
	}

	hits, err := s.collect(origPtr, kindPtr, cursor.Lamport, limit)
	if err != nil {
		return nil, cursor, err
	}

	next := cursor
	if len(hits) > 0 {
		next.Lamport = hits[len(hits)-1].LamportTime
	}
	return hits, next, nil
}

// collect is the shared scan kernel for Iterate + IterSince.
// limit == 0 means unbounded (used by Iterate).
func (s *BadgerStore) collect(
	originator *string, kind *gossip.Kind, sinceLamport uint64, limit int,
) ([]gossip.SignedEvent, error) {
	var hits []gossip.SignedEvent

	// Declared outside the View closure so the post-scan re-sort
	// branch can reach it.
	var rewriteOriginatorOrder bool

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		// Choose prefix based on filters. The branch order matches
		// the cost ordering: a single-originator scan is the
		// cheapest; a global scan is the most expensive.
		var prefix []byte
		switch {
		case originator != nil:
			prefix = chainPrefix(*originator)
		case kind != nil:
			prefix = kindIndexPrefix(string(*kind))
			// kind index orders (kind, lamport, orig); we will
			// re-sort in memory to (orig, lamport) for contract
			// compliance.
			rewriteOriginatorOrder = true
		default:
			prefix = allChainsPrefix()
		}
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			// For the chain-index scans (originator-or-global) we
			// can extract lamport directly from the key and
			// short-circuit the SinceLamport filter without a
			// value fetch.
			if !rewriteOriginatorOrder && sinceLamport > 0 {
				lamp, lerr := lamportFromChainKey(item.KeyCopy(nil))
				if lerr == nil && lamp <= sinceLamport {
					continue
				}
			}
			var eventID [32]byte
			if verr := item.Value(func(raw []byte) error {
				if len(raw) != 32 {
					return fmt.Errorf("gossipstore: index value length=%d, want 32", len(raw))
				}
				copy(eventID[:], raw)
				return nil
			}); verr != nil {
				return verr
			}
			ev, gerr := getEvent(txn, eventID)
			if gerr != nil {
				return gerr
			}
			if ev.LamportTime <= sinceLamport {
				continue
			}
			// Kind filter when scanning chainPrefix.
			if kind != nil && ev.Kind != *kind {
				continue
			}
			hits = append(hits, ev)
			if limit > 0 && !rewriteOriginatorOrder && len(hits) >= limit {
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if rewriteOriginatorOrder {
		sort.Slice(hits, func(i, j int) bool {
			if hits[i].Originator != hits[j].Originator {
				return hits[i].Originator < hits[j].Originator
			}
			return hits[i].LamportTime < hits[j].LamportTime
		})
		if limit > 0 && len(hits) > limit {
			hits = hits[:limit]
		}
	}
	return hits, nil
}

// LatestSTH implements gossip.Store. Uses the per-originator STH
// reverse index (subSTHIndex) so the scan reads at most one entry
// (the lexicographically largest under the originator prefix).
func (s *BadgerStore) LatestSTH(
	ctx context.Context, originator string,
) (gossip.SignedEvent, bool, error) {
	if err := ctx.Err(); err != nil {
		return gossip.SignedEvent{}, false, err
	}
	if originator == "" {
		return gossip.SignedEvent{}, false, fmt.Errorf("%w: originator empty",
			gossip.ErrInvalidConfig)
	}

	var (
		ev gossip.SignedEvent
		found bool
	)
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.Reverse = true
		opts.Prefix = sthIndexPrefix(originator)

		it := txn.NewIterator(opts)
		defer it.Close()

		// Reverse iteration starts from the last key under the
		// prefix; Seek to the prefix's "last possible" upper bound
		// to position correctly.
		seek := append([]byte{}, opts.Prefix...)
		// Append 0xFF * 8 to position past the highest lamport
		// under this originator's STH prefix.
		seek = append(seek, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
		it.Seek(seek)
		if !it.Valid() {
			return nil
		}
		var eventID [32]byte
		if verr := it.Item().Value(func(raw []byte) error {
			if len(raw) != 32 {
				return fmt.Errorf("gossipstore: STH index value length=%d", len(raw))
			}
			copy(eventID[:], raw)
			return nil
		}); verr != nil {
			return verr
		}
		full, gerr := getEvent(txn, eventID)
		if gerr != nil {
			return gerr
		}
		ev = full
		found = true
		return nil
	})
	return ev, found, err
}

// Stats implements gossip.Store. EventCount + OriginatorCount come
// from the singleton stats record (O(1) read). The Heads map is
// populated by scanning the head-pointer prefix (one entry per
// originator).
func (s *BadgerStore) Stats(ctx context.Context) (gossip.StoreStats, error) {
	if err := ctx.Err(); err != nil {
		return gossip.StoreStats{}, err
	}
	out := gossip.StoreStats{
		Heads: make(map[string]uint64),
	}
	err := s.db.View(func(txn *badger.Txn) error {
		// Counter (O(1)).
		if item, gerr := txn.Get(statsKey()); gerr == nil {
			derr := item.Value(func(raw []byte) error {
				rec, perr := decodeStats(raw)
				if perr != nil {
					return perr
				}
				out.EventCount = int(rec.eventCount)
				out.OriginatorCount = int(rec.originatorCount)
				return nil
			})
			if derr != nil {
				return derr
			}
		} else if !errors.Is(gerr, badger.ErrKeyNotFound) {
			return fmt.Errorf("gossipstore: stats lookup: %w", gerr)
		}

		// Heads (one entry per originator).
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.Prefix = allHeadsPrefix()
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			origin, oerr := originatorFromHeadKey(item.KeyCopy(nil))
			if oerr != nil {
				return oerr
			}
			var rec headRecord
			verr := item.Value(func(raw []byte) error {
				var perr error
				rec, perr = decodeHead(raw)
				return perr
			})
			if verr != nil {
				return verr
			}
			out.Heads[origin] = rec.lamport
		}
		return nil
	})
	return out, err
}

// getEvent decodes the SignedEvent at eventID under the subEvent
// prefix. Returns gossip.ErrEventNotFound when absent — callers
// in collect() treat that as a fatal inconsistency (an index
// pointed at a missing event), but propagate the error verbatim
// so the ledger notices.
func getEvent(txn *badger.Txn, eventID [32]byte) (gossip.SignedEvent, error) {
	item, err := txn.Get(eventKey(eventID))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return gossip.SignedEvent{}, gossip.ErrEventNotFound
	}
	if err != nil {
		return gossip.SignedEvent{}, err
	}
	var ev gossip.SignedEvent
	verr := item.Value(func(raw []byte) error {
		return json.Unmarshal(raw, &ev)
	})
	return ev, verr
}
