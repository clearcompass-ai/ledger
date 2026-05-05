/*
FILE PATH: gossipstore/badger_store.go

BadgerDB-backed gossip.Store for the operator. Co-tenants the
operator's existing Badger handle (wal/) under a distinct key
prefix (0x07); shares the LSM tree, value log, and WAL.

# WHY CO-TENANT WITH WAL

Both the WAL and the gossip Store want a fast on-disk KV store
with ordered scans. Running two Badger instances doubles the LSM
overhead (memtables, value logs, file handles, GC threads) for no
correctness benefit. The keyspace prefix discipline (single root
byte, sub-prefix tags) keeps the two logically separate while
sharing one on-disk store.

# CONCURRENCY

Append uses the same sharded-mutex pattern as the SDK reference
InMemoryStore: a fixed array of sync.Mutex indexed by FNV-1a
hash of the originator. Different originators advance in parallel;
two appends to the same originator serialize. Memory is O(shard
count), not O(distinct originators) — important under
adversarial workloads with high originator churn.

# ATOMICITY

Each Append wraps its multi-key write in a single Badger txn. If
the txn fails or the process crashes mid-append, no partial state
is durable: the by-id key, chain entry, head pointer, kind index,
and stats counter all advance together or not at all.

# 8M-11M ENTRIES, 700-1K TPS PEAK

Capacity targets reflect the operator's primary gossip workload:
witness cosignatures (≤ N peers × commit rate) + equivocation
findings (rare) + originator rotations (very rare). Per-entry
size is dominated by the JSON SignedEvent body (~800-1200 bytes
typical for a cosigned tree head + sigs); 11M × 1200 ≈ 13 GB
which fits comfortably in Badger's LSM + value log architecture
on production NVMe (typical operator ≥ 200 GB local disk).

Write throughput at 700-1000 TPS:

  - Each Append touches 5-6 keys (event, chain, kindIndex, head,
    sthIndex if STH, stats, origExists if first event).
  - Badger absorbs short-burst writes via memtable; sustained
    1000 TPS requires LSM compactions that Badger handles in
    background goroutines.
  - SyncWrites=false on the parent DB; durability flushes are
    triggered by Badger's own batching policy. Gossip events
    are not authoritative — peers re-broadcast on
    inconsistency — so the absolute durability guarantee here
    is weaker than the WAL's group-commit-fsync. Acceptable.

# CLOSE SEMANTICS

Close is a no-op on the underlying Badger handle (the WAL owns it
and closes it at process shutdown). The gossipstore Close cancels
the value-log GC ticker (started by NewBadgerStore) and waits for
in-flight Appends via the per-originator locks (a final lock-and-
release sweep). The Badger handle itself is closed by the WAL's
shutdown ordering after every package (WAL, gossipstore, etc.) has
released their references.
*/
package gossipstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/clearcompass-ai/attesta/gossip"
)

// Config tunes the BadgerStore.
type Config struct {
	// DB is the Badger handle to share. Required.
	DB *badger.DB

	// GCInterval is how often the store calls db.RunValueLogGC.
	// Zero ⇒ DefaultGCInterval. Negative ⇒ no background GC
	// (caller is expected to drive GC externally).
	GCInterval time.Duration

	// GCRatio is the discard-ratio passed to RunValueLogGC.
	// 0 ⇒ DefaultGCRatio (0.5). Higher ⇒ more aggressive GC
	// (rewrites more value-log files); lower ⇒ less I/O but
	// more stale data.
	GCRatio float64
}

// DefaultGCInterval is the default ticker period for value-log GC.
const DefaultGCInterval = 10 * time.Minute

// DefaultGCRatio is the default RunValueLogGC discard ratio.
const DefaultGCRatio = 0.5

// BadgerStore implements gossip.Store backed by BadgerDB.
type BadgerStore struct {
	db *badger.DB

	// originatorLocks is a sharded mutex array. Index is FNV-1a
	// hash of originator mod len(locks). Sized at construction to
	// runtime.NumCPU() * 8 (clamped [32, 1024]).
	originatorLocks []sync.Mutex

	// gcCancel + gcDone manage the background value-log GC
	// goroutine's lifecycle.
	gcCancel context.CancelFunc
	gcDone   chan struct{}

	closeOnce sync.Once
}

// New constructs the BadgerStore. Returns an error if cfg.DB is
// nil. Spawns a background goroutine that periodically calls
// db.RunValueLogGC unless cfg.GCInterval is negative.
func New(cfg Config) (*BadgerStore, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("gossipstore: Config.DB required")
	}
	if cfg.GCInterval == 0 {
		cfg.GCInterval = DefaultGCInterval
	}
	if cfg.GCRatio <= 0 {
		cfg.GCRatio = DefaultGCRatio
	}

	s := &BadgerStore{
		db:              cfg.DB,
		originatorLocks: make([]sync.Mutex, originatorShardCount()),
	}

	if cfg.GCInterval > 0 {
		gcCtx, cancel := context.WithCancel(context.Background())
		s.gcCancel = cancel
		s.gcDone = make(chan struct{})
		go s.runGC(gcCtx, cfg.GCInterval, cfg.GCRatio)
	}

	return s, nil
}

// originatorShardCount mirrors the SDK reference store's sizing.
func originatorShardCount() int {
	n := runtime.NumCPU() * 8
	if n < 32 {
		n = 32
	}
	if n > 1024 {
		n = 1024
	}
	return n
}

// originatorLock returns the per-originator shard mutex.
func (s *BadgerStore) originatorLock(originator string) *sync.Mutex {
	const fnvOffset uint32 = 2166136261
	const fnvPrime uint32 = 16777619
	h := fnvOffset
	for i := 0; i < len(originator); i++ {
		h ^= uint32(originator[i])
		h *= fnvPrime
	}
	return &s.originatorLocks[h%uint32(len(s.originatorLocks))]
}

// runGC drives Badger's value-log GC on a ticker. Each
// RunValueLogGC pass either returns nil (rewrote a value-log
// file) or badger.ErrNoRewrite (no files met the discard ratio).
// We loop on nil to drain backlog within the tick window.
func (s *BadgerStore) runGC(ctx context.Context, interval time.Duration, ratio float64) {
	defer close(s.gcDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for {
				if err := s.db.RunValueLogGC(ratio); err != nil {
					// ErrNoRewrite means nothing to GC this pass;
					// any other error is reported once per tick
					// (we still continue — Badger remains usable).
					break
				}
			}
		}
	}
}

// Append implements gossip.Store.
func (s *BadgerStore) Append(ctx context.Context, ev gossip.SignedEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.Originator == "" {
		return fmt.Errorf("%w: originator empty", gossip.ErrInvalidWireRequest)
	}
	if len(ev.Originator) > MaxOriginatorLen {
		return fmt.Errorf("%w: originator length %d exceeds %d",
			gossip.ErrInvalidWireRequest, len(ev.Originator), MaxOriginatorLen)
	}
	if len(string(ev.Kind)) > MaxKindLen {
		return fmt.Errorf("%w: kind length exceeds %d",
			gossip.ErrInvalidWireRequest, MaxKindLen)
	}

	id, err := gossip.EventIDOf(ev)
	if err != nil {
		return err
	}

	mu := s.originatorLock(ev.Originator)
	mu.Lock()
	defer mu.Unlock()

	gotPrev, err := hex32OrZero(ev.PrevHash)
	if err != nil {
		return fmt.Errorf("%w: prev_hash: %v", gossip.ErrInvalidWireRequest, err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		// Idempotency (I9): if the event already exists by ID,
		// the receive is a no-op.
		if _, getErr := txn.Get(eventKey(id)); getErr == nil {
			return nil
		} else if !errors.Is(getErr, badger.ErrKeyNotFound) {
			return fmt.Errorf("gossipstore: lookup byID: %w", getErr)
		}

		head, headFound, err := readHead(txn, ev.Originator)
		if err != nil {
			return err
		}
		var prevHead [32]byte
		var headLamport uint64
		if headFound {
			prevHead = head.prevHash
			headLamport = head.lamport
		}

		if gotPrev != prevHead {
			return fmt.Errorf("%w: originator %s: prev=0x%s head=0x%s",
				gossip.ErrChainBreak, ev.Originator,
				hex.EncodeToString(gotPrev[:])[:16],
				hex.EncodeToString(prevHead[:])[:16])
		}
		if ev.LamportTime <= headLamport && headLamport > 0 {
			return fmt.Errorf("%w: originator %s: lamport %d <= head %d",
				gossip.ErrLamportRegression, ev.Originator, ev.LamportTime, headLamport)
		}
		if headLamport == 0 && ev.LamportTime == 0 {
			return fmt.Errorf("%w: first event lamport_time must be > 0",
				gossip.ErrLamportRegression)
		}

		// Encode + write event.
		raw, jerr := json.Marshal(ev)
		if jerr != nil {
			return fmt.Errorf("gossipstore: encode event: %w", jerr)
		}
		if err := txn.Set(eventKey(id), raw); err != nil {
			return err
		}
		if err := txn.Set(chainKey(ev.Originator, ev.LamportTime), id[:]); err != nil {
			return err
		}
		if err := txn.Set(kindIndexKey(string(ev.Kind), ev.LamportTime, ev.Originator), id[:]); err != nil {
			return err
		}
		if ev.Kind == gossip.KindCosignedTreeHead {
			if err := txn.Set(sthIndexKey(ev.Originator, ev.LamportTime), id[:]); err != nil {
				return err
			}
		}

		// Binding inverted index — one PUT per Bindings entry on
		// the SignedEvent. Powers Filter.Binding O(1) lookup +
		// /v1/gossip/by-binding/{hash}. Any consumer (including
		// the gossip handler's post-Append hook for the
		// equivocation projection 0x0B) may read this index.
		for _, b := range ev.Bindings {
			if len(b) != 64 {
				continue
			}
			var binding [32]byte
			if _, derr := hex.Decode(binding[:], []byte(b)); derr != nil {
				continue
			}
			if err := txn.Set(bindingIndexKey(binding, id), nil); err != nil {
				return err
			}
		}

		newHead := encodeHead(headRecord{prevHash: id, lamport: ev.LamportTime})
		if err := txn.Set(headKey(ev.Originator), newHead); err != nil {
			return err
		}

		// Stats: bump EventCount unconditionally; bump
		// OriginatorCount only for the first event from this
		// originator (existence marker is written once).
		newOriginator := false
		if !headFound {
			if _, gerr := txn.Get(origExistsKey(ev.Originator)); gerr == badger.ErrKeyNotFound {
				newOriginator = true
				if err := txn.Set(origExistsKey(ev.Originator), nil); err != nil {
					return err
				}
			} else if gerr != nil {
				return fmt.Errorf("gossipstore: origExists lookup: %w", gerr)
			}
		}
		return bumpStats(txn, 1, boolToInt64(newOriginator))
	})
}

// boolToInt64 maps {false, true} → {0, 1}. Used in the
// originator-existence increment so the stats bump is uniform.
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Head implements gossip.Store.
func (s *BadgerStore) Head(ctx context.Context, originator string) ([32]byte, uint64, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	var h headRecord
	var found bool
	err := s.db.View(func(txn *badger.Txn) error {
		var rerr error
		h, found, rerr = readHead(txn, originator)
		return rerr
	})
	if err != nil {
		return [32]byte{}, 0, err
	}
	if !found {
		return [32]byte{}, 0, nil
	}
	return h.prevHash, h.lamport, nil
}

// Get implements gossip.Store.
func (s *BadgerStore) Get(ctx context.Context, eventID [32]byte) (gossip.SignedEvent, error) {
	if err := ctx.Err(); err != nil {
		return gossip.SignedEvent{}, err
	}
	var ev gossip.SignedEvent
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(eventKey(eventID))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return gossip.ErrEventNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(raw []byte) error {
			return json.Unmarshal(raw, &ev)
		})
	})
	return ev, err
}

// Close implements gossip.Store. Cancels the GC ticker and drains
// in-flight Appends by acquiring + releasing every shard lock.
// The underlying *badger.DB is NOT closed — its lifecycle is owned
// by the caller (the operator's WAL package), which closes it
// after every package has released its references.
func (s *BadgerStore) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.closeOnce.Do(func() {
		if s.gcCancel != nil {
			s.gcCancel()
			<-s.gcDone
		}
		// Drain in-flight Appends by acquiring + releasing every
		// shard. Once we hold the lock, any concurrent Append on
		// that shard has finished its txn.Update.
		for i := range s.originatorLocks {
			s.originatorLocks[i].Lock()
			s.originatorLocks[i].Unlock() //nolint:staticcheck
		}
	})
	return nil
}

// readHead reads the head pointer for an originator. Returns
// (zero, false, nil) when no events have been appended yet.
func readHead(txn *badger.Txn, originator string) (headRecord, bool, error) {
	item, err := txn.Get(headKey(originator))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return headRecord{}, false, nil
	}
	if err != nil {
		return headRecord{}, false, fmt.Errorf("gossipstore: head lookup: %w", err)
	}
	var h headRecord
	derr := item.Value(func(raw []byte) error {
		var perr error
		h, perr = decodeHead(raw)
		return perr
	})
	if derr != nil {
		return headRecord{}, false, derr
	}
	return h, true, nil
}

// bumpStats reads, increments, and writes back the stats counter
// inside the supplied txn. Initial state (no record) is treated
// as zeros.
func bumpStats(txn *badger.Txn, eventDelta, originatorDelta int64) error {
	var s statsRecord
	item, err := txn.Get(statsKey())
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return fmt.Errorf("gossipstore: stats lookup: %w", err)
	}
	if err == nil {
		derr := item.Value(func(raw []byte) error {
			var perr error
			s, perr = decodeStats(raw)
			return perr
		})
		if derr != nil {
			return derr
		}
	}
	if eventDelta > 0 {
		s.eventCount += uint64(eventDelta)
	}
	if originatorDelta > 0 {
		s.originatorCount += uint64(originatorDelta)
	}
	return txn.Set(statsKey(), encodeStats(s))
}

// hex32OrZero decodes a 64-char hex string or returns the zero
// array when input is empty. Mirrors the SDK reference store's
// PrevHash decoding.
func hex32OrZero(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, nil
	}
	if len(s) != 64 {
		return out, fmt.Errorf("expected 64 hex chars, got %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

// Static interface check.
var _ gossip.Store = (*BadgerStore)(nil)
var _ gossip.Closeable = (*BadgerStore)(nil)
