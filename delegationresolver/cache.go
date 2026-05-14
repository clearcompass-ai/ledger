/*
FILE PATH:

	delegationresolver/cache.go

DESCRIPTION:

	Cached — an LRU wrapper around any delegation.EntrySource.
	Issued under PR-B (issue #75) as the substrate gates 3 and 4
	depend on so per-request admission doesn't pay a disk hit on
	every delegation lookup.

KEY ARCHITECTURAL DECISIONS:

  - The wrapper IS-A delegation.EntrySource. Callers pass *Cached
    directly to delegation.NewResolver — no glue code, no
    indirection layer.
  - LRU eviction is the right shape because the working set of
    "DIDs whose delegation we just looked up" is small relative
    to the total population, and recency is the dominant access
    pattern (re-visiting the same DID across burst admissions).
  - Misses cache attestation.ErrUnknownDelegate as a NEGATIVE
    result. A flood of admissions referencing an unknown
    delegate would otherwise pound the underlying source on
    every miss; the negative cache amortises that cost while
    Invalidate() lets the operator clear it on remediation.
  - All state is behind one mutex. The cache is on the read hot
    path; a fancier sharded structure would help only if the
    contention analysis showed mutex hold-time as a measurable
    fraction of admission latency. It does not today (single-
    digit microseconds per Get).
  - Capacity is fixed at construction time. Resizing live would
    add complexity for no gain — operators set capacity from
    LEDGER_DELEGATION_CACHE_CAPACITY and restart for changes.

CACHE SHAPE:

	An entry → cacheValue carries either a populated DelegationEntry
	(positive cache) or an "unknown" sentinel (negative cache). The
	LRU list orders entries by access recency; an evicting Put
	drops from the back.
*/
package delegationresolver

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/delegation"
)

// DefaultCacheCapacity is the fallback when the operator does not
// set LEDGER_DELEGATION_CACHE_CAPACITY. Sized for a deployment
// that admits ~150 entries/sec from ~10k distinct delegate DIDs;
// roughly half-resident in cache. Override at boot.
const DefaultCacheCapacity = 4096

// cacheValue is the LRU element value. Either Entry is populated
// (positive cache) or NotFound is true (negative cache); never both.
type cacheValue struct {
	Entry    delegation.DelegationEntry
	NotFound bool
}

// cacheEntry is the LRU node body — pairs the lookup key with the
// stored value so eviction can both clear the map and the list in
// O(1).
type cacheEntry struct {
	Key string
	Val cacheValue
}

// Cached wraps a delegation.EntrySource with an LRU. The wrapper
// itself satisfies delegation.EntrySource so it drops in wherever
// the underlying source did.
//
// Construct via NewCached. Capacity is fixed for the lifetime;
// see DefaultCacheCapacity.
type Cached struct {
	source   delegation.EntrySource
	capacity int
	metrics  *Metrics

	mu    sync.Mutex
	order *list.List               // front = most recently used
	index map[string]*list.Element // key → node
}

// NewCached wraps source with an LRU of the given capacity. A
// capacity <= 0 falls back to DefaultCacheCapacity. metrics may
// be nil (counters become no-ops). source must be non-nil.
func NewCached(source delegation.EntrySource, capacity int, metrics *Metrics) (*Cached, error) {
	if source == nil {
		return nil, errors.New("delegationresolver: NewCached source is nil")
	}
	if capacity <= 0 {
		capacity = DefaultCacheCapacity
	}
	return &Cached{
		source:   source,
		capacity: capacity,
		metrics:  metrics,
		order:    list.New(),
		index:    make(map[string]*list.Element, capacity),
	}, nil
}

// DelegationOf implements delegation.EntrySource. Returns the
// cached value when present; on miss, calls the underlying source
// and caches the result (positive OR negative — see cacheValue).
//
// Returns attestation.ErrUnknownDelegate when the underlying source
// reports the delegate doesn't exist; this is the SDK's signal
// that the chain has reached its root and the walker should stop.
func (c *Cached) DelegationOf(ctx context.Context, delegateDID string) (delegation.DelegationEntry, error) {
	if delegateDID == "" {
		return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
	}

	// Hot path: cache hit (positive or negative).
	c.mu.Lock()
	if elem, ok := c.index[delegateDID]; ok {
		c.order.MoveToFront(elem)
		val := elem.Value.(*cacheEntry).Val
		c.mu.Unlock()
		c.metrics.recordHit()
		if val.NotFound {
			return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
		}
		return val.Entry, nil
	}
	c.mu.Unlock()

	// Slow path: miss → underlying lookup.
	c.metrics.recordMiss()
	entry, err := c.source.DelegationOf(ctx, delegateDID)
	switch {
	case err == nil:
		c.put(delegateDID, cacheValue{Entry: entry})
		return entry, nil
	case errors.Is(err, attestation.ErrUnknownDelegate):
		c.put(delegateDID, cacheValue{NotFound: true})
		return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
	default:
		// Transport / parse failures are NOT cached — they're
		// transient and retrying may succeed on the next request.
		// The SDK's source contract documents this: the resolver
		// propagates non-ErrUnknownDelegate errors as-is.
		return delegation.DelegationEntry{}, err
	}
}

// put inserts (key, val) at the front of the LRU. Evicts the
// least-recently-used entry when capacity would be exceeded.
func (c *Cached) put(key string, val cacheValue) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.index[key]; ok {
		// Concurrent Get of the same key may have populated this
		// while we were in the underlying lookup. Refresh value
		// + recency, no eviction.
		existing.Value.(*cacheEntry).Val = val
		c.order.MoveToFront(existing)
		return
	}
	if c.order.Len() >= c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.index, oldest.Value.(*cacheEntry).Key)
		}
	}
	c.index[key] = c.order.PushFront(&cacheEntry{Key: key, Val: val})
}

// Invalidate removes the entry for delegateDID. No-op when the
// key isn't present. Returns true on actual removal — useful for
// tests and metrics. See WireRotationListener (invalidation.go)
// for the production invocation path.
func (c *Cached) Invalidate(delegateDID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.index[delegateDID]
	if !ok {
		return false
	}
	c.order.Remove(elem)
	delete(c.index, delegateDID)
	c.metrics.recordInvalidation(1)
	return true
}

// InvalidateAll clears every entry. Used by integration tests
// and as the safety hatch for "we just witnessed a network-level
// rotation event whose specific DID we couldn't extract".
func (c *Cached) InvalidateAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.order.Len()
	c.order.Init()
	c.index = make(map[string]*list.Element, c.capacity)
	if n > 0 {
		c.metrics.recordInvalidation(int64(n))
	}
	return n
}

// Len reports the current number of cached entries (positive +
// negative). Used by tests and the cache_size gauge.
func (c *Cached) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Capacity reports the configured maximum. Stable for the
// lifetime of the Cached.
func (c *Cached) Capacity() int { return c.capacity }
