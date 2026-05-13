/*
FILE PATH:

	delegationresolver/cache_test.go

DESCRIPTION:

	Behavioural tests for the LRU cache wrapper. Uses the SDK's
	delegation.InMemorySource as the underlying source (real
	fixture, no fake-fake) — the cache's correctness is independent
	of where the data comes from.

	Tests pin:
	  - Hit path returns cached value without re-asking the source
	  - Miss path consults the source and caches positive result
	  - Negative cache: ErrUnknownDelegate is itself cached
	  - Transient errors are NOT cached (retry-friendly)
	  - LRU eviction order under capacity pressure
	  - Invalidate clears one row; InvalidateAll clears all
	  - Empty DID returns ErrUnknownDelegate without consulting source
	  - Concurrent Get is safe (race-detected under -race)
*/
package delegationresolver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/delegation"
)

// countingSource wraps a delegation.EntrySource with a counter
// so tests can assert the cache eliminated underlying calls.
type countingSource struct {
	inner delegation.EntrySource
	calls atomic.Int64
}

func (s *countingSource) DelegationOf(ctx context.Context, did string) (delegation.DelegationEntry, error) {
	s.calls.Add(1)
	return s.inner.DelegationOf(ctx, did)
}

// failingSource always returns the configured error. Used to
// pin "transient errors aren't cached" behaviour.
type failingSource struct {
	err   error
	calls atomic.Int64
}

func (s *failingSource) DelegationOf(ctx context.Context, _ string) (delegation.DelegationEntry, error) {
	s.calls.Add(1)
	return delegation.DelegationEntry{}, s.err
}

// realInner builds a delegation.InMemorySource pre-populated with n
// distinct delegate DIDs whose delegator is "did:web:root".
func realInner(t *testing.T, n int) *delegation.InMemorySource {
	t.Helper()
	src := delegation.NewInMemorySource()
	for i := 0; i < n; i++ {
		err := src.Add(delegation.DelegationEntry{
			DelegateDID:  fmt.Sprintf("did:web:delegate-%d", i),
			DelegatorDID: "did:web:root",
			Live:         true,
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return src
}

func TestNewCached_RejectsNilSource(t *testing.T) {
	t.Parallel()

	if _, err := NewCached(nil, 10, nil); err == nil {
		t.Error("NewCached(nil) succeeded; expected error")
	}
}

func TestNewCached_DefaultCapacityWhenZero(t *testing.T) {
	t.Parallel()

	c, err := NewCached(realInner(t, 1), 0, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	if c.Capacity() != DefaultCacheCapacity {
		t.Errorf("Capacity=%d, want default %d", c.Capacity(), DefaultCacheCapacity)
	}
}

func TestCached_HitDoesNotCallSource(t *testing.T) {
	t.Parallel()

	src := &countingSource{inner: realInner(t, 1)}
	cache, err := NewCached(src, 10, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := cache.DelegationOf(ctx, "did:web:delegate-0")
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
	}
	if got := src.calls.Load(); got != 1 {
		t.Errorf("source called %d times; want exactly 1 (cache hit)", got)
	}
}

func TestCached_NegativeResultIsCached(t *testing.T) {
	t.Parallel()

	src := &countingSource{inner: realInner(t, 1)}
	cache, err := NewCached(src, 10, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := cache.DelegationOf(ctx, "did:web:not-in-source")
		if !errors.Is(err, attestation.ErrUnknownDelegate) {
			t.Errorf("get %d: err=%v, want ErrUnknownDelegate", i, err)
		}
	}
	// First miss → 1 source call. Subsequent calls hit the negative cache.
	if got := src.calls.Load(); got != 1 {
		t.Errorf("source called %d times; want 1 (negative cache should absorb 4 of 5)", got)
	}
}

func TestCached_TransientErrorIsNotCached(t *testing.T) {
	t.Parallel()

	transient := errors.New("transport: connection refused")
	src := &failingSource{err: transient}
	cache, err := NewCached(src, 10, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := cache.DelegationOf(ctx, "did:web:any")
		if !errors.Is(err, transient) {
			t.Errorf("get %d: err=%v, want transient", i, err)
		}
	}
	// Each call MUST hit the source — transient errors don't cache.
	if got := src.calls.Load(); got != 3 {
		t.Errorf("source called %d times; want 3 (transient errors retry-friendly)", got)
	}
}

func TestCached_LRUEvictsOldestUnderPressure(t *testing.T) {
	t.Parallel()

	src := realInner(t, 5)
	// Capacity 3 — adding a 4th forces eviction of the LRU.
	cache, err := NewCached(src, 3, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_, err := cache.DelegationOf(ctx, fmt.Sprintf("did:web:delegate-%d", i))
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
	}
	if cache.Len() != 3 {
		t.Errorf("Len=%d, want 3 (capacity)", cache.Len())
	}
	// delegate-0 was first in, no recent access → evicted.
	// Re-asking it forces a source call (countable via wrapper).
	counted := &countingSource{inner: src}
	cache2, _ := NewCached(counted, 3, nil)
	for i := 0; i < 4; i++ {
		_, _ = cache2.DelegationOf(ctx, fmt.Sprintf("did:web:delegate-%d", i))
	}
	calls := counted.calls.Load()
	_, _ = cache2.DelegationOf(ctx, "did:web:delegate-0") // evicted, hits source again
	after := counted.calls.Load()
	if after != calls+1 {
		t.Errorf("expected 1 additional source call for evicted key; got %d", after-calls)
	}
}

func TestCached_RecentAccessProtectsFromEviction(t *testing.T) {
	t.Parallel()

	src := realInner(t, 5)
	cache, err := NewCached(src, 3, nil)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	ctx := context.Background()
	// Populate 0, 1, 2.
	for i := 0; i < 3; i++ {
		_, _ = cache.DelegationOf(ctx, fmt.Sprintf("did:web:delegate-%d", i))
	}
	// Touch 0 (now most-recent).
	_, _ = cache.DelegationOf(ctx, "did:web:delegate-0")
	// Insert 3 → should evict 1 (LRU), not 0.
	_, _ = cache.DelegationOf(ctx, "did:web:delegate-3")

	counted := &countingSource{inner: src}
	cache.source = counted
	// 0 should still be cached (zero source call expected).
	_, _ = cache.DelegationOf(ctx, "did:web:delegate-0")
	if got := counted.calls.Load(); got != 0 {
		t.Errorf("recently-touched key was evicted; source called %d times", got)
	}
}

func TestCached_InvalidateRemovesEntry(t *testing.T) {
	t.Parallel()

	src := &countingSource{inner: realInner(t, 1)}
	cache, _ := NewCached(src, 10, nil)
	ctx := context.Background()
	_, _ = cache.DelegationOf(ctx, "did:web:delegate-0")
	if cache.Len() != 1 {
		t.Fatalf("Len=%d, want 1", cache.Len())
	}
	if !cache.Invalidate("did:web:delegate-0") {
		t.Error("Invalidate returned false on present key")
	}
	if cache.Len() != 0 {
		t.Errorf("Len=%d after Invalidate, want 0", cache.Len())
	}
	// Re-fetching now hits the source again.
	_, _ = cache.DelegationOf(ctx, "did:web:delegate-0")
	if src.calls.Load() != 2 {
		t.Errorf("source called %d times; want 2 (post-invalidation refetch)", src.calls.Load())
	}
}

func TestCached_InvalidateMissingKeyReturnsFalse(t *testing.T) {
	t.Parallel()

	cache, _ := NewCached(realInner(t, 0), 10, nil)
	if cache.Invalidate("did:web:never-cached") {
		t.Error("Invalidate returned true on absent key")
	}
}

func TestCached_InvalidateAll(t *testing.T) {
	t.Parallel()

	src := realInner(t, 5)
	cache, _ := NewCached(src, 10, nil)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = cache.DelegationOf(ctx, fmt.Sprintf("did:web:delegate-%d", i))
	}
	if cache.Len() != 5 {
		t.Fatalf("Len=%d, want 5", cache.Len())
	}
	if got := cache.InvalidateAll(); got != 5 {
		t.Errorf("InvalidateAll cleared %d, want 5", got)
	}
	if cache.Len() != 0 {
		t.Errorf("Len=%d after InvalidateAll, want 0", cache.Len())
	}
}

func TestCached_EmptyDIDReturnsUnknownWithoutSourceCall(t *testing.T) {
	t.Parallel()

	src := &countingSource{inner: realInner(t, 1)}
	cache, _ := NewCached(src, 10, nil)
	_, err := cache.DelegationOf(context.Background(), "")
	if !errors.Is(err, attestation.ErrUnknownDelegate) {
		t.Errorf("err=%v, want ErrUnknownDelegate", err)
	}
	if src.calls.Load() != 0 {
		t.Errorf("source called %d times for empty DID; want 0", src.calls.Load())
	}
}

func TestCached_ConcurrentGetIsSafe(t *testing.T) {
	t.Parallel()

	src := &countingSource{inner: realInner(t, 100)}
	cache, _ := NewCached(src, 50, nil)
	ctx := context.Background()
	const workers = 16
	const each = 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				key := fmt.Sprintf("did:web:delegate-%d", (seed+i)%100)
				_, _ = cache.DelegationOf(ctx, key)
			}
		}(w)
	}
	wg.Wait()
	// No assertion on call count (race-dependent); the test
	// passes by virtue of -race not flagging anything.
}

func TestCached_PutOverwriteOnConcurrentMissForSameKey(t *testing.T) {
	t.Parallel()

	src := &countingSource{inner: realInner(t, 1)}
	cache, _ := NewCached(src, 10, nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.DelegationOf(ctx, "did:web:delegate-0")
		}()
	}
	wg.Wait()
	if cache.Len() != 1 {
		t.Errorf("Len=%d, want exactly 1 (no duplicate cache rows)", cache.Len())
	}
}
