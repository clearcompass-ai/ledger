/*
FILE PATH:

	delegationresolver/invalidation_test.go

DESCRIPTION:

	Pin the rotation-aware invalidation helpers. The hot property:
	an admitted entry that itself updates a delegation MUST result
	in cache eviction for the affected DelegateDID.
*/
package delegationresolver

import (
	"context"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/delegation"
)

func TestInvalidateOnEntry_NilCacheNoop(t *testing.T) {
	t.Parallel()

	if InvalidateOnEntry(nil, &envelope.Entry{}) {
		t.Error("InvalidateOnEntry(nil cache) returned true; want no-op")
	}
}

func TestInvalidateOnEntry_NilEntryNoop(t *testing.T) {
	t.Parallel()

	cache, _ := NewCached(delegation.NewInMemorySource(), 10, nil)
	if InvalidateOnEntry(cache, nil) {
		t.Error("InvalidateOnEntry(nil entry) returned true; want no-op")
	}
}

func TestInvalidateOnEntry_NonDelegationEntryNoop(t *testing.T) {
	t.Parallel()

	cache, _ := NewCached(delegation.NewInMemorySource(), 10, nil)
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		// DelegateDID nil → not a delegation event
		SignerDID: "did:web:irrelevant",
	}}
	if InvalidateOnEntry(cache, entry) {
		t.Error("InvalidateOnEntry on non-delegation entry returned true; want no-op")
	}
}

func TestInvalidateOnEntry_EmptyDelegateDIDNoop(t *testing.T) {
	t.Parallel()

	cache, _ := NewCached(delegation.NewInMemorySource(), 10, nil)
	empty := ""
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		DelegateDID: &empty,
	}}
	if InvalidateOnEntry(cache, entry) {
		t.Error("InvalidateOnEntry on empty DelegateDID returned true; want no-op")
	}
}

func TestInvalidateOnEntry_EvictsCachedDelegation(t *testing.T) {
	t.Parallel()

	src := delegation.NewInMemorySource()
	if err := src.Add(delegation.DelegationEntry{
		DelegateDID:  "did:web:rotated",
		DelegatorDID: "did:web:root",
		Live:         true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cache, _ := NewCached(src, 10, nil)
	ctx := context.Background()
	if _, err := cache.DelegationOf(ctx, "did:web:rotated"); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache not warmed: Len=%d", cache.Len())
	}

	// Synthetic "delegation rotated" entry referencing the same DID.
	rotated := "did:web:rotated"
	entry := &envelope.Entry{Header: envelope.ControlHeader{
		SignerDID:   "did:web:root",
		DelegateDID: &rotated,
	}}
	if !InvalidateOnEntry(cache, entry) {
		t.Error("InvalidateOnEntry returned false; want eviction")
	}
	if cache.Len() != 0 {
		t.Errorf("cache not cleared: Len=%d", cache.Len())
	}
}

func TestInvalidateOnEntries_FansAcrossSlice(t *testing.T) {
	t.Parallel()

	src := delegation.NewInMemorySource()
	for _, did := range []string{"did:web:a", "did:web:b", "did:web:c"} {
		_ = src.Add(delegation.DelegationEntry{
			DelegateDID:  did,
			DelegatorDID: "did:web:root",
			Live:         true,
		})
	}
	cache, _ := NewCached(src, 10, nil)
	ctx := context.Background()
	for _, did := range []string{"did:web:a", "did:web:b", "did:web:c"} {
		_, _ = cache.DelegationOf(ctx, did)
	}
	if cache.Len() != 3 {
		t.Fatalf("cache not warmed: Len=%d", cache.Len())
	}

	mkEntry := func(did string) *envelope.Entry {
		copyDID := did
		return &envelope.Entry{Header: envelope.ControlHeader{
			SignerDID:   "did:web:root",
			DelegateDID: &copyDID,
		}}
	}
	entries := []*envelope.Entry{
		mkEntry("did:web:a"),
		mkEntry("did:web:b"),
		mkEntry("did:web:not-cached"), // no-op for this entry
	}
	if got := InvalidateOnEntries(cache, entries); got != 2 {
		t.Errorf("evicted %d, want 2 (a + b; not-cached is no-op)", got)
	}
	if cache.Len() != 1 {
		t.Errorf("Len=%d, want 1 (c remains)", cache.Len())
	}
}

func TestInvalidateOnEntries_EmptyAndNilNoop(t *testing.T) {
	t.Parallel()

	cache, _ := NewCached(delegation.NewInMemorySource(), 10, nil)
	if InvalidateOnEntries(cache, nil) != 0 {
		t.Error("InvalidateOnEntries(nil) returned non-zero")
	}
	if InvalidateOnEntries(cache, []*envelope.Entry{}) != 0 {
		t.Error("InvalidateOnEntries(empty) returned non-zero")
	}
	if InvalidateOnEntries(nil, []*envelope.Entry{{}}) != 0 {
		t.Error("InvalidateOnEntries(nil cache) returned non-zero")
	}
}
