// FILE PATH: latency/histogram_test.go
//
// Focused tests for the Histogram. Verifies the empty / bucket-
// boundary / concurrent-Observe / p99-semantics cases. Locks in the
// behaviour relied on by the sequencer (Tessera AppendLeaf
// histogram), wal (Submit duration), and any future consumer.
package latency

import (
	"sync"
	"testing"
	"time"
)

func TestHistogram_Empty(t *testing.T) {
	h := New()
	snap := h.Snapshot()
	if snap.Count != 0 {
		t.Fatalf("Count = %d, want 0", snap.Count)
	}
	if snap.MinUs != 0 || snap.MaxUs != 0 {
		t.Fatalf("Min/Max = %d/%d, want 0/0 when empty", snap.MinUs, snap.MaxUs)
	}
	if got := snap.MeanUs(); got != 0 {
		t.Fatalf("MeanUs = %v, want 0", got)
	}
	if got := snap.Format(); got != "n=0" {
		t.Fatalf("Format = %q, want %q", got, "n=0")
	}
}

func TestHistogram_BucketBoundaries(t *testing.T) {
	h := New()
	// One observation in each bucket — values picked to land just
	// under each upper bound so a future bucket-shift bug surfaces
	// loudly (count would migrate to the neighbour).
	observations := []time.Duration{
		500 * time.Microsecond, // bucket 0 (< 1ms)
		4 * time.Millisecond,   // bucket 1 (< 5ms)
		9 * time.Millisecond,   // bucket 2 (< 10ms)
		49 * time.Millisecond,  // bucket 3 (< 50ms)
		99 * time.Millisecond,  // bucket 4 (< 100ms)
		499 * time.Millisecond, // bucket 5 (< 500ms)
		999 * time.Millisecond, // bucket 6 (< 1s)
		2 * time.Second,        // bucket 7 (>= 1s)
	}
	for _, d := range observations {
		h.Observe(d)
	}
	snap := h.Snapshot()
	if snap.Count != uint64(len(observations)) {
		t.Fatalf("Count = %d, want %d", snap.Count, len(observations))
	}
	for i, b := range snap.Buckets {
		if b != 1 {
			t.Errorf("bucket[%d] = %d, want 1", i, b)
		}
	}
	if snap.MinUs != 500 {
		t.Errorf("MinUs = %d, want 500", snap.MinUs)
	}
	if snap.MaxUs != 2_000_000 {
		t.Errorf("MaxUs = %d, want 2_000_000", snap.MaxUs)
	}
}

func TestHistogram_ConcurrentObserve(t *testing.T) {
	const goroutines = 32
	const perGoroutine = 1000
	h := New()
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				// Stagger durations so min/max contention paths execute.
				// Start at 1µs (not 0) so MinUs is unambiguously
				// post-observation rather than the empty-sentinel collapse.
				h.Observe(time.Duration(seed*10+i+1) * time.Microsecond)
			}
		}(g)
	}
	wg.Wait()
	snap := h.Snapshot()
	want := uint64(goroutines * perGoroutine)
	if snap.Count != want {
		t.Fatalf("Count = %d, want %d (lost observations under contention)",
			snap.Count, want)
	}
	var bucketSum uint64
	for _, b := range snap.Buckets {
		bucketSum += b
	}
	if bucketSum != want {
		t.Fatalf("sum(buckets) = %d, want %d", bucketSum, want)
	}
	if snap.MinUs == 0 {
		t.Fatalf("MinUs = 0, want >0 after observations")
	}
	if snap.MaxUs == 0 || snap.MaxUs < snap.MinUs {
		t.Fatalf("MaxUs = %d (Min=%d): invariant violated", snap.MaxUs, snap.MinUs)
	}
}

func TestHistogram_ApproxP99(t *testing.T) {
	// p99 of 100 observations is the 99th-ranked value, so a 1% slow
	// tail is HIDDEN at p99 (visible only in MaxUs). A 50% slow tail
	// is captured. Both behaviours pinned below to prevent silent
	// semantic drift in ApproxP99.
	t.Run("one_percent_tail_hidden_in_p99", func(t *testing.T) {
		h := New()
		for i := 0; i < 99; i++ {
			h.Observe(2 * time.Millisecond) // bucket 1 (< 5ms)
		}
		h.Observe(750 * time.Millisecond) // bucket 6 (< 1s)
		snap := h.Snapshot()
		if got := snap.ApproxP99(); got != "<5.0ms" {
			t.Fatalf("ApproxP99 = %q, want %q (99th rank is fast)",
				got, "<5.0ms")
		}
		// And the max correctly captures the 1% tail.
		if snap.MaxUs != 750_000 {
			t.Fatalf("MaxUs = %d, want 750000 (1%% tail not captured)",
				snap.MaxUs)
		}
	})

	t.Run("fifty_percent_tail_visible_in_p99", func(t *testing.T) {
		h := New()
		for i := 0; i < 50; i++ {
			h.Observe(2 * time.Millisecond)   // bucket 1 (< 5ms)
			h.Observe(750 * time.Millisecond) // bucket 6 (< 1s)
		}
		snap := h.Snapshot()
		// UsToString(1_000_000) formats the bucket-6 upper bound as
		// "1.00s" because the < 1_000_000 boundary is strict — both
		// the formatter and ApproxP99 use the same bound, so the
		// printed value is self-consistent.
		if got := snap.ApproxP99(); got != "<1.00s" {
			t.Fatalf("ApproxP99 = %q, want %q (50%% in slow bucket)",
				got, "<1.00s")
		}
	})

	t.Run("overflow_bucket_returns_open_ended_bound", func(t *testing.T) {
		h := New()
		// All observations land in the overflow bucket; p99 must
		// surface that the distribution is entirely beyond the
		// resolved range.
		for i := 0; i < 10; i++ {
			h.Observe(2 * time.Second)
		}
		snap := h.Snapshot()
		if got := snap.ApproxP99(); got != ">=1s" {
			t.Fatalf("ApproxP99 = %q, want %q (overflow)", got, ">=1s")
		}
	})
}
