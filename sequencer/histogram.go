/*
FILE PATH: sequencer/histogram.go

A small, lock-free latency histogram for per-call timing
observations. The purpose is operational, not statistical: enough
buckets to read the shape of the distribution off a soak summary
without pulling in a percentile library, no more.

WHY THIS FILE EXISTS

The sequencer already records per-entry Tessera AppendLeaf elapsed
times at DEBUG level — useful for forensics but invisible when
running INFO-level. Aggregating those elapsed values into a
histogram lets the soak's end-of-run summary answer the operational
question evidence-first:

    "Does Tessera AppendLeaf latency degrade as we raise
     LEDGER_SEQUENCER_MAX_INFLIGHT?"

If the histogram stays flat across MaxInFlight={4,8,16,32}, Tessera
is not the bottleneck. If p99 climbs sharply at a specific
MaxInFlight, the antispam-checkpoint serialization point is the
ceiling and the conversation moves to the SDK with numbers
attached. Either way the decision is data-driven; no SDK changes
land on theory.

DESIGN

  - Eight fixed buckets covering 1µs to 1s (Tessera's expected
    operating envelope), plus an overflow bucket. Bucket bounds
    chosen so p50/p95/p99 of typical Tessera traffic land in
    different buckets — distribution shape is readable directly
    from bucket counts.

  - count, sum (µs), min (µs), max (µs) as atomic counters. min
    and max use a CAS loop so concurrent Observe calls compose
    correctly without taking a lock.

  - Snapshot returns a non-atomic value copy for printing /
    exporting. The Mean and ApproxPercentile helpers are pure
    functions on the snapshot.

ZERO-OBSERVATION SAFETY

  Snapshot.MinUs is zero when Count == 0 (callers can check
  Count before reading Min/Max/Mean). Live atomic state stores
  ^uint64(0) as the min sentinel; Snapshot collapses it to 0
  when Count is also 0.

CONCURRENCY

  Observe is lock-free and safe for concurrent calls. Snapshot
  takes a non-atomic point-in-time read — under heavy contention
  the eight bucket loads + sum/count loads may not all reflect
  the exact same instant, but for end-of-soak summary purposes
  the drift is negligible (the per-load skew is sub-microsecond
  and the soak has already stopped emitting by the time
  Snapshot runs).
*/
package sequencer

import (
	"fmt"
	"sync/atomic"
	"time"
)

// LatencyHistogram accumulates timing observations into a fixed set
// of buckets, plus min/max/count/sum aggregates. All fields are
// atomic; concurrent Observe is safe.
type LatencyHistogram struct {
	count atomic.Uint64
	sumUs atomic.Uint64
	minUs atomic.Uint64 // ^uint64(0) sentinel before first Observe
	maxUs atomic.Uint64
	// buckets count observations whose µs value is strictly less than
	// the corresponding upper bound; the final bucket is the
	// "overflow" sink (>= 1s).
	//   [0] < 1ms       [4] < 100ms
	//   [1] < 5ms       [5] < 500ms
	//   [2] < 10ms      [6] < 1s
	//   [3] < 50ms      [7] >= 1s
	buckets [8]atomic.Uint64
}

// newLatencyHistogram returns a histogram primed for observation
// (min set to its uninitialized sentinel so the first observation
// wins the CAS).
func newLatencyHistogram() *LatencyHistogram {
	h := &LatencyHistogram{}
	h.minUs.Store(^uint64(0))
	return h
}

// Observe records one elapsed measurement.
func (h *LatencyHistogram) Observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	us := uint64(d.Microseconds())
	h.count.Add(1)
	h.sumUs.Add(us)
	// Min — only swap if observation strictly lowers the recorded
	// value; the inverse holds for max. Both loops terminate in at
	// most a few iterations under contention.
	for {
		cur := h.minUs.Load()
		if us >= cur || h.minUs.CompareAndSwap(cur, us) {
			break
		}
	}
	for {
		cur := h.maxUs.Load()
		if us <= cur || h.maxUs.CompareAndSwap(cur, us) {
			break
		}
	}
	h.buckets[bucketIndex(us)].Add(1)
}

// bucketIndex maps a µs observation to its histogram bucket.
func bucketIndex(us uint64) int {
	switch {
	case us < 1_000:
		return 0
	case us < 5_000:
		return 1
	case us < 10_000:
		return 2
	case us < 50_000:
		return 3
	case us < 100_000:
		return 4
	case us < 500_000:
		return 5
	case us < 1_000_000:
		return 6
	default:
		return 7
	}
}

// LatencyHistogramSnapshot is a non-atomic copy for callers
// (Prometheus, log lines, end-of-soak summaries).
type LatencyHistogramSnapshot struct {
	Count   uint64
	SumUs   uint64
	MinUs   uint64
	MaxUs   uint64
	Buckets [8]uint64
}

// Snapshot returns a point-in-time copy of the histogram state.
// Safe to call concurrently with Observe.
func (h *LatencyHistogram) Snapshot() LatencyHistogramSnapshot {
	s := LatencyHistogramSnapshot{
		Count: h.count.Load(),
		SumUs: h.sumUs.Load(),
		MinUs: h.minUs.Load(),
		MaxUs: h.maxUs.Load(),
	}
	if s.Count == 0 {
		// Collapse the sentinel into a friendly zero when there's
		// nothing to report.
		s.MinUs = 0
	}
	for i := range h.buckets {
		s.Buckets[i] = h.buckets[i].Load()
	}
	return s
}

// MeanUs returns the arithmetic mean observation in microseconds.
// Returns 0 when no observations have been recorded.
func (s LatencyHistogramSnapshot) MeanUs() float64 {
	if s.Count == 0 {
		return 0
	}
	return float64(s.SumUs) / float64(s.Count)
}

// BucketUpperBoundsUs returns the µs upper bound for each bucket;
// the final entry is 0 to denote the open-ended overflow bucket.
// Useful for emitting bucket-labelled log fields.
func BucketUpperBoundsUs() [8]uint64 {
	return [8]uint64{
		1_000, 5_000, 10_000, 50_000,
		100_000, 500_000, 1_000_000, 0,
	}
}

// Format returns a compact one-line representation suitable for
// slog log values:
//
//	"n=10000 min=2.1ms mean=8.7ms max=312.4ms p99~50ms b=[12 1402 6210 2350 24 2 0 0]"
//
// The p99 bound is the upper edge of the bucket containing the 99th
// percentile observation (overflow bucket shows as ">=1s"). It is a
// coarse but honest estimate — fine for "is the curve flat or does
// it cliff at MaxInFlight=N" capacity-planning questions.
func (s LatencyHistogramSnapshot) Format() string {
	if s.Count == 0 {
		return "n=0"
	}
	return fmt.Sprintf(
		"n=%d min=%s mean=%s max=%s p99~%s b=%v",
		s.Count,
		usToString(s.MinUs),
		usToString(uint64(s.MeanUs())),
		usToString(s.MaxUs),
		s.approxP99(),
		s.Buckets,
	)
}

// approxP99 returns a human-readable upper bound for the 99th
// percentile bucket. Coarse — see Format documentation.
func (s LatencyHistogramSnapshot) approxP99() string {
	if s.Count == 0 {
		return "n/a"
	}
	target := s.Count - s.Count/100
	if target == 0 {
		target = 1
	}
	bounds := BucketUpperBoundsUs()
	var running uint64
	for i, b := range s.Buckets {
		running += b
		if running >= target {
			if bounds[i] == 0 {
				return ">=1s"
			}
			return "<" + usToString(bounds[i])
		}
	}
	return ">=1s"
}

// usToString prints a µs count in the most legible time unit.
func usToString(us uint64) string {
	switch {
	case us < 1_000:
		return fmt.Sprintf("%dµs", us)
	case us < 1_000_000:
		return fmt.Sprintf("%.1fms", float64(us)/1_000)
	default:
		return fmt.Sprintf("%.2fs", float64(us)/1_000_000)
	}
}
