/*
FILE PATH: shipper/bench_harness_test.go

Scaffold B — reusable in-memory benchmark harness for shipper SLO
tests. Provides:

  - benchBytestore: a fast in-memory bytestore that records every
    write and applies a configurable latency model per WriteEntry.
    Two latency samplers are built in: fixed(d) and lognormal(p50,
    p99). New tests pick whichever model matches the failure mode
    they want to exercise.

  - runShipperBench: runs a shipper against a pre-seeded fakeWAL
    + benchBytestore for a fixed wall-clock window, collects shipped
    counts + latencies, and returns benchResult.

  - newPreSeededFakeWAL: helper that seeds N StateSequenced entries
    so the shipper has continuous work for the whole window.

Reuse model:

	Other items in the production-readiness top-10 (backpressure SLO,
	retry-storm tolerance, HWM-advance latency, error-budget burn)
	can call runShipperBench with their own Config and latency
	sampler. The harness intentionally does NOT couple to any
	specific SLO threshold — that's the calling test's job. Keep
	this file SLO-free.

NOT IN THIS FILE (deliberately):
  - SLO thresholds. Those live in shipper/slo.go and are referenced
    by individual *_slo_test.go files.
  - Workload distribution generators (uniform / Pareto / hotspot).
    Add when the first item that needs them shows up.
*/
package shipper

import (
	"context"
	"crypto/sha256"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Latency samplers
// ─────────────────────────────────────────────────────────────────────

// latencySampler returns a per-write latency. Implementations MUST
// be goroutine-safe (called concurrently from MaxInFlight workers).
type latencySampler func() time.Duration

// fixedLatency returns a sampler that yields the same duration every
// call. Use this when the test cares about deterministic timing
// (Item 1, throughput SLO).
func fixedLatency(d time.Duration) latencySampler {
	return func() time.Duration { return d }
}

// lognormalLatency returns a sampler that draws from a lognormal
// distribution shaped to match p50 + p99 targets. This approximates
// real S3-like backends where tail latency is materially larger than
// the median (occasional 95th/99th-percentile slow PUTs).
//
// Parameter mapping: the lognormal distribution has parameters
// (mu, sigma). We solve for those given the requested percentiles:
//
//	p50 = exp(mu)
//	p99 = exp(mu + 2.326 * sigma)
//
// → mu = ln(p50), sigma = (ln(p99) - mu) / 2.326
//
// The 2.326 quantile is the standard-normal inverse at 0.99. Callers
// pass p99 > p50; otherwise the returned sampler degenerates to
// fixedLatency(p50).
//
// Goroutine-safe via a per-call rand source seeded from time.Now;
// adequate for benchmark variance, NOT a cryptographic RNG.
func lognormalLatency(p50, p99 time.Duration) latencySampler {
	if p99 <= p50 {
		return fixedLatency(p50)
	}
	mu := math.Log(float64(p50))
	sigma := (math.Log(float64(p99)) - mu) / 2.326
	var mu64 = mu
	var sigma64 = sigma

	// One source per sampler is fine for the harness; benchmark
	// determinism is not required, and rand.Source is goroutine-
	// unsafe so we guard with a mutex.
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)
	var mu_lock sync.Mutex

	return func() time.Duration {
		mu_lock.Lock()
		n := rng.NormFloat64()
		mu_lock.Unlock()
		d := math.Exp(mu64 + sigma64*n)
		if d < 0 || math.IsInf(d, 0) || math.IsNaN(d) {
			return p50
		}
		return time.Duration(d)
	}
}

// ─────────────────────────────────────────────────────────────────────
// benchBytestore — purpose-built for shipper benchmarks
// ─────────────────────────────────────────────────────────────────────

// benchBytestore is a Shipper-compatible Bytestore that applies a
// per-call latency model and counts writes. Unlike fakeBytestore
// (used by correctness tests with stallSeq / stallEvery knobs),
// benchBytestore is optimized for high call rates: no per-call
// mutex contention on counter increment, latency drawn from a
// pluggable sampler.
type benchBytestore struct {
	latency  latencySampler
	calls    atomic.Uint64 // total WriteEntry invocations
	bytes    atomic.Uint64 // total bytes written
	failRate float64       // 0.0 .. 1.0 ; probability per call to return an error
	failOnce sync.Once     // gate against rand init in hot path

	// rng + rngMu used only when failRate > 0. Skipped otherwise.
	rngMu sync.Mutex
	rng   *rand.Rand
}

func newBenchBytestore(sampler latencySampler) *benchBytestore {
	if sampler == nil {
		sampler = fixedLatency(0)
	}
	return &benchBytestore{latency: sampler}
}

// WithFailRate returns the receiver after enabling a per-call
// failure probability. Used by error-budget tests (NOT Item 1).
func (b *benchBytestore) WithFailRate(p float64) *benchBytestore {
	b.failRate = p
	b.failOnce.Do(func() {
		b.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	})
	return b
}

func (b *benchBytestore) WriteEntry(ctx context.Context, seq uint64, _ [32]byte, wireBytes []byte) error {
	if d := b.latency(); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}

	if b.failRate > 0 {
		b.rngMu.Lock()
		fail := b.rng.Float64() < b.failRate
		b.rngMu.Unlock()
		if fail {
			return errBenchInduced
		}
	}

	b.calls.Add(1)
	b.bytes.Add(uint64(len(wireBytes)))
	return nil
}

// Calls returns total WriteEntry successes.
func (b *benchBytestore) Calls() uint64 { return b.calls.Load() }

var errBenchInduced = &benchInducedErr{}

type benchInducedErr struct{}

func (*benchInducedErr) Error() string { return "benchBytestore: induced failure" }

// ─────────────────────────────────────────────────────────────────────
// WAL pre-seeding
// ─────────────────────────────────────────────────────────────────────

// seedFakeWAL fills a fakeWAL with N StateSequenced entries with seqs
// 1..N (since the WAL HWM starts at 0, fromSeq=0 yields all of them).
// Wire bytes are 256 random-ish bytes per entry; the size is small
// enough not to bottleneck on memory yet large enough to be a non-
// trivial bytestore payload.
func seedFakeWAL(f *fakeWAL, n int) {
	const wireSize = 256
	wire := make([]byte, wireSize)
	for i := 0; i < wireSize; i++ {
		wire[i] = byte(i)
	}
	for i := 1; i <= n; i++ {
		// Distinct hashes per seq, so the fakeWAL's hash→meta map
		// doesn't dedupe.
		var seed [8]byte
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		seed[2] = byte(i >> 16)
		seed[3] = byte(i >> 24)
		hash := sha256.Sum256(seed[:])
		f.seed(uint64(i), hash, wire)
	}
}

// ─────────────────────────────────────────────────────────────────────
// runShipperBench — primary entry point for SLO tests
// ─────────────────────────────────────────────────────────────────────

// benchResult is the output of runShipperBench. EntriesPerSecond is
// computed from UniqueShipped over the wall-clock window — NOT
// the inflated Shipped counter, which double-counts under
// dispatch races.
type benchResult struct {
	WallClock        time.Duration
	UniqueShipped    uint64
	EntriesPerSecond float64

	// HWMAdvance is the WAL HWM at the end of the run. Lags
	// UniqueShipped by the size of the out-of-order completion
	// hold-set in the hwmAdvancer.
	HWMAdvance uint64

	// SkippedInflight surfaces the in-flight-dedupe guard activity.
	// Non-zero ⇒ the scan loop is racing workers (PollInterval too
	// tight for shipOne latency). Useful for diagnosing throughput
	// regressions.
	SkippedInflight uint64

	// MeanShipLatencyMS is the mean per-entry shipping latency
	// the shipper itself measured, in milliseconds. Compare against
	// the bytestore's latency model to see how much overhead the
	// shipper adds.
	MeanShipLatencyMS float64

	// BytestoreCalls is the total WriteEntry invocations the
	// bytestore observed. ≥ UniqueShipped under dispatch racing
	// (each entry may be uploaded multiple times); the gap is the
	// wasted-write factor.
	BytestoreCalls uint64
}

// runShipperBench seeds a fresh fakeWAL with N entries, runs a
// Shipper with the given Config + bytestore for wallClock duration,
// then cancels and returns a benchResult.
//
// The fakeWAL and benchBytestore are NOT returned — callers should
// add fields to benchResult if they need them. This keeps the
// harness simple and the return signature stable across SLO tests.
func runShipperBench(t *testing.T, cfg Config, seedN int, bs *benchBytestore, wallClock time.Duration) benchResult {
	t.Helper()

	if bs == nil {
		t.Fatal("runShipperBench: bytestore is nil")
	}
	if seedN <= 0 {
		t.Fatal("runShipperBench: seedN must be > 0")
	}

	f := newFakeWAL()
	seedFakeWAL(f, seedN)

	shp := NewShipper(f, bs, cfg)

	// Decouple from the test's context so cancellation is under our
	// control — we want to measure exactly wallClock seconds of
	// shipping, not whatever the parent context might do.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = shp.Run(ctx)
	}()

	start := time.Now()
	time.Sleep(wallClock)
	cancel()

	// Bounded wait for Run to return. If the shipper deadlocks on
	// shutdown, the test surfaces that here rather than hanging.
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("runShipperBench: shipper did not shut down within 10s")
	}
	elapsed := time.Since(start)

	snap := shp.Metrics()
	return benchResult{
		WallClock:         elapsed,
		UniqueShipped:     snap.UniqueShipped,
		EntriesPerSecond:  float64(snap.UniqueShipped) / elapsed.Seconds(),
		HWMAdvance:        snap.HWM,
		SkippedInflight:   snap.SkippedInflight,
		MeanShipLatencyMS: snap.ShipLatencyMeanMillis,
		BytestoreCalls:    bs.Calls(),
	}
}
