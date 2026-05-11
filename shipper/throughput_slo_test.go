/*
FILE PATH: shipper/throughput_slo_test.go

Item 1 — Shipper Throughput SLO regression gate.

ASSERTION:

	With a 1ms-per-write bytestore (much faster than real S3/GCS,
	chosen so the bytestore is NOT the bottleneck), the shipper
	using PRODUCTION DEFAULT Config sustains at least
	SLOThroughputEntriesPerSec entries/sec over a fixed measurement
	window. See shipper/slo.go for the SLO rationale.

WHY DEFAULT CONFIG:

	Tests that pass with hand-tuned config but fail with defaults
	provide no protection: production operators run the defaults.
	This test gates the SHIPPED defaults; a regression that lowers
	throughput by raising PollInterval or lowering MaxInFlight has
	to update the SLO or change the defaults.

NEGATIVE CONTROL:

	A second test asserts the gate has teeth: with a deliberately
	pathological Config (MaxInFlight=1, PollInterval=10s), the SLO
	MUST be violated. If both tests pass with the same shipper
	behavior, the gate is broken and a regression would slip
	through silently.

EXPECTED FAILURE MODE TODAY:

	With current defaults (MaxInFlight=4, PollInterval=1s), this
	test fails. Theoretical ceiling is 4 ent/ms = 4000 ent/sec
	if the scanner kept the channel full, but PollInterval=1s gates
	rescans, so realised throughput is ~8 ent/sec. The fix is to
	lower PollInterval and raise MaxInFlight; that work happens in
	a follow-up commit gated by THIS test.

WALL-CLOCK BUDGET:

	5 second measurement window. Long enough that startup-latency
	jitter (first scan, worker spin-up) averages out; short enough
	that the test runs in <10s including shipper shutdown.
*/
package shipper

import (
	"testing"
	"time"
)

// TestShipperThroughput_MeetsSLO asserts the production-default
// shipper sustains the throughput SLO with a 1ms-per-write bytestore.
//
// Until the defaults are tuned to satisfy this SLO, this test FAILS
// — by design. The failure value (entries/sec actually achieved) is
// the gap that the tuning work has to close.
func TestShipperThroughput_MeetsSLO(t *testing.T) {
	const (
		bytestoreLatency = 1 * time.Millisecond
		wallWindow       = 5 * time.Second
		seedBacklog      = 100_000 // far more than the SLO * wallWindow ⇒ shipper never starves
	)

	bs := newBenchBytestore(fixedLatency(bytestoreLatency))

	// Production-default Config — leaving fields zero forces
	// NewShipper to apply its defaults, which is exactly what
	// production runs with.
	result := runShipperBench(t, Config{}, seedBacklog, bs, wallWindow)

	t.Logf("shipper benchmark: shipped %d in %v ⇒ %.1f ent/sec (HWM=%d, skipped_inflight=%d, mean_ship_ms=%.2f, bytestore_calls=%d)",
		result.UniqueShipped, result.WallClock, result.EntriesPerSecond,
		result.HWMAdvance, result.SkippedInflight,
		result.MeanShipLatencyMS, result.BytestoreCalls)

	if result.EntriesPerSecond < float64(SLOThroughputEntriesPerSec) {
		t.Fatalf("shipper throughput %.1f ent/sec < SLO %d ent/sec "+
			"(default Config{}, 1ms bytestore, %v wall, %d shipped)\n"+
			"  -> production defaults do not meet the throughput SLO\n"+
			"  -> tune PollInterval / MaxInFlight in shipper.Config defaults",
			result.EntriesPerSecond, SLOThroughputEntriesPerSec,
			result.WallClock, result.UniqueShipped)
	}
}

// TestShipperThroughput_SLO_DetectsRegression is the negative control.
// A deliberately pathological config (1 worker, 10s scan interval)
// MUST violate the SLO. If this test ever passes, the SLO gate has
// lost its discriminating power and the positive test would silently
// accept regressed behavior.
func TestShipperThroughput_SLO_DetectsRegression(t *testing.T) {
	const (
		bytestoreLatency = 1 * time.Millisecond
		wallWindow       = 3 * time.Second
		seedBacklog      = 100_000
	)

	bs := newBenchBytestore(fixedLatency(bytestoreLatency))

	// Pathological: one worker, scan loop barely runs during window.
	badCfg := Config{
		MaxInFlight:  1,
		PollInterval: 10 * time.Second,
	}

	result := runShipperBench(t, badCfg, seedBacklog, bs, wallWindow)

	t.Logf("negative-control bench: shipped %d in %v ⇒ %.1f ent/sec (HWM=%d)",
		result.UniqueShipped, result.WallClock, result.EntriesPerSecond,
		result.HWMAdvance)

	if result.EntriesPerSecond >= float64(SLOThroughputEntriesPerSec) {
		t.Fatalf("negative control passed SLO: %.1f ent/sec ≥ %d ent/sec — "+
			"the SLO gate has no discriminating power and would let a "+
			"throughput regression land silently. "+
			"Pathological config: MaxInFlight=%d PollInterval=%v",
			result.EntriesPerSecond, SLOThroughputEntriesPerSec,
			badCfg.MaxInFlight, badCfg.PollInterval)
	}
}
