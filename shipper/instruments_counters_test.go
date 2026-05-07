/*
FILE PATH: shipper/instruments_counters_test.go

DESCRIPTION:
    Pins the canonical-shipper-alerts contract: every counter
    in shipper.MetricsSnapshot that drives an alert MUST be
    surfaced as an OTel ObservableCounter via InstallCounters.

    Catches a future refactor that drops one of the five
    counters (e.g. removes uniqueShipped because it "looks
    unused") — the alert ratio shipped/uniqueShipped breaks
    silently. With this test, the regression fails at CI.

    Also pins idempotency: a second InstallCounters call MUST
    return false without panicking on duplicate-instrument-
    registration.
*/
package shipper

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// withCountersReader returns an OTel meter backed by a manual
// reader with a freshly-constructed shipper. Test-cleanup
// resets the package-level installed flag so subsequent tests
// start clean.
func withCountersReader(t *testing.T) (*metric.ManualReader, *Shipper, func()) {
	t.Helper()
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	meter := mp.Meter("test")

	// Minimal shipper. We don't call Run; we just need the
	// metrics struct backing for the callback to read.
	s := &Shipper{}

	if !InstallCounters(meter, s) {
		t.Fatal("InstallCounters returned false on first call")
	}
	cleanup := func() {
		countersState.mu.Lock()
		countersState.installed = false
		countersState.mu.Unlock()
		_ = mp.Shutdown(context.Background())
	}
	return reader, s, cleanup
}

// collectCounter returns the cumulative value of a Sum[int64]
// metric by name, or -1 if not present.
func collectCounter(t *testing.T, reader *metric.ManualReader, name string) int64 {
	t.Helper()
	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %s: data is %T, want Sum[int64]", name, m.Data)
			}
			if len(sum.DataPoints) != 1 {
				t.Fatalf("metric %s: %d data points, want 1", name, len(sum.DataPoints))
			}
			return sum.DataPoints[0].Value
		}
	}
	return -1
}

// TestInstallCounters_AllFiveSurfaceTheRightAtomics asserts that
// each of the 5 OTel counters reads from the matching atomic in
// shipper.Metrics. The contract is what the alerts rely on; if
// the wiring drifts (e.g. a refactor swaps shipped and
// uniqueShipped), the alert math breaks.
func TestInstallCounters_AllFiveSurfaceTheRightAtomics(t *testing.T) {
	reader, s, cleanup := withCountersReader(t)
	defer cleanup()

	// Distinct, non-zero values per atomic so a swap wiring bug
	// is detectable.
	s.metrics.shipped.Add(11)
	s.metrics.uniqueShipped.Add(7)
	s.metrics.skippedInflight.Add(13)
	s.metrics.retries.Add(3)
	s.metrics.markShippedFailures.Add(2)

	cases := []struct {
		name string
		want int64
	}{
		{"attesta_shipper_shipped_total", 11},
		{"attesta_shipper_shipped_unique_total", 7},
		{"attesta_shipper_skipped_inflight_total", 13},
		{"attesta_shipper_retries_total", 3},
		{"attesta_shipper_mark_failures_total", 2},
	}
	for _, tc := range cases {
		got := collectCounter(t, reader, tc.name)
		if got != tc.want {
			t.Errorf("counter %s = %d; want %d", tc.name, got, tc.want)
		}
	}
}

// TestInstallCounters_Idempotent pins the second-call contract:
// a re-Install on the same package state must return false
// (without panicking on OTel duplicate-instrument errors).
func TestInstallCounters_Idempotent(t *testing.T) {
	_, s, cleanup := withCountersReader(t)
	defer cleanup()

	// First install happened in withCountersReader. Second
	// install on the SAME package state must short-circuit.
	mp := metric.NewMeterProvider(metric.WithReader(metric.NewManualReader()))
	if InstallCounters(mp.Meter("test2"), s) {
		t.Error("InstallCounters returned true on second call; expected idempotent false")
	}
}

// TestInstallCounters_NilGuards pins the defensive nil checks.
func TestInstallCounters_NilGuards(t *testing.T) {
	if InstallCounters(nil, &Shipper{}) {
		t.Error("InstallCounters(nil meter, ...) = true; want false")
	}
	mp := metric.NewMeterProvider()
	if InstallCounters(mp.Meter("nil-shipper"), nil) {
		t.Error("InstallCounters(meter, nil) = true; want false")
	}
}
