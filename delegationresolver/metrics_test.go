/*
FILE PATH:

	delegationresolver/metrics_test.go

DESCRIPTION:

	Pin the OTel install + nil-safety contracts.

	Note: we don't reach into the OTel SDK to assert specific
	counter values — that's the responsibility of the OTel
	exporter's own test suite. We pin two properties that ARE
	the package's contract:

	  1. Install is idempotent (second call returns false; the
	     installed instruments are the ones from the first call).
	  2. nil *Metrics receivers no-op without panic, so the cache
	     can run unmetered in tests.
*/
package delegationresolver

import (
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func resetPackageMetrics(t *testing.T) {
	t.Helper()
	metricsState.mu.Lock()
	metricsState.current = nil
	metricsState.mu.Unlock()
}

func TestInstall_NilMeterReturnsFalse(t *testing.T) {
	resetPackageMetrics(t)
	if Install(nil) {
		t.Error("Install(nil) returned true; want false (no-op)")
	}
	if CurrentMetrics() != nil {
		t.Error("CurrentMetrics non-nil after nil-meter install")
	}
}

func TestInstall_IsIdempotent(t *testing.T) {
	resetPackageMetrics(t)
	provider := sdkmetric.NewMeterProvider()
	defer func() { _ = provider.Shutdown(t.Context()) }()
	meter := provider.Meter("test")

	if !Install(meter) {
		t.Fatal("first Install returned false; want true")
	}
	first := CurrentMetrics()
	if first == nil {
		t.Fatal("CurrentMetrics nil after successful install")
	}
	if Install(meter) {
		t.Error("second Install returned true; want false (idempotency)")
	}
	if CurrentMetrics() != first {
		t.Error("second Install replaced the package-level Metrics; should preserve")
	}
}

func TestMetrics_NilReceiverIsNoop(t *testing.T) {
	t.Parallel()

	var m *Metrics
	// These must not panic.
	m.recordHit()
	m.recordMiss()
	m.recordInvalidation(5)
}

func TestMetrics_NewMetricsConstructAllInstruments(t *testing.T) {
	t.Parallel()

	provider := sdkmetric.NewMeterProvider()
	defer func() { _ = provider.Shutdown(t.Context()) }()
	m, err := NewMetrics(provider.Meter("test-direct"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	if m.hits == nil || m.misses == nil || m.invalidations == nil {
		t.Errorf("NewMetrics left nil instruments: hits=%v misses=%v invalidations=%v",
			m.hits == nil, m.misses == nil, m.invalidations == nil)
	}
	// Recording on a real meter must not error/panic.
	m.recordHit()
	m.recordMiss()
	m.recordInvalidation(3)
}

func TestCached_IntegratesWithRealMetrics(t *testing.T) {
	t.Parallel()

	provider := sdkmetric.NewMeterProvider()
	defer func() { _ = provider.Shutdown(t.Context()) }()
	m, err := NewMetrics(provider.Meter("test-cached"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	cache, err := NewCached(realInner(t, 1), 10, m)
	if err != nil {
		t.Fatalf("NewCached: %v", err)
	}
	ctx := t.Context()
	// Miss → Hit → Invalidate. Each call must not panic the
	// metrics path; the SDK does not surface the value back so we
	// just assert no panic + the cache itself behaves correctly.
	if _, err := cache.DelegationOf(ctx, "did:web:delegate-0"); err != nil {
		t.Fatalf("first get: %v", err)
	}
	if _, err := cache.DelegationOf(ctx, "did:web:delegate-0"); err != nil {
		t.Fatalf("second get (cache hit): %v", err)
	}
	if !cache.Invalidate("did:web:delegate-0") {
		t.Error("Invalidate returned false")
	}
}
