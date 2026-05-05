/*
FILE PATH: api/errors_test.go

Tests the PT-6 wiring:

  - InstallErrorCounter is idempotent on the same meter; a second
    install attempt is rejected (not silently overwritten).
  - InstallErrorCounter(nil) is a safe no-op.
  - writeTypedError writes the JSON body AND increments the OTel
    counter with the correct (error_class, http_status) attributes.
  - writeTypedJSONError mirrors writeTypedError for the alternate
    body shape used by escrow_override.
  - With the package-level counter unset, the increment is a
    no-op (no panic on dev/test path).

The counter assertion uses an in-process manual reader from
go.opentelemetry.io/otel/sdk/metric — no Prometheus scrape, no
HTTP plumbing. Hermetic.
*/
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/clearcompass-ai/ledger/apitypes"
)

func newManualReader(t *testing.T) (*metric.MeterProvider, *metric.ManualReader) {
	t.Helper()
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	return mp, reader
}

// collectErrorCounter returns the aggregated count of
// attesta_api_errors_total observations matching the supplied
// (error_class, http_status) tuple. Returns 0 when no match is
// found.
func collectErrorCounter(
	t *testing.T,
	reader *metric.ManualReader,
	wantClass string,
	wantStatus int,
) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "attesta_api_errors_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q data type = %T, want Sum[int64]",
					m.Name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				gotClass, _ := dp.Attributes.Value(attribute.Key("error_class"))
				gotStatus, _ := dp.Attributes.Value(attribute.Key("http_status"))
				if gotClass.AsString() == wantClass && int(gotStatus.AsInt64()) == wantStatus {
					return dp.Value
				}
			}
		}
	}
	return 0
}

func TestInstallErrorCounter_NilMeterIsNoOp(t *testing.T) {
	resetErrorCounterForTest()
	if got := InstallErrorCounter(nil); got {
		t.Error("InstallErrorCounter(nil) returned true; want false")
	}
	// Subsequent Inc must not panic.
	incErrorCounter(context.Background(), apitypes.ErrorClassMalformedJSON, 400)
}

func TestInstallErrorCounter_Idempotent(t *testing.T) {
	resetErrorCounterForTest()
	mp, _ := newManualReader(t)
	meter := mp.Meter("test")
	if got := InstallErrorCounter(meter); !got {
		t.Fatal("first install should succeed")
	}
	// Second install must be rejected (counter already wired).
	if got := InstallErrorCounter(meter); got {
		t.Error("second install should be a no-op (returned true)")
	}
}

func TestWriteTypedError_IncrementsCounter(t *testing.T) {
	resetErrorCounterForTest()
	mp, reader := newManualReader(t)
	meter := mp.Meter("test")
	if !InstallErrorCounter(meter) {
		t.Fatal("install failed")
	}

	rr := httptest.NewRecorder()
	writeTypedError(context.Background(), rr,
		apitypes.ErrorClassMalformedJSON, http.StatusBadRequest, "bad json")

	// Body shape preserved: {"error":"bad json"}.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "bad json" {
		t.Errorf("error msg = %q, want %q", body["error"], "bad json")
	}

	// Counter incremented with the right attributes.
	if got := collectErrorCounter(t, reader, "malformed_json", 400); got != 1 {
		t.Errorf("counter[malformed_json,400] = %d, want 1", got)
	}
	// And NOT incremented for an unrelated tuple.
	if got := collectErrorCounter(t, reader, "signature_invalid", 401); got != 0 {
		t.Errorf("unrelated counter = %d, want 0", got)
	}
}

func TestWriteTypedError_DistinctClassesIncrementSeparately(t *testing.T) {
	resetErrorCounterForTest()
	mp, reader := newManualReader(t)
	if !InstallErrorCounter(mp.Meter("test")) {
		t.Fatal("install failed")
	}

	// Hostile-flavor + network-noise — separate dimensions.
	for i := 0; i < 3; i++ {
		writeTypedError(context.Background(), httptest.NewRecorder(),
			apitypes.ErrorClassSignatureInvalid, http.StatusUnauthorized, "x")
	}
	for i := 0; i < 5; i++ {
		writeTypedError(context.Background(), httptest.NewRecorder(),
			apitypes.ErrorClassMalformedJSON, http.StatusBadRequest, "y")
	}

	if got := collectErrorCounter(t, reader, "signature_invalid", 401); got != 3 {
		t.Errorf("signature_invalid count = %d, want 3", got)
	}
	if got := collectErrorCounter(t, reader, "malformed_json", 400); got != 5 {
		t.Errorf("malformed_json count = %d, want 5", got)
	}
}

func TestWriteTypedError_NoCounterInstalledIsNoOp(t *testing.T) {
	resetErrorCounterForTest()
	// Explicitly no InstallErrorCounter call.
	rr := httptest.NewRecorder()
	// Must not panic.
	writeTypedError(context.Background(), rr,
		apitypes.ErrorClassWALBackpressure, http.StatusServiceUnavailable, "queue full")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestWriteTypedJSONError_IncrementsCounter(t *testing.T) {
	resetErrorCounterForTest()
	mp, reader := newManualReader(t)
	if !InstallErrorCounter(mp.Meter("test")) {
		t.Fatal("install failed")
	}

	rr := httptest.NewRecorder()
	writeTypedJSONError(context.Background(), rr,
		apitypes.ErrorClassEscrowOverrideFailed, http.StatusBadGateway, "peer unreachable")

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
	if got := collectErrorCounter(t, reader, "escrow_override_failed", 502); got != 1 {
		t.Errorf("escrow_override_failed count = %d, want 1", got)
	}
}
