/*
FILE PATH: api/errors.go

PT-6 — A10 (Strict Error Dimensionality) + P10 (SRE-grade
Observability):

  Every api/ error-emission site funnels through writeTypedError,
  which increments a single OpenTelemetry Int64Counter with two
  bounded-cardinality attributes (error_class + http_status) AND
  writes the JSON error body. SREs distinguish hostile traffic
  (signature_invalid) from network noise (malformed_json) at
  alert time without parsing log lines.

# PACKAGE-LEVEL COUNTER

The counter is a package-level variable initialized once at boot
via api.InstallErrorCounter(meter). This mirrors OTel's own
idioms (otel.GetMeterProvider() is global) and avoids threading
the counter through 9 Deps structs across 7 handler files.

  - Default: an unset counter is a NO-OP. Tests pass; api/ never
    panics on missing metrics. OPERATOR_METRICS_ENABLE=true wires
    a real counter at boot.
  - Idempotent install: re-calling InstallErrorCounter with the
    same meter is a no-op. A second meter (operationally a bug)
    is rejected with a logged warning so the original wiring
    isn't silently overwritten.

# CARDINALITY BUDGET

  ErrorClass values:    ~30 (apitypes.ErrorClass enum)
  HTTP statuses:        ~10 (4xx + 5xx + 404 in practice)
  Total time-series:    ~30 × ~10 = ~300

  Well under Prometheus's recommended ~10k/metric ceiling.
*/
package api

import (
	"context"
	"net/http"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// Attribute keys. Unexported; the only writers are inside this
// file.
const (
	attrErrorClass = "error_class"
	attrHTTPStatus = "http_status"
)

// errorCounterState holds the package-level OTel counter. nil
// counter is a no-op — the default at process start.
var errorCounterState struct {
	mu      sync.RWMutex
	counter metric.Int64Counter
}

// InstallErrorCounter wires the package-level error counter
// from an OTel meter. Idempotent on the same meter; safe to
// call from cmd/operator/main.go after MeterProvider construction.
//
// nil meter is honored — the counter remains a no-op. Returns
// false when a counter is already installed (operator wiring
// bug — re-install is rejected to keep the metric stable across
// scrape windows).
func InstallErrorCounter(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	errorCounterState.mu.Lock()
	defer errorCounterState.mu.Unlock()
	if errorCounterState.counter != nil {
		return false
	}
	c, err := meter.Int64Counter(
		"attesta_api_errors_total",
		metric.WithDescription(
			"Count of api/ errors emitted via writeError, broken down by typed error_class + http_status."),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Downgrade silently rather than crash: a metric
		// registration failure should never take the operator
		// offline. The counter stays a no-op; the operator
		// logs at the construction site.
		return false
	}
	errorCounterState.counter = c
	return true
}

// resetErrorCounterForTest is a test-only escape hatch that
// clears the package-level counter so consecutive test runs
// don't observe a stale instance. Lives next to InstallErrorCounter
// because both touch the same locked state; visibility limited
// to this package.
func resetErrorCounterForTest() {
	errorCounterState.mu.Lock()
	errorCounterState.counter = nil
	errorCounterState.mu.Unlock()
}

// incErrorCounter increments the package-level counter for one
// (errorClass, httpStatus) observation. Safe to call
// concurrently; nil counter is a no-op.
func incErrorCounter(ctx context.Context, class apitypes.ErrorClass, httpStatus int) {
	errorCounterState.mu.RLock()
	c := errorCounterState.counter
	errorCounterState.mu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(attrErrorClass, class.String()),
			attribute.Int(attrHTTPStatus, httpStatus),
		))
}

// writeTypedError centralizes the error response + counter
// emission. Every api/ handler funnels error responses through
// this path so the metric increment is guaranteed.
//
// Mirrors writeError(w, status, msg) but adds:
//   - ctx for OTel span attribution
//   - class for the typed dimension
func writeTypedError(
	ctx context.Context,
	w http.ResponseWriter,
	class apitypes.ErrorClass,
	status int,
	msg string,
) {
	incErrorCounter(ctx, class, status)
	writeError(w, status, msg)
}

// writeTypedJSONError mirrors writeJSONError (used by
// api/escrow_override.go which already emits a slightly
// different body shape). Same metric increment.
func writeTypedJSONError(
	ctx context.Context,
	w http.ResponseWriter,
	class apitypes.ErrorClass,
	status int,
	msg string,
) {
	incErrorCounter(ctx, class, status)
	writeJSONError(w, status, msg)
}
