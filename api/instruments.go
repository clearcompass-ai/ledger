/*
FILE PATH:

	api/instruments.go

DESCRIPTION:

	D3 — Request-duration histogram for api/ HTTP handlers.

	    attesta_api_request_duration_seconds{route, method, status}

	Package-level instrument installed at boot from
	cmd/ledger/main.go via api.InstallRequestDurationHistogram.
	Same idiom as InstallErrorCounter: a global meter set up
	once, no threading through the handler tree.

KEY ARCHITECTURAL DECISIONS:
  - One histogram per request, recorded by an http.Handler
    middleware (RequestDurationMiddleware). Mounted at the
    top of the chain so it captures the full request budget
    including authn middleware.
  - Bounded label cardinality: route is the stdlib mux pattern
    (literal — not the URL). method is the verb (GET / POST /
    DELETE — 4 values typical). status is the HTTP code
    (~10 values). Total: ~30 routes × ~4 methods × ~10 statuses
    ≈ 1200 series. Well under Prometheus's recommended ceiling.
  - Buckets tuned for 1ms-10s admission p99: standard OTel
    defaults are wider; we use a custom set that lands the
    ledger's typical p99 mid-range (so the histogram has high
    resolution where SREs care most).
  - nil meter is a no-op. Tests + dev runs that don't enable
    metrics still pass through the middleware with zero overhead.
*/
package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// requestDurationState holds the package-level histogram. nil
// histogram is a no-op — the default at process start.
var requestDurationState struct {
	mu        sync.RWMutex
	histogram metric.Float64Histogram
}

// InstallRequestDurationHistogram wires the api request
// duration histogram from an OTel meter. Same idempotency
// contract as InstallErrorCounter. Returns true on first
// install, false on a re-install attempt.
//
// Suggested bucket boundaries (seconds): 1ms 5ms 10ms 25ms 50ms
// 100ms 250ms 500ms 1s 2.5s 5s 10s. Targets the ledger's typical
// admission p99 (sub-100ms) with high resolution while still
// capturing tail outliers up to 10s.
func InstallRequestDurationHistogram(meter metric.Meter) bool {
	if meter == nil {
		return false
	}
	requestDurationState.mu.Lock()
	defer requestDurationState.mu.Unlock()
	if requestDurationState.histogram != nil {
		return false
	}
	h, err := meter.Float64Histogram(
		"attesta_api_request_duration_seconds",
		metric.WithDescription("HTTP request duration broken down by route + method + status."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(
			0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
		),
	)
	if err != nil {
		return false
	}
	requestDurationState.histogram = h
	return true
}

// RequestDurationMiddleware wraps an http.Handler with the
// duration histogram. Mount at the outermost layer so authn +
// every other middleware is included in the measurement.
//
// route is the static label (typically the stdlib mux pattern,
// e.g., "/v1/entries" or "/v1/tree/inclusion/{seq}"). When the
// caller can't supply a static route (e.g., dynamic dispatch),
// pass r.URL.Path with the understanding that label cardinality
// will explode.
func RequestDurationMiddleware(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		rw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		recordRequestDuration(r.Context(), route, r.Method, rw.status, time.Since(t0))
	})
}

// resetRequestDurationForTest clears the package-level
// histogram so consecutive test runs don't observe a stale
// instance. Test-only escape hatch.
func resetRequestDurationForTest() {
	requestDurationState.mu.Lock()
	requestDurationState.histogram = nil
	requestDurationState.mu.Unlock()
}

// statusCapturingResponseWriter wraps http.ResponseWriter to
// capture the status code so the histogram can label by it.
// Default status is 200 if WriteHeader is never explicitly
// called (matches stdlib).
type statusCapturingResponseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (rw *statusCapturingResponseWriter) WriteHeader(status int) {
	if !rw.wrote {
		rw.status = status
		rw.wrote = true
	}
	rw.ResponseWriter.WriteHeader(status)
}

// recordRequestDuration records one observation. nil histogram
// is a no-op (default state when LEDGER_METRICS_ENABLE=false).
func recordRequestDuration(ctx context.Context, route, method string, status int, d time.Duration) {
	requestDurationState.mu.RLock()
	h := requestDurationState.histogram
	requestDurationState.mu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds(),
		metric.WithAttributes(
			attribute.String("route", route),
			attribute.String("method", method),
			attribute.String("status", strconv.Itoa(status)),
		),
	)
}
