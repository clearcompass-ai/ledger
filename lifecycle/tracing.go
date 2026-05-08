/*
FILE PATH:

	lifecycle/tracing.go

DESCRIPTION:

	D2 — OpenTelemetry tracing setup. Builds a TracerProvider
	based on LEDGER_OTLP_TRACES_ENDPOINT:

	    unset → NoOp tracer (zero overhead, default for laptop dev)
	    "stdout" → stdouttrace (single-line spans to stderr; debug)
	    "<host:port>" → OTLP HTTP exporter to that endpoint

	The supervisor's shutdownChain calls the returned Shutdown
	func at the end of shutdown so spans flush before OTel meter.

KEY ARCHITECTURAL DECISIONS:
  - Default NoOp. A laptop / unit-test / one-shot tool runs
    with zero tracing overhead and zero new dependencies on
    the wire path.
  - "stdout" sink for the run-local.sh workflow: administrators
    iterating on the ledger see spans in their terminal
    without standing up an OTel collector.
  - OTLP HTTP (not gRPC) because the HTTP exporter has lighter
    transitive deps and serves Jaeger / Tempo / Honeycomb /
    OTel collectors equally well. The collector / Jaeger can
    receive HTTP/protobuf at /v1/traces.
  - Resource attributes mirror what the meter provider sets
    (service.name, service.version, deployment.environment)
    so traces and metrics align in dashboards.

OVERVIEW:

	cmd/ledger/main.go calls:

	    tp, shutdownTracer, err := lifecycle.NewTracerProvider(
	        lifecycle.TracerProviderConfig{
	            ServiceName:    "ledger",
	            ServiceVersion: cfg.ServiceVersion,
	            Environment:    cfg.MetricsEnvironment,
	            OTLPEndpoint:   cfg.OTLPTracesEndpoint,
	        })
	    if err != nil { ... }
	    otel.SetTracerProvider(tp)
	    // register shutdownTracer in the shutdownChain at the end

	Then any package can call otel.Tracer("name").Start(ctx, ...)
	to emit spans. NoOp provider produces no-op spans (allocations
	are minimal but non-zero — call-site nil-check pattern is
	still appropriate for the very-hot admission thread).

KEY DEPENDENCIES:
  - go.opentelemetry.io/otel/sdk/trace: TracerProvider impl
  - go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp:
    production OTLP HTTP exporter
  - go.opentelemetry.io/otel/exporters/stdout/stdouttrace:
    laptop-dev sink
*/
package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// -------------------------------------------------------------------------------------------------
// 1) Config
// -------------------------------------------------------------------------------------------------

// TracerProviderConfig configures NewTracerProvider.
type TracerProviderConfig struct {
	// ServiceName is the OTel resource service.name attribute.
	// Required; defaults to "ledger" when empty.
	ServiceName string

	// ServiceVersion is the OTel resource service.version
	// attribute. Defaults to "dev" when empty.
	ServiceVersion string

	// Environment is the OTel resource deployment.environment
	// attribute. Defaults to "dev" when empty.
	Environment string

	// OTLPEndpoint controls the exporter:
	//   "" / unset           → NoOp tracer (zero overhead)
	//   "stdout"             → stdouttrace (debug; spans to stderr)
	//   "host:port" or URL   → OTLP HTTP exporter to that endpoint
	//
	// For OTLP, "localhost:4318" is the default OTel-collector port.
	// HTTPS endpoints are accepted ("https://otel.example.com").
	OTLPEndpoint string

	// SampleRatio controls trace sampling. 0 → never sample;
	// 1.0 → always sample; default 1.0 for OTLP/stdout.
	SampleRatio float64
}

// -------------------------------------------------------------------------------------------------
// 2) Public API
// -------------------------------------------------------------------------------------------------

// NewTracerProvider returns a TracerProvider + a Shutdown
// closure suitable for the shutdownChain. Always returns a
// non-nil provider (NoOp when no exporter is configured), so
// callers can safely call otel.SetTracerProvider on the result.
//
// The Shutdown closure flushes pending spans + closes the
// exporter. Bound to a 5-second budget by the shutdownChain step.
func NewTracerProvider(cfg TracerProviderConfig) (trace.TracerProvider, func(ctx context.Context) error, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "ledger"
	}
	if cfg.ServiceVersion == "" {
		cfg.ServiceVersion = "dev"
	}
	if cfg.Environment == "" {
		cfg.Environment = "dev"
	}
	if cfg.SampleRatio == 0 {
		cfg.SampleRatio = 1.0
	}

	// NoOp path — zero overhead default.
	if cfg.OTLPEndpoint == "" {
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle/tracing: resource: %w", err)
	}

	var exporter sdktrace.SpanExporter
	switch cfg.OTLPEndpoint {
	case "stdout":
		exporter, err = stdouttrace.New(
			stdouttrace.WithPrettyPrint(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("lifecycle/tracing: stdout exporter: %w", err)
		}
	default:
		opts := []otlptracehttp.Option{
			otlptracehttp.WithTimeout(10 * time.Second),
		}
		// Strip http(s):// prefix; OTLP HTTP exporter accepts a
		// host:port and adds the scheme based on
		// WithInsecure / no-WithInsecure.
		ep := cfg.OTLPEndpoint
		insecure := false
		if strings.HasPrefix(ep, "http://") {
			ep = strings.TrimPrefix(ep, "http://")
			insecure = true
		} else if strings.HasPrefix(ep, "https://") {
			ep = strings.TrimPrefix(ep, "https://")
		}
		opts = append(opts, otlptracehttp.WithEndpoint(ep))
		if insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptrace.New(
			context.Background(),
			otlptracehttp.NewClient(opts...),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("lifecycle/tracing: otlp http exporter (%s): %w", cfg.OTLPEndpoint, err)
		}
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRatio)),
	)

	shutdown := func(ctx context.Context) error {
		return tp.Shutdown(ctx)
	}
	return tp, shutdown, nil
}
