/*
FILE PATH:

	bench/admission/admission_bench_test.go

DESCRIPTION:

	Benchmark functions that capture and report the admission-path
	SLA. Run via:

	    go test -bench=. -benchtime=10s ./bench/admission/...

	The output reports ns/op (the standard Go bench number) AND
	custom p50/p95/p99/p999 metrics via b.ReportMetric — those are
	the SLA dimensions every gate PR (PR-C through PR-F) MUST be
	compared against.

	A separate "capture-baseline" entry point (TestMain-driven via
	the LEDGER_BENCH_CAPTURE_BASELINE env var) writes
	bench/admission/baseline.json so the committed baseline can be
	regenerated atomically without manually copy-pasting numbers.
*/
package admission

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkVerify_DefaultMix is the load-bearing SLA bench. PR-C
// through PR-F MUST run this on their branch and compare the
// reported p99/p999 to the baseline; a regression beyond budget
// fails the gate's CI.
//
// Reports the standard ns/op (Go's mean) PLUS p50/p95/p99/p999
// custom metrics. Use `go test -bench=BenchmarkVerify_DefaultMix
// -benchtime=10s` for stable percentiles; shorter benchtime
// produces noisy tails.
func BenchmarkVerify_DefaultMix(b *testing.B) {
	mix, err := BuildMix(60)
	if err != nil {
		b.Fatalf("BuildMix: %v", err)
	}
	report, err := MeasureVerify(context.Background(), mix, b.N)
	if err != nil {
		b.Fatalf("MeasureVerify: %v", err)
	}
	// Custom metrics surface the SLA dimensions in the standard
	// `go test -bench` output. The "ns/op" metric is replaced by
	// the per-op mean we compute ourselves so the two columns
	// don't disagree about the same number.
	b.ReportMetric(float64(report.MeanNs), "ns/op")
	b.ReportMetric(float64(report.P50Ns), "p50_ns/op")
	b.ReportMetric(float64(report.P95Ns), "p95_ns/op")
	b.ReportMetric(float64(report.P99Ns), "p99_ns/op")
	b.ReportMetric(float64(report.P999Ns), "p999_ns/op")
}

// BenchmarkVerify_PerBucket runs one sub-benchmark per size bucket
// so per-size cost can be inspected independently. Useful when
// a regression is concentrated in one bucket (e.g., a hashing
// inefficiency that scales with payload size).
func BenchmarkVerify_PerBucket(b *testing.B) {
	for _, bucket := range DefaultMix {
		bucket := bucket
		b.Run(bucket.Name, func(b *testing.B) {
			mix := []SignedEntry{}
			signed, err := buildSignedEntry(0, bucket)
			if err != nil {
				b.Fatalf("buildSignedEntry: %v", err)
			}
			mix = append(mix, signed)
			report, err := MeasureVerify(context.Background(), mix, b.N)
			if err != nil {
				b.Fatalf("MeasureVerify: %v", err)
			}
			b.ReportMetric(float64(report.MeanNs), "ns/op")
			b.ReportMetric(float64(report.P50Ns), "p50_ns/op")
			b.ReportMetric(float64(report.P99Ns), "p99_ns/op")
		})
	}
}

// TestCaptureBaseline writes a fresh baseline.json when the
// LEDGER_BENCH_CAPTURE_BASELINE env var is set. Run as:
//
//	LEDGER_BENCH_CAPTURE_BASELINE=1 go test -count=1 \
//	    -run TestCaptureBaseline ./bench/admission/...
//
// Without the env var, the test no-ops so the regular `go test`
// flow stays fast (the baseline capture takes O(seconds) on
// laptop-class hardware).
//
// Why a Test, not a Benchmark: the capture wants a deterministic
// iteration count (10000) so repeated invocations produce
// directly-comparable numbers. b.N is auto-tuned by `go test
// -benchtime`, which makes it the wrong shape for a committed
// baseline.
func TestCaptureBaseline(t *testing.T) {
	if os.Getenv("LEDGER_BENCH_CAPTURE_BASELINE") == "" {
		t.Skip("set LEDGER_BENCH_CAPTURE_BASELINE=1 to regenerate baseline.json")
	}
	const iterations = 10000
	mix, err := BuildMix(60)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	report, err := MeasureVerify(context.Background(), mix, iterations)
	if err != nil {
		t.Fatalf("MeasureVerify: %v", err)
	}
	report.Description = "PR-A baseline: legacy single-sig admission path " +
		"(signatures.VerifyEntry). Captured before any gate is enabled."

	// Write to the committed baseline path under repo root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	target := filepath.Join(wd, "baseline.json")
	if err := SaveReport(target, report); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	t.Logf("baseline captured: p50=%dns p95=%dns p99=%dns p999=%dns max=%dns iterations=%d",
		report.P50Ns, report.P95Ns, report.P99Ns, report.P999Ns, report.MaxNs, report.Iterations)
}

// TestBaselineFile_Present pins the existence of baseline.json.
// PR-A's acceptance criterion is "baseline numbers committed";
// this test fails if the baseline file is deleted or missing.
//
// The file's CONTENTS aren't asserted — captured numbers vary by
// hardware. The presence is what's load-bearing for downstream
// gates' CompareToBaseline calls.
func TestBaselineFile_Present(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	path := filepath.Join(wd, "baseline.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("baseline.json missing at %s: %v\n"+
			"Run: LEDGER_BENCH_CAPTURE_BASELINE=1 go test -count=1 "+
			"-run TestCaptureBaseline ./bench/admission/...", path, err)
	}
	report, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if report.Iterations == 0 {
		t.Error("baseline.json has Iterations=0; did capture succeed?")
	}
	if report.MixVersion != BaselineMixVersion {
		t.Errorf("baseline mix_version=%d, current=%d; capture is stale",
			report.MixVersion, BaselineMixVersion)
	}
}
