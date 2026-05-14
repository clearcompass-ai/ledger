/*
FILE PATH:

	bench/admission/admission_load_test.go

DESCRIPTION:

	Correctness tests for the bench harness itself. The harness
	measures admission latency, but the harness's measurement is
	only meaningful if the harness is itself correct — every entry
	it generates verifies, the percentile arithmetic is right, the
	JSON round-trips, and the baseline-comparison helper computes
	percent deltas the way ops dashboards expect.

	These tests run under `go test`, NOT `go test -bench`, so they
	gate every CI build. The bench functions in
	admission_bench_test.go run only when explicitly invoked.
*/
package admission

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildMix_RejectsZero(t *testing.T) {
	t.Parallel()

	if _, err := BuildMix(0); err == nil {
		t.Error("BuildMix(0) succeeded; expected error")
	}
}

func TestBuildMix_GeneratesRequestedCount(t *testing.T) {
	t.Parallel()

	mix, err := BuildMix(9)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	if len(mix) != 9 {
		t.Errorf("len(mix)=%d, want 9", len(mix))
	}
	// Each entry has distinct DID + key (no caching dominance).
	seen := make(map[string]struct{}, 9)
	for _, e := range mix {
		if _, dup := seen[e.SignerDID]; dup {
			t.Errorf("duplicate SignerDID %q", e.SignerDID)
		}
		seen[e.SignerDID] = struct{}{}
		if e.PublicKey == nil {
			t.Errorf("entry %q has nil PublicKey", e.SignerDID)
		}
		if len(e.Signature) == 0 {
			t.Errorf("entry %q has empty Signature", e.SignerDID)
		}
	}
}

func TestBuildMix_CyclesThroughBuckets(t *testing.T) {
	t.Parallel()

	// 9 entries → 3 of each bucket exactly.
	mix, err := BuildMix(9)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	for i, entry := range mix {
		want := DefaultMix[i%len(DefaultMix)]
		got := len(entry.Entry.DomainPayload)
		if got != want.PayloadSize {
			t.Errorf("entry %d: payload size %d, want %d (bucket %s)",
				i, got, want.PayloadSize, want.Name)
		}
	}
}

func TestMapResolver_AnswersBuiltMix(t *testing.T) {
	t.Parallel()

	mix, err := BuildMix(3)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	resolver := NewMapResolver(mix)
	for _, entry := range mix {
		pub, err := resolver.ResolvePublicKey(context.Background(), entry.SignerDID)
		if err != nil {
			t.Errorf("resolver miss for %q: %v", entry.SignerDID, err)
		}
		if pub != entry.PublicKey {
			t.Errorf("resolver returned wrong pubkey for %q", entry.SignerDID)
		}
	}
}

func TestMapResolver_RejectsUnknownDID(t *testing.T) {
	t.Parallel()

	mix, err := BuildMix(1)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	resolver := NewMapResolver(mix)
	_, err = resolver.ResolvePublicKey(context.Background(), "did:web:not.in.mix")
	if err == nil {
		t.Error("resolver accepted unknown DID; expected error")
	}
}

func TestMeasureVerify_AllEntriesVerify(t *testing.T) {
	t.Parallel()

	mix, err := BuildMix(6)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	report, err := MeasureVerify(context.Background(), mix, 60)
	if err != nil {
		t.Fatalf("MeasureVerify: %v", err)
	}
	if report.Iterations != 60 {
		t.Errorf("Iterations=%d, want 60", report.Iterations)
	}
	if report.MixVersion != BaselineMixVersion {
		t.Errorf("MixVersion=%d, want %d", report.MixVersion, BaselineMixVersion)
	}
	// Per-bucket counts cover all three buckets when iterations
	// span every bucket.
	for _, b := range DefaultMix {
		if report.PerBucket[b.Name] == 0 {
			t.Errorf("bucket %q got zero iterations", b.Name)
		}
	}
	// Sanity: ordered percentiles.
	if !(report.P50Ns <= report.P95Ns && report.P95Ns <= report.P99Ns && report.P99Ns <= report.MaxNs) {
		t.Errorf("percentiles not monotonic: p50=%d p95=%d p99=%d max=%d",
			report.P50Ns, report.P95Ns, report.P99Ns, report.MaxNs)
	}
}

func TestMeasureVerify_RejectsTooFewIterations(t *testing.T) {
	t.Parallel()

	mix, err := BuildMix(10)
	if err != nil {
		t.Fatalf("BuildMix: %v", err)
	}
	if _, err := MeasureVerify(context.Background(), mix, 5); err == nil {
		t.Error("MeasureVerify accepted iterations < len(mix); expected error")
	}
}

func TestPercentDelta_ZeroBaseline(t *testing.T) {
	t.Parallel()

	if got := PercentDelta(0, 100); got != 0 {
		t.Errorf("PercentDelta(0, 100)=%v, want 0", got)
	}
}

func TestPercentDelta_RegressionAndImprovement(t *testing.T) {
	t.Parallel()

	if got := PercentDelta(100, 110); !approx(got, 10.0, 0.001) {
		t.Errorf("PercentDelta(100, 110)=%v, want 10", got)
	}
	if got := PercentDelta(100, 90); !approx(got, -10.0, 0.001) {
		t.Errorf("PercentDelta(100, 90)=%v, want -10", got)
	}
}

func TestSaveAndLoadReport_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	original := LatencyReport{
		MixVersion: BaselineMixVersion,
		Iterations: 1000,
		MeanNs:     50000,
		P50Ns:      48000,
		P95Ns:      75000,
		P99Ns:      120000,
		P999Ns:     250000,
		MaxNs:      300000,
		PerBucket:  map[string]int{"small": 333, "medium": 333, "large": 334},
		CapturedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := SaveReport(path, original); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	roundTripped, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if roundTripped.P50Ns != original.P50Ns {
		t.Errorf("P50Ns mismatch: got %d, want %d", roundTripped.P50Ns, original.P50Ns)
	}
	if roundTripped.MixVersion != original.MixVersion {
		t.Errorf("MixVersion mismatch: got %d, want %d", roundTripped.MixVersion, original.MixVersion)
	}
}

func TestLoadBaseline_MissingFile(t *testing.T) {
	t.Parallel()

	if _, err := LoadBaseline("/nonexistent/baseline.json"); err == nil {
		t.Error("LoadBaseline accepted missing file; expected error")
	}
}

func TestLoadBaseline_MalformedJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := LoadBaseline(path); err == nil {
		t.Error("LoadBaseline accepted malformed JSON; expected error")
	}
}

func TestCompareToBaseline_ShapeMatchesPercentiles(t *testing.T) {
	t.Parallel()

	baseline := LatencyReport{P50Ns: 100, P95Ns: 200, P99Ns: 400, P999Ns: 800}
	current := LatencyReport{P50Ns: 110, P95Ns: 220, P99Ns: 360, P999Ns: 800}
	rows := CompareToBaseline(baseline, current)
	if len(rows) != 4 {
		t.Fatalf("len(rows)=%d, want 4", len(rows))
	}
	wantNames := []string{"p50", "p95", "p99", "p999"}
	wantDeltas := []float64{10.0, 10.0, -10.0, 0.0}
	for i, row := range rows {
		if row.Name != wantNames[i] {
			t.Errorf("row %d: Name=%q, want %q", i, row.Name, wantNames[i])
		}
		if !approx(row.DeltaPct, wantDeltas[i], 0.01) {
			t.Errorf("row %d: DeltaPct=%v, want %v", i, row.DeltaPct, wantDeltas[i])
		}
	}
}

func TestSaveReport_JSONStructureStable(t *testing.T) {
	t.Parallel()

	// The on-disk shape is consumed by external tooling
	// (dashboards, comparison scripts); pinning the field names
	// here surfaces an accidental rename as a test failure rather
	// than a silent dashboard break.
	report := LatencyReport{
		MixVersion: 1,
		P50Ns:      100,
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantedKeys := []string{
		`"mix_version"`, `"iterations"`, `"total_ns"`, `"mean_ns"`,
		`"p50_ns"`, `"p95_ns"`, `"p99_ns"`, `"p999_ns"`,
		`"max_ns"`, `"per_bucket_count"`, `"captured_at"`,
	}
	js := string(data)
	for _, k := range wantedKeys {
		if !contains(js, k) {
			t.Errorf("expected key %s missing from JSON: %s", k, js)
		}
	}
}

func approx(a, b, eps float64) bool { return math.Abs(a-b) < eps }

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
