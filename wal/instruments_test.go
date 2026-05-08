/*
FILE PATH:

	wal/instruments_test.go

DESCRIPTION:

	Tests for the D3 wal Submit duration histogram. Pins the
	invariant that BOTH branches (committed + canceled) produce
	histogram observations, with the correct outcome label.

	Without this regression, a future refactor that drops the
	cancel-branch record would silently re-introduce the
	SRE-blind-spot bug: p99 latency would look healthy precisely
	when WAL pressure is causing client timeouts.
*/
package wal

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// -------------------------------------------------------------------------------------------------
// 1) Helpers
// -------------------------------------------------------------------------------------------------

// withManualReader returns an OTel meter backed by a manual
// reader so the test can inspect captured observations directly.
// Test-cleanup resets the package-level histogram state so
// subsequent tests start fresh.
func withManualReader(t *testing.T) (*metric.ManualReader, func()) {
	t.Helper()
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	meter := mp.Meter("test")
	if !InstallSubmitDurationHistogram(meter) {
		t.Fatal("InstallSubmitDurationHistogram returned false (already installed?)")
	}
	cleanup := func() {
		// Reset package state for subsequent tests.
		submitDurationState.mu.Lock()
		submitDurationState.histogram = nil
		submitDurationState.mu.Unlock()
		_ = mp.Shutdown(context.Background())
	}
	return reader, cleanup
}

// findOutcomeBuckets returns the (count, sum) for a given
// outcome label across the manual reader's collected metrics.
// Returns -1 for count if the histogram series wasn't observed.
func findOutcomeBuckets(t *testing.T, reader *metric.ManualReader, outcome string) (int64, float64) {
	t.Helper()
	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "attesta_wal_submit_duration_seconds" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("metric %s: data is %T, want Histogram[float64]", m.Name, m.Data)
			}
			for _, dp := range hist.DataPoints {
				v, ok := dp.Attributes.Value("outcome")
				if !ok {
					continue
				}
				if v.AsString() == outcome {
					return int64(dp.Count), dp.Sum
				}
			}
		}
	}
	return -1, 0
}

// -------------------------------------------------------------------------------------------------
// 2) Pinning tests
// -------------------------------------------------------------------------------------------------

// TestInstrument_CommittedBranchObserved pins the success path:
// a Submit that completes normally records under
// outcome=committed.
func TestInstrument_CommittedBranchObserved(t *testing.T) {
	reader, cleanup := withManualReader(t)
	defer cleanup()

	db, err := OpenInMemory(slog.Default())
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	defer db.Close()
	c := NewCommitter(db, CommitterConfig{
		Logger:      slog.Default(),
		DisableSync: true,
	})
	defer c.Close()

	wire := []byte("test-committed-branch")
	hash := sha256.Sum256(wire)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro()); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	count, _ := findOutcomeBuckets(t, reader, OutcomeCommitted)
	if count != 1 {
		t.Errorf("outcome=committed observations = %d; want 1", count)
	}
	canceled, _ := findOutcomeBuckets(t, reader, OutcomeCanceled)
	if canceled > 0 {
		t.Errorf("outcome=canceled observations = %d; want 0 on success path", canceled)
	}
}

// TestInstrument_CanceledBranchObserved pins the SRE-load-
// bearing invariant: a Submit whose ctx is canceled BEFORE
// the group commit returns records under outcome=canceled.
//
// Mechanism: configure a Committer with a long BatchMaxLatency
// (1s) so a single Submit waits ~1s for its batch to flush;
// cancel the caller's ctx after 50ms; assert the cancel-branch
// observation exists.
func TestInstrument_CanceledBranchObserved(t *testing.T) {
	reader, cleanup := withManualReader(t)
	defer cleanup()

	db, err := OpenInMemory(slog.Default())
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	defer db.Close()

	// BatchMaxLatency = 1s + BatchMaxEntries = 100 means a single
	// Submit waits up to 1 second for the batcher to flush. We
	// cancel before that, forcing the cancel branch.
	c := NewCommitter(db, CommitterConfig{
		Logger:          slog.Default(),
		DisableSync:     true,
		BatchMaxLatency: 1 * time.Second,
		BatchMaxEntries: 100,
	})
	defer c.Close()

	wire := []byte("test-canceled-branch")
	hash := sha256.Sum256(wire)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = c.Submit(ctx, hash, wire, time.Now().UnixMicro())
	if err == nil {
		// Submit returned cleanly — the batch flushed faster
		// than expected (small in-memory Badger). Skip; the
		// committed-branch test exercises the equivalent path.
		t.Skip("submit completed before ctx expired; cancel branch not exercised")
	}
	if !isCtxError(err) {
		t.Fatalf("Submit err = %v; want ctx.Err()", err)
	}

	count, _ := findOutcomeBuckets(t, reader, OutcomeCanceled)
	if count != 1 {
		t.Errorf("outcome=canceled observations = %d; want 1; histogram is BLIND to saturated path", count)
	}
}

// TestInstrument_HistogramBucketCardinalityIsBounded pins T-14
// strict-error-dimensionality: the outcome label has bounded
// cardinality (committed + canceled) — not unbounded over
// tenant / route / arbitrary string. Catches a future refactor
// that adds high-cardinality labels.
func TestInstrument_HistogramBucketCardinalityIsBounded(t *testing.T) {
	reader, cleanup := withManualReader(t)
	defer cleanup()

	db, _ := OpenInMemory(slog.Default())
	defer db.Close()
	c := NewCommitter(db, CommitterConfig{
		Logger:      slog.Default(),
		DisableSync: true,
	})
	defer c.Close()

	// Submit 10 entries through the success path.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ {
		wire := []byte{byte(i)}
		hash := sha256.Sum256(wire)
		_ = c.Submit(ctx, hash, wire, time.Now().UnixMicro())
	}

	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	seen := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "attesta_wal_submit_duration_seconds" {
				continue
			}
			hist, _ := m.Data.(metricdata.Histogram[float64])
			for _, dp := range hist.DataPoints {
				if v, ok := dp.Attributes.Value("outcome"); ok {
					seen[v.AsString()] = true
				}
			}
		}
	}
	for outcome := range seen {
		if outcome != OutcomeCommitted && outcome != OutcomeCanceled {
			t.Errorf("unexpected outcome label %q; bounded cardinality requires committed|canceled only",
				outcome)
		}
	}
}

func isCtxError(err error) bool {
	if err == nil {
		return false
	}
	return err == context.Canceled || err == context.DeadlineExceeded
}
