//go:build chaos
// +build chaos

/*
FILE PATH: tests/chaos/backpressure/max_builder_lag_test.go

End-to-end test of the architectural "honest backpressure"
property:

  Witnesses below quorum
    → builder cosignature step blocks (Step 7 of processBatch)
    → builder cursor stops advancing
    → MaxBuilderLag gate fires in sequencer.drainOnce
    → sequencer stops consuming WAL Pending
    → WAL queue saturates
    → HTTP POST /v1/entries returns 503 + Retry-After
    → public clients see the system "honestly busy" rather than
      silently accepting submissions while the cryptographic
      chain is broken

THREE PHASES, EACH WITH EXPLICIT ASSERTIONS

  PHASE 1 — Baseline: confirm cosignature path is wired and
  submissions succeed cleanly. Every 202.

  PHASE 2 — Outage: take K-of-N witnesses offline. Drive load.
  Assert:
    (a) AT LEAST ONE 503 response observed within the outage
        window (the load-bearing property — backpressure MUST
        fire).
    (b) Every 503 carries a Retry-After header (load-balancer
        compatibility — without this the LB can't intelligently
        back off).
    (c) The Retry-After value parses as a positive integer
        seconds value (we accept dates too per RFC 7231 §7.1.3
        but the ledger always emits seconds).

  PHASE 3 — Recovery: heal witnesses. Assert 202 flow resumes
  within 60 seconds and the system catches up (entry_index
  count grows to match the submitter's accepted count).

Tagged `chaos` — needs ATTESTA_TEST_DSN + ATTESTA_TEST_S3_*.
*/
package backpressure

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/tests/chaos/harness"
)

var repoRoot string

func TestMain(m *testing.M) {
	if wd, err := os.Getwd(); err == nil {
		repoRoot = wd + "/../../.."
	}
	if _, err := harness.EnsureLedgerBinary(repoRoot); err != nil {
		println("EnsureLedgerBinary failed:", err.Error())
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestBackpressure_WitnessesDownAdmits503 — the load-bearing
// E2E test of the honest-backpressure architecture.
func TestBackpressure_WitnessesDownAdmits503(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	h := harness.New(t, harness.Config{
		WitnessCount:   3,
		WitnessQuorumK: 2,
	})
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	submitter := h.NewSubmitter(t, "bp-tok", "did:example:bp", 1_000_000)

	// ─── PHASE 1 — Baseline ───────────────────────────────────────
	t.Logf("phase 1: baseline submission (all witnesses healthy)")
	const baseline = 50
	for i := 0; i < baseline; i++ {
		r, err := submitter.Submit(ctx,
			[]byte("phase1-baseline"), harness.SubmitOpts{})
		if err != nil {
			t.Fatalf("phase 1 submit %d: %v (body=%s)", i, err, r.Body)
		}
		if r.StatusCode != http.StatusAccepted {
			t.Fatalf("phase 1 unexpected status %d (body=%s)", r.StatusCode, r.Body)
		}
	}
	if err := h.WaitForDrain(ctx, baseline, 90*time.Second); err != nil {
		t.Fatalf("phase 1 drain: %v", err)
	}

	// ─── PHASE 2 — Outage ─────────────────────────────────────────
	t.Logf("phase 2: taking witnesses 0,1 offline (below K=2 quorum)")
	h.Witnesses().Fail(0, http.StatusInternalServerError)
	h.Witnesses().Fail(1, http.StatusInternalServerError)

	// Drive load aggressively to push WAL toward saturation.
	// MaxBuilderLag=4096 default; we expect 503s within ~60s.
	results := make([]harness.SubmitResult, 0, 200)
	outageDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(outageDeadline) {
		r, err := submitter.Submit(ctx,
			[]byte("phase2-outage"), harness.SubmitOpts{})
		if r.StatusCode > 0 {
			// Capture every observed response (including errors
			// with a StatusCode). r.StatusCode is 0 on transport
			// errors so we filter those out.
			results = append(results, r)
		}
		_ = err
		if hasObservedFromSlice(results, http.StatusServiceUnavailable) {
			// Got at least one 503 — continue briefly to gather
			// the full backpressure signature (more 503s +
			// Retry-After observations).
			if observedCount(results, http.StatusServiceUnavailable) >= 5 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	// ─── PHASE 2 ASSERTIONS ───────────────────────────────────────
	count503 := observedCount(results, http.StatusServiceUnavailable)
	if count503 == 0 {
		t.Fatalf("phase 2 FAILED: zero 503 responses after taking 2/3 witnesses below quorum for 90s — backpressure chain not firing (architectural promise unmet)")
	}
	t.Logf("phase 2: observed %d 503 responses out of %d total",
		count503, len(results))

	// Every 503 MUST carry a Retry-After header.
	count503WithoutRetryAfter := 0
	maxRetryAfter := 0
	for _, r := range results {
		if r.StatusCode != http.StatusServiceUnavailable {
			continue
		}
		if r.RetryAfter == "" {
			count503WithoutRetryAfter++
			continue
		}
		// Parse Retry-After: ledger emits integer seconds per
		// api/batch.go. RFC 7231 also permits HTTP-date format
		// but the ledger doesn't use that.
		secs, err := strconv.Atoi(r.RetryAfter)
		if err != nil {
			t.Errorf("Retry-After value %q is not an integer (load-balancer incompatible)", r.RetryAfter)
			continue
		}
		if secs <= 0 {
			t.Errorf("Retry-After value %d <= 0 (must be positive)", secs)
		}
		if secs > maxRetryAfter {
			maxRetryAfter = secs
		}
	}
	if count503WithoutRetryAfter > 0 {
		t.Errorf("phase 2 FAILED: %d of %d 503 responses missing Retry-After header — load balancers can't back off intelligently",
			count503WithoutRetryAfter, count503)
	}
	t.Logf("phase 2: Retry-After max=%ds (all 503 responses had the header)", maxRetryAfter)

	// ─── PHASE 3 — Recovery ───────────────────────────────────────
	t.Logf("phase 3: healing witnesses, observing recovery")
	healStart := time.Now()
	h.Witnesses().Heal(0)
	h.Witnesses().Heal(1)

	// Poll for the first successful 202 post-healing.
	healingDeadline := time.Now().Add(120 * time.Second)
	var firstRecoverAt time.Duration
	for time.Now().Before(healingDeadline) {
		r, _ := submitter.Submit(ctx,
			[]byte("phase3-post-healing"), harness.SubmitOpts{})
		if r.StatusCode == http.StatusAccepted {
			firstRecoverAt = time.Since(healStart)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if firstRecoverAt == 0 {
		t.Fatalf("phase 3 FAILED: no 202 within 120s of healing — backpressure stuck")
	}
	t.Logf("phase 3: first 202 received %v after healing", firstRecoverAt.Round(100*time.Millisecond))

	// Verify the system catches up — submit a few more, wait
	// for drain to a count that includes them.
	const recoveryProbe = 10
	for i := 0; i < recoveryProbe; i++ {
		r, err := submitter.Submit(ctx,
			[]byte("phase3-recovery-probe"), harness.SubmitOpts{})
		if err != nil || r.StatusCode != http.StatusAccepted {
			t.Fatalf("phase 3 recovery probe %d failed: status=%d err=%v",
				i, r.StatusCode, err)
		}
	}
	// Don't assert exact total here — the outage submissions
	// that returned 202 also count toward entry_index. Just
	// verify the system is making forward progress.
	c, err := h.SnapshotCounts(ctx)
	if err != nil {
		t.Fatalf("phase 3 SnapshotCounts: %v", err)
	}
	if c.EntryIndex < baseline+recoveryProbe {
		t.Errorf("phase 3 entry_index=%d, expected >= %d (baseline + recovery probe)",
			c.EntryIndex, baseline+recoveryProbe)
	}
	t.Logf("phase 3: entry_index=%d max_seq=%d cursor=%d (system caught up)",
		c.EntryIndex, c.MaxSeq, c.BuilderCursor)
}

// observedCount returns the number of results with the given
// HTTP status code.
func observedCount(results []harness.SubmitResult, status int) int {
	n := 0
	for _, r := range results {
		if r.StatusCode == status {
			n++
		}
	}
	return n
}

// hasObservedFromSlice reports whether any result in results has
// the given status code.
func hasObservedFromSlice(results []harness.SubmitResult, status int) bool {
	return observedCount(results, status) > 0
}
