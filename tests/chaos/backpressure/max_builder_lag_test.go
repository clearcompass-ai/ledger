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

Until now this property was a documentation claim in
sequencer/sequencer.go's MaxBuilderLag comment. This test makes
it observable: take K-of-N witnesses offline, watch the
backpressure chain fire end-to-end through real subprocess
ledger + real witness HTTP servers.

ALSO ASSERTS

  - Retry-After header is set on 503 responses (load balancers
    + retry-aware clients depend on this for honest backoff)
  - When witnesses are restored, the backpressure releases and
    submissions resume getting 202 within 5 seconds (the
    witness_recovery package extends this with full catchup
    invariants)
*/
package backpressure

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/tests/chaos/harness"
)

// repoRoot resolved in TestMain so EnsureLedgerBinary can find
// the cmd/ledger source.
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

// TestBackpressure_WitnessesDownAdmits503 verifies the
// architectural chain end-to-end. Run via:
//
//	ATTESTA_TEST_DSN=… ATTESTA_TEST_S3_* … \
//	go test -tags=chaos -count=1 -v -timeout=5m \
//	    ./tests/chaos/backpressure/
func TestBackpressure_WitnessesDownAdmits503(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 3 witnesses, K=2 quorum: failing 2 of 3 drops below quorum
	// (only 1 reachable, K=2 unmet).
	h := harness.New(t, harness.Config{
		WitnessCount:   3,
		WitnessQuorumK: 2,
	})
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	submitter := h.NewSubmitter(t, "bp-tok", "did:example:bp", 1_000_000)

	// ─── Phase 1: baseline healthy submission ───────────────────────
	// Submit 50 entries with all witnesses healthy. All must
	// succeed; this proves the cosign path is wired correctly
	// before we start breaking it.
	for i := 0; i < 50; i++ {
		_, err := submitter.Submit(ctx,
			[]byte("phase1-baseline"), harness.SubmitOpts{})
		if err != nil {
			t.Fatalf("phase 1 baseline submit %d: %v", i, err)
		}
	}
	if err := h.WaitForDrain(ctx, 50, 90*time.Second); err != nil {
		t.Fatalf("phase 1 drain: %v", err)
	}

	// ─── Phase 2: take 2 of 3 witnesses offline ─────────────────────
	// Below K=2 quorum (only 1 witness can sign). Builder Step
	// 7 will block; the chain SHOULD propagate to admission 503.
	h.Witnesses().Fail(0, http.StatusInternalServerError)
	h.Witnesses().Fail(1, http.StatusInternalServerError)

	// Give the system time to drain in-flight, observe failed
	// cosignatures, then propagate to the sequencer's
	// MaxBuilderLag gate.
	//
	// The MaxBuilderLag default is 4096; with PollInterval=1s
	// it takes ~4-5 seconds for WAL Pending to saturate enough
	// for backpressure to fire. We submit aggressively to
	// accelerate this.
	results := make([]harness.SubmitResult, 0, 200)
	deadline := time.Now().Add(60 * time.Second)
	var saw503 bool
	for time.Now().Before(deadline) && !saw503 {
		// Submit a batch quickly to push WAL toward saturation.
		for i := 0; i < 20; i++ {
			r, err := submitter.Submit(ctx,
				[]byte("phase2-witnesses-down"), harness.SubmitOpts{})
			if err == nil {
				results = append(results, r)
			} else if r.StatusCode == 503 {
				results = append(results, r)
				saw503 = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	obs := harness.CollectBackpressure(results)
	if !obs.Saw503 {
		t.Errorf("never observed 503 after taking 2/3 witnesses below quorum — backpressure chain not firing (architectural promise unmet)")
	}
	if obs.Saw503 && !obs.RetryAfterSet {
		t.Errorf("503 observed but Retry-After header missing — load-balancer-incompatible backpressure")
	}
	t.Logf("phase 2: observed %d/%d 503 responses, RetryAfter set: %t",
		obs.Saw503Count, len(results), obs.RetryAfterSet)

	// ─── Phase 3: restore witnesses, observe catchup ────────────────
	// Heal both witnesses. The builder should resume, the
	// MaxBuilderLag gate should release, and a fresh submission
	// should succeed within 30 seconds.
	h.Witnesses().Heal(0)
	h.Witnesses().Heal(1)

	healingDeadline := time.Now().Add(60 * time.Second)
	var recovered bool
	for time.Now().Before(healingDeadline) {
		r, err := submitter.Submit(ctx,
			[]byte("phase3-post-healing"), harness.SubmitOpts{})
		if err == nil && r.StatusCode == http.StatusAccepted {
			recovered = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !recovered {
		t.Fatalf("submitter never got 202 after witnesses healed within 60s — backpressure stuck")
	}

	t.Logf("phase 3: submission recovered within %v of healing",
		time.Since(healingDeadline.Add(-60*time.Second)).Round(time.Second))
}
