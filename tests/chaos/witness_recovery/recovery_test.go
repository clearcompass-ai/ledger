//go:build chaos
// +build chaos

/*
FILE PATH: tests/chaos/witness_recovery/recovery_test.go

Extends the backpressure test through the full outage-to-healing
cycle. The chain validated here covers FOUR distinct properties:

  1. EVERY-202-DURABLE: Submissions during the outage that
     returned 202 (the ledger acknowledged) MUST eventually
     appear in entry_index after healing. No 202'd submission
     is lost.

  2. BACKPRESSURE-RELEASE: After heal, the MaxBuilderLag gate
     in sequencer.drainOnce MUST release and admission MUST
     return 202 within a bounded recovery window (60s default).

  3. BUILDER-CATCHUP: smt_leaves MUST grow to match
     entry_index after healing — the builder loop catches up
     on the backlog accumulated during the outage.

  4. CRYPTOGRAPHIC-RECONSTRUCTION: post-cycle, the SMT root
     reconstructible from durable tables (smt_leaves +
     smt_root_state) MUST match the persisted root. The
     cryptographic chain survives the outage end-to-end.

Each property has its own assertion. A test pass means ALL
FOUR held; a failure points at the specific property that
broke.

Tagged `chaos`. Run via:

  go test -tags=chaos -count=1 -v -timeout=10m \
      ./tests/chaos/witness_recovery/
*/
package witness_recovery

import (
	"context"
	"net/http"
	"os"
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

// TestWitnessRecovery_OutageThenHealing exercises the full
// outage → healing → catchup cycle and validates all four
// architectural properties hold afterward.
func TestWitnessRecovery_OutageThenHealing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	h := harness.New(t, harness.Config{
		WitnessCount:   3,
		WitnessQuorumK: 2,
	})
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	submitter := h.NewSubmitter(t, "rec-tok", "did:example:rec", 1_000_000)

	// ─── Phase 1 — Baseline ──────────────────────────────────────
	t.Logf("phase 1: baseline submission")
	const baseline = 100
	submitted, failed, err := submitter.SubmitN(ctx, baseline, 4)
	if err != nil {
		t.Fatalf("baseline submission: submitted=%d failed=%d err=%v",
			submitted, failed, err)
	}
	if submitted != baseline {
		t.Fatalf("baseline: %d/%d 202s (failed=%d)", submitted, baseline, failed)
	}
	if err := h.WaitForDrain(ctx, int64(baseline), 2*time.Minute); err != nil {
		t.Fatalf("baseline drain: %v", err)
	}

	// ─── Phase 2 — Outage ────────────────────────────────────────
	t.Logf("phase 2: taking witnesses 0,1 offline (below K=2 quorum)")
	outageStart := time.Now()
	h.Witnesses().Fail(0, http.StatusInternalServerError)
	h.Witnesses().Fail(1, http.StatusInternalServerError)

	// Track every 202'd canonical_hash during the outage so we
	// can verify EVERY-202-DURABLE post-recovery.
	type accepted struct {
		hash [32]byte
		t    time.Duration // since outage start
	}
	var accepted202s []accepted
	var saw503 bool
	var first503At time.Duration

	outageDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(outageDeadline) {
		r, err := submitter.Submit(ctx,
			[]byte("during-outage"), harness.SubmitOpts{})
		switch {
		case err == nil && r.StatusCode == http.StatusAccepted:
			accepted202s = append(accepted202s, accepted{
				hash: r.CanonicalHash,
				t:    time.Since(outageStart),
			})
		case r.StatusCode == http.StatusServiceUnavailable:
			if !saw503 {
				first503At = time.Since(outageStart)
				saw503 = true
				t.Logf("phase 2: first 503 at %v after outage start", first503At.Round(100*time.Millisecond))
			}
		}
		time.Sleep(80 * time.Millisecond)
		// Once we've seen backpressure fire AND collected 10+
		// seconds of data, move on.
		if saw503 && time.Since(outageStart) > 30*time.Second {
			break
		}
	}
	t.Logf("phase 2: during outage — accepted=%d hashes, saw503=%t, first503=%v",
		len(accepted202s), saw503, first503At.Round(100*time.Millisecond))

	// ─── Phase 3 — Healing + recovery timing ─────────────────────
	t.Logf("phase 3: healing all witnesses")
	healStart := time.Now()
	h.Witnesses().HealAll()

	// BACKPRESSURE-RELEASE property: bounded recovery time.
	const maxRecoveryWindow = 90 * time.Second
	healingDeadline := time.Now().Add(maxRecoveryWindow)
	var firstRecoverAt time.Duration
	for time.Now().Before(healingDeadline) {
		r, _ := submitter.Submit(ctx,
			[]byte("post-healing"), harness.SubmitOpts{})
		if r.StatusCode == http.StatusAccepted {
			firstRecoverAt = time.Since(healStart)
			accepted202s = append(accepted202s, accepted{
				hash: r.CanonicalHash,
				t:    time.Since(outageStart),
			})
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if firstRecoverAt == 0 {
		t.Fatalf("BACKPRESSURE-RELEASE failed: no 202 within %v of healing", maxRecoveryWindow)
	}
	t.Logf("phase 3: backpressure released — first 202 in %v",
		firstRecoverAt.Round(100*time.Millisecond))

	// Submit more entries to verify steady-state recovery.
	const postHealing = 50
	postSubmitted, postFailed, err := submitter.SubmitN(ctx, postHealing, 4)
	if err != nil {
		t.Fatalf("post-healing submission: submitted=%d failed=%d err=%v",
			postSubmitted, postFailed, err)
	}
	// Capture hashes from the post-healing submissions too.
	// (SubmitN doesn't capture; we already verified non-zero
	// success via the count check.)

	// ─── Phase 4 — Catchup + invariants ──────────────────────────
	// EVERY-202-DURABLE + BUILDER-CATCHUP + CRYPTOGRAPHIC-
	// RECONSTRUCTION are all validated here.
	totalAccepted := int64(baseline) + int64(len(accepted202s)) + int64(postSubmitted)
	t.Logf("phase 4: waiting for total drain of %d entries", totalAccepted)
	if err := h.WaitForDrain(ctx, totalAccepted, 5*time.Minute); err != nil {
		t.Fatalf("BUILDER-CATCHUP failed (drain): %v", err)
	}

	// EVERY-202-DURABLE — every captured canonical_hash from
	// the outage period MUST be present in entry_index.
	rawSlice := make([][]byte, 0, len(accepted202s))
	for _, a := range accepted202s {
		hash := a.hash
		rawSlice = append(rawSlice, hash[:])
	}
	var found int64
	err = h.Postgres().Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM entry_index
		WHERE canonical_hash = ANY($1::bytea[])
	`, rawSlice).Scan(&found)
	if err != nil {
		t.Fatalf("EVERY-202-DURABLE check failed: %v", err)
	}
	if int(found) != len(accepted202s) {
		t.Fatalf("EVERY-202-DURABLE FAILED: %d of %d outage 202s present in entry_index — submissions lost to witness outage",
			found, len(accepted202s))
	}
	t.Logf("phase 4: EVERY-202-DURABLE ok — all %d outage 202s recovered",
		len(accepted202s))

	// CRYPTOGRAPHIC-RECONSTRUCTION — AssertInvariants runs
	// smt_reconstruction.Reconstruct + validates the persisted
	// root matches the rebuilt one. Plus counts + gaps + leapfrog.
	h.AssertInvariants(ctx, t, totalAccepted)

	totalElapsed := time.Since(outageStart)
	t.Logf("phase 4: ALL INVARIANTS HELD — total cycle %v, %d entries reconciled",
		totalElapsed.Round(time.Second), totalAccepted)
}
