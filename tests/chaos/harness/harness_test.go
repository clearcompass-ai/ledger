// FILE PATH: tests/chaos/harness/harness_test.go
//
// Smoke test for the chaos harness itself. Validates that the
// pieces compose: build binary, spawn subprocess, wait for
// /healthz, submit one entry, SIGKILL, restart, observe that
// the entry survives. If this test green, the four downstream
// chaos suites (kill_restart, backpressure, witness_recovery,
// smt_reconstruction-via-harness) have a working foundation.
//
// Skipped when ATTESTA_TEST_DSN / ATTESTA_TEST_S3_* are not
// configured. Tagged with `chaos` so it doesn't run under the
// default `go test ./...`.

//go:build chaos
// +build chaos

package harness

import (
	"context"
	"os"
	"testing"
	"time"
)

// repoRoot is the absolute path of the ledger module root. The
// harness needs it to invoke `go build ./cmd/ledger`. TestMain
// resolves it relative to this test file's location.
var repoRoot string

func TestMain(m *testing.M) {
	// Resolve module root from a known marker. The chaos tests
	// run from tests/chaos/harness so the repo root is three
	// directories up. Use working directory at startup +
	// climbing for portability.
	if wd, err := os.Getwd(); err == nil {
		// wd ends in tests/chaos/harness — strip three.
		repoRoot = wd + "/../../.."
	}
	if _, err := EnsureLedgerBinary(repoRoot); err != nil {
		// If build fails, all tests below would fail too. Print
		// once + exit non-zero so the operator sees the build
		// error before a wall of test-skip noise.
		println("EnsureLedgerBinary failed:", err.Error())
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestHarness_StartSubmitKillRestart is the load-bearing smoke
// test. The flow:
//
//  1. New + Start a fresh harness.
//  2. Submit 5 entries; assert each gets a 202 SCT.
//  3. Wait for the drain — all 5 must reach entry_index.
//  4. SIGKILL the subprocess.
//  5. Restart against the same on-disk state.
//  6. Submit 5 more entries.
//  7. Wait for the drain — total 10.
//  8. AssertInvariants — counts, gaps, leapfrog, SMT root all
//     consistent.
//
// If this fails on Restart or AssertInvariants, the entire kill-
// restart chaos suite is unreliable. Run with:
//
//   ATTESTA_TEST_DSN=… ATTESTA_TEST_S3_* … \
//   go test -tags=chaos -count=1 -v -run TestHarness ./tests/chaos/harness/...
func TestHarness_StartSubmitKillRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	h := New(t, Config{
		WitnessCount:   1,
		WitnessQuorumK: 1,
	})
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	submitter := h.NewSubmitter(t, "chaos-smoke-tok",
		"did:example:chaos-smoke", 1_000_000)

	// Submit 5 entries before the kill.
	for i := 0; i < 5; i++ {
		_, err := submitter.Submit(ctx,
			[]byte("pre-kill-payload"), SubmitOpts{})
		if err != nil {
			t.Fatalf("Submit %d before kill: %v", i, err)
		}
	}
	if err := h.WaitForDrain(ctx, 5, 60*time.Second); err != nil {
		t.Fatalf("WaitForDrain pre-kill: %v", err)
	}

	// SIGKILL.
	if err := h.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	// Restart against same on-disk state. No chaos injection
	// this time — just a clean restart.
	if err := h.Restart(ctx, RestartOpts{}); err != nil {
		t.Fatalf("Restart: %v", err)
	}

	// Submit 5 more.
	for i := 0; i < 5; i++ {
		_, err := submitter.Submit(ctx,
			[]byte("post-restart-payload"), SubmitOpts{})
		if err != nil {
			t.Fatalf("Submit %d after restart: %v", i, err)
		}
	}
	if err := h.WaitForDrain(ctx, 10, 60*time.Second); err != nil {
		t.Fatalf("WaitForDrain post-restart: %v", err)
	}

	// All invariants must hold across the kill cycle.
	h.AssertInvariants(ctx, t, 10)
}
