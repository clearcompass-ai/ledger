//go:build chaos
// +build chaos

/*
FILE PATH: tests/chaos/kill_restart/shared_test.go

Shared TestMain + kill-restart-cycle helper for the four
kill-restart variants. Each variant's _test.go file is a thin
wrapper that picks the panic point + the AFTER_N threshold and
calls runKillRestartCycle.

The kill-restart-cycle flow:

  1. New + Start harness with chaos config:
       LEDGER_CHAOS_PANIC_AT=<point>
       LEDGER_CHAOS_PANIC_AFTER_N=<afterN>
  2. Submit submitBeforeKill entries. The subprocess panics
     after the AFTER_N-th trigger fires; expected behaviour:
     some submissions return 202 (the ledger accepted them),
     subsequent ones get errors (connection refused or
     reset) once the process dies.
  3. Wait for the process to die (cmd.Wait inside Process.kill
     blocks). Assert the panic marker (chaos.Marker constant)
     appears in stderr — confirms the panic fired at the
     intended point, not from an unrelated cause.
  4. Restart against the same on-disk state with NO chaos
     injection.
  5. Submit submitAfterRestart entries. All MUST get 202.
  6. WaitForDrain to (submittedBeforeKill + submitAfterRestart).
  7. AssertInvariants — entries from both phases reconcile;
     no gaps, no leapfrog, SMT root reconstructible.
*/
package kill_restart

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/chaos"
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

// killRestartCycle runs the standard kill-restart cycle for one
// injection point. Each variant test (kill_appendleaf_test.go
// etc.) calls this with its specific panicAt + afterN.
func killRestartCycle(t *testing.T, opts cycleOpts) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	h := harness.New(t, harness.Config{
		WitnessCount:   1,
		WitnessQuorumK: 1,
	})
	// First Start has the chaos trigger pre-armed. The
	// AFTER_N gate makes the subprocess panic after the Nth
	// trigger match, NOT immediately — so the ledger has time
	// to accept submissions, the kill point fires mid-stream.
	startCtx, startCancel := context.WithTimeout(ctx, 60*time.Second)
	defer startCancel()
	if err := h.Start(startCtx); err != nil {
		t.Fatalf("initial Start: %v", err)
	}
	// Reconfigure the subprocess for chaos at the SECOND start
	// (via Restart after the initial healthy boot — see below).
	// We need a healthy initial boot so /healthz comes up.
	// Then we Kill + Restart with chaos panic config armed,
	// then submit.
	if err := h.Kill(); err != nil {
		t.Fatalf("Kill (pre-arming chaos): %v", err)
	}
	if err := h.Restart(ctx, harness.RestartOpts{
		PanicAt:     opts.panicAt,
		PanicAfterN: opts.afterN,
	}); err != nil {
		t.Fatalf("Restart with chaos armed: %v", err)
	}

	submitter := h.NewSubmitter(t, "kr-tok", "did:example:kr", 1_000_000)

	// Phase 1: submit until the panic fires.
	var accepted int64
	deadline := time.Now().Add(90 * time.Second)
	for i := 0; i < opts.submitBeforeKill && time.Now().Before(deadline); i++ {
		r, err := submitter.Submit(ctx, []byte("pre-kill"), harness.SubmitOpts{})
		if err == nil && r.StatusCode == http.StatusAccepted {
			accepted++
			continue
		}
		// Any error past the first half is likely the panic
		// having fired (connection refused / reset).
		if accepted >= int64(opts.afterN) {
			break
		}
	}
	t.Logf("phase 1: submitted %d entries before panic", accepted)
	if accepted == 0 {
		t.Fatalf("zero submissions accepted before panic — harness misconfigured")
	}

	// Wait for the process to fully die. Process.Kill blocks on
	// cmd.Wait, so calling it now formalises the dead state.
	_ = h.Kill()

	// Confirm the panic marker appeared in stderr — proves the
	// process died from chaos.Trigger at the intended point,
	// not from some unrelated panic.
	if !markerFound(h, opts.panicAt) {
		t.Errorf("chaos panic marker not found in stderr — kill may have been unrelated\n--- stderr ---\n%s",
			h.Process().StderrSnapshot())
	}

	// Phase 2: clean restart (no chaos).
	if err := h.Restart(ctx, harness.RestartOpts{}); err != nil {
		t.Fatalf("clean Restart after panic: %v", err)
	}

	// Phase 3: submit more.
	for i := 0; i < opts.submitAfterRestart; i++ {
		_, err := submitter.Submit(ctx,
			[]byte("post-restart"), harness.SubmitOpts{})
		if err != nil {
			t.Fatalf("post-restart submit %d: %v", i, err)
		}
	}

	// Final invariants. Expected = (accepted-during-phase-1) +
	// submitAfterRestart. The accepted count is what the
	// ledger acknowledged with a 202 — those entries MUST
	// survive the kill cycle.
	expected := accepted + int64(opts.submitAfterRestart)
	if err := h.WaitForDrain(ctx, expected, 3*time.Minute); err != nil {
		t.Fatalf("WaitForDrain post-restart: %v", err)
	}
	h.AssertInvariants(ctx, t, expected)
}

type cycleOpts struct {
	// panicAt — value passed as LEDGER_CHAOS_PANIC_AT.
	panicAt string

	// afterN — value passed as LEDGER_CHAOS_PANIC_AFTER_N.
	// Set so the panic fires mid-stream rather than at the
	// first trigger match.
	afterN int

	// submitBeforeKill — upper bound on submission attempts in
	// phase 1. Loop terminates earlier if errors start
	// happening past the AFTER_N threshold (panic took down
	// the process).
	submitBeforeKill int

	// submitAfterRestart — entries submitted after the clean
	// restart. All must succeed.
	submitAfterRestart int
}

// markerFound scans the subprocess stderr for the chaos panic
// marker AND the matching point name. Both must be present —
// "LEDGER_CHAOS_PANIC name=post_appendleaf count=N".
func markerFound(h *harness.Harness, panicAt string) bool {
	if h.Process() == nil {
		return false
	}
	s := h.Process().StderrSnapshot()
	return strings.Contains(s, chaos.Marker) &&
		strings.Contains(s, "name="+panicAt)
}
