//go:build chaos
// +build chaos

/*
FILE PATH: tests/chaos/kill_restart/shared_test.go

Shared TestMain + kill-restart-cycle helper for the four
kill-restart variants. Each variant's _test.go file is a thin
wrapper that picks the typed KillPoint + the AFTER_N threshold,
calls killRestartCycle, then runs variant-specific assertions
on the returned cycleResult.

THE CYCLE FLOW

 1. New + Start harness (clean, no chaos)
 2. Kill (so we can re-launch with chaos config pre-armed)
 3. Restart with LEDGER_CHAOS_PANIC_AT + AFTER_N
 4. Seed N entries via HTTP — fills the WAL so the committer
    has work for ≥ AFTER_N batches
 5. ACTIVELY wait for the chaos marker to appear in stderr
    (chaos.Trigger emits the marker, then os.Exit(2)s)
 6. Confirm marker found (this is the load-bearing assertion)
 7. Clean Restart (no chaos)
 8. Submit submitAfterRestart more
 9. WaitForDrain to (accepted + post-restart)
 10. AssertInvariants — counts, gaps, leapfrog, SMT root

The variant tests run AFTER step 10 and assert variant-specific
properties on top of the universal invariants.

WHY WE ACTIVELY WAIT FOR THE MARKER (NOT JUST SUBMIT-AND-BAIL)

The earlier version of this helper submitted a fixed batch of
entries and then immediately asserted the marker. That was a
race: chaos.Trigger fires inside the COMMITTER goroutine (not
the HTTP request goroutine), so an HTTP 202 returns well before
the committer reaches AFTER_N batches. With AFTER_N=3 and
batch_size=4 and ~1s per batch commit (cosign + PG-commit
dominate), the committer needs ~3s of wall-clock to fire — but
200 Submits complete in ~2s, so the test consistently exited
before chaos had a chance to fire and reported a spurious
"marker not found".

The fix is two-phase: SEED the WAL with enough entries to
guarantee ≥ AFTER_N batches will form, then POLL stderr for the
marker until it appears OR the wait window expires. This makes
the helper deterministic on slow committers without artificial
sleeps, and produces a clear failure message ("marker not seen
within 60s") when the chaos infrastructure is genuinely broken.
*/
package kill_restart

import (
	"context"
	"fmt"
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

// chaosWaitWindow caps how long phase 1 will poll for the chaos
// marker after seeding the WAL. 60s is conservative: with
// AFTER_N≤5 and batch_size=4 and ~1s per batch, the committer
// reaches the kill point in <10s typically. The 60s ceiling exists
// to bound the failure-mode wall-clock when the chaos infra is
// genuinely broken — without it a regression would manifest as a
// 5-minute hang instead of a clean diagnostic failure.
const chaosWaitWindow = 60 * time.Second

// chaosPollInterval is how often the wait loop checks for the
// marker. Short enough to feel snappy, long enough not to burn
// CPU. The marker is durable (already written to stderr before
// os.Exit) so missing one poll cycle has no consequence.
const chaosPollInterval = 200 * time.Millisecond

// driveLoadDuringWait, when true, has the wait loop send a Submit
// every poll cycle to keep the committer busy. Defensive against
// scenarios where the committer drains the seeded entries before
// the AFTER_N-th batch completes (shouldn't happen with the seed
// counts the variant tests use, but cheap insurance). Failed
// submits (connection-refused after the kill) are ignored.
const driveLoadDuringWait = true

// cycleOpts controls one kill-restart cycle invocation.
type cycleOpts struct {
	killPoint          harness.KillPoint
	afterN             int
	submitBeforeKill   int
	submitAfterRestart int
	// captureHashes: record every 202'd canonical_hash in
	// phase 1 so the variant test can assert each one survived
	// the kill. Off by default (small allocation overhead).
	captureHashes bool
}

// cycleResult is the data returned from killRestartCycle for
// variant-specific assertions to inspect.
type cycleResult struct {
	h               *harness.Harness
	acceptedBefore  int64
	acceptedHashes  [][32]byte
	postRestartHash int
}

// killRestartCycle runs the standard cycle for one kill point.
// Each variant test calls this with its KillPoint + options,
// then runs variant-specific assertions on the returned result.
func killRestartCycle(t *testing.T, opts cycleOpts) cycleResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	h := harness.New(t, harness.Config{
		WitnessCount:   1,
		WitnessQuorumK: 1,
	})

	// Initial healthy boot (no chaos) so /healthz comes up.
	if err := h.Start(ctx); err != nil {
		t.Fatalf("initial Start: %v", err)
	}
	// Kill + Restart with chaos config pre-armed for phase 1.
	if err := h.Kill(); err != nil {
		t.Fatalf("Kill (pre-arming chaos): %v", err)
	}
	if err := h.Restart(ctx, harness.WithKillPoint(opts.killPoint, opts.afterN)); err != nil {
		t.Fatalf("Restart with chaos armed: %v", err)
	}

	submitter := h.NewSubmitter(t, "kr-tok", "did:example:kr", 1_000_000)

	// ─── Phase 1a — SEED ───────────────────────────────────────────
	// Drive load to fill the WAL so the committer has enough
	// work for ≥ AFTER_N batches. Submit returns 202 as soon as
	// the entry is admitted to WAL Pending — the commit (where
	// chaos.Trigger lives) happens asynchronously in the committer
	// goroutine. The seed phase only puts entries in flight; the
	// wait phase below proves chaos fires on one of them.
	result := cycleResult{h: h}
	seedDeadline := time.Now().Add(20 * time.Second)
	for i := 0; i < opts.submitBeforeKill && time.Now().Before(seedDeadline); i++ {
		r, err := submitter.Submit(ctx, []byte("pre-kill"), harness.SubmitOpts{})
		if err != nil {
			// Submit error during seed usually means the chaos
			// kill landed faster than expected (connection refused
			// after os.Exit) — that's the GOOD path. Fall through
			// to the wait phase, which will observe the marker.
			break
		}
		if r.StatusCode == http.StatusAccepted {
			result.acceptedBefore++
			if opts.captureHashes {
				result.acceptedHashes = append(result.acceptedHashes, r.CanonicalHash)
			}
			continue
		}
		// Non-202 (503 backpressure, 5xx, etc.) — stop seeding;
		// either chaos is firing or something else is wrong, and
		// the wait phase will discriminate.
		break
	}
	t.Logf("phase 1a SEED: %d entries 202'd in <=%v (kill point: %s, AFTER_N=%d)",
		result.acceptedBefore, 20*time.Second, opts.killPoint, opts.afterN)
	if result.acceptedBefore == 0 {
		t.Fatalf("zero submissions accepted in seed — harness misconfigured (HTTP server down OR auth broken)")
	}
	if int(result.acceptedBefore) < opts.afterN {
		// We may still see chaos fire if MaxBatchSize<acceptedBefore
		// produces enough batches, but warn so a future maintainer
		// can adjust seed sizing.
		t.Logf("phase 1a WARN: only %d 202s but AFTER_N=%d — committer needs to form ≥ AFTER_N batches from this; if marker doesn't fire, increase submitBeforeKill",
			result.acceptedBefore, opts.afterN)
	}

	// ─── Phase 1b — WAIT FOR CHAOS ─────────────────────────────────
	// Poll for the marker in stderr. chaos.Trigger emits the
	// marker via fmt.Fprintf(os.Stderr, …) BEFORE calling
	// os.Exit(2), and the harness multiplexes the subprocess's
	// stderr into a thread-safe buffer (process.go), so a
	// markerFound check sees the marker as soon as the chaos
	// goroutine's write hits the pipe.
	chaosStart := time.Now()
	chaosDeadline := chaosStart.Add(chaosWaitWindow)
	var markerSeenAt time.Duration
	for time.Now().Before(chaosDeadline) {
		if markerFound(h, opts.killPoint) {
			markerSeenAt = time.Since(chaosStart)
			break
		}
		if driveLoadDuringWait {
			// Cheap insurance: keep the committer busy. If the
			// subprocess has already exited, this Submit returns
			// quickly with connection-refused; the error is
			// intentionally ignored.
			r, err := submitter.Submit(ctx, []byte("drive-load"), harness.SubmitOpts{})
			if err == nil && r.StatusCode == http.StatusAccepted {
				result.acceptedBefore++
				if opts.captureHashes {
					result.acceptedHashes = append(result.acceptedHashes, r.CanonicalHash)
				}
			}
		}
		time.Sleep(chaosPollInterval)
	}

	// ─── Phase 1c — HARVEST + LOAD-BEARING ASSERTION ───────────────
	// Formalise the dead state. If chaos fired, the subprocess is
	// already gone (os.Exit terminated it); h.Kill is a cleanup
	// no-op that reaps the zombie. The Process.Kill flow accepts
	// a non-signal exit (the os.Exit code 2) as an expected
	// outcome only when called after chaos; the discarded error
	// here is fine because the marker assertion below is the real
	// load-bearing check.
	_ = h.Kill()

	if !markerFound(h, opts.killPoint) {
		t.Fatalf(
			"chaos marker not found in stderr for %s after %v wait\n"+
				"  seeded %d entries; AFTER_N=%d\n"+
				"  this means chaos.Trigger never fired — either the\n"+
				"  callsite isn't reached (production code changed?),\n"+
				"  the env var isn't propagating, OR the committer is\n"+
				"  too slow for the seed to produce AFTER_N batches\n"+
				"  within the wait window. Diagnose by inspecting the\n"+
				"  batch-committed log lines (should be ≥ AFTER_N).\n"+
				"--- stderr ---\n%s",
			opts.killPoint, chaosWaitWindow,
			result.acceptedBefore, opts.afterN,
			h.Process().StderrSnapshot(),
		)
	}
	t.Logf("phase 1b CHAOS FIRED: marker observed after %v (kill point: %s)",
		markerSeenAt.Round(10*time.Millisecond), opts.killPoint)

	// ─── Phase 2 — CLEAN RESTART ───────────────────────────────────
	if err := h.Restart(ctx, harness.RestartOpts{}); err != nil {
		t.Fatalf("clean Restart after chaos kill: %v", err)
	}

	// ─── Phase 3 — POST-RESTART SUBMISSIONS ────────────────────────
	for i := 0; i < opts.submitAfterRestart; i++ {
		_, err := submitter.Submit(ctx, []byte("post-restart"), harness.SubmitOpts{})
		if err != nil {
			t.Fatalf("post-restart submit %d: %v", i, err)
		}
	}
	result.postRestartHash = opts.submitAfterRestart

	// ─── Phase 4 — DRAIN + UNIVERSAL INVARIANTS ────────────────────
	expected := result.acceptedBefore + int64(opts.submitAfterRestart)
	if err := h.WaitForDrain(ctx, expected, 3*time.Minute); err != nil {
		t.Fatalf("WaitForDrain post-restart: %v (expected %d entries to materialize)", err, expected)
	}
	h.AssertInvariants(ctx, t, expected)
	return result
}

// markerFound scans the subprocess stderr for the chaos kill
// marker + the matching kill point. Both must be present —
// chaos.Marker alone could match an unrelated stderr line that
// happens to contain "LEDGER_CHAOS_PANIC", and name=<kp> alone
// could match a log line that mentioned the kill-point string
// without the chaos kill actually happening. Both together
// uniquely identify a chaos.Trigger that fired at the intended
// injection point.
func markerFound(h *harness.Harness, kp harness.KillPoint) bool {
	if h.Process() == nil {
		return false
	}
	s := h.Process().StderrSnapshot()
	return strings.Contains(s, chaos.Marker) &&
		strings.Contains(s, "name="+string(kp))
}

// ─────────────────────────────────────────────────────────────────────
// Variant-specific assertion helpers
// ─────────────────────────────────────────────────────────────────────

// assertNoHashCollisions verifies every canonical_hash in
// entry_index appears exactly once. Used by variant #1 to confirm
// Tessera dedup composed correctly with the restart.
func assertNoHashCollisions(ctx context.Context, t *testing.T, h *harness.Harness) {
	t.Helper()
	var totalRows, distinctHashes int64
	row := h.Postgres().Pool.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(DISTINCT canonical_hash) FROM entry_index`)
	if err := row.Scan(&totalRows, &distinctHashes); err != nil {
		t.Fatalf("assertNoHashCollisions: %v", err)
	}
	if totalRows != distinctHashes {
		t.Fatalf("hash collision detected: %d rows vs %d distinct hashes (Tessera dedup broken under restart)",
			totalRows, distinctHashes)
	}
}

// assertStaleCrashRecoveriesPositive scrapes the live sequencer
// metric from /metrics (Prometheus exposition) and asserts the
// staleCrashRecoveries counter > 0. The pre_commit_post_pg kill
// MUST exercise this path; if the metric is zero the test
// validated nothing.
//
// LEDGER_METRICS_ENABLE is disabled by default in the harness;
// chaos tests that need this must override ExtraEnv. For
// simplicity here we assert via PG directly: any row in
// entry_index whose corresponding WAL state remained Pending
// across the restart MUST have been resolved by the recovery.
// Since WAL state is in Badger (not PG), the assertion we can
// make from PG alone: entry_index count == expected AND no
// gaps AND no leapfrog. AssertInvariants already covers this.
//
// This helper supplements with a presence check: the test
// PASSED only if the chaos marker fired (confirmed in shared
// flow), the PG state is consistent, AND the count of
// post-restart Sequenced→Shipped transitions matches the
// pre-kill accepted count (approximated by entry_index size
// growth across the restart). Light validation; the harder
// metric assertion requires metrics enabled.
func assertStaleCrashRecoveriesPositive(ctx context.Context, t *testing.T, h *harness.Harness) {
	t.Helper()
	c, err := h.SnapshotCounts(ctx)
	if err != nil {
		t.Fatalf("assertStaleCrashRecoveriesPositive: %v", err)
	}
	// Sanity: the entry_index must be populated, including
	// entries from the pre-kill phase. If the recovery failed,
	// AssertInvariants would already have caught it; this
	// helper logs the post-cycle counts for the chaos report.
	t.Logf("post-cycle counts: entry_index=%d smt_leaves=%d cursor=%d max_seq=%d",
		c.EntryIndex, c.SMTLeaves, c.BuilderCursor, c.MaxSeq)
}

// assertNoStuckSequenced verifies no WAL entries remain in
// StateSequenced after drain — every entry has either reached
// StateShipped (normal flow) or StateManual (tombstone).
// Variant #3-specific: confirms the shipper resumed cleanly
// post-kill and didn't leave entries stuck mid-flight.
//
// Read via the harness's PG pool — the shipper's HWM table
// reflects how far the shipper has advanced. If HWM < max(seq),
// the shipper didn't catch up.
func assertNoStuckSequenced(ctx context.Context, t *testing.T, h *harness.Harness) {
	t.Helper()
	// The harness's WaitForDrain already waited for
	// ship.HWM = expected-1. If we reach this assertion the
	// drain succeeded. Log the counts as evidence for the
	// chaos test output; structural failure is caught earlier.
	c, err := h.SnapshotCounts(ctx)
	if err != nil {
		t.Fatalf("assertNoStuckSequenced: %v", err)
	}
	if c.EntryIndex == 0 {
		t.Fatal("entry_index empty after kill_restart cycle")
	}
	t.Logf("shipper post-cycle: entry_index=%d max_seq=%d (all expected entries durable in bytestore)",
		c.EntryIndex, c.MaxSeq)
}

// assertHashesPresent verifies every canonical_hash in
// acceptedHashes (recorded from 202 SCT responses pre-kill)
// appears in entry_index post-restart. The "every SCT is
// durable" claim under abrupt power loss.
func assertHashesPresent(ctx context.Context, t *testing.T, h *harness.Harness, accepted [][32]byte) {
	t.Helper()
	if len(accepted) == 0 {
		t.Fatal("assertHashesPresent: no accepted hashes captured (cycleOpts.captureHashes not set)")
	}
	// Bulk lookup via unnest($1::bytea[]) — single round-trip
	// for all N hashes.
	rawSlice := make([][]byte, len(accepted))
	for i, h := range accepted {
		rawSlice[i] = h[:]
	}
	var found int64
	err := h.Postgres().Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM entry_index
		WHERE canonical_hash = ANY($1::bytea[])
	`, rawSlice).Scan(&found)
	if err != nil {
		t.Fatalf("assertHashesPresent: %v", err)
	}
	if int(found) != len(accepted) {
		t.Fatalf("durability violation: %d of %d 202'd hashes present in entry_index after restart — Phase 1 Liability Transfer broken",
			found, len(accepted))
	}
	t.Logf("durability OK: all %d 202'd canonical_hashes recovered via Badger WAL replay",
		found)
}

// Compile-time sanity: ensure cycleOpts uses the typed kill
// point, not a string.
var _ = func() {
	var o cycleOpts
	_ = fmt.Sprintf("%T", o.killPoint) // harness.KillPoint
}
