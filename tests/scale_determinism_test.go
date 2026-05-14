//go:build scale
// +build scale

/*
FILE PATH: tests/scale_determinism_test.go

At-scale validation of the P5 idempotent-replay contract:

  byte-identical wire input → byte-identical SCT bytes

# DESIGN: continuous end-to-end per iteration

Each worker goroutine runs its own continuous loop:

  for not-done {
      build wire FRESH (EventTime = now)
      submit first  → SCT_A
      submit second → SCT_B (replay)
      verify canonical_hash + log_time_micros + signature byte-identity
      next
  }

This is the **transaction-shape** the real-world client uses — one
submission round-trip at a time, fully validated, then move on.
The earlier batched shape (pre-build N envelopes, blast through a
shared queue) had two structural defects that this redesign
eliminates by construction:

  Bug B: pre-built envelopes go stale
    The freshness policy rejects entries with EventTime older than
    5 minutes. Pre-building all N envelopes at t=0 and draining
    them over wall-time T means the last (T/5min × rate) envelopes
    are stale at submission. Observed at ~3300 pairs / 5 min in
    the bulk shape. Per-iteration construction stamps EventTime
    at the moment of submission — staleness is impossible.

  Bug C: shared-worker-pool fail-fatal silently kills workers
    submitEntry calls t.Fatalf on any non-202 response. From a
    worker goroutine, t.Fatalf invokes runtime.Goexit, killing
    the worker without returning to the caller. The previous
    test's `if first == nil { submitErrors.Add(1) }` branch was
    unreachable on real failure paths; the "0 errors" reported
    next to "completed=3329 expected=10000" was the artifact.
    This redesign uses trySubmitEntry (returns (map, error)) so
    every failure increments the diagnostic counter correctly.

# WHAT IT VALIDATES

  1. SDK primitive determinism (attesta v1.5.2 RFC 6979 ECDSA).
     Drift on `signature` alone → SDK regression.

  2. Ledger dedup-and-replay path. canonical_hash + log_time_micros
     must be persisted at first admission and returned verbatim on
     replay. Drift in either → ledger persistence regression.

  3. Pipeline integrity under concurrent realistic load.

# STOPPING CONDITIONS (whichever fires first)

  - target N pairs completed
  - per-test max-duration safety net (ATTESTA_SCALE_DETERMINISM_MAX_DURATION)
  - first drift detected (ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT)

# HOW TO RUN

  Direct:
    ATTESTA_SCALE_DETERMINISM_N=10000 \
    ATTESTA_SCALE_DETERMINISM_CONCURRENCY=8 \
    ATTESTA_TEST_DSN=postgres://... \
    go test -tags=scale -count=1 -timeout=20m \
      -run TestScale_DeterministicReplay -v ./tests/

  Via wrapper script:
    ./scripts/run-scale-determinism.sh

# DEFAULTS

  N            = 1000 pairs (= 2000 submissions) — fast smoke; ~80s
  CONCURRENCY  = 8 workers
  MAX_DURATION = 15 minutes (safety net)
  STOP_ON_DRIFT = true (fail fast on contract violation)
*/
package tests

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// ─────────────────────────────────────────────────────────────────
// Env tuning — file-local names; soak/scale tags don't overlap
// ─────────────────────────────────────────────────────────────────

func getScaleDeterminismN() int { return scaleDetEnvInt("ATTESTA_SCALE_DETERMINISM_N", 1000) }

func getScaleDeterminismConcurrency() int {
	return scaleDetEnvInt("ATTESTA_SCALE_DETERMINISM_CONCURRENCY", 8)
}

func getScaleDeterminismMaxDuration() time.Duration {
	v := os.Getenv("ATTESTA_SCALE_DETERMINISM_MAX_DURATION")
	if v == "" {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 15 * time.Minute
	}
	return d
}

func getScaleDeterminismStopOnDrift() bool {
	v := os.Getenv("ATTESTA_SCALE_DETERMINISM_STOP_ON_DRIFT")
	// Default: true. Explicit "0" / "false" disables.
	if v == "0" || v == "false" {
		return false
	}
	return true
}

func scaleDetEnvInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ─────────────────────────────────────────────────────────────────
// driftDetail — captured on first byte-identity violation
// ─────────────────────────────────────────────────────────────────

type driftDetail struct {
	workerID                                   int
	iteration                                  int64
	hashFirst, hashSecond                      string
	timeFirst, timeSecond                      any
	sigFirst, sigSecond                        string
	hashDrifted, timeDrifted, sigDrifted       bool
}

func compareSCTPair(workerID int, iter int64, first, second map[string]any) *driftDetail {
	hF, _ := first["canonical_hash"].(string)
	hS, _ := second["canonical_hash"].(string)
	sF, _ := first["signature"].(string)
	sS, _ := second["signature"].(string)
	tF := first["log_time_micros"]
	tS := second["log_time_micros"]

	hashDrift := hF != hS
	timeDrift := tF != tS
	sigDrift := sF != sS

	if !hashDrift && !timeDrift && !sigDrift {
		return nil
	}
	return &driftDetail{
		workerID:    workerID,
		iteration:   iter,
		hashFirst:   hF,
		hashSecond:  hS,
		timeFirst:   tF,
		timeSecond:  tS,
		sigFirst:    sF,
		sigSecond:   sS,
		hashDrifted: hashDrift,
		timeDrifted: timeDrift,
		sigDrifted:  sigDrift,
	}
}

// ─────────────────────────────────────────────────────────────────
// TestScale_DeterministicReplay — continuous per-iteration loop
// ─────────────────────────────────────────────────────────────────

func TestScale_DeterministicReplay(t *testing.T) {
	target := int64(getScaleDeterminismN())
	concurrency := getScaleDeterminismConcurrency()
	maxDuration := getScaleDeterminismMaxDuration()
	stopOnDrift := getScaleDeterminismStopOnDrift()
	if concurrency < 1 {
		concurrency = 1
	}

	op := startTestLedger(t)
	op.seedSession(t, "tok-det-scale", "did:example:det-scale-exchange", target*4+1000)

	t.Logf("scale-determinism: target=%d concurrency=%d max_duration=%s stop_on_drift=%v",
		target, concurrency, maxDuration, stopOnDrift)

	deadline := time.Now().Add(maxDuration)

	var (
		completed        atomic.Int64
		submitErrors     atomic.Int64
		driftCount       atomic.Int64
		firstDriftFound  atomic.Bool
		firstDriftDetail atomic.Pointer[driftDetail]
	)

	startTotal := time.Now()
	progressEvery := target / 10
	if progressEvery < 1 {
		progressEvery = 1
	}

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var iter int64
			for {
				// Stopping conditions (cheap checks, in order of likelihood).
				if completed.Load() >= target {
					return
				}
				if time.Now().After(deadline) {
					return
				}
				if stopOnDrift && firstDriftFound.Load() {
					return
				}

				// Reserve a slot. Bail if we lost the race.
				idx := completed.Add(1) - 1
				if idx >= target {
					return
				}
				iter++

				// FRESH wire — EventTime stamped at this moment, not
				// at test setup. Eliminates Bug B (staleness) by
				// construction.
				wire := buildWireEntry(t, envelope.ControlHeader{
					SignerDID: "did:example:det-scale-signer",
				}, []byte(fmt.Sprintf("scale-det-w%d-iter%010d", workerID, iter)))

				// First submission — captures the persisted SCT.
				first, err := trySubmitEntry(op.BaseURL, "tok-det-scale", wire)
				if err != nil {
					submitErrors.Add(1)
					if submitErrors.Load() <= 5 {
						t.Logf("submit_error[%d] worker=%d iter=%d (first): %v",
							submitErrors.Load(), workerID, iter, err)
					}
					// Rewind the completion counter so the next worker
					// loop tries again — failure to admit means we have
					// no pair to verify. If errors are systemic the
					// safety-net deadline catches us.
					completed.Add(-1)
					continue
				}

				// Replay submission — must hit the dedup path and
				// return byte-identical SCT.
				second, err := trySubmitEntry(op.BaseURL, "tok-det-scale", wire)
				if err != nil {
					submitErrors.Add(1)
					if submitErrors.Load() <= 5 {
						t.Logf("submit_error[%d] worker=%d iter=%d (replay): %v",
							submitErrors.Load(), workerID, iter, err)
					}
					completed.Add(-1)
					continue
				}

				// Per-iteration end-to-end verification — the load-
				// bearing assertion. No phase-3 batch; we verify
				// here, while the SCTs are still hot.
				if drift := compareSCTPair(workerID, iter, first, second); drift != nil {
					driftCount.Add(1)
					if firstDriftFound.CompareAndSwap(false, true) {
						firstDriftDetail.Store(drift)
					}
					if stopOnDrift {
						return
					}
				}

				// Progress log every 10% — bounded chatter.
				c := completed.Load()
				if progressEvery > 0 && c%progressEvery == 0 && c > 0 {
					rate := float64(c) / time.Since(startTotal).Seconds()
					t.Logf("  scale-determinism progress: pairs=%d/%d (%.1f pairs/sec) drifts=%d errors=%d",
						c, target, rate, driftCount.Load(), submitErrors.Load())
				}
			}
		}(w)
	}
	wg.Wait()

	totalElapsed := time.Since(startTotal)
	finalCompleted := completed.Load()
	if finalCompleted < 0 {
		finalCompleted = 0
	}
	rate := 0.0
	if totalElapsed.Seconds() > 0 {
		rate = float64(finalCompleted) / totalElapsed.Seconds()
	}

	t.Logf("scale-determinism: %d pairs end-to-end in %s (%.1f pairs/sec) "+
		"drifts=%d submit_errors=%d",
		finalCompleted, totalElapsed.Round(time.Millisecond), rate,
		driftCount.Load(), submitErrors.Load())

	// ─────────────────────────────────────────────────────────────
	// Verdict
	// ─────────────────────────────────────────────────────────────

	if driftCount.Load() > 0 {
		if d := firstDriftDetail.Load(); d != nil {
			t.Logf("FIRST_DRIFT_EXAMPLE worker=%d iter=%d", d.workerID, d.iteration)
			if d.hashDrifted {
				t.Logf("  canonical_hash drift: first=%s second=%s",
					safeHashPrefix(d.hashFirst), safeHashPrefix(d.hashSecond))
			}
			if d.timeDrifted {
				t.Logf("  log_time_micros drift: first=%v second=%v",
					d.timeFirst, d.timeSecond)
			}
			if d.sigDrifted {
				t.Logf("  signature drift: first=%s second=%s",
					safeHashPrefix(d.sigFirst), safeHashPrefix(d.sigSecond))
			}
		}
		t.Fatalf("scale-determinism: byte-identity violated — %d drifts in %d pairs. "+
			"Drift type → regression layer: "+
			"canonical_hash = wire-construction mutation; "+
			"log_time_micros = ledger persisted-replay regression; "+
			"signature = SDK RFC 6979 regression OR random state in the signed payload.",
			driftCount.Load(), finalCompleted)
	}

	if submitErrors.Load() > 0 {
		t.Fatalf("scale-determinism: %d submission errors (see submit_error[N] log lines above)",
			submitErrors.Load())
	}

	if finalCompleted < target {
		t.Fatalf("scale-determinism: only %d/%d pairs completed before deadline (%s). "+
			"Increase ATTESTA_SCALE_DETERMINISM_MAX_DURATION or reduce N.",
			finalCompleted, target, maxDuration)
	}

	t.Logf("scale-determinism PASS: %d pairs end-to-end, all byte-identical "+
		"(canonical_hash + log_time_micros + signature)", finalCompleted)
}

// safeHashPrefix returns the first 16 chars of a hex hash, or the
// whole string if shorter. Used in drift logging so the example
// line stays readable.
func safeHashPrefix(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
