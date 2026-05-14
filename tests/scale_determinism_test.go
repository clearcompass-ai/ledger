//go:build scale
// +build scale

/*
FILE PATH: tests/scale_determinism_test.go

At-scale validation of the P5 idempotent-replay contract:

  byte-identical wire input → byte-identical SCT bytes

The single-shot version of this test is
TestHTTP_IdempotentReplay_ByteIdenticalSCT (one pair). This file
extends the same assertion to N pairs concurrently — proves the
contract holds under realistic submitter load, not just in the
single-request happy path.

# WHAT IT VALIDATES (END-TO-END)

  1. SDK primitive determinism (attesta v1.5.2 RFC 6979 ECDSA).
     If the primitive ever regressed to random-k, every pair would
     drift on `signature`.

  2. Ledger dedup-and-replay path. canonical_hash + log_time_micros
     must be persisted at first admission and returned verbatim on
     replay. Drift in either field means the dedup branch is
     re-deriving instead of replaying.

  3. Pipeline integrity under concurrency. N submitter goroutines,
     each issuing (first, second) pairs in tight succession.
     Catches any per-request mutable state (timestamps, nonces,
     server-side state) that would leak into the SCT canonicalization.

# WHAT FAILURE LOOKS LIKE

  Per-pair drift is reported with the seq, hash prefix, and which
  field drifted (canonical_hash | log_time_micros | signature).
  A run that passes today + fails tomorrow on signature drift only
  → SDK regression. Drift on log_time_micros → ledger persistence
  regression. Drift on canonical_hash → wire-construction regression
  (would surface upstream of the SCT contract).

# HOW TO RUN

  Direct:
    ATTESTA_SCALE_DETERMINISM_N=10000 \
    ATTESTA_SCALE_DETERMINISM_CONCURRENCY=8 \
    ATTESTA_TEST_DSN=postgres://... \
    go test -tags=scale -count=1 -timeout=15m \
      -run TestScale_DeterministicReplay -v ./tests/

  Via wrapper script:
    ./scripts/run-scale-determinism.sh

# DEFAULTS

  N = 1000 entries (2000 submissions) — fast smoke; ~10s.
  CONCURRENCY = 8 — same as the soak default.
  P99 = 200ms — submit p99 ceiling; soft check only (logged, not
  failed) because the focus is determinism, not throughput.
*/
package tests

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// ─────────────────────────────────────────────────────────────────
// Env tuning
// ─────────────────────────────────────────────────────────────────

func getScaleDeterminismN() int { return scaleDetEnvInt("ATTESTA_SCALE_DETERMINISM_N", 1000) }

func getScaleDeterminismConcurrency() int {
	return scaleDetEnvInt("ATTESTA_SCALE_DETERMINISM_CONCURRENCY", 8)
}

func getScaleDeterminismP99Ms() int {
	return scaleDetEnvInt("ATTESTA_SCALE_DETERMINISM_P99_MS", 200)
}

// scaleDetEnvInt: file-local helper. Distinct name from
// scale_test.go::getScaleN / soak_test.go::envInt so the three
// scale/soak files can coexist in a future build that activates
// multiple tags.
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
// pair: tracks the two SCTs returned for a single payload
// ─────────────────────────────────────────────────────────────────

type determinismPair struct {
	idx           int
	canonicalHash string
	first         map[string]any
	second        map[string]any
	firstLatency  time.Duration
	secondLatency time.Duration
}

// ─────────────────────────────────────────────────────────────────
// TestScale_DeterministicReplay — N pairs, concurrent
// ─────────────────────────────────────────────────────────────────

func TestScale_DeterministicReplay(t *testing.T) {
	n := getScaleDeterminismN()
	concurrency := getScaleDeterminismConcurrency()
	p99BoundMs := getScaleDeterminismP99Ms()
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > n {
		concurrency = n
	}

	op := startTestLedger(t)
	op.seedSession(t, "tok-det-scale", "did:example:det-scale-exchange", int64(n)*4)

	t.Logf("scale-determinism: n=%d concurrency=%d p99_bound_ms=%d", n, concurrency, p99BoundMs)

	// Pre-build N unique wire envelopes. Each is signed once at
	// build time; both submissions of the pair re-send byte-identical
	// bytes (that's the input invariant we're testing).
	wires := make([][]byte, n)
	for i := 0; i < n; i++ {
		wires[i] = buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:det-scale-signer",
		}, []byte(fmt.Sprintf("scale-det-payload-%010d", i)))
	}

	pairs := make([]determinismPair, n)
	var (
		submitErrors atomic.Int64
		completed    atomic.Int64
	)

	// Worker goroutines pull pair indices from a single channel.
	// Each worker submits the SAME wire twice in sequence, captures
	// both SCTs, and emits the pair. Sequential submission within a
	// worker keeps the second clearly a replay (the dedup path is
	// what we're validating). Across workers, submissions are
	// concurrent — that's the realistic load shape.
	jobCh := make(chan int, n)
	for i := 0; i < n; i++ {
		jobCh <- i
	}
	close(jobCh)

	startTotal := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				t1 := time.Now()
				first := submitEntry(t, op.BaseURL, "tok-det-scale", wires[idx])
				if first == nil {
					submitErrors.Add(1)
					continue
				}
				firstLatency := time.Since(t1)

				t2 := time.Now()
				second := submitEntry(t, op.BaseURL, "tok-det-scale", wires[idx])
				if second == nil {
					submitErrors.Add(1)
					continue
				}
				secondLatency := time.Since(t2)

				hashStr, _ := first["canonical_hash"].(string)
				pairs[idx] = determinismPair{
					idx:           idx,
					canonicalHash: hashStr,
					first:         first,
					second:        second,
					firstLatency:  firstLatency,
					secondLatency: secondLatency,
				}
				c := completed.Add(1)
				// Progress every 10% of N for long runs.
				if n >= 100 && c%int64(n/10) == 0 {
					rate := float64(c) / time.Since(startTotal).Seconds()
					t.Logf("  scale-determinism progress: pairs=%d/%d (%.0f pairs/sec)",
						c, n, rate)
				}
			}
		}()
	}
	wg.Wait()

	totalElapsed := time.Since(startTotal)
	t.Logf("scale-determinism: %d pairs submitted in %s (%.0f pairs/sec, %d errors)",
		completed.Load(), totalElapsed,
		float64(completed.Load())/totalElapsed.Seconds(),
		submitErrors.Load())

	if errs := submitErrors.Load(); errs > 0 {
		t.Fatalf("scale-determinism: %d submission errors", errs)
	}
	if completed.Load() != int64(n) {
		t.Fatalf("scale-determinism: completed=%d, expected %d", completed.Load(), n)
	}

	// ─────────────────────────────────────────────────────────────
	// Byte-identity verification — the load-bearing assertion
	// ─────────────────────────────────────────────────────────────

	var (
		hashDrift  int
		timeDrift  int
		sigDrift   int
		firstMismatchExample *determinismPair
	)
	for i := range pairs {
		p := &pairs[i]
		if p.first == nil || p.second == nil {
			continue
		}
		mismatch := false
		if p.first["canonical_hash"] != p.second["canonical_hash"] {
			hashDrift++
			mismatch = true
		}
		if p.first["log_time_micros"] != p.second["log_time_micros"] {
			timeDrift++
			mismatch = true
		}
		if p.first["signature"] != p.second["signature"] {
			sigDrift++
			mismatch = true
		}
		if mismatch && firstMismatchExample == nil {
			firstMismatchExample = p
		}
	}

	if hashDrift+timeDrift+sigDrift > 0 {
		// Print one detailed example so the operator can see WHAT
		// drifted before drowning in counts.
		if firstMismatchExample != nil {
			t.Logf("FIRST_DRIFT_EXAMPLE pair[%d] hash_prefix=%s",
				firstMismatchExample.idx,
				safeHashPrefix(firstMismatchExample.canonicalHash))
			t.Logf("  first.canonical_hash   = %v", firstMismatchExample.first["canonical_hash"])
			t.Logf("  second.canonical_hash  = %v", firstMismatchExample.second["canonical_hash"])
			t.Logf("  first.log_time_micros  = %v", firstMismatchExample.first["log_time_micros"])
			t.Logf("  second.log_time_micros = %v", firstMismatchExample.second["log_time_micros"])
			t.Logf("  first.signature        = %v", firstMismatchExample.first["signature"])
			t.Logf("  second.signature       = %v", firstMismatchExample.second["signature"])
		}
		t.Fatalf("scale-determinism: byte-identity violated — hash_drift=%d "+
			"time_drift=%d sig_drift=%d (n=%d). "+
			"Each drift type points at a distinct regression: "+
			"hash_drift = wire-construction mutation; "+
			"time_drift = ledger persisted-replay regression; "+
			"sig_drift = SDK RFC 6979 regression OR something mixing fresh random state into the signed payload.",
			hashDrift, timeDrift, sigDrift, n)
	}

	// ─────────────────────────────────────────────────────────────
	// Latency reporting — soft check on submit p99
	// ─────────────────────────────────────────────────────────────

	allLatencies := make([]time.Duration, 0, 2*n)
	for _, p := range pairs {
		if p.first != nil {
			allLatencies = append(allLatencies, p.firstLatency)
			allLatencies = append(allLatencies, p.secondLatency)
		}
	}
	sort.Slice(allLatencies, func(i, j int) bool { return allLatencies[i] < allLatencies[j] })
	p50 := allLatencies[len(allLatencies)*50/100]
	p99 := allLatencies[len(allLatencies)*99/100]
	p99Ms := p99.Milliseconds()
	t.Logf("scale-determinism: submit latency p50=%s p99=%s (bound=%dms)",
		p50.Round(time.Microsecond), p99.Round(time.Microsecond), p99BoundMs)
	if p99Ms > int64(p99BoundMs) {
		t.Logf("WARN: submit p99=%dms exceeds bound=%dms (soft check — determinism "+
			"contract still verified above)", p99Ms, p99BoundMs)
	}

	t.Logf("scale-determinism PASS: %d pairs, all byte-identical "+
		"(canonical_hash + log_time_micros + signature)", n)
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

// (unused context import retained for symmetry with scale_test.go
// helpers; if the determinism test later grows a Postgres consistency
// check it'll need ctx)
var _ = context.Background
