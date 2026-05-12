/*
FILE PATH: tests/chaos/harness/invariants.go

Invariant assertions for chaos tests — what every post-kill,
post-restart test must verify before declaring success. Five
properties, each readable from durable Postgres state:

  1. entry_index row count == expected_count
  2. entry_index sequence_number space is contiguous [0, count-1]
  3. zero gaps: (MAX(seq)+1) - COUNT(*) == 0
  4. zero leapfrog: (cursor+1) - COUNT(smt_leaves) == 0
  5. SMT root reconstructible: smt_reconstruction.Reconstruct().Match

(1-4) are cheap COUNT/MIN/MAX queries. (5) walks every leaf so
it's heavier but absolutely load-bearing — without it we'd
declare success on a tree whose root is internally inconsistent.

Plus drain helpers — WaitForDrain blocks until the ledger has
processed every entry the test has submitted (ship.HWM catches
up to the submitted count, smt_leaves grows to match
entry_index).
*/
package harness

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/tests/chaos/smt_reconstruction"
)

// Counts is a snapshot of the diagnostic counters used by
// every invariant assertion. Read in one batch via a single
// serializable txn so the snapshot is internally consistent.
type Counts struct {
	EntryIndex   int64
	SMTLeaves    int64
	BuilderCursor int64
	MaxSeq       int64
	MinSeq       int64
	// Gaps    = (MaxSeq+1) - EntryIndex; 0 when contiguous.
	Gaps int64
	// Leapfrog = (BuilderCursor+1) - SMTLeaves; >0 means cursor
	// advanced past missing leaves (real bug if persistent).
	Leapfrog int64
}

// SnapshotCounts queries the test PG database for the five
// diagnostic counters + derives Gaps + Leapfrog. All reads inside
// a single transaction so a builder commit landing mid-snapshot
// doesn't produce a read-skew false positive.
func (h *Harness) SnapshotCounts(ctx context.Context) (Counts, error) {
	var c Counts
	tx, err := h.pg.Pool.Begin(ctx)
	if err != nil {
		return c, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"); err != nil {
		// Older PG may not allow SET TRANSACTION here; fall back.
	}

	// entry_index count + MIN/MAX
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(MIN(sequence_number), 0), COALESCE(MAX(sequence_number), -1)
		 FROM entry_index`,
	).Scan(&c.EntryIndex, &c.MinSeq, &c.MaxSeq); err != nil {
		return c, fmt.Errorf("entry_index counts: %w", err)
	}

	// smt_leaves count
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM smt_leaves`).Scan(&c.SMTLeaves); err != nil {
		return c, fmt.Errorf("smt_leaves count: %w", err)
	}

	// builder cursor (may be missing if no commit landed yet)
	row := tx.QueryRow(ctx,
		`SELECT COALESCE(last_processed_sequence, -1) FROM builder_cursor WHERE id = 1`)
	if err := row.Scan(&c.BuilderCursor); err != nil {
		// Treat "no row" as cursor=-1 (pre-first-commit state).
		c.BuilderCursor = -1
	}

	// Derived: Gaps + Leapfrog
	if c.MaxSeq >= 0 {
		c.Gaps = (c.MaxSeq + 1) - c.EntryIndex
	}
	if c.BuilderCursor >= 0 {
		c.Leapfrog = (c.BuilderCursor + 1) - c.SMTLeaves
	}
	return c, nil
}

// WaitForDrain polls SnapshotCounts until entry_index.EntryIndex
// == expected AND smt_leaves == expected AND Gaps == 0 AND
// Leapfrog == 0, OR ctx/timeout expires.
//
// Used by chaos tests after Submit + Restart cycles: "wait for
// the system to finish processing everything we submitted before
// asserting invariants".
//
// On timeout, returns the last counts in the error string so
// the failure log includes the stuck-state diagnostic.
func (h *Harness) WaitForDrain(ctx context.Context, expected int64, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var last Counts
	for {
		c, err := h.SnapshotCounts(ctx)
		if err == nil {
			last = c
			if c.EntryIndex == expected &&
				c.SMTLeaves == expected &&
				c.Gaps == 0 &&
				c.Leapfrog == 0 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("drain timeout after %v: expected=%d entry_index=%d smt_leaves=%d gaps=%d leapfrog=%d cursor=%d max_seq=%d (%w)",
				timeout, expected, last.EntryIndex, last.SMTLeaves,
				last.Gaps, last.Leapfrog, last.BuilderCursor,
				last.MaxSeq, ctx.Err())
		case <-ticker.C:
		}
	}
}

// AssertInvariants is the load-bearing post-test check. Calls
// t.Fatalf on any failure:
//
//   - entry_index row count == expected
//   - sequence space is contiguous [0, expected-1] (MinSeq=0,
//     MaxSeq=expected-1, Gaps=0)
//   - smt_leaves count == expected
//   - Leapfrog == 0
//   - smt_reconstruction.Reconstruct().Match == true
//
// All five must hold for the chaos test to pass.
func (h *Harness) AssertInvariants(ctx context.Context, t *testing.T, expected int64) {
	t.Helper()

	c, err := h.SnapshotCounts(ctx)
	if err != nil {
		t.Fatalf("AssertInvariants: SnapshotCounts: %v", err)
	}

	if c.EntryIndex != expected {
		t.Fatalf("entry_index row count = %d, want %d", c.EntryIndex, expected)
	}
	if c.SMTLeaves != expected {
		t.Fatalf("smt_leaves count = %d, want %d (builder didn't catch up)",
			c.SMTLeaves, expected)
	}
	if c.Gaps != 0 {
		t.Fatalf("entry_index has %d gaps (MaxSeq=%d, count=%d)",
			c.Gaps, c.MaxSeq, c.EntryIndex)
	}
	if c.Leapfrog != 0 {
		t.Fatalf("builder cursor leapfrogged by %d (cursor=%d, smt_leaves=%d)",
			c.Leapfrog, c.BuilderCursor, c.SMTLeaves)
	}
	if expected > 0 {
		if c.MinSeq != 0 {
			t.Fatalf("MIN(sequence_number) = %d, want 0", c.MinSeq)
		}
		if c.MaxSeq != expected-1 {
			t.Fatalf("MAX(sequence_number) = %d, want %d",
				c.MaxSeq, expected-1)
		}
	}

	// SMT root reconstruction — heaviest check, last so the
	// cheaper assertions fail-fast.
	result, err := smt_reconstruction.Reconstruct(ctx, h.pg.Pool)
	if err != nil {
		t.Fatalf("SMT reconstruct: %v", err)
	}
	if !result.Match {
		t.Fatalf("%s", result.FormatMismatch())
	}
	if result.LeafCount != int(expected) {
		t.Fatalf("SMT reconstruction loaded %d leaves, want %d",
			result.LeafCount, expected)
	}
}

// AssertNo503DuringSubmissions reports whether the submitter
// saw any 503 responses during its submission run. Some chaos
// tests assert ZERO 503s (kill-restart shouldn't break admission);
// the backpressure test asserts AT LEAST ONE 503 (witnesses-down
// MUST trigger backpressure).
type BackpressureObservation struct {
	Saw503        bool
	Saw503Count   int
	RetryAfterSet bool
}

// CollectBackpressure scans the submitter's recent SubmitResult
// outcomes (caller is responsible for collecting them) and
// returns aggregate observations. Used by the backpressure test
// to confirm 503 + Retry-After fired.
func CollectBackpressure(results []SubmitResult) BackpressureObservation {
	var obs BackpressureObservation
	for _, r := range results {
		if r.StatusCode == 503 {
			obs.Saw503 = true
			obs.Saw503Count++
			if r.RetryAfter != "" {
				obs.RetryAfterSet = true
			}
		}
	}
	return obs
}
