/*
FILE PATH: tests/chaos/harness/invariants.go

Invariant assertions for chaos tests — what every post-kill,
post-restart test must verify before declaring success. Five
properties, each readable from durable Postgres state:

 1. entry_index PRIMARY count == expected (rows with status<>2)
 2. entry_index TOTAL count == expected + ghost-leaf count
 3. zero gaps: every Tessera seq has a row (primary or ghost)
 4. smt_leaves count == expected (ghosts are NOT SMT leaves)
 5. SMT root reconstructible: smt_reconstruction.Reconstruct().Match

(1-4) are cheap COUNT/MIN/MAX queries plus a stderr scan. (5)
walks every leaf so it's heavier but absolutely load-bearing —
without it we'd declare success on a tree whose root is
internally inconsistent.

GHOST LEAVES + CONTIGUITY

Under the v0.4.1+ "Ghost Leaf" recovery model (see migration
0006), a Tessera antispam dedup gap across a crash produces a
duplicate Tessera leaf at a fresh seq whose canonical_hash
already lives at a PRIMARY seq in entry_index. The committer's
flushBatch:

 1. INSERT the new row with `ON CONFLICT (canonical_hash) DO
    NOTHING` — partial unique index admits one PRIMARY per hash.
 2. For each skipped row, write a GHOST row (status=2) at the
    Tessera-assigned seq, carrying the same canonical_hash.

Result: entry_index has rows for EVERY Tessera-assigned seq
(no gaps). PRIMARY rows are unique per canonical_hash; ghost
rows redirect to their primaries via FetchPrimarySeqByHash.

The harness counts ghost rows from the ledger's stderr (each
recovery emits the stable ghostLeafMarker WARN line) and
asserts the projection arithmetic:

	total = primaries + ghosts
	primaries == expected
	smt_leaves == expected  (ghosts not in SMT)
	MaxSeq == expected - 1 + ghosts (Tessera assigned that many seqs)
	Gaps == 0                       (every seq has a row)

Plus drain helpers — WaitForDrain blocks until the ledger has
processed every entry the test has submitted (ship.HWM catches
up to the submitted count, smt_leaves grows to match the
primary entry_index count).
*/
package harness

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ledger/tests/chaos/smt_reconstruction"
)

// ghostLeafMarker is the stable substring the harness greps for
// in subprocess stderr to count canonical_hash collision
// recoveries (ghost leaves). MUST match the WARN log line emitted
// by sequencer/committer.go's flushBatch when the Ghost Leaf path
// fires. Stable; do not change without updating both sides.
const ghostLeafMarker = "PG canonical_hash collision"

// Counts is a snapshot of the diagnostic counters used by
// every invariant assertion. Read in one batch via a single
// serializable txn so the snapshot is internally consistent.
//
// EntryIndex counts PRIMARY rows only (status<>2). Tests compare
// it directly against expected, since ghost rows are an internal
// recovery artifact and not part of the "entries submitted" count.
//
// EntryIndexTotal counts ALL rows including ghosts. Used for the
// contiguity invariant: every Tessera seq has a row (primary or
// ghost). EntryIndexTotal == MaxSeq + 1 when contiguous.
//
// EntryIndexGhost counts status=2 rows. Equals the canonical_hash
// collision recovery count under the new Ghost Leaf design.
type Counts struct {
	EntryIndex      int64 // primary rows (status<>2)
	EntryIndexTotal int64 // all rows (status<>2 + status=2)
	EntryIndexGhost int64 // ghost rows (status=2)
	SMTLeaves       int64
	BuilderCursor   int64
	MaxSeq          int64
	MinSeq          int64
	// Gaps = (MaxSeq+1) - EntryIndexTotal; must be 0 under Ghost
	// Leaf semantics (every Tessera seq has a row).
	Gaps int64
	// Leapfrog = (BuilderCursor+1) - SMTLeaves - EntryIndexGhost;
	// >0 means cursor advanced past missing live leaves (real bug).
	// Ghost rows are expected to advance the cursor without
	// producing SMT leaves, so they're subtracted from the gap.
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

	// entry_index counts split by status. The primary count
	// (status<>2) is what "expected" compares against; the total
	// (status<>2 + status=2) is what should equal MaxSeq+1 under
	// the no-gaps contiguity invariant.
	if err := tx.QueryRow(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE status <> 2),
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 2),
			COALESCE(MIN(sequence_number), 0),
			COALESCE(MAX(sequence_number), -1)
		 FROM entry_index`,
	).Scan(&c.EntryIndex, &c.EntryIndexTotal, &c.EntryIndexGhost,
		&c.MinSeq, &c.MaxSeq); err != nil {
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

	// Derived: Gaps (TOTAL space - rows) + Leapfrog (cursor moved
	// past live leaves; ghosts don't produce SMT leaves so they
	// reduce the leapfrog signal accordingly).
	if c.MaxSeq >= 0 {
		c.Gaps = (c.MaxSeq + 1) - c.EntryIndexTotal
	}
	if c.BuilderCursor >= 0 {
		c.Leapfrog = (c.BuilderCursor + 1) - c.SMTLeaves - c.EntryIndexGhost
	}
	return c, nil
}

// CountGhostLeafRecoveries returns the number of canonical_hash
// collision recoveries the live subprocess has logged. Scans the
// captured stderr for the stable ghostLeafMarker substring; each
// occurrence corresponds to one ghost leaf produced by the
// committer's Ghost Leaf path.
//
// Returns 0 when there's no Process attached (cleanup race) or
// when no collisions have fired (steady state).
func (h *Harness) CountGhostLeafRecoveries() int {
	if h.process == nil {
		return 0
	}
	stderr := h.process.StderrSnapshot()
	return strings.Count(stderr, ghostLeafMarker)
}

// WaitForDrain polls SnapshotCounts until:
//
//	primary entry_index rows == expected
//	smt_leaves == expected
//	gaps == 0 (every Tessera seq has a row, primary or ghost)
//	leapfrog == 0 (no missing live leaves)
//	ghost-row count in PG == ghost-row count in stderr log
//
// The last condition rules out "phantom" ghost rows: every ghost
// row in PG must correspond to a stderr-logged collision recovery,
// otherwise an unaccounted ghost row indicates the recovery
// pipeline produced one without the expected log line — a
// silent-error case the harness will not allow.
//
// Used by chaos tests after Submit + Restart cycles. On timeout,
// returns the last counts in the error string so the failure log
// includes the stuck-state diagnostic.
func (h *Harness) WaitForDrain(ctx context.Context, expected int64, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var last Counts
	var lastGhostLeaves int64
	for {
		c, err := h.SnapshotCounts(ctx)
		if err == nil {
			last = c
			ghosts := int64(h.CountGhostLeafRecoveries())
			lastGhostLeaves = ghosts
			if c.EntryIndex == expected &&
				c.SMTLeaves == expected &&
				c.Gaps == 0 &&
				c.Leapfrog == 0 &&
				c.EntryIndexGhost == ghosts {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("drain timeout after %v: expected=%d entry_index=%d entry_index_total=%d ghost_rows_pg=%d ghost_rows_log=%d smt_leaves=%d gaps=%d leapfrog=%d cursor=%d max_seq=%d (%w)",
				timeout, expected, last.EntryIndex, last.EntryIndexTotal,
				last.EntryIndexGhost, lastGhostLeaves,
				last.SMTLeaves, last.Gaps, last.Leapfrog,
				last.BuilderCursor, last.MaxSeq, ctx.Err())
		case <-ticker.C:
		}
	}
}

// AssertInvariants is the load-bearing post-test check. Calls
// t.Fatalf on any failure:
//
//   - primary entry_index row count == expected
//   - PG ghost-row count == stderr-logged ghost-leaf count
//   - smt_leaves count == expected
//   - Gaps == 0 (every Tessera seq has a row)
//   - Leapfrog == 0 (no missing live leaves)
//   - MaxSeq == expected - 1 + ghost_leaves (every Tessera seq
//     accounted for in the [0, MaxSeq] contiguous space)
//   - smt_reconstruction.Reconstruct().Match == true
//
// All seven must hold. Ghost rows preserve contiguity; they are
// expected only when the live subprocess emitted matching
// collision-recovery WARN lines.
func (h *Harness) AssertInvariants(ctx context.Context, t *testing.T, expected int64) {
	t.Helper()

	c, err := h.SnapshotCounts(ctx)
	if err != nil {
		t.Fatalf("AssertInvariants: SnapshotCounts: %v", err)
	}
	ghostLeaves := int64(h.CountGhostLeafRecoveries())

	if c.EntryIndex != expected {
		t.Fatalf("entry_index primary count = %d, want %d (ghost_rows_pg=%d, ghost_rows_log=%d)",
			c.EntryIndex, expected, c.EntryIndexGhost, ghostLeaves)
	}
	if c.EntryIndexGhost != ghostLeaves {
		t.Fatalf("entry_index ghost rows in PG = %d, want %d (from stderr log) — phantom ghost row OR missed log line",
			c.EntryIndexGhost, ghostLeaves)
	}
	if c.SMTLeaves != expected {
		t.Fatalf("smt_leaves count = %d, want %d (builder didn't catch up; ghost_leaves=%d)",
			c.SMTLeaves, expected, ghostLeaves)
	}
	if c.Gaps != 0 {
		t.Fatalf("entry_index has %d gaps (MaxSeq=%d, total=%d) — Tessera assigned seqs missing rows; ghost-leaf path failed",
			c.Gaps, c.MaxSeq, c.EntryIndexTotal)
	}
	if c.Leapfrog != 0 {
		t.Fatalf("builder cursor leapfrog = %d (cursor=%d, smt_leaves=%d, ghost=%d) — missing live-leaf bug",
			c.Leapfrog, c.BuilderCursor, c.SMTLeaves, c.EntryIndexGhost)
	}
	if expected > 0 {
		if c.MinSeq != 0 {
			t.Fatalf("MIN(sequence_number) = %d, want 0", c.MinSeq)
		}
		// MaxSeq is expected-1 + ghostLeaves: the primary entries
		// occupy expected seqs, plus one ghost-leaf seq slot per
		// recovery sits in the seq space above the primary max.
		// Total rows occupy [0, MaxSeq] contiguously.
		wantMax := expected - 1 + ghostLeaves
		if c.MaxSeq != wantMax {
			t.Fatalf("MAX(sequence_number) = %d, want %d (expected-1=%d + ghost_leaves=%d)",
				c.MaxSeq, wantMax, expected-1, ghostLeaves)
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
