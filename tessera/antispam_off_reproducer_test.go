/*
FILE PATH: tessera/antispam_off_reproducer_test.go

REPRODUCER for the soak's "WAL HWM stuck at 5" failure.

WHAT THIS TEST PINS:

	With Antispam OFF (the test harness's default — see
	tests/witnessed_harness_test.go:132-139, which constructs
	AppenderOptions WITHOUT the Antispam field), concurrent
	AppendLeaf calls from two callers (the sequencer + the builder
	loop) get DISTINCT sequence numbers per hash submitted, even
	when the hash bytes are identical.

	This is by design — the EmbeddedAppender treats every Add as
	a fresh log entry unless an Antispam adapter is wired. But it
	breaks the production assumption in:

	  sequencer/loop.go:236: "Step 4: Tessera AppendLeaf —
	                          antispam-idempotent under retries."

	With antispam off and BOTH the sequencer and the builder
	calling AppendLeaf for the same hashes, Tessera assigns each
	call a different seq. The sequencer writes wal.Sequence(hash,
	tessera_seq) into the WAL's seqIndex; the builder's calls
	consume seqs but don't write to WAL. Result: the WAL seqIndex
	has GAPS at the seqs the builder claimed. The Shipper iterates
	those WAL seqs and ships them. Each shipped seq sends a
	completion. The hwmAdvancer's "contiguous run from HWM+1"
	invariant requires no gaps to advance. The builder's gap-
	claimed seqs never enter the WAL → never get a completion →
	HWM stalls at the first gap.

	The soak's drain trace at hwm=5 stuck-forever, with
	shipped=1000 unique=1000, exactly matches this pattern: the
	first 6 calls (seqs 0..5) happened before the builder caught
	up to entry_index, then the builder started AppendLeaf-ing the
	same hashes, creating sparse seqs from seq=6 onward.

WHAT "INDISPUTABLE EVIDENCE" LOOKS LIKE HERE:

  - Two concurrent AppendLeaf streams produce DISTINCT seqs for
    duplicate hashes when antispam is off.
  - The same hashes against an antispam-on Tessera produce the
    SAME seq (dedup).

	The first half of this test asserts the off case (the bug); a
	follow-up test asserting the on case lives in a separate file
	once we wire the antispam fix.
*/
package tessera

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/storage/posix"
	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"
)

// TestAntispamOff_DuplicateHashGetsDistinctSeqs reproduces the
// soak's HWM-stall root cause: with antispam off, two callers
// AppendLeaf-ing the SAME hash get DIFFERENT seqs back. The
// sequencer's WAL writes are sparse (only its own seqs), so the
// shipper's HWM advancer can't fill the gaps and stalls.
func TestAntispamOff_DuplicateHashGetsDistinctSeqs(t *testing.T) {
	app, _, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	const N = 20
	hashes := make([][32]byte, N)
	for i := 0; i < N; i++ {
		hashes[i] = sha256.Sum256([]byte(fmt.Sprintf("repro-%d", i)))
	}

	// Two concurrent appender streams — sequencer simulation and
	// builder simulation. Each calls AppendLeaf for every hash.
	// With antispam off, each call gets a distinct seq.
	type result struct {
		caller string
		seqs   []uint64
	}
	resCh := make(chan result, 2)
	var wg sync.WaitGroup

	for _, caller := range []string{"sequencer", "builder"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			seqs := make([]uint64, N)
			for i, h := range hashes {
				seq, err := app.AppendLeaf(ctx, h[:])
				if err != nil {
					t.Errorf("%s AppendLeaf(%d): %v", name, i, err)
					return
				}
				seqs[i] = seq
			}
			resCh <- result{caller: name, seqs: seqs}
		}(caller)
	}
	wg.Wait()
	close(resCh)

	var seqA, seqB []uint64
	for r := range resCh {
		switch r.caller {
		case "sequencer":
			seqA = r.seqs
		case "builder":
			seqB = r.seqs
		}
	}

	// Critical assertion: for each hash i, the two callers got
	// DIFFERENT seqs (antispam off → no dedup).
	collisions := 0
	for i := 0; i < N; i++ {
		if seqA[i] == seqB[i] {
			collisions++
		}
	}
	if collisions == N {
		t.Fatalf("antispam-off invariant broken: every duplicate hash got same seq " +
			"(perhaps antispam was enabled? this test relies on antispam OFF)")
	}

	// The combined seq space MUST have 2*N distinct seqs (no overlap),
	// because antispam-off gives each call a fresh seq.
	seen := make(map[uint64]int) // seq → count
	for _, s := range seqA {
		seen[s]++
	}
	for _, s := range seqB {
		seen[s]++
	}
	if len(seen) != 2*N {
		t.Fatalf("expected 2*N=%d distinct seqs across both streams, got %d",
			2*N, len(seen))
	}
	for s, c := range seen {
		if c != 1 {
			t.Fatalf("seq=%d appeared %d times across the two streams (expected 1)", s, c)
		}
	}

	// Now the production-grade question: if the sequencer-side
	// stream is what gets persisted to WAL (via wal.Sequence(hash,
	// tessera_seq)), does the sequencer's seq space have gaps?
	//
	// Sort sequencer's seqs and check for contiguity from min.
	minSeq := seqA[0]
	maxSeq := seqA[0]
	for _, s := range seqA[1:] {
		if s < minSeq {
			minSeq = s
		}
		if s > maxSeq {
			maxSeq = s
		}
	}
	spanCovered := maxSeq - minSeq + 1
	if spanCovered == uint64(N) {
		// Sequencer happened to win every race — no gaps. The
		// soak's stuck-at-5 trace shows this DID NOT happen
		// (6 consecutive then a gap). Without a forced
		// interleaving here, this test's failure mode depends on
		// scheduling — log the lucky-no-gap outcome instead of
		// asserting.
		t.Logf("sequencer-side seqs span %d..%d (size %d) = contiguous; "+
			"in production this race is non-deterministic and will produce "+
			"gaps under load — see the soak's hwm=5 trace.", minSeq, maxSeq, N)
		return
	}
	// Expected case: gaps in the sequencer's seqs because builder
	// claimed seqs in between.
	t.Logf("REPRODUCED: sequencer-side seqs span %d..%d (size %d) but holds %d entries — "+
		"%d gaps where builder's stream claimed seqs. Under the production wiring this "+
		"is what causes wal.seqIndex to be sparse and Shipper.hwmAdvancer to stall.",
		minSeq, maxSeq, spanCovered, N, spanCovered-uint64(N))

	// Now poll head until Tessera's checkpoint reflects both
	// streams' work. Tree size MUST be 2*N (no dedup).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h, err := app.Head()
		if err == nil && h.TreeSize >= uint64(2*N) {
			t.Logf("tree_size=%d (2*N=%d) — confirmed antispam off: every AppendLeaf added a fresh leaf",
				h.TreeSize, 2*N)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tree never reached size %d within deadline — Tessera may not have integrated all calls", 2*N)
}

// TestAntispamOn_DuplicateHashGetsSameSeq is the positive control:
// with antispam wired, duplicate AppendLeaf calls for the SAME hash
// return the SAME seq. This is the dedup invariant the sequencer's
// loop.go:236 comment depends on ("antispam-idempotent under
// retries") and the soak's sequencer+builder co-existence needs.
//
// If this test ever fails, the antispam wiring is broken at the
// AppenderOptions boundary — either the upstream library changed
// or the wiring regression silently broke dedup.
func TestAntispamOn_DuplicateHashGetsSameSeq(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		t.Fatalf("posix.New: %v", err)
	}
	antispam, err := tposixantispam.NewAntispam(ctx,
		filepath.Join(dir, "antispam"), tposixantispam.AntispamOpts{})
	if err != nil {
		t.Fatalf("tposixantispam.NewAntispam: %v", err)
	}

	signer, _, err := GenerateEphemeralSigner("test-antispam-on")
	if err != nil {
		t.Fatalf("GenerateEphemeralSigner: %v", err)
	}
	app, err := NewEmbeddedAppender(ctx, driver, AppenderOptions{
		Origin:             "test-antispam-on",
		Signer:             signer,
		CheckpointInterval: 100 * time.Millisecond,
		BatchSize:          16,
		BatchMaxAge:        50 * time.Millisecond,
		Antispam:           antispam,
	}, nil)
	if err != nil {
		t.Fatalf("NewEmbeddedAppender: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.Close(shutdownCtx)
	})

	const N = 20
	hashes := make([][32]byte, N)
	for i := 0; i < N; i++ {
		hashes[i] = sha256.Sum256([]byte(fmt.Sprintf("antispam-on-%d", i)))
	}

	// Two concurrent streams, identical hash inputs. With antispam
	// ON, both should converge to the same per-hash seq.
	type result struct {
		caller string
		seqs   []uint64
	}
	resCh := make(chan result, 2)
	var wg sync.WaitGroup
	for _, caller := range []string{"sequencer", "builder"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			seqs := make([]uint64, N)
			for i, h := range hashes {
				seq, err := app.AppendLeaf(ctx, h[:])
				if err != nil {
					t.Errorf("%s AppendLeaf(%d): %v", name, i, err)
					return
				}
				seqs[i] = seq
			}
			resCh <- result{caller: name, seqs: seqs}
		}(caller)
	}
	wg.Wait()
	close(resCh)

	var seqA, seqB []uint64
	for r := range resCh {
		switch r.caller {
		case "sequencer":
			seqA = r.seqs
		case "builder":
			seqB = r.seqs
		}
	}

	for i := 0; i < N; i++ {
		if seqA[i] != seqB[i] {
			t.Fatalf("antispam-on dedup failed: hash[%d] got seq=%d from sequencer, seq=%d from builder",
				i, seqA[i], seqB[i])
		}
	}

	// Combined seq space should be exactly N (no extras from racing).
	seen := make(map[uint64]int)
	for _, s := range seqA {
		seen[s]++
	}
	if len(seen) != N {
		t.Fatalf("expected %d distinct seqs total, got %d — duplicate-hash calls allocated new seqs",
			N, len(seen))
	}

	// Tree size should match — each unique hash is one leaf.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h, err := app.Head()
		if err == nil && h.TreeSize >= uint64(N) {
			if h.TreeSize > uint64(N) {
				t.Fatalf("tree_size=%d > N=%d — antispam dedup not effective",
					h.TreeSize, N)
			}
			t.Logf("tree_size=%d == N=%d — antispam dedup working", h.TreeSize, N)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tree never reached size %d within deadline", N)
}
