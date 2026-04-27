/*
FILE PATH: tests/scale_test.go

Scale tests. Measures builder throughput, sequence allocation rate,
Postgres write behavior, and queue drain time under sustained load.

Gated by ORTHOLOG_TEST_DSN — skips without Postgres.
Entry count configurable via ORTHOLOG_SCALE_N (default 1,000,000).

POST-WAVE-1.5 NOTES:
  - Wire format used in HTTP throughput tests is protocol v5.
  - Mode A throughput test (TestScale_HTTPAdmission_10K) exercises the
    fast path (authenticated, no stamp).
  - Mode B throughput test (TestScale_HTTPAdmission_ModeB_1K) exercises
    the slow path (compute stamp at low difficulty for tractable runtime).

Run:

	ORTHOLOG_TEST_DSN="postgres://ortholog:ortholog@localhost:5432/ortholog_test?sslmode=disable" \
	  go test ./tests/ -v -count=1 -run TestScale -timeout 30m

	# Start smaller:
	ORTHOLOG_SCALE_N=100000 go test ./tests/ -v -count=1 -run TestScale -timeout 30m
*/
package tests

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	optessera "github.com/clearcompass-ai/ortholog-operator/tessera"
)

// getScaleN returns the entry count from ORTHOLOG_SCALE_N (default 1M).
func getScaleN() int {
	if v := os.Getenv("ORTHOLOG_SCALE_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 1_000_000
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. Sequence Allocation Throughput
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_SequenceAllocation(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	const N = 100_000
	start := time.Now()
	for i := 0; i < N; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = es.NextSequence(ctx, tx)
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	elapsed := time.Since(start)
	rate := float64(N) / elapsed.Seconds()
	t.Logf("SEQUENCE ALLOCATION: %d sequences in %s (%.0f seq/sec)", N, elapsed, rate)

	if rate < 1000 {
		t.Logf("WARNING: sequence rate %.0f/sec is below 1K/sec — may bottleneck admission", rate)
	}
}

func TestScale_SequenceAllocation_Concurrent(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	const perGoroutine = 10_000
	const goroutines = 10
	var total atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				tx, err := pool.Begin(ctx)
				if err != nil {
					return
				}
				_, err = es.NextSequence(ctx, tx)
				if err != nil {
					tx.Rollback(ctx)
					return
				}
				tx.Commit(ctx)
				total.Add(1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	rate := float64(total.Load()) / elapsed.Seconds()
	t.Logf("CONCURRENT SEQUENCE: %d sequences in %s (%.0f seq/sec, %d goroutines)",
		total.Load(), elapsed, rate, goroutines)
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Bulk Entry Insertion (measures Postgres write throughput)
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_BulkInsert(t *testing.T) {
	pool := connectPostgres(t) // No cleanup clean — QueryIndex reads this data.
	ctx := context.Background()
	cleanTables(t, pool) // Clean at start only.
	N := getScaleN()

	t.Logf("inserting %d entries into Postgres...", N)

	const batchSize = 10_000
	totalInserted := 0
	start := time.Now()
	reportEvery := N / 10
	if reportEvery == 0 {
		reportEvery = 1
	}

	for batch := 0; batch < N/batchSize; batch++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin batch %d: %v", batch, err)
		}

		for i := 0; i < batchSize; i++ {
			seq := uint64(batch*batchSize + i + 1)
			signerIdx := seq / 100
			payload := make([]byte, 8)
			binary.BigEndian.PutUint64(payload, seq)

			entry := makeEntry(t, envelope.ControlHeader{
				SignerDID: fmt.Sprintf("did:example:signer%d", signerIdx),
			}, payload)
			hash := envelope.EntryIdentity(entry)

			_, err := tx.Exec(ctx, `
				INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
					sig_algorithm_id, signer_did)
				VALUES ($1, $2, $3, $4, $5)`,
				seq, hash[:], time.Now().UTC(),
				uint16(1), fmt.Sprintf("did:example:signer%d", signerIdx),
			)
			if err != nil {
				tx.Rollback(ctx)
				t.Fatalf("insert seq=%d: %v", seq, err)
			}
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit batch %d: %v", batch, err)
		}

		totalInserted += batchSize
		if totalInserted%reportEvery == 0 {
			elapsed := time.Since(start)
			rate := float64(totalInserted) / elapsed.Seconds()
			t.Logf("  %d/%d inserted (%.0f entries/sec, %s elapsed)", totalInserted, N, rate, elapsed.Round(time.Second))
		}
	}

	// Handle remainder if N is not divisible by batchSize.
	remainder := N % batchSize
	if remainder > 0 {
		tx, _ := pool.Begin(ctx)
		for i := 0; i < remainder; i++ {
			seq := uint64(totalInserted + i + 1)
			signerIdx := seq / 100
			payload := make([]byte, 8)
			binary.BigEndian.PutUint64(payload, seq)
			entry := makeEntry(t, envelope.ControlHeader{
				SignerDID: fmt.Sprintf("did:example:signer%d", signerIdx),
			}, payload)
			hash := envelope.EntryIdentity(entry)
			tx.Exec(ctx, `
				INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
					sig_algorithm_id, signer_did)
				VALUES ($1, $2, $3, $4, $5)`,
				seq, hash[:], time.Now().UTC(),
				uint16(1), fmt.Sprintf("did:example:signer%d", signerIdx),
			)
		}
		tx.Commit(ctx)
		totalInserted += remainder
	}

	elapsed := time.Since(start)
	rate := float64(totalInserted) / elapsed.Seconds()
	t.Logf("BULK INSERT: %d entries in %s (%.0f entries/sec)", totalInserted, elapsed, rate)

	var count int64
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM entry_index").Scan(&count)
	if count != int64(N) {
		t.Fatalf("expected %d entries, got %d", N, count)
	}

	var tableSize string
	pool.QueryRow(ctx, "SELECT pg_size_pretty(pg_total_relation_size('entry_index'))").Scan(&tableSize)
	t.Logf("entry_index table size: %s", tableSize)
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Query Index Performance at Scale
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_QueryIndex(t *testing.T) {
	pool := connectPostgres(t) // NO clean — reads BulkInsert data
	ctx := context.Background()

	var count int64
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM entry_index").Scan(&count)
	if count < 100_000 {
		t.Skipf("need at least 100K entries (have %d) — run TestScale_BulkInsert first", count)
	}

	// Benchmark raw Postgres index speed (no byte hydration — bytes are in Tessera).
	// This measures the INDEX, not the full OperatorQueryAPI pipeline.

	// SignerDID index hit.
	start := time.Now()
	var signerCount int64
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM entry_index WHERE signer_did = $1`,
		"did:example:signer0").Scan(&signerCount)
	elapsed := time.Since(start)
	t.Logf("QUERY signer_did COUNT: %d results in %s", signerCount, elapsed)

	start = time.Now()
	rows, _ := pool.Query(ctx, `SELECT sequence_number, log_time, sig_algorithm_id
		FROM entry_index WHERE signer_did = $1 ORDER BY sequence_number ASC`,
		"did:example:signer0")
	var rowCount int
	for rows.Next() {
		var seq uint64
		var lt time.Time
		var algo int16
		rows.Scan(&seq, &lt, &algo)
		rowCount++
	}
	rows.Close()
	elapsed = time.Since(start)
	t.Logf("QUERY signer_did FETCH: %d rows in %s", rowCount, elapsed)

	// Scan from middle — PK range.
	start = time.Now()
	rows, _ = pool.Query(ctx, `SELECT sequence_number, log_time, sig_algorithm_id
		FROM entry_index WHERE sequence_number >= $1 ORDER BY sequence_number ASC LIMIT 1000`,
		count/2)
	rowCount = 0
	for rows.Next() {
		var seq uint64
		var lt time.Time
		var algo int16
		rows.Scan(&seq, &lt, &algo)
		rowCount++
	}
	rows.Close()
	elapsed = time.Since(start)
	t.Logf("QUERY scan(mid, 1000): %d rows in %s", rowCount, elapsed)

	// Max scan (10K).
	start = time.Now()
	rows, _ = pool.Query(ctx, `SELECT sequence_number, log_time, sig_algorithm_id
		FROM entry_index WHERE sequence_number >= 1 ORDER BY sequence_number ASC LIMIT 10000`,
	)
	rowCount = 0
	for rows.Next() {
		var seq uint64
		var lt time.Time
		var algo int16
		rows.Scan(&seq, &lt, &algo)
		rowCount++
	}
	rows.Close()
	elapsed = time.Since(start)
	t.Logf("QUERY scan(1, 10000): %d rows in %s", rowCount, elapsed)

	// entry_index row size (should be ~50 bytes, NOT ~600 bytes).
	var avgRowSize string
	pool.QueryRow(ctx, `SELECT pg_size_pretty(pg_total_relation_size('entry_index') / GREATEST(COUNT(*),1))
		FROM entry_index`).Scan(&avgRowSize)
	t.Logf("ENTRY_INDEX avg row size: %s (target: ~50 bytes, no canonical_bytes/sig_bytes)", avgRowSize)
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Builder Throughput — Full Queue Drain
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_BuilderThroughput(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	N := getScaleN()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cleanTables(t, pool)

	// Entry byte store — created BEFORE seeding because seeding writes bytes here.
	entryBytes := optessera.NewInMemoryEntryStore()

	t.Logf("seeding %d entries + queue...", N)

	const batchSize = 10_000
	seedStart := time.Now()
	seeded := 0

	for batch := 0; batch < N/batchSize; batch++ {
		tx, _ := pool.Begin(ctx)
		for i := 0; i < batchSize; i++ {
			seq := uint64(batch*batchSize + i + 1)
			payload := make([]byte, 8)
			binary.BigEndian.PutUint64(payload, seq)

			entry := makeEntry(t, envelope.ControlHeader{
				SignerDID: fmt.Sprintf("did:example:scale-signer%d", seq/100),
			}, payload)
			hash := envelope.EntryIdentity(entry)
			wire := envelope.Serialize(entry)

			tx.Exec(ctx, `
				INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
					sig_algorithm_id, signer_did)
				VALUES ($1, $2, $3, $4, $5)`,
				seq, hash[:], time.Now().UTC(),
				uint16(envelope.SigAlgoECDSA), fmt.Sprintf("did:example:scale-signer%d", seq/100),
			)
			tx.Exec(ctx, `INSERT INTO builder_queue (sequence_number) VALUES ($1)`, seq)
			// v7.75: wire bytes ARE canonical bytes; no separate sig.
			entryBytes.WriteEntry(seq, wire, nil)
		}
		tx.Commit(ctx)
		seeded += batchSize

		if seeded%(N/10) == 0 {
			elapsed := time.Since(seedStart)
			rate := float64(seeded) / elapsed.Seconds()
			t.Logf("  seeded %d/%d (%.0f entries/sec, %s elapsed)", seeded, N, rate, elapsed.Round(time.Second))
		}
	}

	// Remainder.
	remainder := N % batchSize
	if remainder > 0 {
		tx, _ := pool.Begin(ctx)
		for i := 0; i < remainder; i++ {
			seq := uint64(seeded + i + 1)
			payload := make([]byte, 8)
			binary.BigEndian.PutUint64(payload, seq)
			entry := makeEntry(t, envelope.ControlHeader{
				SignerDID: fmt.Sprintf("did:example:scale-signer%d", seq/100),
			}, payload)
			hash := envelope.EntryIdentity(entry)
			wire := envelope.Serialize(entry)
			tx.Exec(ctx, `
				INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
					sig_algorithm_id, signer_did)
				VALUES ($1, $2, $3, $4, $5)`,
				seq, hash[:], time.Now().UTC(),
				uint16(envelope.SigAlgoECDSA), fmt.Sprintf("did:example:scale-signer%d", seq/100),
			)
			tx.Exec(ctx, `INSERT INTO builder_queue (sequence_number) VALUES ($1)`, seq)
			// v7.75: wire bytes ARE canonical bytes; no separate sig.
			entryBytes.WriteEntry(seq, wire, nil)
		}
		tx.Commit(ctx)
		seeded += remainder
	}

	seedElapsed := time.Since(seedStart)
	t.Logf("seeding complete: %d entries in %s (%.0f entries/sec)", seeded, seedElapsed, float64(seeded)/seedElapsed.Seconds())

	var queueCount int64
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM builder_queue WHERE status = 0").Scan(&queueCount)
	t.Logf("queue pending: %d", queueCount)

	// Wire up builder — entryBytes already created above during seeding.
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool, 100_000)
	tree := smt.NewTree(leafStore, nodeCache)
	fetcher := store.NewPostgresEntryFetcher(pool, entryBytes, testLogDID)
	queue := opbuilder.NewQueue(pool)
	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer := sdkbuilder.NewDeltaWindowBuffer(10)
	merkle := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}
	witness := &stubWitnessCosigner{}
	commitPub := opbuilder.NewCommitmentPublisher(
		testLogDID,
		testLogDID,
		opbuilder.CommitmentPublisherConfig{IntervalEntries: 100_000, IntervalTime: 24 * time.Hour},
		func(e *envelope.Entry) error { return nil },
		logger,
	)

	loopCfg := opbuilder.DefaultLoopConfig(testLogDID)
	loopCfg.PollInterval = 10 * time.Millisecond
	loopCfg.BatchSize = 5000

	bl := opbuilder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		queue, fetcher, nil, deltaBuffer, bufferStore, commitPub,
		merkle, witness, logger,
	)

	// Start builder.
	t.Logf("starting builder (batch_size=%d)...", loopCfg.BatchSize)
	buildStart := time.Now()
	go bl.Run(ctx)

	// Poll until queue drained.
	lastPending := int64(N)
	lastReport := time.Now()
	for {
		time.Sleep(1 * time.Second)
		var pending int64
		pool.QueryRow(ctx, "SELECT COUNT(*) FROM builder_queue WHERE status != 2").Scan(&pending)

		if time.Since(lastReport) > 10*time.Second || pending == 0 {
			elapsed := time.Since(buildStart)
			processed := N - int(pending)
			rate := float64(processed) / elapsed.Seconds()
			t.Logf("  builder: %d/%d processed (%.0f entries/sec, %s elapsed)",
				processed, N, rate, elapsed.Round(time.Second))
			lastReport = time.Now()
		}

		if pending == 0 {
			break
		}
		if pending == lastPending {
			var processing int64
			pool.QueryRow(ctx, "SELECT COUNT(*) FROM builder_queue WHERE status = 1").Scan(&processing)
			if processing > 0 {
				continue
			}
		}
		lastPending = pending

		if time.Since(buildStart) > 25*time.Minute {
			t.Fatalf("builder timed out with %d entries pending", pending)
		}
	}

	buildElapsed := time.Since(buildStart)
	cancel()

	rate := float64(N) / buildElapsed.Seconds()
	t.Logf("═══════════════════════════════════════════════════════════")
	t.Logf("BUILDER THROUGHPUT: %d entries in %s", N, buildElapsed.Round(time.Second))
	t.Logf("  Rate:       %.0f entries/sec", rate)
	t.Logf("  Batch size: %d", loopCfg.BatchSize)
	t.Logf("═══════════════════════════════════════════════════════════")

	// Verify completeness.
	var doneCount int64
	pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM builder_queue WHERE status = 2").Scan(&doneCount)
	if doneCount != int64(N) {
		t.Fatalf("expected %d done, got %d", N, doneCount)
	}

	// Table sizes.
	reportTableSizes(t, pool)

	// Dead tuples.
	reportDeadTuples(t, pool)

	// Builder stats.
	batches, entries, errs := bl.Stats()
	t.Logf("  Builder stats: batches=%d entries=%d errors=%d", batches, entries, errs)
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SDK ProcessBatch Throughput (in-memory, no Postgres)
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_SDKProcessBatch(t *testing.T) {
	// Scale benchmark — generates getScaleN() entries (default 1M)
	// and runs them through builder.ProcessBatch + SMT root
	// computation. At N=1M the SMT root walk dominates and the
	// test runs >10 minutes on commodity hardware. Skip under
	// -short so `go test -short ./...` stays fast; opt in via
	// `go test -run TestScale_SDKProcessBatch ./tests/` (or set
	// ORTHOLOG_SCALE_N=1000 for a quicker smoke test).
	if testing.Short() {
		t.Skip("scale benchmark skipped under -short; run without -short or with ORTHOLOG_SCALE_N=1000 for a smoke test")
	}
	N := getScaleN()

	t.Logf("generating %d entries in memory...", N)
	genStart := time.Now()

	entries := make([]*envelope.Entry, N)
	positions := make([]types.LogPosition, N)
	for i := 0; i < N; i++ {
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(i))

		var ap *envelope.AuthorityPath
		if i%5 == 0 {
			v := envelope.AuthoritySameSigner
			ap = &v
		}
		entries[i] = makeEntry(t, envelope.ControlHeader{
			SignerDID:     fmt.Sprintf("did:example:sdk-signer%d", i/100),
			AuthorityPath: ap,
		}, payload)
		positions[i] = types.LogPosition{LogDID: testLogDID, Sequence: uint64(i + 1)}
	}
	t.Logf("generation: %s (%.0f entries/sec)", time.Since(genStart),
		float64(N)/time.Since(genStart).Seconds())

	f := newMockFetcher()
	t.Log("populating mock fetcher...")
	for i, e := range entries {
		f.storeEntry(positions[i], e)
	}
	t.Logf("mock fetcher populated: %d entries", N)

	// Benchmark at different batch sizes.
	for _, bs := range []int{1_000, 10_000, 100_000} {
		if bs > N {
			continue
		}
		treeCopy := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
		bufCopy := sdkbuilder.NewDeltaWindowBuffer(10)

		t.Logf("  starting batch_size=%d (%d iterations)...", bs, (N+bs-1)/bs)
		start := time.Now()
		lastLog := start
		totalLeaves := 0
		processed := 0
		for offset := 0; offset < N; offset += bs {
			end := offset + bs
			if end > N {
				end = N
			}
			result, err := sdkbuilder.ProcessBatch(
				treeCopy, entries[offset:end], positions[offset:end],
				f, nil, testLogDID, bufCopy,
			)
			if err != nil {
				t.Fatalf("ProcessBatch at offset %d: %v", offset, err)
			}
			totalLeaves += result.NewLeafCounts
			if result.UpdatedBuffer != nil {
				bufCopy = result.UpdatedBuffer
			}
			processed += end - offset

			if time.Since(lastLog) > 5*time.Second {
				rate := float64(processed) / time.Since(start).Seconds()
				t.Logf("    batch=%d: %d/%d processed (%.0f entries/sec)", bs, processed, N, rate)
				lastLog = time.Now()
			}
		}
		elapsed := time.Since(start)
		rate := float64(N) / elapsed.Seconds()
		t.Logf("SDK ProcessBatch (batch=%d): %d entries in %s (%.0f entries/sec, %d leaves)",
			bs, N, elapsed.Round(time.Millisecond), rate, totalLeaves)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. HTTP Admission Pipeline Throughput (Mode A — fast path)
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_HTTPAdmission_10K(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-scale", "did:example:exchange-scale", 100_000)

	const N = 10_000
	start := time.Now()
	var errCount int

	for i := 0; i < N; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: fmt.Sprintf("did:example:http-scale%d", i/100),
		}, []byte(fmt.Sprintf("scale-entry-%d", i)))

		result := submitEntry(t, op.BaseURL, "tok-scale", wire)
		if result == nil {
			errCount++
		}

		if (i+1)%(N/10) == 0 {
			elapsed := time.Since(start)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf("  HTTP admission: %d/%d (%.0f entries/sec)", i+1, N, rate)
		}
	}

	elapsed := time.Since(start)
	rate := float64(N) / elapsed.Seconds()
	t.Logf("HTTP ADMISSION (Mode A): %d entries in %s (%.0f entries/sec, %d errors)", N, elapsed, rate, errCount)

	// Wait for builder to drain.
	t.Log("waiting for builder to drain queue...")
	drainStart := time.Now()
	for {
		pending, _ := op.Queue.PendingCount(context.Background())
		if pending == 0 {
			break
		}
		if time.Since(drainStart) > 2*time.Minute {
			t.Fatalf("builder did not drain within 2 minutes (%d pending)", pending)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("builder drain: %s", time.Since(drainStart))
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. HTTP Admission — Mode B (compute stamp) Throughput
//
// Mode B is intentionally slower than Mode A — every submission requires
// a proof-of-work stamp before the operator will accept it. This test
// uses low difficulty (8 bits) to keep runtime tractable while still
// exercising the full SDK admission verification path: the wire-format
// AdmissionProofBody → ProofFromWire adapter → 8-arg VerifyStamp.
//
// Failure modes this test would catch:
//   - ProofFromWire bug → 100% rejection rate
//   - Epoch math drift between client and operator → 100% rejection rate
//   - Difficulty controller returning wrong target → bursty rejections
//   - Operator's epoch acceptance window incorrectly enforced → flaky
// ═════════════════════════════════════════════════════════════════════════════

func TestScale_HTTPAdmission_ModeB_1K(t *testing.T) {
	op := startTestOperator(t)

	// 1K Mode B entries at difficulty 8 → ~50ms per entry on commodity HW.
	// At difficulty 16 (operator default) this would take ~10x longer; we
	// use 8 to keep test runtime under 5 minutes.
	const (
		N          = 1_000
		difficulty = 8
	)

	// First, lower the operator's required difficulty to match what we'll
	// generate. We can't change DifficultyController from the test, so we
	// have to use difficulty == operator.MinDifficulty (8 by default).

	start := time.Now()
	accepted := 0
	rejected := 0

	for i := 0; i < N; i++ {
		header := envelope.ControlHeader{
			SignerDID: fmt.Sprintf("did:example:modeb-scale%d", i/100),
		}
		wire := buildModeBWireEntry(t, header, []byte(fmt.Sprintf("modeb-scale-%d", i)), testLogDID, difficulty)

		req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusAccepted:
			accepted++
		case http.StatusForbidden:
			rejected++
			if i < 3 {
				// Log first few rejections for diagnosis.
				t.Logf("  early rejection #%d: %s", i, body)
			}
		default:
			t.Fatalf("unexpected status %d: %s", resp.StatusCode, body)
		}

		if (i+1)%(N/10) == 0 {
			elapsed := time.Since(start)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf("  Mode B admission: %d/%d (accepted=%d rejected=%d, %.1f entries/sec)",
				i+1, N, accepted, rejected, rate)
		}
	}

	elapsed := time.Since(start)
	rate := float64(N) / elapsed.Seconds()
	t.Logf("HTTP ADMISSION (Mode B): %d entries in %s (%.1f entries/sec)", N, elapsed, rate)
	t.Logf("  Accepted: %d (%.1f%%)", accepted, 100*float64(accepted)/float64(N))
	t.Logf("  Rejected: %d (%.1f%%)", rejected, 100*float64(rejected)/float64(N))

	// Validation: at least 95% should be accepted. Any higher rejection
	// rate suggests a misconfiguration (clock drift, difficulty mismatch)
	// rather than a stamp validity issue.
	if accepted < (95*N)/100 {
		t.Fatalf("Mode B acceptance rate too low: %d/%d (%.1f%%) — investigate clock skew or difficulty config",
			accepted, N, 100*float64(accepted)/float64(N))
	}

	// Wait for builder drain.
	drainStart := time.Now()
	for {
		pending, _ := op.Queue.PendingCount(context.Background())
		if pending == 0 {
			break
		}
		if time.Since(drainStart) > 5*time.Minute {
			t.Fatalf("builder did not drain within 5 minutes (%d pending)", pending)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("builder drain: %s", time.Since(drainStart))
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

func reportTableSizes(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"entry_index", "smt_leaves", "smt_nodes", "builder_queue", "delta_window_buffers"} {
		var size string
		pool.QueryRow(context.Background(),
			fmt.Sprintf("SELECT pg_size_pretty(pg_total_relation_size('%s'))", table)).Scan(&size)
		var rowCount int64
		pool.QueryRow(context.Background(),
			fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&rowCount)
		t.Logf("  %-25s %8s  (%d rows)", table, size, rowCount)
	}
}

func reportDeadTuples(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	rows, _ := pool.Query(context.Background(), `
		SELECT relname, n_live_tup, n_dead_tup, last_autovacuum
		FROM pg_stat_user_tables
		WHERE relname IN ('entry_index', 'smt_leaves', 'builder_queue')
		ORDER BY n_dead_tup DESC`)
	defer rows.Close()
	t.Logf("  %-25s %12s %12s %s", "TABLE", "LIVE", "DEAD", "LAST_VACUUM")
	for rows.Next() {
		var name string
		var live, dead int64
		var lastVacuum *time.Time
		rows.Scan(&name, &live, &dead, &lastVacuum)
		vacStr := "never"
		if lastVacuum != nil {
			vacStr = lastVacuum.Format("15:04:05")
		}
		t.Logf("  %-25s %12d %12d %s", name, live, dead, vacStr)
	}
}

// Suppress unused imports.
var _ = middleware.DefaultDifficultyConfig
