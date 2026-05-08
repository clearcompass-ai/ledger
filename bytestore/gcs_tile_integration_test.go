//go:build gcs_integration
// +build gcs_integration

/*
FILE PATH:

	bytestore/gcs_tile_integration_test.go

DESCRIPTION:

	Real-GCS-only integration tests for GCSTiles. Build-tag-
	isolated so `go test ./...` never invokes them — these tests
	require a real bucket, real ADC credentials, and real network
	round-trips. Opt-in via:

	    ATTESTA_TEST_GCS_BUCKET=ledger-tile-integration-<your-instance> \
	    GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json \
	    go test -tags=gcs_integration ./bytestore/ -run TestGCSTilesIntegration -v -count=1 -timeout 5m

	The default unit-test path (bytestore/gcs_tile_test.go,
	untagged) covers fake-gcs-server smoke + path-validation +
	constructor defaults and runs in CI. THIS file covers the
	properties only real GCS exercises:

	  - Concurrent reads at scale (1000 parallel goroutines).
	  - MaxTileBytes ceiling against a real 16-MiB+ upload.
	  - ErrNotExist mapping against the live storage.ErrObjectNotExist.
	  - Byte-identical round-trip across the wire (defends against
	    Content-Encoding / compression injection).
	  - Path-traversal rejection BEFORE the GCS API is called
	    (verified by timing — a rejected hostile path must complete
	    in sub-millisecond time, no network round-trip).

KEY ARCHITECTURAL DECISIONS:
  - Reuses requireGCS from gcs_test.go for credentials + cleanup.
    requireGCS skips when env is unset; this file's tests will
    simply skip in the same scenario, so the build tag is the
    ONLY enforcement layer that real GCS is required.
  - Each test gets a per-test prefix (via tilesFor) so concurrent
    runs don't collide and t.Cleanup wipes its own object set.
  - Latency assertion is conservative (p99 < 5s under 1000-way
    concurrency) so flaky cloud weather doesn't fail the test.
    The architectural property pinned is "the backend handles
    1000-parallel reads without serialization or auth-flush";
    the exact latency depends on the runner's network.
  - Tests do NOT exercise the HTTP layer (api.NewTileHandler) —
    that is fully covered by api/tile_handler_test.go with stub
    backends. Re-running the same handler shape against real GCS
    adds no incremental coverage; this file focuses on what only
    real GCS can prove.

OVERVIEW:

	Each test:
	    1. requireGCS(t) returns a configured *GCS or t.Skip.
	    2. tilesFor(t, g) wraps it with a *GCSTiles under a per-
	       test prefix.
	    3. Direct uploadObject puts synthetic bytes (bypasses the
	       entry-layout key scheme used by *GCS.WriteEntry).
	    4. Exercise the contract through the real wire.

KEY DEPENDENCIES:
  - requireGCS, tilesFor, uploadObject (from gcs_test.go and
    gcs_tile_test.go).
  - cloud.google.com/go/storage: live storage.ErrObjectNotExist.
*/
package bytestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) Byte-identical round-trip across the wire
// -------------------------------------------------------------------------------------------------

// TestGCSTilesIntegration_ByteIdenticalRoundTrip_RealGCS uploads
// a non-trivial-sized tile (32 KiB) and asserts the bytes returned
// by ReadTileByPath are byte-equal to the bytes uploaded — no
// content-encoding injection, no transparent compression, no
// per-byte mutation. Defends against a future GCS client config
// that flips on transcoding by default.
func TestGCSTilesIntegration_ByteIdenticalRoundTrip_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 32 KiB random bytes — large enough to trip transparent gzip
	// at the wire layer, small enough to upload in seconds.
	want := make([]byte, 32*1024)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	uploadObject(t, ctx, g, prefix+"/tile/0/x001/067", want)

	got, err := tb.ReadTileByPath(ctx, "tile/0/x001/067")
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("byte-equality violated: got %d bytes, want %d bytes (head got=%x want=%x)",
			len(got), len(want), got[:16], want[:16])
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Checkpoint round-trip across the wire
// -------------------------------------------------------------------------------------------------

func TestGCSTilesIntegration_CheckpointRoundTrip_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	want := []byte("origin.example\n42\nroot==\n\n— signer base64sig\n")
	uploadObject(t, ctx, g, prefix+"/checkpoint", want)

	got, err := tb.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("checkpoint mismatch: got=%q want=%q", got, want)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Concurrent reads at 1000-way parallelism
// -------------------------------------------------------------------------------------------------

// TestGCSTilesIntegration_ConcurrentReads_RealGCS pre-uploads N
// distinct tiles, then fans out N goroutines each reading one
// tile concurrently. Asserts (a) every read succeeds, (b) every
// read returns the right bytes, (c) p99 latency is bounded.
//
// Pins the load-bearing property: the storage layer handles
// 1000-parallel reads without auth flush, mutex serialization,
// or connection-pool exhaustion. The actual latency depends on
// the runner's network; the assertion is conservative (5s p99)
// so cloud-weather flakiness doesn't fail the gate.
func TestGCSTilesIntegration_ConcurrentReads_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	const N = 1000

	uploadCtx, uploadCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer uploadCancel()

	// Pre-populate N distinct tile keys with deterministic bytes.
	// Run uploads with bounded parallelism so we don't blow the
	// 5000-write/sec/bucket quota or the GCS goroutine pool.
	t.Logf("pre-uploading %d tiles for concurrent-read fan-out...", N)
	uploadStart := time.Now()
	const uploadWorkers = 32
	uploadCh := make(chan int, N)
	var uploadWg sync.WaitGroup
	uploadWg.Add(uploadWorkers)
	for w := 0; w < uploadWorkers; w++ {
		go func() {
			defer uploadWg.Done()
			for i := range uploadCh {
				key := fmt.Sprintf("%s/tile/0/x%03d/%03d", prefix, i/256, i%256)
				body := []byte(fmt.Sprintf("tile-bytes-seq-%d", i))
				uploadObject(t, uploadCtx, g, key, body)
			}
		}()
	}
	for i := 0; i < N; i++ {
		uploadCh <- i
	}
	close(uploadCh)
	uploadWg.Wait()
	t.Logf("uploaded %d tiles in %s", N, time.Since(uploadStart))

	// Fan out N concurrent reads.
	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer readCancel()

	var (
		errCount    atomic.Int64
		mismatchCnt atomic.Int64
		latencies   = make([]time.Duration, N)
	)

	var wg sync.WaitGroup
	wg.Add(N)
	fanoutStart := time.Now()
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("tile/0/x%03d/%03d", i/256, i%256)
			wantBody := []byte(fmt.Sprintf("tile-bytes-seq-%d", i))

			t0 := time.Now()
			got, err := tb.ReadTileByPath(readCtx, path)
			latencies[i] = time.Since(t0)

			if err != nil {
				errCount.Add(1)
				t.Logf("read %s: %v", path, err)
				return
			}
			if !bytes.Equal(got, wantBody) {
				mismatchCnt.Add(1)
				t.Logf("read %s: body mismatch", path)
			}
		}(i)
	}
	wg.Wait()
	totalElapsed := time.Since(fanoutStart)

	if errCount.Load() > 0 {
		t.Fatalf("%d/%d concurrent reads failed", errCount.Load(), N)
	}
	if mismatchCnt.Load() > 0 {
		t.Fatalf("%d/%d concurrent reads returned wrong bytes", mismatchCnt.Load(), N)
	}

	// Latency percentiles.
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[N*50/100]
	p99 := latencies[N*99/100]
	max := latencies[N-1]

	t.Logf("fan-out %d reads: total=%s p50=%s p99=%s max=%s",
		N, totalElapsed, p50, p99, max)

	// Conservative bound — flaky cloud weather should not fail this.
	// The assertion encodes "the storage layer is not pathologically
	// serializing reads"; tighter latency budgets belong in a
	// dedicated load test.
	const p99Bound = 5 * time.Second
	if p99 > p99Bound {
		t.Errorf("p99 = %s exceeds bound %s — possible serialization regression",
			p99, p99Bound)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) MaxTileBytes ceiling against a real 16-MiB+ upload
// -------------------------------------------------------------------------------------------------

// TestGCSTilesIntegration_OversizeTileRejected_RealGCS uploads
// MaxTileBytes+1 bytes to a tile key, asserts ReadTileByPath
// rejects with "exceeds MaxTileBytes". Defends auditors against
// a hostile or misbehaving GCS object that streams unbounded
// bytes within the readTimeout window.
func TestGCSTilesIntegration_OversizeTileRejected_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	// 16-MiB upload over a typical link is several seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// MaxTileBytes+1 is the smallest payload that must be rejected.
	oversized := make([]byte, MaxTileBytes+1)
	t.Logf("uploading %d bytes (MaxTileBytes+1) for ceiling check...", len(oversized))
	uploadStart := time.Now()
	uploadObject(t, ctx, g, prefix+"/tile/0/oversize", oversized)
	t.Logf("upload completed in %s", time.Since(uploadStart))

	_, err := tb.ReadTileByPath(ctx, "tile/0/oversize")
	if err == nil {
		t.Fatal("ReadTileByPath of oversize body returned nil; want rejection")
	}
	if !strings.Contains(err.Error(), "exceeds MaxTileBytes") {
		t.Errorf("err = %v; want 'exceeds MaxTileBytes'", err)
	}
}

// TestGCSTilesIntegration_AtCeilingAccepted_RealGCS uploads
// EXACTLY MaxTileBytes bytes and asserts the read succeeds.
// Pins the off-by-one boundary: the ceiling rejects N+1, accepts
// N. Without this test, a future refactor could silently change
// the comparison from > to >= and break entry-bundle reads at
// full capacity.
func TestGCSTilesIntegration_AtCeilingAccepted_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, prefix := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	atCeiling := make([]byte, MaxTileBytes)
	t.Logf("uploading %d bytes (exactly MaxTileBytes) for boundary check...", len(atCeiling))
	uploadObject(t, ctx, g, prefix+"/tile/entries/x001/067", atCeiling)

	got, err := tb.ReadTileByPath(ctx, "tile/entries/x001/067")
	if err != nil {
		t.Fatalf("ReadTileByPath at ceiling failed: %v", err)
	}
	if int64(len(got)) != MaxTileBytes {
		t.Errorf("body length = %d; want %d (MaxTileBytes)", len(got), MaxTileBytes)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) ErrNotExist mapping against live storage.ErrObjectNotExist
// -------------------------------------------------------------------------------------------------

// TestGCSTilesIntegration_ErrNotExistMapping_RealGCS asserts that
// reading a missing tile / checkpoint produces an error that
// errors.Is(err, os.ErrNotExist). The SDK's
// log/tessera_fetcher.fetchTesseraTile drives the partial-then-
// full fallback off this exact sentinel; fake-gcs-server's error
// path may or may not match real GCS's, so this real-bucket test
// is the load-bearing assertion.
func TestGCSTilesIntegration_ErrNotExistMapping_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, _ := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("tile", func(t *testing.T) {
		_, err := tb.ReadTileByPath(ctx, "tile/0/missing/x000/000")
		if err == nil {
			t.Fatal("ReadTileByPath on missing tile returned nil; want os.ErrNotExist")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("err = %v; want errors.Is(.., os.ErrNotExist)", err)
		}
	})

	t.Run("checkpoint", func(t *testing.T) {
		_, err := tb.ReadCheckpoint(ctx)
		if err == nil {
			t.Fatal("ReadCheckpoint on empty bucket returned nil; want os.ErrNotExist")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("err = %v; want errors.Is(.., os.ErrNotExist)", err)
		}
	})
}

// -------------------------------------------------------------------------------------------------
// 6) Path-traversal rejected BEFORE GCS round-trip
// -------------------------------------------------------------------------------------------------

// TestGCSTilesIntegration_PathTraversalNoGCSRoundTrip_RealGCS
// asserts a hostile path is rejected fast — the storage layer's
// objectKey validator runs BEFORE the bucket.Object().NewReader
// call, so the rejection completes in sub-millisecond time.
//
// Verified by timing: a real-GCS round-trip is ≥10ms (TLS handshake
// + auth + GET); a synchronous validator rejection is sub-1ms.
// The timing assertion is loose (sub-100ms) so jittery test
// hosts don't fail the gate; the architectural property is "the
// validator runs first".
func TestGCSTilesIntegration_PathTraversalNoGCSRoundTrip_RealGCS(t *testing.T) {
	requireRealGCS(t)
	g := requireGCS(t)
	tb, _ := tilesFor(t, g)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hostile := []string{
		"../etc/passwd",
		"a/../b",
		"/absolute/path",
		"valid\x00null",
	}
	for _, p := range hostile {
		t.Run(p, func(t *testing.T) {
			t0 := time.Now()
			_, err := tb.ReadTileByPath(ctx, p)
			elapsed := time.Since(t0)

			if err == nil {
				t.Errorf("hostile path %q accepted; want rejection", p)
			}
			if elapsed > 100*time.Millisecond {
				t.Errorf("hostile path %q took %s — looks like GCS round-trip happened",
					p, elapsed)
			}
		})
	}
}

// -------------------------------------------------------------------------------------------------
// 7) Helpers
// -------------------------------------------------------------------------------------------------

// requireRealGCS skips the test if the env points at fake-gcs-
// server (ATTESTA_TEST_GCS_ENDPOINT set). The build tag already
// gates the file, but a developer can have ATTESTA_TEST_GCS_ENDPOINT
// in their shell from a fake-gcs run; this guard keeps the test
// honest about what it's exercising.
func requireRealGCS(t *testing.T) {
	t.Helper()
	if os.Getenv("ATTESTA_TEST_GCS_ENDPOINT") != "" {
		t.Skip("ATTESTA_TEST_GCS_ENDPOINT set — these tests require REAL GCS, not fake-gcs-server")
	}
	if os.Getenv("ATTESTA_TEST_GCS_BUCKET") == "" {
		t.Skip("ATTESTA_TEST_GCS_BUCKET unset — real-GCS integration tests require a bucket")
	}
}
