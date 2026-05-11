//go:build soak
// +build soak

/*
FILE PATH:

	tests/s3preflight_test.go

DESCRIPTION:

	Validates each piece of S3 / SeaweedFS infrastructure that
	TestSoak_LedgerBytestore depends on, BEFORE the soak runs. If
	any subtest fails, the soak's "InternalError, please try again"
	cascade is unambiguously attributable to the failed probe — no
	more guessing whether it's env-var, region, path-style, bucket,
	or volume-server health.

	The probes run as subtests of TestS3Preflight so the failure
	pinpoints the exact unverified claim:

	  TestS3Preflight/01_env_vars                  — what env vars
	                                                 the soak will
	                                                 actually read
	  TestS3Preflight/02_master_cluster_status     — SeaweedFS
	                                                 master alive
	  TestS3Preflight/03_volume_server_status      — volumes
	                                                 healthy +
	                                                 writable
	  TestS3Preflight/04_s3_client_construction    — same client
	                                                 the soak
	                                                 builds
	  TestS3Preflight/05_list_buckets              — S3 gateway
	                                                 actually
	                                                 serves
	  TestS3Preflight/06_put_head_get_delete       — full
	                                                 roundtrip
	                                                 with the same
	                                                 client the
	                                                 shipper uses

ORDERING:

	"TestS3Preflight" sorts before "TestSoak_LedgerBytestore"
	(S=83, '3'=51, 'o'=111 → TestS3 < TestSo) so go test runs it
	first by default. If you want to run ONLY the preflight:

	  go test -tags=soak -run TestS3Preflight -v ./tests/

WHY THIS EXISTS:

	The shipper failure manifests as N×500-InternalError responses
	from SeaweedFS PutObject. SeaweedFS returns 500 for many
	upstream issues (region mismatch, signature failure, volume
	server unreachable, disk full, bucket missing, anonymous-mode
	misconfig). The S3 error response itself is intentionally
	opaque — that's why we need staged probes, not a single
	"hit it and see."
*/
package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithy "github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
)

func TestS3Preflight(t *testing.T) {
	if os.Getenv("ATTESTA_SOAK_BYTESTORE_BACKEND") != "s3" {
		t.Skip("ATTESTA_SOAK_BYTESTORE_BACKEND != \"s3\" — preflight only relevant for S3 soak")
	}
	if os.Getenv("ATTESTA_TEST_S3_BUCKET") == "" {
		t.Skip("ATTESTA_TEST_S3_BUCKET unset — preflight requires bucket configured")
	}

	t.Run("01_env_vars", testS3Preflight_EnvVars)
	t.Run("02_master_cluster_status", testS3Preflight_MasterStatus)
	t.Run("03_volume_server_status", testS3Preflight_VolumeStatus)
	t.Run("04_s3_client_construction", testS3Preflight_ClientConstruction)
	t.Run("05_list_buckets", testS3Preflight_ListBuckets)
	t.Run("06_put_head_get_delete", testS3Preflight_PutHeadGetDelete)
	t.Run("07_concurrent_burst", testS3Preflight_ConcurrentBurst)
}

// 01 — dump every env var the soak will read so we can confirm the
// values that reached the test process exactly match what the user
// expects from `./scripts/infra env`.
func testS3Preflight_EnvVars(t *testing.T) {
	keys := []string{
		"ATTESTA_SOAK_BYTESTORE_BACKEND",
		"ATTESTA_TEST_S3_BUCKET",
		"ATTESTA_TEST_S3_ENDPOINT",
		"ATTESTA_TEST_S3_REGION",
		"ATTESTA_TEST_S3_PATH_STYLE",
		"ATTESTA_TEST_S3_ACCESS_KEY",
		"ATTESTA_TEST_S3_SECRET_KEY",
		// LEDGER_BYTE_STORE_S3_* are read by the production binary,
		// not the test — log them so the user can confirm they MATCH
		// the ATTESTA_TEST_S3_* values (env divergence between the
		// two sets has been a footgun before).
		"LEDGER_BYTE_STORE_BACKEND",
		"LEDGER_BYTE_STORE_S3_BUCKET",
		"LEDGER_BYTE_STORE_S3_ENDPOINT",
		"LEDGER_BYTE_STORE_S3_REGION",
		"LEDGER_BYTE_STORE_S3_PATH_STYLE",
		"LEDGER_BYTE_STORE_S3_ACCESS_KEY",
		"LEDGER_BYTE_STORE_S3_SECRET_KEY",
	}
	t.Logf("env vars relevant to soak S3 path:")
	for _, k := range keys {
		v := os.Getenv(k)
		switch {
		case v == "":
			t.Logf("  %-40s = <unset>", k)
		case strings.Contains(k, "SECRET") || strings.Contains(k, "ACCESS"):
			t.Logf("  %-40s = %s (len=%d)", k, mask(v), len(v))
		default:
			t.Logf("  %-40s = %q", k, v)
		}
	}
	// Cross-check: the two env sets MUST agree on bucket / endpoint
	// / region / path-style or the production binary and the test
	// will use different paths, hiding bugs.
	pairs := [][2]string{
		{"ATTESTA_TEST_S3_BUCKET", "LEDGER_BYTE_STORE_S3_BUCKET"},
		{"ATTESTA_TEST_S3_ENDPOINT", "LEDGER_BYTE_STORE_S3_ENDPOINT"},
		{"ATTESTA_TEST_S3_REGION", "LEDGER_BYTE_STORE_S3_REGION"},
		{"ATTESTA_TEST_S3_PATH_STYLE", "LEDGER_BYTE_STORE_S3_PATH_STYLE"},
	}
	for _, p := range pairs {
		a, b := os.Getenv(p[0]), os.Getenv(p[1])
		if a != "" && b != "" && a != b {
			t.Errorf("env mismatch: %s=%q vs %s=%q (the two paths read different values)", p[0], a, p[1], b)
		}
	}
}

// 02 — SeaweedFS master /cluster/status reveals whether the master
// is reachable and how many volume servers are participating.
//
// Master defaults to port 9333 alongside the S3 frontend on 8333.
// The infra script's healthcheck hits this same endpoint, so a
// failure here means the infra is in a worse state than the script
// reported.
func testS3Preflight_MasterStatus(t *testing.T) {
	endpoint := masterEndpointFromS3Endpoint(t)
	url := endpoint + "/cluster/status"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v (master unreachable — infra not up?)", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status=%d body=%s", url, resp.StatusCode, body)
	}
	t.Logf("master /cluster/status (status=%d):", resp.StatusCode)
	t.Logf("  %s", string(body))
}

// 03 — /dir/status enumerates volume servers and their per-volume
// disk usage. If volumes are missing, write-only, or out of disk,
// PutObject returns 500 InternalError because the S3 frontend can't
// place the chunk.
func testS3Preflight_VolumeStatus(t *testing.T) {
	endpoint := masterEndpointFromS3Endpoint(t)
	url := endpoint + "/dir/status"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status=%d body=%s", url, resp.StatusCode, body)
	}
	t.Logf("master /dir/status (status=%d):", resp.StatusCode)
	t.Logf("  %s", string(body))
	if !strings.Contains(string(body), "Topology") && !strings.Contains(string(body), "DataCenters") {
		t.Errorf("/dir/status response missing Topology/DataCenters keys — volume servers may not be registered")
	}
}

// 04 — construct the bytestore.S3 backend with the EXACT same
// config the soak harness builds. If env reads produce a degenerate
// Bucket/Endpoint/Region this is where it surfaces (vs the soak
// failing later inside PutObject).
func testS3Preflight_ClientConstruction(t *testing.T) {
	bucket := os.Getenv("ATTESTA_TEST_S3_BUCKET")
	endpoint := os.Getenv("ATTESTA_TEST_S3_ENDPOINT")
	region := os.Getenv("ATTESTA_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	pathStyle := os.Getenv("ATTESTA_TEST_S3_PATH_STYLE") != "false"

	t.Logf("constructing S3 backend with:")
	t.Logf("  bucket     = %q", bucket)
	t.Logf("  endpoint   = %q", endpoint)
	t.Logf("  region     = %q (default us-east-1 if env was empty)", region)
	t.Logf("  path-style = %v", pathStyle)

	cfg := opbytestore.Config{
		Backend:     "s3",
		Bucket:      bucket,
		S3Endpoint:  endpoint,
		S3AccessKey: os.Getenv("ATTESTA_TEST_S3_ACCESS_KEY"),
		S3SecretKey: os.Getenv("ATTESTA_TEST_S3_SECRET_KEY"),
		S3Region:    region,
		S3PathStyle: pathStyle,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	be, err := opbytestore.NewFromConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("opbytestore.NewFromConfig (matches soak harness wiring): %v", err)
	}
	if be == nil {
		t.Fatalf("NewFromConfig returned nil backend")
	}
	t.Logf("S3 backend constructed OK (matches soak harness wiring at soak_test.go:240-261)")
}

// 05 — ListBuckets is the canonical "is the S3 frontend alive +
// signing OK" probe. If region/path-style/credentials are wrong,
// this fails before we ever try a Put.
//
// Uses raw aws-sdk-go-v2 (not the bytestore wrapper) to surface the
// underlying SDK error verbatim. SeaweedFS sometimes maps signing
// failures to 500 instead of 403, so the SDK error code is the only
// signal that disambiguates.
func testS3Preflight_ListBuckets(t *testing.T) {
	client := buildS3ClientForPreflight(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets: %v\n  (region/path-style/credentials mismatch surfaces here before PutObject)", err)
	}
	t.Logf("ListBuckets returned %d bucket(s):", len(out.Buckets))
	for _, b := range out.Buckets {
		t.Logf("  %s (created %v)", aws.ToString(b.Name), aws.ToTime(b.CreationDate))
	}
	want := os.Getenv("ATTESTA_TEST_S3_BUCKET")
	found := false
	for _, b := range out.Buckets {
		if aws.ToString(b.Name) == want {
			found = true
		}
	}
	if !found {
		t.Errorf("bucket %q not in ListBuckets response — the soak's reads will fail with NoSuchBucket OR (worse) silent SeaweedFS 500 InternalError", want)
	}
}

// 06 — full Put → Head → Get → Delete roundtrip with the SAME
// underlying S3 client the soak harness uses. If this passes, the
// shipper's PutObject failures are NOT a server-side rejection —
// they're something the shipper does differently (concurrency,
// timeouts, content-type, etc.) and we look upstream of S3.
//
// If this fails, we have the exact upstream error to trace.
func testS3Preflight_PutHeadGetDelete(t *testing.T) {
	bucket := os.Getenv("ATTESTA_TEST_S3_BUCKET")
	client := buildS3ClientForPreflight(t)

	// Random key so concurrent preflights don't collide.
	rnd := make([]byte, 8)
	_, _ = rand.Read(rnd)
	key := fmt.Sprintf("preflight/test-%s.bin", hex.EncodeToString(rnd))

	// Tiny payload so we can compare bytes round-tripped exactly.
	payload := []byte("preflight-roundtrip-payload-" + hex.EncodeToString(rnd))
	h := sha256.Sum256(payload)
	t.Logf("roundtrip key=%s payload-sha256=%x", key, h)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Put
	t0 := time.Now()
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(payload),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		t.Fatalf("PutObject(bucket=%s key=%s): %v\n  (this is the shipper's exact upstream call; if it fails here the soak will fail identically)", bucket, key, err)
	}
	t.Logf("PutObject OK in %s", time.Since(t0))

	// Head
	t0 = time.Now()
	_, err = client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("HeadObject(bucket=%s key=%s): %v\n  (Put returned OK but object isn't visible — read-after-write consistency violation)", bucket, key, err)
	}
	t.Logf("HeadObject OK in %s", time.Since(t0))

	// Get
	t0 = time.Now()
	gotResp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObject(bucket=%s key=%s): %v", bucket, key, err)
	}
	gotBytes, err := io.ReadAll(gotResp.Body)
	gotResp.Body.Close()
	if err != nil {
		t.Fatalf("GetObject body read: %v", err)
	}
	if !bytes.Equal(gotBytes, payload) {
		t.Fatalf("GetObject returned %d bytes, payload was %d (content corruption — backend is not durable)", len(gotBytes), len(payload))
	}
	t.Logf("GetObject OK (%d bytes) in %s — content matches", len(gotBytes), time.Since(t0))

	// Delete
	t0 = time.Now()
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("DeleteObject (best-effort cleanup): %v", err)
		return
	}
	t.Logf("DeleteObject OK in %s", time.Since(t0))
}

// 07 — concurrent burst that mirrors the shipper's exact load
// pattern. Steps 01-06 confirmed the path WORKS in isolation, so
// the soak's 500-InternalError cascade must be triggered by what
// the shipper does differently: sustained concurrent writes against
// a single SeaweedFS volume server with the full wire-byte payload.
//
// Pattern matched to soak_test.go:359-374 + bytestore.S3.WriteEntry:
//
//   - Workers       = 16              (default MaxInFlight; overridable
//                                       via ATTESTA_TEST_S3_BURST_WORKERS)
//   - Payload       = 500 bytes       (typical wire-byte envelope size;
//                                       actual integration tests show
//                                       ~190-1000 bytes per entry)
//   - Total ops     = 5000            (10s × 500/s sustained shipper rate;
//                                       overridable via ATTESTA_TEST_S3_BURST_OPS)
//   - Key shape     = entries/<seq16>/<hash64>  (matches layoutKey
//                                       in bytestore/bytestore.go:139)
//   - ContentType   = application/octet-stream  (matches WriteEntry)
//   - SDK config    = identical (buildS3ClientForPreflight mirrors NewS3)
//
// What it surfaces:
//
//   - Error classification by HTTP status + smithy ErrorCode +
//     plain-text classification (timeout, conn-reset, ctx-cancel)
//   - Latency histogram (p50/p90/p99/max)
//   - Throughput achieved (ops/s)
//   - First N error samples verbatim (so the EXACT shape of the
//     500 cascade is in the test output, not just counts)
//
// If 07 reproduces 500-InternalError under burst, we have a tight
// repro that doesn't need the soak. If 07 passes too, the issue is
// even more shipper-specific (ctx lifecycle, retry interaction,
// transport reuse across goroutines, etc.) — the next probe lives
// in the shipper itself.
func testS3Preflight_ConcurrentBurst(t *testing.T) {
	bucket := os.Getenv("ATTESTA_TEST_S3_BUCKET")
	workers := envIntOr("ATTESTA_TEST_S3_BURST_WORKERS", 16)
	totalOps := envIntOr("ATTESTA_TEST_S3_BURST_OPS", 5000)
	payloadBytes := envIntOr("ATTESTA_TEST_S3_BURST_PAYLOAD_BYTES", 500)

	t.Logf("burst config: workers=%d total_ops=%d payload_bytes=%d", workers, totalOps, payloadBytes)
	t.Logf("matches: shipper.MaxInFlight=16 (default), shipper.ContentType=application/octet-stream,")
	t.Logf("         shipper key shape entries/<seq16>/<hash64>, payload sized like a wire envelope")

	client := buildS3ClientForPreflight(t)

	// Pre-seed all payloads so the timing measures Put latency, not
	// payload generation. Each payload is unique so SeaweedFS dedup
	// (if any) doesn't mask real write amplification.
	type job struct {
		key  string
		body []byte
	}
	jobs := make([]job, totalOps)
	burstID := make([]byte, 8)
	_, _ = rand.Read(burstID)
	burstHex := hex.EncodeToString(burstID)
	for i := 0; i < totalOps; i++ {
		body := make([]byte, payloadBytes)
		_, _ = rand.Read(body)
		hash := sha256.Sum256(body)
		// burst-prefixed under entries/ so the soak's normal layout
		// is unaffected and burst keys are easy to clean up after.
		key := fmt.Sprintf("entries/burst-%s/%016x/%s", burstHex, uint64(i), hex.EncodeToString(hash[:]))
		jobs[i] = job{key: key, body: body}
	}

	// Worker pool. Each worker pulls indices off a shared atomic
	// counter — no channel back-pressure, just a tight loop matching
	// the shipper's "as-fast-as-possible bounded by MaxInFlight"
	// pattern.
	var nextIdx atomic.Int64
	var (
		okCount       atomic.Int64
		errCount      atomic.Int64
		latNs         []int64
		latMu         sync.Mutex
		errSamples    []burstError
		errSamplesMu  sync.Mutex
		errClassCount sync.Map // string → *atomic.Int64
	)
	const maxErrSamples = 5

	classify := func(err error) (status int, code, msgClass string) {
		if err == nil {
			return 0, "", ""
		}
		// Walk smithy error chain.
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			code = apiErr.ErrorCode()
		}
		var httpErr *smithyhttp.ResponseError
		if errors.As(err, &httpErr) {
			if httpErr.HTTPStatusCode() != 0 {
				status = httpErr.HTTPStatusCode()
			}
		}
		// Plain-text classification for non-HTTP failures.
		s := err.Error()
		switch {
		case strings.Contains(s, "context canceled"), strings.Contains(s, "context deadline exceeded"):
			msgClass = "ctx"
		case strings.Contains(s, "connection reset"):
			msgClass = "conn-reset"
		case strings.Contains(s, "EOF"):
			msgClass = "eof"
		case strings.Contains(s, "no route to host"), strings.Contains(s, "connection refused"):
			msgClass = "net-down"
		case strings.Contains(s, "timeout"):
			msgClass = "timeout"
		default:
			msgClass = "other"
		}
		return status, code, msgClass
	}

	bumpErrClass := func(class string) {
		v, ok := errClassCount.Load(class)
		if !ok {
			v, _ = errClassCount.LoadOrStore(class, &atomic.Int64{})
		}
		v.(*atomic.Int64).Add(1)
	}

	// Bound the whole burst to 60s — at 16 workers × 30s/PutObject
	// timeout the worst case is bounded, but if everything 500s the
	// SDK's 3-attempt retry + backoff makes each call 5-15s, so a
	// 5000-op burst could take 5000/16 × 15s ≈ 78m without a budget.
	burstCtx, burstCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer burstCancel()

	t0 := time.Now()
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				if burstCtx.Err() != nil {
					return
				}
				idx := nextIdx.Add(1) - 1
				if idx >= int64(totalOps) {
					return
				}
				j := jobs[idx]
				start := time.Now()
				_, err := client.PutObject(burstCtx, &s3.PutObjectInput{
					Bucket:      aws.String(bucket),
					Key:         aws.String(j.key),
					Body:        bytes.NewReader(j.body),
					ContentType: aws.String("application/octet-stream"),
				})
				lat := time.Since(start).Nanoseconds()
				latMu.Lock()
				latNs = append(latNs, lat)
				latMu.Unlock()

				if err != nil {
					errCount.Add(1)
					status, code, class := classify(err)
					classKey := fmt.Sprintf("status=%d code=%q class=%s", status, code, class)
					bumpErrClass(classKey)
					errSamplesMu.Lock()
					if len(errSamples) < maxErrSamples {
						errSamples = append(errSamples, burstError{
							idx:     int(idx),
							key:     j.key,
							lat:     lat,
							status:  status,
							code:    code,
							class:   class,
							message: err.Error(),
						})
					}
					errSamplesMu.Unlock()
					continue
				}
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(t0)

	// Best-effort cleanup of burst-prefixed keys we just wrote.
	defer func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		for i := 0; i < totalOps; i++ {
			_, _ = client.DeleteObject(cleanCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(jobs[i].key),
			})
		}
	}()

	ok := okCount.Load()
	failed := errCount.Load()
	t.Logf("burst result: ok=%d failed=%d total=%d elapsed=%s throughput=%.1f ops/s",
		ok, failed, ok+failed, elapsed, float64(ok+failed)/elapsed.Seconds())

	// Latency histogram.
	if len(latNs) > 0 {
		latMu.Lock()
		sort.Slice(latNs, func(i, j int) bool { return latNs[i] < latNs[j] })
		p := func(q float64) time.Duration {
			i := int(float64(len(latNs)-1) * q)
			return time.Duration(latNs[i])
		}
		t.Logf("latency: p50=%s p90=%s p99=%s max=%s",
			p(0.50), p(0.90), p(0.99), time.Duration(latNs[len(latNs)-1]))
		latMu.Unlock()
	}

	// Error classification.
	if failed > 0 {
		t.Logf("error classification (status / smithy code / msg-class → count):")
		errClassCount.Range(func(k, v any) bool {
			t.Logf("  %s → %d", k.(string), v.(*atomic.Int64).Load())
			return true
		})
		t.Logf("first %d error sample(s) verbatim:", min(int(failed), maxErrSamples))
		for i, e := range errSamples {
			t.Logf("  [%d] idx=%d key=%s lat=%s", i, e.idx, e.key, time.Duration(e.lat))
			t.Logf("       status=%d code=%q class=%s", e.status, e.code, e.class)
			t.Logf("       %s", e.message)
		}
		// We don't t.Errorf — the preflight's job is diagnostic
		// reporting, not pass/fail. The user reads the output to
		// decide whether the burst pattern reproduces the soak's
		// 500-cascade.
		t.Logf("NOTE: failures observed. If status=500 and code=\"InternalError\" dominates, this is the same shape as the soak shipper's failures — the burst pattern is the trigger, not the request shape.")
	} else {
		t.Logf("no failures observed under burst — soak failure is NOT a concurrency / load issue at the SeaweedFS S3 layer.")
	}
}

type burstError struct {
	idx     int
	key     string
	lat     int64
	status  int
	code    string
	class   string
	message string
}

func envIntOr(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────

// mask returns the secret with everything but the last 4 chars
// replaced by stars. For very short secrets it just returns "****".
func mask(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}

// masterEndpointFromS3Endpoint converts http://localhost:8333 → http://localhost:9333.
// SeaweedFS conventionally exposes the S3 frontend on 8333 and the
// master on 9333; this helper rewrites the port without assuming
// the host name. If the env points at a non-default S3 port the
// helper returns the input unchanged and the master probe uses the
// same URL (which is wrong, but logs explicitly).
func masterEndpointFromS3Endpoint(t *testing.T) string {
	s3Endpoint := os.Getenv("ATTESTA_TEST_S3_ENDPOINT")
	if s3Endpoint == "" {
		t.Fatalf("ATTESTA_TEST_S3_ENDPOINT unset — cannot derive master endpoint")
	}
	masterURL := strings.Replace(s3Endpoint, ":8333", ":9333", 1)
	if masterURL == s3Endpoint {
		t.Logf("WARN: S3 endpoint %q does not contain :8333; master probe will hit the same URL (likely wrong)", s3Endpoint)
	}
	return masterURL
}

// buildS3ClientForPreflight constructs a raw aws-sdk-go-v2 *s3.Client
// from env vars, mirroring bytestore.NewS3's option flow exactly
// (loadDefaultConfig + region + static creds + base endpoint +
// path-style + tuned transport). We bypass bytestore.NewS3 so we can
// surface SDK errors verbatim — the bytestore wrapper translates
// errors into its own format which loses the request-id / smithy
// detail we need to differentiate signing failure from server error.
//
// MUST stay in lockstep with bytestore/s3.go:NewS3. If NewS3 changes
// (new transport tuning, new region resolution rules, etc.), this
// helper has to change with it or the preflight starts probing a
// DIFFERENT code path than the shipper.
func buildS3ClientForPreflight(t *testing.T) *s3.Client {
	t.Helper()
	endpoint := os.Getenv("ATTESTA_TEST_S3_ENDPOINT")
	region := os.Getenv("ATTESTA_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	pathStyle := os.Getenv("ATTESTA_TEST_S3_PATH_STYLE") != "false"
	access := os.Getenv("ATTESTA_TEST_S3_ACCESS_KEY")
	secret := os.Getenv("ATTESTA_TEST_S3_SECRET_KEY")

	httpClient := awshttp.NewBuildableClient().
		WithTransportOptions(func(tr *http.Transport) {
			tr.MaxIdleConns = 512
			tr.MaxIdleConnsPerHost = 256
		})

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
		awsconfig.WithHTTPClient(httpClient),
	}
	if access != "" && secret != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(access, secret, ""),
		))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	clientOpts := []func(*s3.Options){}
	if endpoint != "" {
		ep := endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	if pathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	// Sanity check: round-trip cfg through opbytestore.Config so a
	// signature drift between this helper and NewS3 would fail at
	// compile time (we touch the same Config fields the soak does).
	_ = opbytestore.Config{
		Backend:     "s3",
		Bucket:      os.Getenv("ATTESTA_TEST_S3_BUCKET"),
		S3Endpoint:  endpoint,
		S3Region:    region,
		S3AccessKey: access,
		S3SecretKey: secret,
		S3PathStyle: pathStyle,
	}

	return s3.NewFromConfig(awsCfg, clientOpts...)
}
