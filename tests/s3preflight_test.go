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
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

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
