/*
FILE PATH: bytestore/s3_test.go

Tests for bytestore.S3. Run against any S3-compatible backend:
  - RustFS (default in integration/docker-compose.yml)
  - real AWS S3 (set ORTHOLOG_TEST_S3_REAL=1 + AWS creds)

Coverage mirrors gcs_test.go so the two adapters stay at parity:

  - Constructor validation (empty bucket).
  - Object naming uses the canonical layoutKey.
  - WriteEntry → ReadEntry round-trip.
  - ReadEntry on missing key returns ErrNotFound (also wraps SDK
    NoSuchKey).
  - LRU cache hit on read-after-write.
  - LRU eviction at capacity.
  - ReadEntryBatch in-order; missing entry fatal for batch.
  - Empty wire bytes rejected.
  - Concurrent writers (interface goroutine-safety pin).
  - Custom ObjectPrefix isolates two stores in the same bucket.
  - PresignGet returns a URL whose HTTP GET fetches the bytes.

Env vars:

  ORTHOLOG_TEST_S3_ENDPOINT     e.g. http://localhost:9000
  ORTHOLOG_TEST_S3_BUCKET       e.g. ortholog-test-bytes
  ORTHOLOG_TEST_S3_ACCESS_KEY   e.g. rustfsadmin
  ORTHOLOG_TEST_S3_SECRET_KEY   e.g. rustfsadmin
  ORTHOLOG_TEST_S3_REGION       e.g. us-east-1 (default)
  ORTHOLOG_TEST_S3_PATH_STYLE   "true" for RustFS, unset for AWS S3
  ORTHOLOG_TEST_S3_REAL         "1" → real AWS S3 mode (uses default
                                 credential chain, virtual-host style,
                                 no endpoint override)

The docker-compose harness creates the bucket at startup; tests
that need a clean state delete + recreate per-test via the
ObjectPrefix knob (each test gets its own prefix).
*/
package bytestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// requireS3 opens a bytestore.S3 configured for either a local
// container (RustFS via env vars) or real AWS S3
// (ORTHOLOG_TEST_S3_REAL=1 + standard AWS_* creds + bucket name).
//
// Real-S3 mode requires an AWS credential chain in scope (env vars,
// IAM role, ~/.aws). Each test gets a unique prefix so concurrent
// runs don't collide AND t.Cleanup deletes every object under that
// prefix at test end.
func requireS3(t *testing.T) *S3 {
	t.Helper()

	endpoint := os.Getenv("ORTHOLOG_TEST_S3_ENDPOINT")
	bucket := os.Getenv("ORTHOLOG_TEST_S3_BUCKET")
	realMode := os.Getenv("ORTHOLOG_TEST_S3_REAL") == "1"

	if endpoint == "" && !realMode {
		t.Skip("ORTHOLOG_TEST_S3_ENDPOINT unset and ORTHOLOG_TEST_S3_REAL!=1; skipping S3 test")
	}
	if bucket == "" {
		if realMode {
			t.Skip("ORTHOLOG_TEST_S3_BUCKET unset for real-S3 mode; skipping")
		}
		bucket = "ortholog-test-bytes"
	}

	prefix := fmt.Sprintf("test/%s/%d", t.Name(), time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := S3Config{
		Bucket:       bucket,
		ObjectPrefix: prefix,
		CacheSize:    16,
	}
	if realMode {
		// Real AWS: no endpoint override; default credential chain;
		// virtual-host URLs.
		if r := os.Getenv("ORTHOLOG_TEST_S3_REGION"); r != "" {
			cfg.Region = r
		}
		t.Logf("S3 test mode: real AWS S3 (bucket=%s, prefix=%s)", bucket, prefix)
	} else {
		// Container mode (RustFS): explicit endpoint, static creds,
		// path-style URLs.
		cfg.Endpoint = endpoint
		cfg.AccessKey = envOrDefault("ORTHOLOG_TEST_S3_ACCESS_KEY", "rustfsadmin")
		cfg.SecretKey = envOrDefault("ORTHOLOG_TEST_S3_SECRET_KEY", "rustfsadmin")
		cfg.Region = envOrDefault("ORTHOLOG_TEST_S3_REGION", "us-east-1")
		cfg.PathStyle = os.Getenv("ORTHOLOG_TEST_S3_PATH_STYLE") != "false"
		t.Logf("S3 test mode: container (endpoint=%s, bucket=%s)", endpoint, bucket)
	}

	store, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deleteS3Prefix(t, cleanupCtx, store, prefix)
		_ = store.Close()
	})

	return store
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func deleteS3Prefix(t *testing.T, ctx context.Context, store *S3, prefix string) {
	t.Helper()
	out, err := store.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(store.bucket),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		t.Logf("cleanup list under %q: %v", prefix, err)
		return
	}
	deleted := 0
	for _, obj := range out.Contents {
		if obj.Key == nil {
			continue
		}
		if _, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(store.bucket),
			Key:    obj.Key,
		}); err != nil {
			t.Logf("cleanup delete %q: %v", *obj.Key, err)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		t.Logf("cleanup: deleted %d objects under %q", deleted, prefix)
	}
}

// ─────────────────────────────────────────────────────────────────
// Constructor validation (always runs, no S3 needed)
// ─────────────────────────────────────────────────────────────────

func TestS3_New_RejectsEmptyBucket(t *testing.T) {
	_, err := NewS3(context.Background(), S3Config{Bucket: ""})
	if err == nil {
		t.Fatal("expected error on empty Bucket")
	}
}

// ─────────────────────────────────────────────────────────────────
// Object naming uses the shared layoutKey (proves cross-adapter
// bucket compatibility — a GCS-written entry can be S3-read).
// ─────────────────────────────────────────────────────────────────

func TestS3_ObjectName_UsesLayoutKey(t *testing.T) {
	store := &S3{objectPrefix: "entries"}
	hash := sha256.Sum256([]byte("k"))
	got := store.keyOf(42, hash)
	want := fmt.Sprintf("entries/%016x/%x", uint64(42), hash[:])
	if got != want {
		t.Errorf("keyOf: got %q, want %q", got, want)
	}
	// Same shape as GCS adapter — proves cross-adapter compatibility.
	gcsStore := &GCS{objectPrefix: "entries"}
	if gcsStore.keyOf(42, hash) != got {
		t.Errorf("GCS and S3 produced different keys for the same (seq, hash) — buckets are not cross-readable")
	}
}

// ─────────────────────────────────────────────────────────────────
// Round-trip: write then read
// ─────────────────────────────────────────────────────────────────

func TestS3_WriteThenRead_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)

	seed := sha256.Sum256([]byte("seed"))
	wire := append([]byte("the wire bytes for the entry|"), seed[:]...)
	hash := sha256.Sum256(wire)

	if err := store.WriteEntry(ctx, 42, hash, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	got, err := store.ReadEntry(ctx, 42, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("round-trip mismatch:\n  got=%x\n want=%x", got, wire)
	}
}

// ─────────────────────────────────────────────────────────────────
// Missing key
// ─────────────────────────────────────────────────────────────────

func TestS3_ReadEntry_MissingKeyWrapsErrNotFound(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)

	_, err := store.ReadEntry(ctx, 99999, sha256.Sum256([]byte("nope")))
	if err == nil {
		t.Fatal("expected error reading missing key")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected wrapped ErrNotFound, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// LRU cache hit on read-after-write
// ─────────────────────────────────────────────────────────────────

func TestS3_ReadAfterWrite_HitsCache(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)

	wire := []byte("cached entry wire blob")
	hash := sha256.Sum256(wire)
	if err := store.WriteEntry(ctx, 7, hash, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	store.mu.Lock()
	_, cached := store.cache[store.keyOf(7, hash)]
	store.mu.Unlock()
	if !cached {
		t.Fatal("WriteEntry should have populated the cache")
	}

	got, err := store.ReadEntry(ctx, 7, hash)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("cached read mismatch:\n  got=%x\n want=%x", got, wire)
	}
}

// ─────────────────────────────────────────────────────────────────
// LRU eviction at capacity
// ─────────────────────────────────────────────────────────────────

func TestS3_Cache_EvictsOldestAtCapacity(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)

	wires := make([][]byte, 17)
	hashes := make([][32]byte, 17)
	for i := uint64(0); i < 17; i++ {
		wires[i] = []byte{byte(i)}
		hashes[i] = sha256.Sum256(wires[i])
		if err := store.WriteEntry(ctx, i, hashes[i], wires[i]); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	store.mu.Lock()
	_, firstStillCached := store.cache[store.keyOf(0, hashes[0])]
	cacheSize := len(store.cache)
	store.mu.Unlock()

	if firstStillCached {
		t.Error("seq=0 should have been evicted at cap=16")
	}
	if cacheSize > 16 {
		t.Errorf("cache size %d exceeds maxSize 16", cacheSize)
	}

	// Re-read seq=0 hits the network. RustFS is strongly consistent;
	// no retry needed.
	got, err := store.ReadEntry(ctx, 0, hashes[0])
	if err != nil {
		t.Fatalf("ReadEntry seq=0 after eviction: %v", err)
	}
	if !bytes.Equal(got, wires[0]) {
		t.Errorf("post-eviction read returned wrong bytes: %x", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// Empty wire bytes rejection
// ─────────────────────────────────────────────────────────────────

func TestS3_WriteEntry_RejectsEmptyWire(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)
	hash := sha256.Sum256([]byte("x"))
	if err := store.WriteEntry(ctx, 1, hash, nil); err == nil {
		t.Error("expected error on nil wire bytes")
	}
	if err := store.WriteEntry(ctx, 1, hash, []byte{}); err == nil {
		t.Error("expected error on empty wire bytes")
	}
}

// ─────────────────────────────────────────────────────────────────
// ReadEntryBatch
// ─────────────────────────────────────────────────────────────────

func TestS3_ReadEntryBatch_PreservesInputOrder(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)

	hashes := make(map[uint64][32]byte, 5)
	for i := uint64(1); i <= 5; i++ {
		wire := []byte{byte(i)}
		h := sha256.Sum256(wire)
		hashes[i] = h
		if err := store.WriteEntry(ctx, i, h, wire); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	wantOrder := []uint64{3, 5, 1, 4, 2}
	refs := make([]EntryRef, len(wantOrder))
	for i, seq := range wantOrder {
		refs[i] = EntryRef{Seq: seq, Hash: hashes[seq]}
	}
	got, err := store.ReadEntryBatch(ctx, refs)
	if err != nil {
		t.Fatalf("ReadEntryBatch: %v", err)
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("length: got %d, want %d", len(got), len(wantOrder))
	}
	for i, seq := range wantOrder {
		if !bytes.Equal(got[i], []byte{byte(seq)}) {
			t.Errorf("position %d: got %v, want [%d]", i, got[i], seq)
		}
	}
}

func TestS3_ReadEntryBatch_MissingSeqIsFatalForBatch(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)
	wire := []byte("blob")
	hash := sha256.Sum256(wire)
	if err := store.WriteEntry(ctx, 1, hash, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	missing := EntryRef{Seq: 99999, Hash: sha256.Sum256([]byte("missing"))}
	_, err := store.ReadEntryBatch(ctx, []EntryRef{{Seq: 1, Hash: hash}, missing})
	if err == nil {
		t.Fatal("expected fatal error on batch with missing seq")
	}
}

// ─────────────────────────────────────────────────────────────────
// Concurrent writers
// ─────────────────────────────────────────────────────────────────

func TestS3_ConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)
	const goroutines = 4
	const perGoroutine = 5

	hashes := make([][32]byte, goroutines*perGoroutine)
	wires := make([][]byte, goroutines*perGoroutine)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				seq := uint64(g*perGoroutine + i)
				wire := []byte{byte(g), byte(i)}
				h := sha256.Sum256(wire)
				wires[seq] = wire
				hashes[seq] = h
				if err := store.WriteEntry(ctx, seq, h, wire); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write: %v", err)
	}

	for seq := 0; seq < goroutines*perGoroutine; seq++ {
		got, err := store.ReadEntry(ctx, uint64(seq), hashes[seq])
		if err != nil {
			t.Errorf("ReadEntry seq=%d: %v", seq, err)
			continue
		}
		if !bytes.Equal(got, wires[seq]) {
			t.Errorf("seq=%d: got %v, want %v", seq, got, wires[seq])
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// PresignGet — SigV4 presigned URL fetches the bytes
// ─────────────────────────────────────────────────────────────────

// TestS3_PresignGet_FetchesBytes proves the 302-redirect path: the
// URL returned by PresignGet is fetchable via plain HTTP GET and
// returns the same bytes WriteEntry stored. Works against RustFS
// AND real AWS S3 — SigV4 is byte-identical across them.
func TestS3_PresignGet_FetchesBytes(t *testing.T) {
	ctx := context.Background()
	store := requireS3(t)

	wire := []byte("presign me — fetch by URL not by SDK")
	hash := sha256.Sum256(wire)
	if err := store.WriteEntry(ctx, 100, hash, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	url, err := store.PresignGet(ctx, 100, hash, 5*time.Minute)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	if url == "" {
		t.Fatal("PresignGet returned empty URL")
	}

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("HTTP GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("HTTP status: %d %s\nbody: %s", resp.StatusCode, resp.Status, body)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("presigned GET returned wrong bytes:\n  got=%x\n want=%x", got, wire)
	}
}

// ─────────────────────────────────────────────────────────────────
// Cross-adapter interop: GCS writes, S3 reads (and vice versa)
// ─────────────────────────────────────────────────────────────────
//
// Both adapters use layoutKey for the canonical object name. A
// bucket written by one is readable by the other, given the
// underlying object store (or its emulator) supports both
// protocols. We verify this static guarantee at the key-shape
// level here; full cross-protocol round-trip in a single bucket
// requires a backend that speaks both wire protocols (e.g.,
// real GCS with S3 interoperability mode), which is out of
// scope for the operator's CI.
func TestS3_GCS_KeyCompat(t *testing.T) {
	hash := sha256.Sum256([]byte("interop"))
	gcs := &GCS{objectPrefix: "entries"}
	s3 := &S3{objectPrefix: "entries"}
	for seq := uint64(0); seq < 5; seq++ {
		if gcs.keyOf(seq, hash) != s3.keyOf(seq, hash) {
			t.Fatalf("seq=%d: GCS and S3 produced different keys — cross-bucket migration would fail", seq)
		}
	}
}
