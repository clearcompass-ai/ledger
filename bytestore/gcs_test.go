/*
FILE PATH: bytestore/gcs_test.go

Tests for bytestore.GCS. Run against the fake-gcs-server harness
exposed by integration/docker-compose.yml. Skip cleanly when the env
vars are unset, mirroring the ATTESTA_TEST_DSN skip pattern in
store/sequence_cursor_test.go and store/commitment_fetcher_test.go.

Coverage:
  - Constructor validation (empty bucket).
  - Object naming uses the canonical layoutKey (<prefix>/<seq:016x>/<hash_hex>).
  - WriteEntry → ReadEntry round-trip.
  - ReadEntry on missing key returns ErrNotFound (also wraps GCS's
    ErrObjectNotExist).
  - LRU cache hit on read-after-write.
  - LRU eviction at capacity.
  - ReadEntryBatch in-order; missing entry fatal for batch.
  - Empty wire bytes rejected.
  - Concurrent writers (interface goroutine-safety pin).
  - Custom ObjectPrefix isolates two stores in the same bucket.
  - PresignGet returns a URL whose HTTP GET fetches the bytes.

Env vars (mirrors the ledger's production LEDGER_BYTE_STORE_*
naming so tests and prod stay in sync):

	ATTESTA_TEST_GCS_ENDPOINT   e.g. http://localhost:4443/storage/v1/
	ATTESTA_TEST_GCS_BUCKET     e.g. attesta-test-bytes

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

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// requireGCS opens a bytestore.GCS configured for either fake-gcs-
// server (integration harness) or real GCS, depending on which env
// vars are set:
//
//	ATTESTA_TEST_GCS_ENDPOINT  set → fake-gcs mode (anonymous=true)
//	ATTESTA_TEST_GCS_BUCKET    set → real GCS mode (ADC)
//	neither set                     → t.Skip
//
// Real-GCS mode requires GOOGLE_APPLICATION_CREDENTIALS pointing at
// a service-account key with storage.objects.create + .get + .delete
// on the named bucket. Each test gets a unique prefix so concurrent
// runs don't collide AND t.Cleanup deletes every object under that
// prefix at test end (real GCS otherwise accumulates test junk).
func requireGCS(t *testing.T) *GCS {
	t.Helper()

	endpoint := os.Getenv("ATTESTA_TEST_GCS_ENDPOINT")
	bucket := os.Getenv("ATTESTA_TEST_GCS_BUCKET")

	if endpoint == "" && bucket == "" {
		t.Skip("neither ATTESTA_TEST_GCS_ENDPOINT nor ATTESTA_TEST_GCS_BUCKET set; skipping GCS test")
	}

	fakeMode := endpoint != ""
	if !fakeMode && bucket == "" {
		t.Skip("ATTESTA_TEST_GCS_BUCKET unset for real-GCS mode; skipping")
	}
	if fakeMode && bucket == "" {
		bucket = "attesta-test-bytes"
	}

	prefix := fmt.Sprintf("test/%s/%d", t.Name(), time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := GCSConfig{
		Bucket:       bucket,
		ObjectPrefix: prefix,
		CacheSize:    16,
	}
	if fakeMode {
		cfg.Endpoint = endpoint
		cfg.Anonymous = true
		t.Logf("GCS test mode: fake-gcs-server (endpoint=%s, bucket=%s)", endpoint, bucket)
	} else {
		t.Logf("GCS test mode: real GCS (bucket=%s, prefix=%s)", bucket, prefix)
	}

	store, err := NewGCS(ctx, cfg)
	if err != nil {
		t.Fatalf("NewGCS: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deletePrefix(t, cleanupCtx, store, prefix)

		if err := store.Close(); err != nil {
			t.Logf("Close (cleanup): %v", err)
		}
	})

	return store
}

func deletePrefix(t *testing.T, ctx context.Context, store *GCS, prefix string) {
	t.Helper()
	it := store.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	deleted := 0
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			t.Logf("cleanup list under %q: %v", prefix, err)
			return
		}
		if delErr := store.bucket.Object(attrs.Name).Delete(ctx); delErr != nil {
			t.Logf("cleanup delete %q: %v", attrs.Name, delErr)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		t.Logf("cleanup: deleted %d objects under %q", deleted, prefix)
	}
}

// ─────────────────────────────────────────────────────────────────
// Constructor validation (always runs, no GCS needed)
// ─────────────────────────────────────────────────────────────────

func TestGCS_New_RejectsEmptyBucket(t *testing.T) {
	_, err := NewGCS(context.Background(), GCSConfig{Bucket: ""})
	if err == nil {
		t.Fatal("expected error on empty Bucket")
	}
}

// ─────────────────────────────────────────────────────────────────
// Object naming uses the shared layoutKey
// ─────────────────────────────────────────────────────────────────

func TestGCS_ObjectName_UsesLayoutKey(t *testing.T) {
	store := &GCS{objectPrefix: "entries"}
	hash := sha256.Sum256([]byte("k"))
	got := store.keyOf(42, hash)
	want := fmt.Sprintf("entries/%016x/%x", uint64(42), hash[:])
	if got != want {
		t.Errorf("keyOf: got %q, want %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────
// Round-trip: write then read
// ─────────────────────────────────────────────────────────────────

func TestGCS_WriteThenRead_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)

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

func TestGCS_ReadEntry_MissingKeyWrapsErrNotFound(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)

	_, err := store.ReadEntry(ctx, 99999, sha256.Sum256([]byte("nope")))
	if err == nil {
		t.Fatal("expected error reading missing key")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected wrapped ErrNotFound, got %v", err)
	}
	if !errors.Is(err, storage.ErrObjectNotExist) {
		t.Errorf("expected wrapped storage.ErrObjectNotExist, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// LRU cache hit on read-after-write
// ─────────────────────────────────────────────────────────────────

func TestGCS_ReadAfterWrite_HitsCache(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)

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

func TestGCS_Cache_EvictsOldestAtCapacity(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)

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

	got, err := readEntryWithRetry(t, store, 0, hashes[0])
	if err != nil {
		t.Fatalf("ReadEntry seq=0 after eviction: %v", err)
	}
	if !bytes.Equal(got, wires[0]) {
		t.Errorf("post-eviction read returned wrong bytes: %x", got)
	}
}

// readEntryWithRetry calls store.ReadEntry, retrying on ErrNotFound
// up to 5 times with 50ms exponential backoff. Exists because
// fake-gcs-server has a brief read-after-write consistency lag under
// bursty writes; real GCS is strongly consistent and the first
// attempt always succeeds.
//
// Production code (bytestore.GCS.ReadEntry) does NOT retry — cache
// miss → ErrNotFound surfaces as "entry doesn't exist". The retry
// here is a fake-gcs-only test workaround.
func readEntryWithRetry(t *testing.T, store *GCS, seq uint64, hash [32]byte) ([]byte, error) {
	t.Helper()
	ctx := context.Background()
	var lastErr error
	delay := 50 * time.Millisecond
	for i := 0; i < 5; i++ {
		got, err := store.ReadEntry(ctx, seq, hash)
		if err == nil {
			return got, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		lastErr = err
		time.Sleep(delay)
		delay *= 2
	}
	return nil, fmt.Errorf("readEntryWithRetry seq=%d: 5 attempts: %w", seq, lastErr)
}

// ─────────────────────────────────────────────────────────────────
// Empty wire bytes rejection
// ─────────────────────────────────────────────────────────────────

func TestGCS_WriteEntry_RejectsEmptyWire(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)
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

func TestGCS_ReadEntryBatch_PreservesInputOrder(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)

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

func TestGCS_ReadEntryBatch_MissingSeqIsFatalForBatch(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)
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

func TestGCS_ConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	store := requireGCS(t)
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
		got, err := readEntryWithRetry(t, store, uint64(seq), hashes[seq])
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
// Custom ObjectPrefix isolates two stores in the same bucket
// ─────────────────────────────────────────────────────────────────

func TestGCS_DifferentObjectPrefix_IsolatesData(t *testing.T) {
	endpoint := os.Getenv("ATTESTA_TEST_GCS_ENDPOINT")
	bucket := os.Getenv("ATTESTA_TEST_GCS_BUCKET")
	if endpoint == "" && bucket == "" {
		t.Skip("neither ATTESTA_TEST_GCS_ENDPOINT nor ATTESTA_TEST_GCS_BUCKET set")
	}
	fakeMode := endpoint != ""
	if fakeMode && bucket == "" {
		bucket = "attesta-test-bytes"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mkStore := func(prefix string) *GCS {
		t.Helper()
		cfg := GCSConfig{
			Bucket:       bucket,
			ObjectPrefix: prefix,
			CacheSize:    8,
		}
		if fakeMode {
			cfg.Endpoint = endpoint
			cfg.Anonymous = true
		}
		s, err := NewGCS(ctx, cfg)
		if err != nil {
			t.Fatalf("NewGCS(%s): %v", prefix, err)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			deletePrefix(t, cleanupCtx, s, prefix)
			_ = s.Close()
		})
		return s
	}

	prefixA := fmt.Sprintf("isolation-test-A/%d", time.Now().UnixNano())
	prefixB := fmt.Sprintf("isolation-test-B/%d", time.Now().UnixNano())

	storeA := mkStore(prefixA)
	storeB := mkStore(prefixB)

	wire := []byte("from A")
	hash := sha256.Sum256(wire)
	if err := storeA.WriteEntry(ctx, 42, hash, wire); err != nil {
		t.Fatalf("storeA write: %v", err)
	}

	_, err := storeB.ReadEntry(ctx, 42, hash)
	if err == nil {
		t.Fatal("storeB should not see storeA's entries (different prefix)")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// PresignGet — V4 signed URL fetches the bytes
// ─────────────────────────────────────────────────────────────────

// TestGCS_PresignGet_FetchesBytes proves the 302-redirect path:
// the URL returned by PresignGet is fetchable via HTTP GET and
// returns the same bytes WriteEntry stored.
//
// Skipped on fake-gcs-server: the local emulator's V4 signing is
// not byte-equivalent to real GCS, and even when the URL parses,
// the server may not validate the signature the way real GCS does.
// Real-GCS mode runs this; fake-gcs mode skips with a log line.
func TestGCS_PresignGet_FetchesBytes(t *testing.T) {
	if os.Getenv("ATTESTA_TEST_GCS_ENDPOINT") != "" {
		t.Skip("PresignGet uses real GCS V4 signing; fake-gcs-server does not validate it")
	}
	ctx := context.Background()
	store := requireGCS(t)

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
		t.Fatalf("HTTP status: %d %s", resp.StatusCode, resp.Status)
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
// Close idempotency
// ─────────────────────────────────────────────────────────────────

func TestGCS_Close_NilSafe(t *testing.T) {
	var s *GCS
	if err := s.Close(); err != nil {
		t.Errorf("nil Close: expected nil, got %v", err)
	}
}
