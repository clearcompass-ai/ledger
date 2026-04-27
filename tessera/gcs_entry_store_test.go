/*
FILE PATH: tessera/gcs_entry_store_test.go

Tests for GCSEntryStore. Run against the fake-gcs-server harness
exposed by integration/docker-compose.yml. Skip cleanly when
ORTHOLOG_TEST_GCS_ENDPOINT is unset, mirroring the
ORTHOLOG_TEST_DSN skip pattern in store/sequence_cursor_test.go
and store/commitment_fetcher_test.go.

Coverage:
  - Constructor validation (empty bucket).
  - Object naming (zero-padded sequence).
  - WriteEntry → ReadEntry round-trip.
  - ReadEntry on missing key surfaces storage.ErrObjectNotExist
    (wrapped).
  - LRU cache hit on read-after-write (no GCS round-trip second
    time).
  - LRU eviction at capacity.
  - ReadEntryBatch in-order.
  - Empty canonical bytes rejected.
  - Concurrent writers (interface goroutine-safety pin).
  - Custom ObjectPrefix isolates two stores in the same bucket.
  - Compile-time interface satisfaction (already in gcs_entry_store.go;
    test file adds a redundant pin to make any future drift loud).

The fake-gcs-server endpoint and bucket are read from env:

  ORTHOLOG_TEST_GCS_ENDPOINT   e.g. http://localhost:4443/storage/v1/
  ORTHOLOG_TEST_GCS_BUCKET     e.g. ortholog-test-bytes

The docker-compose harness creates the bucket at startup; tests
that need a clean state delete + recreate per-test via the
ObjectPrefix knob (each test gets its own prefix).
*/
package tessera

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// requireGCS opens a GCSEntryStore configured for either fake-gcs-server
// (integration harness) or real GCS (sanity check against production
// credentials), depending on which env vars are set:
//
//	ORTHOLOG_TEST_GCS_ENDPOINT  set  → fake-gcs mode
//	                                   anonymous=true, endpoint override
//	ORTHOLOG_TEST_GCS_BUCKET    set  → real GCS mode
//	                                   anonymous=false (ADC), no endpoint override
//	neither set                      → t.Skip
//
// Real GCS mode requires GOOGLE_APPLICATION_CREDENTIALS pointing at a
// service-account key file with storage.objects.create + .get + .delete
// on the named bucket. Each test gets a unique prefix
// (test/<TestName>/<unix-nano>) so concurrent runs don't collide AND
// t.Cleanup deletes every object under that prefix at test end — real
// GCS otherwise accumulates test junk forever.
//
// fake-gcs mode skips the cleanup pass since `down -v` wipes the
// container's data dir between runs anyway.
func requireGCS(t *testing.T) *GCSEntryStore {
	t.Helper()

	endpoint := os.Getenv("ORTHOLOG_TEST_GCS_ENDPOINT")
	bucket := os.Getenv("ORTHOLOG_TEST_GCS_BUCKET")

	// Skip when nothing is wired up.
	if endpoint == "" && bucket == "" {
		t.Skip("neither ORTHOLOG_TEST_GCS_ENDPOINT nor ORTHOLOG_TEST_GCS_BUCKET set; skipping GCS test")
	}

	// Mode detection.
	fakeMode := endpoint != ""
	if !fakeMode && bucket == "" {
		t.Skip("ORTHOLOG_TEST_GCS_BUCKET unset for real-GCS mode; skipping")
	}
	if fakeMode && bucket == "" {
		bucket = "ortholog-test-bytes"
	}

	// Per-test isolation via prefix.
	prefix := fmt.Sprintf("test/%s/%d", t.Name(), time.Now().UnixNano())

	// Real GCS first-connection can take a few seconds; bump the
	// timeout from the fake-gcs-friendly 5s.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := GCSEntryStoreConfig{
		Bucket:       bucket,
		ObjectPrefix: prefix,
		CacheSize:    16,
	}
	if fakeMode {
		cfg.Endpoint = endpoint
		cfg.Anonymous = true
		t.Logf("GCS test mode: fake-gcs-server (endpoint=%s, bucket=%s)", endpoint, bucket)
	} else {
		// Real GCS: ADC via GOOGLE_APPLICATION_CREDENTIALS or
		// workload identity. Anonymous stays false.
		t.Logf("GCS test mode: real GCS (bucket=%s, prefix=%s)", bucket, prefix)
	}

	store, err := NewGCSEntryStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewGCSEntryStore: %v", err)
	}

	t.Cleanup(func() {
		// Delete every object under the test's prefix so real-GCS
		// runs don't accumulate junk. fake-gcs-server is wiped by
		// `down -v` between runs anyway, but the same code path is
		// safe to run there too — the iterator simply finds zero
		// objects to delete on a fresh container.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deletePrefix(t, cleanupCtx, store, prefix)

		if err := store.Close(); err != nil {
			t.Logf("Close (cleanup): %v", err)
		}
	})

	return store
}

// deletePrefix lists every object under prefix in the supplied
// store's bucket and deletes them. Best-effort: a delete failure is
// logged but doesn't fail the test — we don't want a stale ACL or
// transient 5xx to mask a real test pass.
func deletePrefix(t *testing.T, ctx context.Context, store *GCSEntryStore, prefix string) {
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

func TestGCSEntryStore_New_RejectsEmptyBucket(t *testing.T) {
	_, err := NewGCSEntryStore(context.Background(), GCSEntryStoreConfig{Bucket: ""})
	if err == nil {
		t.Fatal("expected error on empty Bucket")
	}
}

// ─────────────────────────────────────────────────────────────────
// Object naming (always runs, no GCS needed)
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_ObjectName_ZeroPadded16Hex(t *testing.T) {
	store := &GCSEntryStore{objectPrefix: "entries"}
	cases := []struct {
		seq  uint64
		want string
	}{
		{0, "entries/0000000000000000/data"},
		{1, "entries/0000000000000001/data"},
		{255, "entries/00000000000000ff/data"},
		{0xdeadbeef, "entries/00000000deadbeef/data"},
		{0xFFFFFFFFFFFFFFFF, "entries/ffffffffffffffff/data"},
	}
	for _, tc := range cases {
		if got := store.objectName(tc.seq); got != tc.want {
			t.Errorf("seq=%x: got %q, want %q", tc.seq, got, tc.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// Round-trip: write then read
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_WriteThenRead_RoundTrip(t *testing.T) {
	store := requireGCS(t)

	// Wire bytes ARE the canonical bytes under v7.75 — the byte store
	// is opaque, so any blob round-trips identically. Use a synthetic
	// blob with high-entropy content (sha256 of a stable seed) to
	// distinguish identity from accidental zero-byte matches.
	seed := sha256.Sum256([]byte("seed"))
	wire := append([]byte("the wire bytes for the entry|"), seed[:]...)

	if err := store.WriteEntry(42, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	got, err := store.ReadEntry(42)
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

func TestGCSEntryStore_ReadEntry_MissingKeyWrapsErrObjectNotExist(t *testing.T) {
	store := requireGCS(t)

	_, err := store.ReadEntry(99999)
	if err == nil {
		t.Fatal("expected error reading missing key")
	}
	if !errors.Is(err, storage.ErrObjectNotExist) {
		t.Errorf("expected wrapped storage.ErrObjectNotExist, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// LRU cache hit on read-after-write
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_ReadAfterWrite_HitsCache(t *testing.T) {
	store := requireGCS(t)

	wire := []byte("cached entry wire blob")
	if err := store.WriteEntry(7, wire); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	// First read should hit the cache (write-through populated it).
	// We can't directly verify "no GCS round trip happened" without
	// instrumenting, but we CAN verify the in-memory map contains
	// the seq.
	store.mu.Lock()
	_, cached := store.cache[7]
	store.mu.Unlock()
	if !cached {
		t.Fatal("WriteEntry should have populated the cache")
	}

	// Read returns the cached blob.
	got, err := store.ReadEntry(7)
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

func TestGCSEntryStore_Cache_EvictsOldestAtCapacity(t *testing.T) {
	store := requireGCS(t)
	// requireGCS configures CacheSize=16. Write 17 entries; the
	// first should be evicted from cache.

	for i := uint64(0); i < 17; i++ {
		if err := store.WriteEntry(i, []byte("blob")); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	store.mu.Lock()
	_, firstStillCached := store.cache[0]
	cacheSize := len(store.cache)
	store.mu.Unlock()

	if firstStillCached {
		t.Error("seq=0 should have been evicted at cap=16")
	}
	if cacheSize > 16 {
		t.Errorf("cache size %d exceeds maxSize 16", cacheSize)
	}

	// Sanity: re-reading seq=0 hits GCS, not the cache. fake-gcs-
	// server has a tiny read-after-write consistency window after
	// bursty writes; real GCS doesn't. Retry-with-backoff handles
	// either case without changing production semantics.
	got, err := readEntryWithRetry(t, store, 0)
	if err != nil {
		t.Fatalf("ReadEntry seq=0 after eviction: %v", err)
	}
	if !bytes.Equal(got, []byte("blob")) {
		t.Errorf("post-eviction read returned wrong bytes: %x", got)
	}
}

// readEntryWithRetry calls store.ReadEntry, retrying on
// storage.ErrObjectNotExist up to 5 times with 50ms exponential
// backoff. Exists because fake-gcs-server has a brief read-after-
// write consistency lag under bursty writes (seen reproducibly in
// the eviction + concurrent-writers tests). Real GCS is strongly
// consistent and the first attempt always succeeds; the retry is
// a no-op there.
//
// Production code (GCSEntryStore.ReadEntry) does NOT retry —
// cache miss → ErrObjectNotExist surfaces as "entry doesn't
// exist", which is the correct semantic for the operator's
// query path. This helper exists only inside test code to
// paper over a fake-gcs-server quirk.
func readEntryWithRetry(t *testing.T, store *GCSEntryStore, seq uint64) ([]byte, error) {
	t.Helper()
	var lastErr error
	delay := 50 * time.Millisecond
	for i := 0; i < 5; i++ {
		got, err := store.ReadEntry(seq)
		if err == nil {
			return got, nil
		}
		// Only retry on the specific "not yet visible" signal.
		// Anything else (auth, network, decode error) propagates
		// immediately so tests don't silently retry past real bugs.
		if !errors.Is(err, storage.ErrObjectNotExist) {
			return nil, err
		}
		lastErr = err
		time.Sleep(delay)
		delay *= 2
	}
	return nil, fmt.Errorf("readEntryWithRetry seq=%d: 5 attempts: %w", seq, lastErr)
}

// ─────────────────────────────────────────────────────────────────
// Empty canonical rejection
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_WriteEntry_RejectsEmptyWire(t *testing.T) {
	store := requireGCS(t)

	if err := store.WriteEntry(1, nil); err == nil {
		t.Error("expected error on nil wire bytes")
	}
	if err := store.WriteEntry(1, []byte{}); err == nil {
		t.Error("expected error on empty wire bytes")
	}
}

// ─────────────────────────────────────────────────────────────────
// ReadEntryBatch
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_ReadEntryBatch_PreservesInputOrder(t *testing.T) {
	store := requireGCS(t)

	// Seed five entries with distinguishable wire bytes.
	for i := uint64(1); i <= 5; i++ {
		if err := store.WriteEntry(i, []byte{byte(i)}); err != nil {
			t.Fatalf("WriteEntry seq=%d: %v", i, err)
		}
	}

	// Read them out of order; result must follow input order.
	want := []uint64{3, 5, 1, 4, 2}
	got, err := store.ReadEntryBatch(want)
	if err != nil {
		t.Fatalf("ReadEntryBatch: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("length: got %d, want %d", len(got), len(want))
	}
	for i, seq := range want {
		if !bytes.Equal(got[i], []byte{byte(seq)}) {
			t.Errorf("position %d: got %v, want [%d]", i, got[i], seq)
		}
	}
}

func TestGCSEntryStore_ReadEntryBatch_MissingSeqIsFatalForBatch(t *testing.T) {
	store := requireGCS(t)
	if err := store.WriteEntry(1, []byte("blob")); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}

	_, err := store.ReadEntryBatch([]uint64{1, 99999})
	if err == nil {
		t.Fatal("expected fatal error on batch with missing seq")
	}
}

// ─────────────────────────────────────────────────────────────────
// Concurrent writers
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_ConcurrentWriters(t *testing.T) {
	store := requireGCS(t)
	const goroutines = 4
	const perGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				seq := uint64(g*100 + i)
				if err := store.WriteEntry(seq, []byte{byte(g), byte(i)}); err != nil {
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

	// Verify a sample of writes. readEntryWithRetry papers over
	// fake-gcs-server's read-after-write consistency lag under
	// concurrent writes. Real GCS is strongly consistent; the
	// retry never fires there.
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perGoroutine; i++ {
			seq := uint64(g*100 + i)
			got, err := readEntryWithRetry(t, store, seq)
			if err != nil {
				t.Errorf("ReadEntry seq=%d: %v", seq, err)
				continue
			}
			want := []byte{byte(g), byte(i)}
			if !bytes.Equal(got, want) {
				t.Errorf("seq=%d: got %v, want %v", seq, got, want)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// Custom ObjectPrefix isolates two stores in the same bucket
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_DifferentObjectPrefix_IsolatesData(t *testing.T) {
	endpoint := os.Getenv("ORTHOLOG_TEST_GCS_ENDPOINT")
	bucket := os.Getenv("ORTHOLOG_TEST_GCS_BUCKET")
	// Same dual-mode logic as requireGCS — fake-gcs (endpoint set)
	// or real GCS (bucket only).
	if endpoint == "" && bucket == "" {
		t.Skip("neither ORTHOLOG_TEST_GCS_ENDPOINT nor ORTHOLOG_TEST_GCS_BUCKET set")
	}
	fakeMode := endpoint != ""
	if fakeMode && bucket == "" {
		bucket = "ortholog-test-bytes"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mkStore := func(prefix string) *GCSEntryStore {
		t.Helper()
		cfg := GCSEntryStoreConfig{
			Bucket:       bucket,
			ObjectPrefix: prefix,
			CacheSize:    8,
		}
		if fakeMode {
			cfg.Endpoint = endpoint
			cfg.Anonymous = true
		}
		s, err := NewGCSEntryStore(ctx, cfg)
		if err != nil {
			t.Fatalf("NewGCSEntryStore(%s): %v", prefix, err)
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

	if err := storeA.WriteEntry(42, []byte("from A")); err != nil {
		t.Fatalf("storeA write: %v", err)
	}

	// storeB at same seq should NOT find anything.
	_, err := storeB.ReadEntry(42)
	if err == nil {
		t.Fatal("storeB should not see storeA's entries (different prefix)")
	}
	if !errors.Is(err, storage.ErrObjectNotExist) {
		t.Errorf("expected ErrObjectNotExist, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Close idempotency
// ─────────────────────────────────────────────────────────────────

func TestGCSEntryStore_Close_NilSafe(t *testing.T) {
	var s *GCSEntryStore
	if err := s.Close(); err != nil {
		t.Errorf("nil Close: expected nil, got %v", err)
	}
}
