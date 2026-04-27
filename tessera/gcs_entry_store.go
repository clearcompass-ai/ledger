/*
FILE PATH: tessera/gcs_entry_store.go

GCSEntryStore — GCS-backed implementation of EntryReader +
EntryWriter. Replaces InMemoryEntryStore for production
deployments where entry bytes must survive operator process
restarts and be addressable from multiple operator instances
(writer + reader sharing the same byte vault).

WHY GCS:

  The user's architectural directive specifies GCS via
  Application Default Credentials (ADC) for the operator's
  byte vault. fake-gcs-server speaks the same wire protocol,
  so integration tests run against the docker-compose harness
  without changing this file.

OBJECT LAYOUT:

  Each entry's bytes live at one object:

    gs://<bucket>/entries/<sequence>/data

  The object body is the same EncodeEntryData(canonical, sig)
  blob InMemoryEntryStore writes — preserves wire-format
  compatibility across the read path (PostgresEntryFetcher,
  scanAndHydrate, etc.). Sequence numbers are zero-padded to
  16 hex digits so lexical ordering matches numeric ordering;
  useful for ad-hoc gsutil ls inspection.

CACHING:

  GCS object reads are 50-200ms. At sustained 100 QPS (the
  user's stated SLO target) with diverse access patterns,
  per-request GCS hits would dominate latency. The store
  fronts GCS with an LRU cache keyed by sequence number.
  Cache size is caller-configurable; the cache stores raw
  RawEntry values (canonical + sig), so a hit avoids the
  decode round-trip too.

  Writes are write-through: WriteEntry pushes the blob to GCS
  AND populates the cache. Read-after-write hits the cache.

CREDENTIALS:

  cloud.google.com/go/storage's NewClient honors ADC by
  default — production deployments running on GCE/GKE pick
  up the workload identity automatically. For local tests,
  fake-gcs-server requires a custom endpoint and accepts
  anonymous credentials; both are supported via
  GCSEntryStoreConfig.{Endpoint, Anonymous}.

CONCURRENCY:

  GCS client is goroutine-safe; the LRU cache is mutex-
  guarded internally. Multiple concurrent readers + writers
  on a single store instance are safe.
*/
package tessera

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// GCSEntryStoreConfig configures NewGCSEntryStore.
type GCSEntryStoreConfig struct {
	// Bucket is the GCS bucket name. REQUIRED.
	Bucket string

	// Endpoint overrides the default GCS endpoint
	// ("https://storage.googleapis.com"). Set this for
	// fake-gcs-server tests (e.g.,
	// "http://localhost:4443/storage/v1/"). Empty = default
	// production endpoint.
	Endpoint string

	// Anonymous bypasses ADC credential discovery. Set true
	// for fake-gcs-server tests. Empty/false = use ADC
	// (production).
	Anonymous bool

	// CacheSize is the LRU cache size (number of RawEntry
	// values held in memory). Defaults to 4096 when zero.
	// Each cached entry is ~1KB on average; 4096 ≈ 4MB RAM.
	CacheSize int

	// ObjectPrefix is prepended to every object name.
	// Defaults to "entries". Useful for sharing a bucket
	// across multiple operator instances (one prefix per
	// log).
	ObjectPrefix string

	// WriteTimeout caps a single WriteEntry call. Defaults to
	// 30s, generous for slow CI / cross-region writes.
	WriteTimeout time.Duration

	// ReadTimeout caps a single ReadEntry / ReadEntryBatch
	// call. Defaults to 30s.
	ReadTimeout time.Duration
}

// GCSEntryStore satisfies EntryReader + EntryWriter against a
// GCS bucket with an LRU cache layer.
type GCSEntryStore struct {
	client       *storage.Client
	bucket       *storage.BucketHandle
	objectPrefix string
	writeTimeout time.Duration
	readTimeout  time.Duration

	mu      sync.Mutex
	cache   map[uint64]RawEntry
	access  map[uint64]int64 // monotonic counter for LRU
	counter int64
	maxSize int
}

// NewGCSEntryStore opens a GCS client and returns a store rooted
// at cfg.Bucket. The bucket must already exist; this function
// does NOT create it.
//
// For fake-gcs-server tests:
//
//	NewGCSEntryStore(ctx, GCSEntryStoreConfig{
//	    Bucket:    "test-bucket",
//	    Endpoint:  "http://localhost:4443/storage/v1/",
//	    Anonymous: true,
//	})
//
// For production:
//
//	NewGCSEntryStore(ctx, GCSEntryStoreConfig{
//	    Bucket: "ortholog-prod-entries",
//	})
//
// The latter form picks up Application Default Credentials
// (workload identity on GCE/GKE; gcloud-auth on dev machines).
func NewGCSEntryStore(ctx context.Context, cfg GCSEntryStoreConfig) (*GCSEntryStore, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("tessera/gcs: NewGCSEntryStore requires non-empty Bucket")
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 4096
	}
	if cfg.ObjectPrefix == "" {
		cfg.ObjectPrefix = "entries"
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}

	var clientOpts []option.ClientOption
	if cfg.Endpoint != "" {
		clientOpts = append(clientOpts, option.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Anonymous {
		// fake-gcs-server runs without auth; use the no-auth path.
		clientOpts = append(clientOpts, option.WithoutAuthentication())
	}

	client, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("tessera/gcs: storage.NewClient: %w", err)
	}

	return &GCSEntryStore{
		client:       client,
		bucket:       client.Bucket(cfg.Bucket),
		objectPrefix: cfg.ObjectPrefix,
		writeTimeout: cfg.WriteTimeout,
		readTimeout:  cfg.ReadTimeout,
		cache:        make(map[uint64]RawEntry, cfg.CacheSize),
		access:       make(map[uint64]int64, cfg.CacheSize),
		maxSize:      cfg.CacheSize,
	}, nil
}

// objectName returns "<prefix>/<seq:016x>/data".
func (s *GCSEntryStore) objectName(seq uint64) string {
	return fmt.Sprintf("%s/%016x/data", s.objectPrefix, seq)
}

// WriteEntry stores the (canonical, sig) blob at entries/<seq>/data
// and populates the in-memory cache. Errors propagate from the GCS
// upload.
func (s *GCSEntryStore) WriteEntry(seq uint64, canonical []byte, sig []byte) error {
	if len(canonical) == 0 {
		return fmt.Errorf("tessera/gcs: WriteEntry seq=%d: empty canonical bytes", seq)
	}

	blob := EncodeEntryData(canonical, sig)

	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()

	obj := s.bucket.Object(s.objectName(seq))
	w := obj.NewWriter(ctx)
	w.ContentType = "application/octet-stream"
	if _, err := io.Copy(w, bytes.NewReader(blob)); err != nil {
		_ = w.Close()
		return fmt.Errorf("tessera/gcs: write seq=%d: %w", seq, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("tessera/gcs: close seq=%d: %w", seq, err)
	}

	// Cache write — copy slices so callers can mutate the
	// inputs after we return without corrupting the cache.
	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	s.cache[seq] = RawEntry{
		CanonicalBytes: append([]byte(nil), canonical...),
		SigBytes:       append([]byte(nil), sig...),
	}
	s.access[seq] = s.counter
	s.mu.Unlock()

	return nil
}

// ReadEntry fetches entries/<seq>/data, decodes the blob into
// (canonical, sig), and returns it as a RawEntry. Errors:
//   - storage.ErrObjectNotExist when the object is missing
//   - wrapped GCS errors for transport failures
func (s *GCSEntryStore) ReadEntry(seq uint64) (RawEntry, error) {
	// Cache hit.
	s.mu.Lock()
	if entry, ok := s.cache[seq]; ok {
		s.counter++
		s.access[seq] = s.counter
		s.mu.Unlock()
		return entry, nil
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
	defer cancel()

	obj := s.bucket.Object(s.objectName(seq))
	r, err := obj.NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return RawEntry{}, fmt.Errorf("tessera/gcs: seq=%d not found: %w", seq, err)
		}
		return RawEntry{}, fmt.Errorf("tessera/gcs: read seq=%d: %w", seq, err)
	}
	defer r.Close()

	blob, err := io.ReadAll(r)
	if err != nil {
		return RawEntry{}, fmt.Errorf("tessera/gcs: read body seq=%d: %w", seq, err)
	}

	canonical, sig, err := DecodeEntryData(blob)
	if err != nil {
		return RawEntry{}, fmt.Errorf("tessera/gcs: decode seq=%d: %w", seq, err)
	}

	entry := RawEntry{
		CanonicalBytes: canonical,
		SigBytes:       sig,
	}

	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	s.cache[seq] = entry
	s.access[seq] = s.counter
	s.mu.Unlock()

	return entry, nil
}

// ReadEntryBatch returns each requested sequence's RawEntry in
// the same order as the input slice. Mirrors
// InMemoryEntryStore.ReadEntryBatch semantics: any missing
// sequence is a fatal error for the whole batch (so callers
// don't get a silent short slice).
//
// Reads run sequentially. A future optimization could fan-out
// concurrent goroutines bounded by a semaphore; the current
// shape is correctness-first, optimize-later. At sustained 100
// QPS with cache hit rates above 80% the sequential path is
// fine.
func (s *GCSEntryStore) ReadEntryBatch(seqs []uint64) ([]RawEntry, error) {
	out := make([]RawEntry, len(seqs))
	for i, seq := range seqs {
		entry, err := s.ReadEntry(seq)
		if err != nil {
			return nil, fmt.Errorf("tessera/gcs: ReadEntryBatch[%d/%d] seq=%d: %w", i, len(seqs), seq, err)
		}
		out[i] = entry
	}
	return out, nil
}

// evictLRULocked drops the lowest-access-counter entry from the
// cache. Caller MUST hold s.mu.
func (s *GCSEntryStore) evictLRULocked() {
	var oldestSeq uint64
	var oldestAccess int64 = 1<<63 - 1
	for seq, ac := range s.access {
		if ac < oldestAccess {
			oldestAccess = ac
			oldestSeq = seq
		}
	}
	delete(s.cache, oldestSeq)
	delete(s.access, oldestSeq)
}

// Close releases the GCS client. Safe to call multiple times —
// underlying client.Close() is idempotent.
func (s *GCSEntryStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

// Compile-time pins.
var (
	_ EntryReader = (*GCSEntryStore)(nil)
	_ EntryWriter = (*GCSEntryStore)(nil)
)
