/*
FILE PATH: bytestore/gcs.go

GCS — GCS-backed bytestore.Store implementation. Production target
where entry bytes must survive operator process restarts and be
addressable from multiple operator instances (writer + reader
sharing the same byte vault).

WHY GCS:

  The operator targets GCS via Application Default Credentials (ADC)
  for the byte vault. fake-gcs-server speaks the same wire protocol,
  so integration tests run against the docker-compose harness without
  changing this file.

OBJECT LAYOUT:

  Each entry's bytes live at one object:

    gs://<bucket>/entries/<sequence>/data

  The object body is the wire bytes verbatim — opaque to the store;
  whatever was written is what reads return. Sequence numbers are
  zero-padded to 16 hex digits so lexical ordering matches numeric
  ordering; useful for ad-hoc gsutil ls inspection.

CACHING:

  GCS object reads are 50-200ms. At sustained 100 QPS with diverse
  access patterns, per-request GCS hits would dominate latency. The
  store fronts GCS with an LRU cache keyed by sequence number. Cache
  size is caller-configurable.

  Writes are write-through: WriteEntry pushes the blob to GCS AND
  populates the cache. Read-after-write hits the cache.

CREDENTIALS:

  cloud.google.com/go/storage's NewClient honors ADC by default —
  production deployments running on GCE/GKE pick up the workload
  identity automatically. For local tests, fake-gcs-server requires
  a custom endpoint and accepts anonymous credentials; both are
  supported via GCSConfig.{Endpoint, Anonymous}.

CONCURRENCY:

  GCS client is goroutine-safe; the LRU cache is mutex-guarded
  internally. Multiple concurrent readers + writers on a single
  store instance are safe.
*/
package bytestore

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

// GCSConfig configures NewGCS.
type GCSConfig struct {
	// Bucket is the GCS bucket name. REQUIRED.
	Bucket string

	// Endpoint overrides the default GCS endpoint
	// ("https://storage.googleapis.com"). Set this for
	// fake-gcs-server tests (e.g.,
	// "http://localhost:4443/storage/v1/"). Empty = default
	// production endpoint.
	Endpoint string

	// Anonymous bypasses ADC credential discovery. Set true for
	// fake-gcs-server tests. Empty/false = use ADC (production).
	Anonymous bool

	// CacheSize is the LRU cache size (number of wire-byte blobs
	// held in memory). Defaults to 4096 when zero. Each cached entry
	// is ~1KB on average; 4096 ≈ 4MB RAM.
	CacheSize int

	// ObjectPrefix is prepended to every object name. Defaults to
	// "entries". Useful for sharing a bucket across multiple
	// operator instances (one prefix per log).
	ObjectPrefix string

	// WriteTimeout caps a single WriteEntry call. Defaults to 30s,
	// generous for slow CI / cross-region writes.
	WriteTimeout time.Duration

	// ReadTimeout caps a single ReadEntry / ReadEntryBatch call.
	// Defaults to 30s.
	ReadTimeout time.Duration
}

// GCS satisfies Store against a GCS bucket with an LRU cache layer.
type GCS struct {
	client       *storage.Client
	bucket       *storage.BucketHandle
	objectPrefix string
	writeTimeout time.Duration
	readTimeout  time.Duration

	mu      sync.Mutex
	cache   map[uint64][]byte
	access  map[uint64]int64 // monotonic counter for LRU
	counter int64
	maxSize int
}

// NewGCS opens a GCS client and returns a store rooted at cfg.Bucket.
// The bucket must already exist; this function does NOT create it.
//
// For fake-gcs-server tests:
//
//	NewGCS(ctx, GCSConfig{
//	    Bucket:    "test-bucket",
//	    Endpoint:  "http://localhost:4443/storage/v1/",
//	    Anonymous: true,
//	})
//
// For production:
//
//	NewGCS(ctx, GCSConfig{
//	    Bucket: "ortholog-prod-entries",
//	})
//
// The latter form picks up Application Default Credentials (workload
// identity on GCE/GKE; gcloud-auth on dev machines).
func NewGCS(ctx context.Context, cfg GCSConfig) (*GCS, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("bytestore/gcs: NewGCS requires non-empty Bucket")
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

	// Force ReadObject calls onto the JSON API instead of the XML
	// API (the SDK default at v1.62.1; flagged to flip in a future
	// release per cloud.google.com/go/storage option.go:124-138).
	//
	// Why this matters: WriteEntry uploads and bucket.Objects()
	// LIST both go through the JSON API (`/storage/v1/...`), and
	// option.WithEndpoint correctly redirects them to fake-gcs.
	// But ObjectHandle.NewReader's XML default builds URLs like
	// `<scheme>://<host>/<bucket>/<object>` — fake-gcs's XML
	// surface has gaps that surface as 404s on read-after-write
	// even when JSON LIST sees the object. Real GCS handles both
	// transports identically so the bug is invisible there.
	//
	// WithJSONReads is recommended by the SDK regardless ("ensure
	// consistency with other client operations"), so this is the
	// right choice for production GCS too — not a fake-gcs-only
	// workaround.
	clientOpts = append(clientOpts, storage.WithJSONReads())

	client, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("bytestore/gcs: storage.NewClient: %w", err)
	}

	return &GCS{
		client:       client,
		bucket:       client.Bucket(cfg.Bucket),
		objectPrefix: cfg.ObjectPrefix,
		writeTimeout: cfg.WriteTimeout,
		readTimeout:  cfg.ReadTimeout,
		cache:        make(map[uint64][]byte, cfg.CacheSize),
		access:       make(map[uint64]int64, cfg.CacheSize),
		maxSize:      cfg.CacheSize,
	}, nil
}

// objectName returns "<prefix>/<seq:016x>/data".
func (s *GCS) objectName(seq uint64) string {
	return fmt.Sprintf("%s/%016x/data", s.objectPrefix, seq)
}

// WriteEntry uploads wire bytes to entries/<seq>/data and populates
// the in-memory cache. Errors propagate from the GCS upload.
func (s *GCS) WriteEntry(seq uint64, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("bytestore/gcs: WriteEntry seq=%d: empty wire bytes", seq)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()

	obj := s.bucket.Object(s.objectName(seq))
	w := obj.NewWriter(ctx)
	w.ContentType = "application/octet-stream"
	if _, err := io.Copy(w, bytes.NewReader(wireBytes)); err != nil {
		_ = w.Close()
		return fmt.Errorf("bytestore/gcs: write seq=%d: %w", seq, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("bytestore/gcs: close seq=%d: %w", seq, err)
	}

	// Cache write — copy the slice so callers can mutate the input
	// after we return without corrupting the cache.
	cp := make([]byte, len(wireBytes))
	copy(cp, wireBytes)
	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	s.cache[seq] = cp
	s.access[seq] = s.counter
	s.mu.Unlock()

	return nil
}

// ReadEntry fetches the wire bytes at entries/<seq>/data. Errors:
//   - storage.ErrObjectNotExist when the object is missing
//   - wrapped GCS errors for transport failures
func (s *GCS) ReadEntry(seq uint64) ([]byte, error) {
	// Cache hit. Copy on the way out so callers cannot mutate the
	// cached value.
	s.mu.Lock()
	if entry, ok := s.cache[seq]; ok {
		s.counter++
		s.access[seq] = s.counter
		cp := make([]byte, len(entry))
		copy(cp, entry)
		s.mu.Unlock()
		return cp, nil
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
	defer cancel()

	obj := s.bucket.Object(s.objectName(seq))
	r, err := obj.NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("bytestore/gcs: seq=%d not found: %w", seq, err)
		}
		return nil, fmt.Errorf("bytestore/gcs: read seq=%d: %w", seq, err)
	}
	defer r.Close()

	blob, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("bytestore/gcs: read body seq=%d: %w", seq, err)
	}

	// Cache the freshly-fetched blob; copy on the way out for the
	// same reason as the cache-hit path.
	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	cached := make([]byte, len(blob))
	copy(cached, blob)
	s.cache[seq] = cached
	s.access[seq] = s.counter
	s.mu.Unlock()

	return blob, nil
}

// ReadEntryBatch returns each requested sequence's wire bytes in the
// same order as the input slice. Mirrors Memory semantics: any
// missing sequence is a fatal error for the whole batch (so callers
// don't get a silent short slice).
//
// Reads run sequentially. A future optimization could fan out
// concurrent goroutines bounded by a semaphore; the current shape
// is correctness-first, optimize-later. At sustained 100 QPS with
// cache hit rates above 80% the sequential path is fine.
func (s *GCS) ReadEntryBatch(seqs []uint64) ([][]byte, error) {
	out := make([][]byte, len(seqs))
	for i, seq := range seqs {
		entry, err := s.ReadEntry(seq)
		if err != nil {
			return nil, fmt.Errorf("bytestore/gcs: ReadEntryBatch[%d/%d] seq=%d: %w", i, len(seqs), seq, err)
		}
		out[i] = entry
	}
	return out, nil
}

// evictLRULocked drops the lowest-access-counter entry from the cache.
// Caller MUST hold s.mu.
func (s *GCS) evictLRULocked() {
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

// Close releases the GCS client. Safe to call multiple times — the
// underlying client.Close() is idempotent.
func (s *GCS) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

// Compile-time pin.
var _ Store = (*GCS)(nil)
