/*
FILE PATH: bytestore/gcs.go

GCS — bytestore.Backend implementation backed by Google Cloud Storage.
Production target where workload identity / ADC is the credential
model. fake-gcs-server speaks the same wire protocol so integration
tests run against the docker-compose harness without changing this
file.

OBJECT LAYOUT:
  All adapters share layoutKey: <prefix>/<seq:016x>/<hash_hex>

CACHING:
  GCS object reads are 50-200ms. The store fronts GCS with an LRU
  cache keyed by the canonical layout key. Writes are write-through.

CREDENTIALS:
  cloud.google.com/go/storage's NewClient honors ADC by default.
  fake-gcs-server requires Endpoint + Anonymous=true.

PRESIGNED URLS:
  V4 signed URLs via storage.SignedURL. Service-account-key sites
  sign locally; workload-identity sites use the IAM signBlob API.
  TTL is clamped to 7 days (the GCS V4 ceiling).

CONCURRENCY:
  GCS client is goroutine-safe; the LRU cache is mutex-guarded.
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

// Maximum TTL allowed by GCS V4 signed URLs.
const gcsMaxPresignTTL = 7 * 24 * time.Hour

// GCSConfig configures NewGCS.
type GCSConfig struct {
	// Bucket is the GCS bucket name. REQUIRED.
	Bucket string

	// Endpoint overrides the default GCS endpoint
	// ("https://storage.googleapis.com"). Set this for
	// fake-gcs-server tests (e.g.,
	// "http://localhost:4443/storage/v1/").
	Endpoint string

	// Anonymous bypasses ADC credential discovery. Set true for
	// fake-gcs-server tests.
	Anonymous bool

	// CacheSize is the LRU cache size (number of wire-byte blobs
	// held in memory). Defaults to 4096.
	CacheSize int

	// ObjectPrefix is the first path segment under the bucket.
	// Defaults to "entries". Useful for sharing a bucket across
	// multiple operator instances (one prefix per log).
	ObjectPrefix string

	// WriteTimeout caps a single WriteEntry call. Defaults to 30s.
	WriteTimeout time.Duration

	// ReadTimeout caps a single ReadEntry / ReadEntryBatch call.
	// Defaults to 30s.
	ReadTimeout time.Duration
}

// GCS satisfies Backend (Store + Presigner) against a GCS bucket
// with an LRU cache layer.
type GCS struct {
	client       *storage.Client
	bucket       *storage.BucketHandle
	bucketName   string
	objectPrefix string
	writeTimeout time.Duration
	readTimeout  time.Duration

	mu      sync.Mutex
	cache   map[string][]byte
	access  map[string]int64
	counter int64
	maxSize int
}

// NewGCS opens a GCS client and returns a store rooted at cfg.Bucket.
// The bucket must already exist.
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
		clientOpts = append(clientOpts, option.WithoutAuthentication())
	}

	// Force JSON reads — see Phase 2 diagnostic. fake-gcs-server's
	// XML surface is incomplete; real GCS handles both.
	clientOpts = append(clientOpts, storage.WithJSONReads())

	client, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("bytestore/gcs: storage.NewClient: %w", err)
	}

	return &GCS{
		client:       client,
		bucket:       client.Bucket(cfg.Bucket),
		bucketName:   cfg.Bucket,
		objectPrefix: cfg.ObjectPrefix,
		writeTimeout: cfg.WriteTimeout,
		readTimeout:  cfg.ReadTimeout,
		cache:        make(map[string][]byte, cfg.CacheSize),
		access:       make(map[string]int64, cfg.CacheSize),
		maxSize:      cfg.CacheSize,
	}, nil
}

func (s *GCS) keyOf(seq uint64, hash [32]byte) string {
	return layoutKey(s.objectPrefix, seq, hash)
}

// WriteEntry uploads wire bytes and populates the cache.
func (s *GCS) WriteEntry(ctx context.Context, seq uint64, hash [32]byte, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("bytestore/gcs: WriteEntry seq=%d: empty wire bytes", seq)
	}

	wctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	key := s.keyOf(seq, hash)
	obj := s.bucket.Object(key)
	w := obj.NewWriter(wctx)
	w.ContentType = "application/octet-stream"
	if _, err := io.Copy(w, bytes.NewReader(wireBytes)); err != nil {
		_ = w.Close()
		return fmt.Errorf("bytestore/gcs: write seq=%d: %w", seq, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("bytestore/gcs: close seq=%d: %w", seq, err)
	}

	cp := make([]byte, len(wireBytes))
	copy(cp, wireBytes)
	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	s.cache[key] = cp
	s.access[key] = s.counter
	s.mu.Unlock()

	return nil
}

// ReadEntry fetches the wire bytes for (seq, hash).
func (s *GCS) ReadEntry(ctx context.Context, seq uint64, hash [32]byte) ([]byte, error) {
	key := s.keyOf(seq, hash)

	s.mu.Lock()
	if entry, ok := s.cache[key]; ok {
		s.counter++
		s.access[key] = s.counter
		cp := make([]byte, len(entry))
		copy(cp, entry)
		s.mu.Unlock()
		return cp, nil
	}
	s.mu.Unlock()

	rctx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()

	obj := s.bucket.Object(key)
	r, err := obj.NewReader(rctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("bytestore/gcs: seq=%d hash=%x: %w (gcs: %v)", seq, hash[:8], ErrNotFound, err)
		}
		return nil, fmt.Errorf("bytestore/gcs: read seq=%d: %w", seq, err)
	}
	defer r.Close()

	blob, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("bytestore/gcs: read body seq=%d: %w", seq, err)
	}

	s.mu.Lock()
	if len(s.cache) >= s.maxSize {
		s.evictLRULocked()
	}
	s.counter++
	cached := make([]byte, len(blob))
	copy(cached, blob)
	s.cache[key] = cached
	s.access[key] = s.counter
	s.mu.Unlock()

	return blob, nil
}

// ReadEntryBatch fetches each ref in input order. Sequential reads;
// any miss fails the batch.
func (s *GCS) ReadEntryBatch(ctx context.Context, refs []EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		entry, err := s.ReadEntry(ctx, r.Seq, r.Hash)
		if err != nil {
			return nil, fmt.Errorf("bytestore/gcs: ReadEntryBatch[%d/%d] seq=%d: %w", i, len(refs), r.Seq, err)
		}
		out[i] = entry
	}
	return out, nil
}

// PresignGet returns a V4 signed URL granting time-bounded GET
// access to the entry's bytes. ttl is clamped to 7 days
// (the GCS V4 ceiling).
//
// Two credential paths:
//   - Service-account JSON key: NewClient picked it up from
//     GOOGLE_APPLICATION_CREDENTIALS, signing happens locally
//     with no extra round-trip.
//   - Workload identity (GCE/GKE): SignedURL falls through to the
//     IAM signBlob API; one extra HTTP call per Presign. Tolerable
//     for the redirect path because the cost is amortized across
//     consumers fetching the URL.
func (s *GCS) PresignGet(ctx context.Context, seq uint64, hash [32]byte, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if ttl > gcsMaxPresignTTL {
		ttl = gcsMaxPresignTTL
	}
	key := s.keyOf(seq, hash)
	opts := &storage.SignedURLOptions{
		Scheme:  storage.SigningSchemeV4,
		Method:  "GET",
		Expires: time.Now().Add(ttl),
	}
	url, err := s.bucket.SignedURL(key, opts)
	if err != nil {
		return "", fmt.Errorf("bytestore/gcs: SignedURL seq=%d: %w", seq, err)
	}
	return url, nil
}

func (s *GCS) evictLRULocked() {
	var oldestKey string
	var oldestAccess int64 = 1<<63 - 1
	for k, ac := range s.access {
		if ac < oldestAccess {
			oldestAccess = ac
			oldestKey = k
		}
	}
	delete(s.cache, oldestKey)
	delete(s.access, oldestKey)
}

// Close releases the GCS client. Safe to call multiple times.
func (s *GCS) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

// Compile-time pin.
var _ Backend = (*GCS)(nil)
