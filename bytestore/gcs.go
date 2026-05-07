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
	"os"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// Maximum TTL allowed by GCS V4 signed URLs.
const gcsMaxPresignTTL = 7 * 24 * time.Hour

// MaxTileBytes is the largest c2sp.org/tlog-tiles tile body the
// GCSTiles backend will read into memory. Mirrors the SDK's
// log/tessera_fetcher.MaxTileBytes (attesta v0.1.2): a fully-
// packed entry-bundle tile is 256 entries × (2-byte uint16 length
// prefix + MaxBundleEntrySize 65535) = 16,777,472 bytes. Hash
// tiles are bounded much more tightly (256 × 32 = 8 KiB), so the
// entry-bundle ceiling is a safe upper bound for every tile shape
// the backend serves.
//
// Defends auditors / CDN origin pulls against a hostile or
// misbehaving GCS object that holds the connection open and
// streams unbounded bytes past the per-request timeout. The
// backend wraps NewReader in io.LimitReader{N: MaxTileBytes + 1}
// and rejects with an explicit "exceeds MaxTileBytes" error.
const MaxTileBytes = 256 * (2 + 65535) // 16,777,472

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
	// multiple ledger instances (one prefix per log).
	ObjectPrefix string

	// WriteTimeout caps a single WriteEntry call. Defaults to 30s.
	WriteTimeout time.Duration

	// ReadTimeout caps a single ReadEntry / ReadEntryBatch call.
	// Defaults to 30s.
	ReadTimeout time.Duration

	// PublicBaseURL is the credential-free monitor URL prefix used
	// by PublicURL. Empty means "use the default for an anonymous-
	// read GCS bucket": https://storage.googleapis.com/{Bucket}.
	// Set explicitly to point at a CDN / custom DNS in front of
	// the bucket.
	//
	// Pre-condition: the bucket must be configured for anonymous
	// read (IAM `allUsers: roles/storage.objectViewer` or
	// equivalent). When the bucket is private, leave this empty
	// and use Presigner.
	PublicBaseURL string
}

// GCS satisfies Backend (Store + Presigner + PublicURLer) against
// a GCS bucket with an LRU cache layer.
type GCS struct {
	client *storage.Client
	bucket *storage.BucketHandle
	bucketName string
	objectPrefix string
	writeTimeout time.Duration
	readTimeout time.Duration

	// publicURL is the deterministic public-URL composer. May be
	// nil-safe (returns ErrPublicURLNotConfigured) when no base
	// URL was supplied.
	publicURL *publicURLMapper

	mu sync.Mutex
	cache map[string][]byte
	access map[string]int64
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

	// Force JSON reads — fake-gcs-server's XML surface is
	// incomplete; real GCS handles both.
	clientOpts = append(clientOpts, storage.WithJSONReads())

	client, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("bytestore/gcs: storage.NewClient: %w", err)
	}

	// Resolve public URL base. Empty cfg.PublicBaseURL falls back
	// to the canonical anonymous-read GCS URL prefix; CDN-fronted
	// deployments override via cfg.PublicBaseURL.
	publicBase := cfg.PublicBaseURL
	if publicBase == "" {
		publicBase = DefaultGCSPublicBaseURL(cfg.Bucket)
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
		publicURL:    newPublicURLMapper(publicBase, cfg.ObjectPrefix),
	}, nil
}

func (s *GCS) keyOf(seq uint64, hash [32]byte) string {
	return layoutKey(s.objectPrefix, seq, hash)
}

// PublicURL returns the credential-free URL for (seq, hash). Used
// by the api 302 handler when the operator is configured for a
// public bucket (LEDGER_BYTE_STORE_BUCKET_PUBLIC=true). See
// publicurl.go for the architectural rationale (CT-log
// convention, RFC 9162, c2sp.org/tlog-tiles).
//
// Pre-condition for working URLs: the bucket must have IAM
// `allUsers: roles/storage.objectViewer` granted. When the bucket
// is private, the URL technically resolves but returns 403 — the
// operator should set BucketPublic=false to stay on Presigner.
func (s *GCS) PublicURL(seq uint64, hash [32]byte) (string, error) {
	return s.publicURL.PublicURL(seq, hash)
}

// WriteEntry uploads wire bytes and populates the cache.
func (s *GCS) WriteEntry(ctx context.Context, seq uint64, hash [32]byte, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("bytestore/gcs: WriteEntry seq=%d: empty wire bytes", seq)
	}

	t0 := time.Now() // D3
	defer func() { recordPutDuration(ctx, "put", time.Since(t0)) }()

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
	t0 := time.Now() // D3
	defer func() { recordPutDuration(ctx, "get", time.Since(t0)) }()

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
			return nil, fmt.Errorf("bytestore/gcs: seq=%d hash=%x: %w (gcs: %w)", seq, hash[:8], ErrNotFound, err)
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

// -------------------------------------------------------------------------------------------------
// GCSTiles — c2sp.org/tlog-tiles read-only backend
// -------------------------------------------------------------------------------------------------

// GCSTiles serves c2sp.org/tlog-tiles paths from a configurable
// prefix in the same bucket the entry bytestore uses. Constructed
// from an existing *GCS so the auth surface, client, and bucket
// handle are reused — there is exactly one GCS client per ledger
// process, regardless of whether it serves entries, tiles, or
// both.
//
// Object layout under the bucket:
//
//	<prefix>/checkpoint
//	<prefix>/tile/<level>/<chunked_index>[.p/<partial_size>]
//	<prefix>/tile/entries/<chunked_index>[.p/<partial_size>]
//
// Empty prefix means tiles live at bucket root (no leading
// directory). The default prefix in cmd/ledger is "tessera/" so
// entries (under "entries/") and tiles (under "tessera/") never
// collide in the same bucket.
//
// Implements bytestore.TileBackend (compile-time pinned at the
// bottom of this file).
type GCSTiles struct {
	bucket      *storage.BucketHandle
	prefix      string // canonical form: trimmed of trailing slash
	readTimeout time.Duration
}

// NewGCSTiles returns a tile backend reusing the supplied *GCS's
// authenticated bucket handle. prefix is the GCS key prefix where
// Tessera writes tiles; trailing slashes are trimmed. Empty
// prefix means tiles at bucket root.
//
// readTimeout caps each ReadTileByPath / ReadCheckpoint call's
// outbound GCS round-trip. 0 defaults to 30 seconds (matches
// the *GCS struct's read budget).
func NewGCSTiles(g *GCS, prefix string, readTimeout time.Duration) *GCSTiles {
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}
	return &GCSTiles{
		bucket:      g.bucket,
		prefix:      strings.TrimSuffix(prefix, "/"),
		readTimeout: readTimeout,
	}
}

// objectKey composes the GCS object key for a c2sp.org/tlog-tiles
// path. Path-traversal defense in depth: the api-layer handler
// already validates these inputs, but the storage layer ALSO
// rejects ".." segments, absolute paths, and non-printable bytes
// so a backend used outside the standard handler still refuses
// hostile input.
func (t *GCSTiles) objectKey(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("bytestore/gcs: tile path empty")
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("bytestore/gcs: tile path rejects '..': %q", path)
	}
	if strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("bytestore/gcs: tile path rejects absolute: %q", path)
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c < 0x20 || c > 0x7E {
			return "", fmt.Errorf("bytestore/gcs: tile path rejects non-printable byte at %d", i)
		}
	}
	if t.prefix == "" {
		return path, nil
	}
	return t.prefix + "/" + path, nil
}

// ReadTileByPath returns the bytes of a c2sp.org/tlog-tiles path
// (e.g., "tile/0/x001/067" or "tile/entries/x001/067"). Returns
// os.ErrNotExist verbatim when the object is absent — the SDK's
// log/tessera_fetcher.fetchTesseraTile drives the partial-then-
// full fallback off this exact sentinel.
//
// Bounded I/O: the response body is wrapped in io.LimitedReader
// at MaxTileBytes+1 so an over-streaming GCS object cannot OOM
// the host, even within the readTimeout window.
func (t *GCSTiles) ReadTileByPath(ctx context.Context, path string) ([]byte, error) {
	key, err := t.objectKey(path)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, t.readTimeout)
	defer cancel()
	rc, err := t.bucket.Object(key).NewReader(rctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("bytestore/gcs: tile %q: %w", key, err)
	}
	defer rc.Close()
	limited := &io.LimitedReader{R: rc, N: MaxTileBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("bytestore/gcs: tile read %q: %w", key, err)
	}
	if int64(len(data)) > MaxTileBytes {
		return nil, fmt.Errorf("bytestore/gcs: tile %q exceeds MaxTileBytes (%d)", key, MaxTileBytes)
	}
	return data, nil
}

// ReadCheckpoint returns the bytes of <prefix>/checkpoint —
// the c2sp.org/tlog-tiles signed checkpoint Tessera writes after
// each integration cycle. Returns os.ErrNotExist before the
// first checkpoint is published.
func (t *GCSTiles) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return t.ReadTileByPath(ctx, "checkpoint")
}

// Compile-time pin: GCSTiles satisfies the read-only
// TileBackend contract the api/ tile-serving handlers consume.
var _ TileBackend = (*GCSTiles)(nil)
