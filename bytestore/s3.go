/*
FILE PATH: bytestore/s3.go

S3 — bytestore.Backend implementation backed by any S3-compatible
object store. Validated against:

  - AWS S3 (production)
  - RustFS (local dev / on-prem / CI)
  - Cloudflare R2, Backblaze B2, etc. (S3-compatible)

The wire is identical across these so one adapter covers them all.
Switching providers is a config change, not a code change.

CREDENTIALS:

	Default credential chain (config.LoadDefaultConfig). Picks up:
	  - explicit AccessKey/SecretKey passed via S3Config (RustFS)
	  - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
	  - ~/.aws/credentials profile
	  - IRSA / ECS task role / EC2 instance role
	In production on AWS, prefer IAM roles — never put keys in env.

PATH-STYLE vs VIRTUAL-HOST URLS:

	AWS S3 uses virtual-host style (bucket.s3.region.amazonaws.com).
	RustFS uses path-style (host:port/bucket/key). The PathStyle
	config field selects between them.

OBJECT LAYOUT:

	Same layoutKey as GCS: <prefix>/<seq:016x>/<hash_hex>. A bucket
	written by GCS can be read by S3 and vice versa.

PUBLIC URLS:

	Buckets are anonymous-read by design (transparency-log
	convention; see publicurl.go). PublicURL composes a
	deterministic credential-free URL. No signing, no expiry,
	CDN-cacheable.

CACHING:

	LRU cache, identical model to the GCS adapter.
*/
package bytestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

// S3Config configures NewS3.
type S3Config struct {
	// Bucket is the S3 bucket name. REQUIRED.
	Bucket string

	// Endpoint overrides the default S3 endpoint. Set this for
	// RustFS (e.g., "http://localhost:9000"). Leave empty for AWS S3.
	Endpoint string

	// Region is the AWS region. Defaults to "us-east-1" if empty.
	// RustFS accepts any region; AWS S3 requires a real one.
	Region string

	// AccessKey + SecretKey are static credentials — set these for
	// RustFS. For AWS S3, prefer leaving them empty so the default
	// credential chain (IAM role, AWS_* env, ~/.aws) takes over.
	AccessKey string
	SecretKey string

	// PathStyle selects path-style vs virtual-host URLs:
	//   - true → host/bucket/key (RustFS)
	//   - false → bucket.host/key (AWS S3 default)
	PathStyle bool

	// CacheSize is the LRU cache size. Defaults to 4096.
	CacheSize int

	// ObjectPrefix is the first path segment under the bucket.
	// Defaults to "entries".
	ObjectPrefix string

	// WriteTimeout caps a single WriteEntry call. Defaults to 30s.
	WriteTimeout time.Duration

	// ReadTimeout caps a single ReadEntry / ReadEntryBatch call.
	// Defaults to 30s.
	ReadTimeout time.Duration

	// PublicBaseURL is the credential-free monitor URL prefix used
	// by PublicURL. Empty means "use the appropriate default":
	//
	//   PathStyle  → DefaultS3PathStylePublicBaseURL(Endpoint, Bucket)
	//                (SeaweedFS, MinIO, RustFS, R2 path-style)
	//   non-PathStyle → DefaultS3VirtualHostPublicBaseURL(Bucket, Region)
	//                   (AWS S3 with public-read bucket policy)
	//
	// Set explicitly to point at a CDN / custom DNS in front of
	// the bucket.
	//
	// Pre-condition: bucket must allow anonymous GET. SeaweedFS in
	// `weed mini` mode does this by default; MinIO requires
	// `mc anonymous set download`; AWS S3 requires a bucket policy
	// + Block-Public-Access opt-out.
	PublicBaseURL string
}

// S3 satisfies Backend (Store + PublicURLer) against any
// S3-compatible object store. Buckets are anonymous-read by
// design; PublicURL composes deterministic credential-free URLs.
type S3 struct {
	client       *s3.Client
	bucket       string
	objectPrefix string
	writeTimeout time.Duration
	readTimeout  time.Duration

	// publicURL is the deterministic public-URL composer. May be
	// nil-safe (returns ErrPublicURLNotConfigured) when no base
	// URL was supplied AND no default could be derived.
	publicURL *publicURLMapper

	mu      sync.Mutex
	cache   map[string][]byte
	access  map[string]int64
	counter int64
	maxSize int
}

// NewS3 opens an S3-compatible client. The bucket must already exist;
// this function does NOT create it.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("bytestore/s3: NewS3 requires non-empty Bucket")
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
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	// HTTP transport tuned for high-concurrency workloads. The SDK's
	// default BuildableClient uses Go's stdlib defaults
	// (MaxIdleConnsPerHost=2), which exhausts the loopback ephemeral
	// port range under sustained shipper concurrency (10s of req/sec
	// with TIME_WAIT pinning ports for 15-30s on most kernels).
	//
	// 256 idle conns per host matches the upper bound of the shipper's
	// MaxInFlight × ledger replica fan-out without wasting kernel
	// memory on idle sockets the soak doesn't keep warm.
	httpClient := awshttp.NewBuildableClient().
		WithTransportOptions(func(t *http.Transport) {
			t.MaxIdleConns = 512
			t.MaxIdleConnsPerHost = 256
		})

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithHTTPClient(httpClient),
	}
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("bytestore/s3: LoadDefaultConfig: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if cfg.Endpoint != "" {
		ep := cfg.Endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	if cfg.PathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)

	// Resolve public URL base. Empty cfg.PublicBaseURL falls back
	// to the appropriate default for the addressing mode:
	//   - PathStyle (SeaweedFS/MinIO/RustFS/R2): {Endpoint}/{Bucket}
	//   - virtual-host (AWS S3 anonymous-read):  https://{Bucket}.s3.{Region}.amazonaws.com
	publicBase := cfg.PublicBaseURL
	if publicBase == "" {
		if cfg.PathStyle && cfg.Endpoint != "" {
			publicBase = DefaultS3PathStylePublicBaseURL(cfg.Endpoint, cfg.Bucket)
		} else if cfg.Region != "" {
			publicBase = DefaultS3VirtualHostPublicBaseURL(cfg.Bucket, cfg.Region)
		}
		// Else: leave empty; PublicURL will return
		// ErrPublicURLNotConfigured — fail-closed: the api 302
		// handler will return 500 to the caller, surfacing the
		// misconfiguration loudly.
	}

	return &S3{
		client:       client,
		bucket:       cfg.Bucket,
		objectPrefix: cfg.ObjectPrefix,
		writeTimeout: cfg.WriteTimeout,
		readTimeout:  cfg.ReadTimeout,
		cache:        make(map[string][]byte, cfg.CacheSize),
		access:       make(map[string]int64, cfg.CacheSize),
		maxSize:      cfg.CacheSize,
		publicURL:    newPublicURLMapper(publicBase, cfg.ObjectPrefix),
	}, nil
}

func (s *S3) keyOf(seq uint64, hash [32]byte) string {
	return layoutKey(s.objectPrefix, seq, hash)
}

// PublicURL returns the credential-free URL for (seq, hash). The
// api 302 handler always issues this URL (transparency-log
// architecture; see publicurl.go for the rationale — RFC 9162,
// c2sp.org/tlog-tiles).
//
// Pre-condition: the bucket MUST allow anonymous GET. SeaweedFS
// and MinIO support this trivially. AWS S3 requires an explicit
// public-read bucket policy. Private buckets are out of scope.
func (s *S3) PublicURL(seq uint64, hash [32]byte) (string, error) {
	return s.publicURL.PublicURL(seq, hash)
}

// WriteEntry uploads wire bytes via PutObject and populates the cache.
func (s *S3) WriteEntry(ctx context.Context, seq uint64, hash [32]byte, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("bytestore/s3: WriteEntry seq=%d: empty wire bytes", seq)
	}

	wctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	key := s.keyOf(seq, hash)
	_, err := s.client.PutObject(wctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(wireBytes),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("bytestore/s3: PutObject seq=%d: %w", seq, err)
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

// isS3NotFound matches the various shapes the AWS SDK uses for
// "this object doesn't exist." NoSuchKey is the canonical S3 error;
// SDK v2 also returns generic smithy.OperationError wrapping
// http 404. Both are checked.
func isS3NotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}

// ReadEntry fetches the wire bytes for (seq, hash).
func (s *S3) ReadEntry(ctx context.Context, seq uint64, hash [32]byte) ([]byte, error) {
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

	out, err := s.client.GetObject(rctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, fmt.Errorf("bytestore/s3: seq=%d hash=%x: %w (s3: %w)", seq, hash[:8], ErrNotFound, err)
		}
		return nil, fmt.Errorf("bytestore/s3: GetObject seq=%d: %w", seq, err)
	}
	defer out.Body.Close()

	blob, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("bytestore/s3: read body seq=%d: %w", seq, err)
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

// ReadEntryBatch fetches each ref in input order.
func (s *S3) ReadEntryBatch(ctx context.Context, refs []EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, r := range refs {
		entry, err := s.ReadEntry(ctx, r.Seq, r.Hash)
		if err != nil {
			return nil, fmt.Errorf("bytestore/s3: ReadEntryBatch[%d/%d] seq=%d: %w", i, len(refs), r.Seq, err)
		}
		out[i] = entry
	}
	return out, nil
}

func (s *S3) evictLRULocked() {
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

// Close is a no-op for the S3 adapter (the AWS SDK doesn't expose a
// client-close primitive — connections release naturally on context
// cancel). Defined to mirror GCS.Close.
func (s *S3) Close() error { return nil }

// Compile-time pin.
var _ Backend = (*S3)(nil)
