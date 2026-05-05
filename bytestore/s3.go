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

PRESIGNED URLS:

	SigV4 via s3.PresignClient.PresignGetObject. TTL clamped to 7 days
	(the AWS SigV4 ceiling). Local SigV4 — no remote round-trip.

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
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Maximum TTL allowed by SigV4 presigned URLs.
const s3MaxPresignTTL = 7 * 24 * time.Hour

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
	//   - true  → host/bucket/key   (RustFS)
	//   - false → bucket.host/key   (AWS S3 default)
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
}

// S3 satisfies Backend (Store + Presigner) against any S3-compatible
// object store.
type S3 struct {
	client       *s3.Client
	presigner    *s3.PresignClient
	bucket       string
	objectPrefix string
	writeTimeout time.Duration
	readTimeout  time.Duration

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

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
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
	presigner := s3.NewPresignClient(client)

	return &S3{
		client:       client,
		presigner:    presigner,
		bucket:       cfg.Bucket,
		objectPrefix: cfg.ObjectPrefix,
		writeTimeout: cfg.WriteTimeout,
		readTimeout:  cfg.ReadTimeout,
		cache:        make(map[string][]byte, cfg.CacheSize),
		access:       make(map[string]int64, cfg.CacheSize),
		maxSize:      cfg.CacheSize,
	}, nil
}

func (s *S3) keyOf(seq uint64, hash [32]byte) string {
	return layoutKey(s.objectPrefix, seq, hash)
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
			return nil, fmt.Errorf("bytestore/s3: seq=%d hash=%x: %w (s3: %v)", seq, hash[:8], ErrNotFound, err)
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

// PresignGet returns a SigV4 presigned URL granting time-bounded
// GET access to the entry's bytes. ttl is clamped to 7 days
// (the SigV4 ceiling). Signing is local — no extra round-trip.
func (s *S3) PresignGet(ctx context.Context, seq uint64, hash [32]byte, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if ttl > s3MaxPresignTTL {
		ttl = s3MaxPresignTTL
	}
	key := s.keyOf(seq, hash)
	req, err := s.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", fmt.Errorf("bytestore/s3: PresignGetObject seq=%d: %w", seq, err)
	}
	return req.URL, nil
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
