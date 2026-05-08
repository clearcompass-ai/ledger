/*
FILE PATH: bytestore/factory.go

Factory for the hexagonal bytestore: one entry point that constructs
the right Backend implementation based on Config.Backend. The
ledger's composition root passes the config through unchanged;
swapping providers is a config change, not a code change.

PRODUCTION VS TEST:

	Backend="memory" returns a wrapper that satisfies Store but NOT
	Backend (no PublicURLer). NewFromConfig refuses to return a
	memory-only Store via the Backend type. Tests that need just a
	Store call NewMemory directly.

CONFIG SHAPE:

	See Config docstring below. Required fields per backend are
	validated here so the composition root gets a single fail-closed
	error path.
*/
package bytestore

import (
	"context"
	"fmt"
	"time"
)

// Config configures NewFromConfig. Fields are a superset across all
// backends; per-backend required fields are validated based on
// Backend.
type Config struct {
	// Backend selects the implementation. Required.
	//   - "gcs" → GCS adapter (production on GCP)
	//   - "s3"  → S3 adapter (production on AWS / RustFS / R2)
	Backend string

	// Bucket is the bucket name. Required for gcs and s3.
	Bucket string

	// Prefix is prepended to every object name. Optional. Default
	// "entries". Useful for sharing a bucket across multiple ledger
	// instances.
	Prefix string

	// CacheSize is the LRU cache size for the read path. Optional.
	// Default 4096.
	CacheSize int

	// WriteTimeout / ReadTimeout cap individual operations. Optional.
	// Defaults to 30s each.
	WriteTimeout time.Duration
	ReadTimeout  time.Duration

	// ── GCS-specific ──────────────────────────────────────────────
	// Endpoint overrides the default GCS endpoint (set for fake-gcs).
	GCSEndpoint string
	// Anonymous bypasses ADC (set true for fake-gcs).
	GCSAnonymous bool

	// ── S3-specific ───────────────────────────────────────────────
	// Endpoint overrides the default S3 endpoint (set for RustFS).
	S3Endpoint string
	// Region defaults to us-east-1.
	S3Region string
	// AccessKey + SecretKey for static creds (RustFS). Leave
	// empty on AWS to use the default credential chain (IAM role,
	// AWS_* env vars, ~/.aws).
	S3AccessKey string
	S3SecretKey string
	// PathStyle: true for RustFS; false for AWS S3.
	S3PathStyle bool

	// ── Public-URL (credential-free) ──────────────────────────────
	// PublicBaseURL is the credential-free monitor URL prefix the
	// PublicURLer adapter uses when the bucket is anonymous-read.
	// Optional — when empty, each adapter computes a sensible
	// default from its own config (bucket name, endpoint, region).
	// Set explicitly to point at a CDN / custom DNS.
	//
	// See bytestore/publicurl.go for the CT-log architectural
	// rationale (RFC 9162, c2sp.org/tlog-tiles).
	PublicBaseURL string
}

// NewFromConfig constructs a Backend per cfg.Backend. Returns a
// fail-closed error on missing required fields or unsupported backend.
//
// The returned Backend is the union of Store + PublicURLer — the
// 302-redirect path in api/entries_read.go requires the credential-
// free public URL surface (transparency-log convention).
func NewFromConfig(ctx context.Context, cfg Config) (Backend, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("bytestore/factory: Bucket required")
	}

	switch cfg.Backend {
	case "gcs":
		return NewGCS(ctx, GCSConfig{
			Bucket:        cfg.Bucket,
			Endpoint:      cfg.GCSEndpoint,
			Anonymous:     cfg.GCSAnonymous,
			CacheSize:     cfg.CacheSize,
			ObjectPrefix:  cfg.Prefix,
			WriteTimeout:  cfg.WriteTimeout,
			ReadTimeout:   cfg.ReadTimeout,
			PublicBaseURL: cfg.PublicBaseURL,
		})
	case "s3":
		return NewS3(ctx, S3Config{
			Bucket:        cfg.Bucket,
			Endpoint:      cfg.S3Endpoint,
			Region:        cfg.S3Region,
			AccessKey:     cfg.S3AccessKey,
			SecretKey:     cfg.S3SecretKey,
			PathStyle:     cfg.S3PathStyle,
			CacheSize:     cfg.CacheSize,
			ObjectPrefix:  cfg.Prefix,
			WriteTimeout:  cfg.WriteTimeout,
			ReadTimeout:   cfg.ReadTimeout,
			PublicBaseURL: cfg.PublicBaseURL,
		})
	case "memory":
		return nil, fmt.Errorf("bytestore/factory: Backend=memory has no PublicURLer; use bytestore.NewMemory directly in test code")
	case "":
		return nil, fmt.Errorf("bytestore/factory: Backend required (gcs|s3)")
	default:
		return nil, fmt.Errorf("bytestore/factory: unsupported Backend %q (gcs|s3)", cfg.Backend)
	}
}
