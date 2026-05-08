/*
FILE PATH:

	bytestore/publicurl.go

DESCRIPTION:

	Public-URL composition for transparency-log-style deployments
	where the bytestore bucket is anonymous-read.

	PublicURLer is the architecture's only read-side URL surface.
	It returns a deterministic, credential-free URL that any third
	party can GET without auth — the only model compatible with
	public verifiability (RFC 9162, c2sp.org/tlog-tiles).

ARCHITECTURE — TRANSPARENCY-LOG CONVENTION:

	Every transparency-log ecosystem — RFC 9162 (Certificate
	Transparency v2), c2sp.org/tlog-tiles, Tessera, Sigsum,
	Sigstore Rekor, Go's golang.org/x/mod/sumdb/tlog — uses
	the same model:

	  "Tile and entry URLs are deterministic compositions of a
	   monitor base URL plus the object key. No signing, no auth,
	   no expiry. Buckets are public-read."

	Reasons:
	  1. Public verifiability. A witness, auditor, or random
	     third party must be able to fetch tiles to reconstruct
	     inclusion proofs. Auth would defeat transparency.
	  2. CDN-friendly. Deterministic URLs cache. Signed URLs
	     change per request and bypass caches.
	  3. Witness independence. A witness checking the log
	     shouldn't need a long-lived credential.
	  4. No signing-key blast radius. Presigning requires a key
	     online and reachable; public URLs don't.

	This file implements the CT-log model for the ledger:

	  PublicURL(seq, hash) = baseURL + "/" + key(seq, hash)
	                          ^^^^^^^^^         ^^^^^^^^^^^^^^^
	                          per-deployment   per-bytestore
	                          (CDN URL,         (deterministic key
	                           bucket URL)       composition shared
	                                             with the write path)

INVARIANTS (every implementation MUST satisfy):

	Pure         — No I/O, no signing, no allocation that fails.
	               Returns only the canonical URL or
	               ErrPublicURLNotConfigured.

	Deterministic — Same (seq, hash) → same URL, forever. This is
	                what makes consumer caches (CDN, witness,
	                auditor) valid.

	Credential-free — URL has no signing query params, no expiry,
	                  no auth tokens. Anyone can fetch it.

	Layout-aligned — URL key MUST match the write path's keyOf().
	                 A bucket written by the GCS adapter is
	                 readable via the GCS adapter's PublicURL.
	                 Cross-adapter compatibility is preserved by
	                 the shared layoutKey() helper in
	                 bytestore.go.

EXTENSIBILITY:

	PublicURLer is part of Backend (Store + PublicURLer). Every
	production backend implements it. Test/dev backends that don't
	need URL emission (memory) satisfy only Store and are gated
	out of production wiring by the factory.

	To add a new public-URL backend (Cloudflare R2 with a
	custom-domain CDN, IPFS gateway, etc.), implement PublicURL
	on the new adapter. The factory wires PublicBaseURL through
	Config.

DEFAULT MAPPERS:

	Most deployments don't need to override the URL pattern.
	Sensible defaults:

	  DefaultGCSPublicBaseURL            (GCS bucket URL)
	  DefaultS3PathStylePublicBaseURL    (SeaweedFS, MinIO, R2 path-style)
	  DefaultS3VirtualHostPublicBaseURL  (AWS S3 virtual-host)

	A CDN-fronted deployment overrides via cfg.PublicBaseURL.
*/
package bytestore

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPublicURLNotConfigured is returned by PublicURL when no base
// URL was configured for the backend. The 302 handler treats this
// as a misconfiguration and returns 500 — the architecture has
// no private-bucket fallback (see file header).
var ErrPublicURLNotConfigured = errors.New(
	"bytestore: public URL not configured (set Config.PublicBaseURL " +
		"or use a backend with a default base URL)")

// PublicURLer is the credential-free URL surface for transparency-
// log deployments where the bytestore bucket is anonymous-read.
// Implementations MUST be pure, deterministic, and credential-free
// (see file header for full invariants).
//
// Returns ErrPublicURLNotConfigured when the backend has no
// configured base URL — fail-closed; misconfiguration surfaces
// loudly rather than silently degrading to credentialed URLs.
type PublicURLer interface {
	PublicURL(seq uint64, hash [32]byte) (string, error)
}

// publicURLMapper is the shared internal implementation of
// PublicURLer used by every adapter. It composes the per-
// deployment base URL with the bytestore.layoutKey output.
//
// Adapters embed this and delegate. Tests pin the composition
// rule against canonical CT-log URL shapes (publicurl_test.go).
type publicURLMapper struct {
	baseURL      string // already-validated, no trailing slash
	objectPrefix string // matches the adapter's keyOf prefix
}

// newPublicURLMapper validates and normalizes baseURL. Empty
// baseURL is permitted — PublicURL will return
// ErrPublicURLNotConfigured.
func newPublicURLMapper(baseURL, objectPrefix string) *publicURLMapper {
	return &publicURLMapper{
		baseURL:      strings.TrimRight(baseURL, "/"),
		objectPrefix: objectPrefix,
	}
}

// PublicURL composes the URL for (seq, hash). MUST stay in sync
// with layoutKey() (bytestore.go) — same prefix, same seq:016x,
// same hash hex. A test pins both call sites against the same
// canonical key.
func (m *publicURLMapper) PublicURL(seq uint64, hash [32]byte) (string, error) {
	if m == nil || m.baseURL == "" {
		return "", ErrPublicURLNotConfigured
	}
	return m.baseURL + "/" + layoutKey(m.objectPrefix, seq, hash), nil
}

// DefaultGCSPublicBaseURL returns the canonical GCS public URL
// prefix for an anonymous-read bucket:
//
//	https://storage.googleapis.com/{bucket}
//
// Pre-condition for use: the bucket must have IAM
// `allUsers: roles/storage.objectViewer` granted (or equivalent
// public-read configuration). If the bucket is private, this URL
// will return 403 — the administrator MUST fix the bucket policy
// (the architecture has no private-bucket read path).
func DefaultGCSPublicBaseURL(bucket string) string {
	return "https://storage.googleapis.com/" + bucket
}

// DefaultS3PathStylePublicBaseURL composes the canonical S3
// path-style public URL prefix for SeaweedFS, MinIO, RustFS, R2
// path-style endpoints, etc.:
//
//	{endpoint}/{bucket}
//
// Endpoint must include scheme (http:// or https://). Trailing
// slashes are normalized away by newPublicURLMapper.
//
// Pre-condition: bucket must be configured for anonymous read
// (e.g., SeaweedFS bucket with default policy; MinIO with
// `mc anonymous set download <alias>/<bucket>`).
func DefaultS3PathStylePublicBaseURL(endpoint, bucket string) string {
	if endpoint == "" || bucket == "" {
		return ""
	}
	return strings.TrimRight(endpoint, "/") + "/" + bucket
}

// DefaultS3VirtualHostPublicBaseURL composes the canonical AWS S3
// virtual-host-style public URL prefix:
//
//	https://{bucket}.s3.{region}.amazonaws.com
//
// Pre-condition: the bucket must have either a public-read bucket
// policy OR an Object Ownership setting that allows anonymous GET.
// Modern AWS defaults block anonymous access; the bucket owner must
// explicitly opt in via bucket policy + S3 Block Public Access
// configuration.
func DefaultS3VirtualHostPublicBaseURL(bucket, region string) string {
	if bucket == "" || region == "" {
		return ""
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, region)
}
