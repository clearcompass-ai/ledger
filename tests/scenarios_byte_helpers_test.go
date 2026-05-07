//go:build scenarios

/*
FILE PATH:
    tests/scenarios_byte_helpers_test.go

DESCRIPTION:
    Layer 0 — fixtures for the byte-for-byte read verification
    family (BYTE-VER-01/02/03). Two pieces:

      1. byteStoreHTTPServer — an httptest.Server that fronts
         the in-process Memory bytestore over an
         unauthenticated GET path matching the production
         layoutKey: "<prefix>/<seq:016x>/<hash_hex>". This is
         the byte path a real auditor would fetch through
         the credential-free public bucket policy
         (RFC 9162 § 4 + c2sp.org/tlog-tiles + bytestore/
         publicurl.go's mapper).

      2. staticPublicURLer — implements api.PublicURLer by
         composing "<base>/<prefix>/<seq:016x>/<hash_hex>"
         and returning that string verbatim. Wired into the
         test ledger via scenariosStackOpts.PublicURLer so
         /v1/entries/{seq}/raw issues a real 302 redirect
         BYTE-VER-02 can follow.

KEY ARCHITECTURAL DECISIONS:
    - Layout discipline. Both the server and the URLer use
      the SAME layout function (byteLayoutKey) — drift
      between them would mean the URL points where bytes
      aren't. Same as bytestore/bytestore.go's layoutKey
      pattern.
    - Hash-only auth. The server returns 200 only when a
      GET path matches the (seq, hash) of a stored entry.
      Mismatched hashes return 404. This matches the
      production GCS / S3 bucket behaviour where the
      object key IS the (seq, hash) — wrong key, no bytes.
    - We do NOT implement HEAD, range requests, or
      conditional GET. Production CDNs do; the test
      contract is "GET returns the bytes" — the rest is
      Tier-2 polish.
    - Concurrency. The Memory bytestore is sync.RWMutex-
      backed; the HTTP server is httptest's stock; both
      are safe under parallel goroutines. BYTE-VER-01
      drives 1000 random fetches across goroutines.

OVERVIEW:
    byteStoreHTTPServer       → fixture handle.
    newByteStoreHTTPServer    → constructor (binds to
                                Memory + cleanup hook).
    .BaseURL()                → URL the URLer composes against.
    .ObjectPrefix()           → layout prefix component.

    staticPublicURLer         → api.PublicURLer impl.
    newStaticPublicURLer      → constructor.

    byteLayoutKey             → the canonical
                                "<prefix>/<seq:016x>/<hash_hex>"
                                — mirrors bytestore.layoutKey.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ledger/bytestore: Memory.
    - github.com/clearcompass-ai/ledger/api: PublicURLer
      interface.
*/
package tests

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	opbytestore "github.com/clearcompass-ai/ledger/bytestore"
)

// -------------------------------------------------------------------------------------------------
// 1) Layout key (mirrors bytestore.layoutKey)
// -------------------------------------------------------------------------------------------------

// byteObjectPrefix is the layout-key prefix string the byte
// fixture uses. Production deployments parameterise this
// per-bucket; the test uses a fixed "entries" string that
// matches bytestore/s3.go and bytestore/gcs.go conformance
// tests' expected_layout pattern.
const byteObjectPrefix = "entries"

// byteLayoutKey returns "<prefix>/<seq:016x>/<hash_hex>" — the
// canonical layout. Mirrors bytestore.layoutKey exactly. Both
// the server and the PublicURLer use this so drift between them
// is a compile-time impossibility (one function, one truth).
func byteLayoutKey(seq uint64, hash [32]byte) string {
	return fmt.Sprintf("%s/%016x/%s", byteObjectPrefix, seq, hex.EncodeToString(hash[:]))
}

// -------------------------------------------------------------------------------------------------
// 2) byteStoreHTTPServer
// -------------------------------------------------------------------------------------------------

// byteStoreHTTPServer fronts a Memory bytestore over HTTP. GET
// requests at "/<prefix>/<seq:016x>/<hash_hex>" return the wire
// bytes; any other path returns 404. Method != GET → 405.
type byteStoreHTTPServer struct {
	srv  *httptest.Server
	mem  *opbytestore.Memory
	base string
}

// newByteStoreHTTPServer returns a fixture serving bytes from
// mem at httptest.NewServer's random port. t.Cleanup tears the
// server down at end-of-test.
func newByteStoreHTTPServer(t *testing.T, mem *opbytestore.Memory) *byteStoreHTTPServer {
	t.Helper()
	if mem == nil {
		t.Fatal("newByteStoreHTTPServer: mem nil")
	}
	bs := &byteStoreHTTPServer{mem: mem}
	bs.srv = httptest.NewServer(http.HandlerFunc(bs.handle))
	bs.base = bs.srv.URL
	t.Cleanup(bs.srv.Close)
	return bs
}

// BaseURL returns the server's URL prefix (no trailing slash).
func (bs *byteStoreHTTPServer) BaseURL() string { return bs.base }

// ObjectPrefix returns the layout-key prefix string the URLer
// must reproduce verbatim.
func (bs *byteStoreHTTPServer) ObjectPrefix() string { return byteObjectPrefix }

// handle parses the URL path into (seq, hash) and serves the
// stored bytes from mem. The expected URL shape is
// "/<prefix>/<seq:016x>/<hash_hex>"; any other shape is 404.
func (bs *byteStoreHTTPServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != byteObjectPrefix {
		http.NotFound(w, r)
		return
	}
	if len(parts[1]) != 16 || len(parts[2]) != 64 {
		http.NotFound(w, r)
		return
	}
	var seq uint64
	if _, err := fmt.Sscanf(parts[1], "%016x", &seq); err != nil {
		http.NotFound(w, r)
		return
	}
	hashBytes, err := hex.DecodeString(parts[2])
	if err != nil || len(hashBytes) != 32 {
		http.NotFound(w, r)
		return
	}
	var hash [32]byte
	copy(hash[:], hashBytes)

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	body, err := bs.mem.ReadEntry(ctx, seq, hash)
	if err != nil {
		if errors.Is(err, opbytestore.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "io error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
	_, _ = w.Write(body)
}

// -------------------------------------------------------------------------------------------------
// 3) staticPublicURLer
// -------------------------------------------------------------------------------------------------

// staticPublicURLer composes the redirect target the
// /v1/entries/{seq}/raw handler returns. The base URL is set
// AFTER ledger construction (chicken-and-egg: the ledger
// boot needs the URLer, but the URLer points at a server
// that needs the ledger's bytestore). SetBaseURL is called
// once, before the first /raw GET.
type staticPublicURLer struct {
	mu      sync.RWMutex
	baseURL string
	prefix  string
}

// newStaticPublicURLer constructs a URLer with an empty base.
// Caller MUST call SetBaseURL before any /raw GET; PublicURL
// returns an error before then.
func newStaticPublicURLer(prefix string) *staticPublicURLer {
	return &staticPublicURLer{prefix: prefix}
}

// SetBaseURL pins the redirect target. Idempotent.
func (u *staticPublicURLer) SetBaseURL(base string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.baseURL = base
}

// PublicURL implements api.PublicURLer.
func (u *staticPublicURLer) PublicURL(seq uint64, hash [32]byte) (string, error) {
	if u == nil {
		return "", errors.New("staticPublicURLer: nil")
	}
	u.mu.RLock()
	base := u.baseURL
	u.mu.RUnlock()
	if base == "" {
		return "", errors.New("staticPublicURLer: base not set")
	}
	return fmt.Sprintf("%s/%s/%016x/%s",
		base, u.prefix, seq, hex.EncodeToString(hash[:])), nil
}
