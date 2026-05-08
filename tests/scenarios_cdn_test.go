//go:build scenarios

/*
FILE PATH:

	tests/scenarios_cdn_test.go

DESCRIPTION:

	CDN tile-file server fixture for the Layer 0 scenarios suite.
	Wraps http.FileServer over the Tessera POSIX storage root and
	injects c2sp.org/tlog-tiles-conformant Cache-Control headers
	(immutable for tile/* paths, max-age=1 for the checkpoint).
	Persona 2 (browser-class auditor) and Persona 5 (indexer) read
	tiles through this server; production deployments serve the
	same paths from GCS / S3 + a real CDN.

KEY ARCHITECTURAL DECISIONS:
  - Strict path classification — paths matching /tile/ or
    /tile/entries/ get the immutable cache header, /checkpoint
    gets max-age=1, anything else (including /etc/passwd via
    ../) is rejected before reaching FileServer. The reject
    happens via filepath.Clean comparison after stripping the
    mount prefix.
  - In-process counter records every served path and how many
    times it was requested. CDN-cache emulation tests assert
    "the origin only saw N requests for K distinct paths" via
    this counter.
  - CORS open-by-default (Access-Control-Allow-Origin: *) so the
    browser-class auditor in Persona 2 doesn't need a separate
    CORS proxy. Production CDNs (Fastly/CloudFront) wire the
    same.
  - Read-only. The fixture explicitly rejects POST / PUT / etc
    with 405; tile state is mutated only by the production
    stack's Tessera writer.

OVERVIEW:

	NewCDNFileServer(t, root) → httptest.Server with:
	    GET /tile/...        → bytes from <root>/tile/...
	    GET /tile/entries/... → bytes from <root>/tile/entries/...
	    GET /checkpoint      → bytes from <root>/checkpoint
	    anything else        → 404 (paths) or 405 (methods)

	BaseURL()                → URL the auditor / DID-doc points to.
	HitCount(path)           → request count for a given path.
	DistinctPaths()          → number of distinct paths served.

KEY DEPENDENCIES:
  - net/http, net/http/httptest: standard server primitives.
  - tests/scenarios_skel_test.go: tmpDir helper.
*/
package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) Cache-Control fragments
// -------------------------------------------------------------------------------------------------

// cdnImmutableCacheControl is the long-TTL header the SDK's
// MaxTileBytes / Tessera tile catalog promises (Tessera's
// production GCS config is `max-age=604800,immutable`). Tiles are
// content-addressed and never mutate; clients can cache forever.
const cdnImmutableCacheControl = "public, max-age=604800, immutable"

// cdnMutableCacheControl is the short-TTL header for /checkpoint.
// Auditors poll this at ~1Hz; max-age=1 lets the CDN dedupe
// burst-poll across clients to ~1 origin hit per second.
const cdnMutableCacheControl = "public, max-age=1"

// -------------------------------------------------------------------------------------------------
// 2) cdnFileServer — the fixture
// -------------------------------------------------------------------------------------------------

// cdnFileServer wraps an httptest.Server serving Tessera POSIX
// tile bytes with CDN-style headers. Embeds an http.FileServer
// for static-file behaviour; the surrounding handler classifies
// paths and injects headers.
type cdnFileServer struct {
	srv  *httptest.Server
	root string

	mu       sync.Mutex
	hits     map[string]int
	servedAt map[string]time.Time
}

// NewCDNFileServer returns a fresh fixture serving root. The root
// is typically the Tessera POSIX storage path; the file server
// strips the prefix so requests like
//
//	GET <baseURL>/tile/0/x000
//
// resolve to <root>/tile/0/x000.
func NewCDNFileServer(t *testing.T, root string) *cdnFileServer {
	t.Helper()
	abs, err := filepath.Abs(root)
	mustNotErr(t, "filepath.Abs", err)

	c := &cdnFileServer{
		root:     abs,
		hits:     make(map[string]int),
		servedAt: make(map[string]time.Time),
	}
	c.srv = httptest.NewServer(c.routerHandler())
	t.Cleanup(c.srv.Close)
	return c
}

// BaseURL returns the URL prefix the auditor / DID-doc encodes.
// No trailing slash, matching the production CDN base form.
func (c *cdnFileServer) BaseURL() string {
	return c.srv.URL
}

// HitCount returns the number of requests served for a given
// path (zero if the path was never requested).
func (c *cdnFileServer) HitCount(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[path]
}

// DistinctPaths returns the count of distinct paths the server
// has handled. Useful for "the origin saw at most K paths" CDN
// emulation assertions.
func (c *cdnFileServer) DistinctPaths() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hits)
}

// LastServedAt returns the time of the most recent request for
// path, or zero time if never requested.
func (c *cdnFileServer) LastServedAt(path string) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.servedAt[path]
}

// -------------------------------------------------------------------------------------------------
// 3) Router
// -------------------------------------------------------------------------------------------------

// routerHandler returns the http.Handler the embedded server uses.
// Behaviour:
//   - Method gating: GET / HEAD only. Other methods → 405.
//   - CORS: every response carries Access-Control-Allow-Origin: *.
//   - Path classification:
//     /tile/...       → immutable cache header
//     /checkpoint     → max-age=1 cache header
//     (anything else) → 404
//   - Path-traversal defence: filepath.Clean(joined) MUST stay
//     under root; otherwise 403.
func (c *cdnFileServer) routerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.Path
		switch {
		case path == "/checkpoint":
			c.serveFile(w, r, "checkpoint", cdnMutableCacheControl)
		case strings.HasPrefix(path, "/tile/"):
			rel := strings.TrimPrefix(path, "/")
			c.serveFile(w, r, rel, cdnImmutableCacheControl)
		default:
			http.NotFound(w, r)
		}
	})
}

// serveFile resolves rel under root, sets the supplied
// Cache-Control header, records the hit, and streams the bytes.
// Path-traversal defence: filepath.Clean of the joined path MUST
// remain a strict prefix of c.root after EvalSymlinks-equivalent
// normalisation. We avoid os.Stat-then-os.Open races by going
// straight to os.Open and trusting the OS to honour the Clean
// result.
func (c *cdnFileServer) serveFile(w http.ResponseWriter, r *http.Request, rel, cacheControl string) {
	full := filepath.Clean(filepath.Join(c.root, rel))
	if !strings.HasPrefix(full, c.root+string(filepath.Separator)) && full != c.root {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c.recordHit(r.URL.Path)
	f, err := os.Open(full)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "io error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "stat error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, full, stat.ModTime(), f)
}

// recordHit increments the per-path counter and timestamp.
func (c *cdnFileServer) recordHit(path string) {
	c.mu.Lock()
	c.hits[path]++
	c.servedAt[path] = time.Now()
	c.mu.Unlock()
}

// -------------------------------------------------------------------------------------------------
// 4) Tests — coverage gate
// -------------------------------------------------------------------------------------------------

// TestCDNFileServer_Conformance covers happy path (tile + checkpoint),
// every error class (method, missing, traversal), header injection,
// and the HitCount / DistinctPaths / LastServedAt accessors.
func TestCDNFileServer_Conformance(t *testing.T) {
	root := tmpDir(t, "cdn")

	// Seed a fixture tile structure mirroring c2sp.org/tlog-tiles.
	mustNotErr(t, "mkdir tile", os.MkdirAll(filepath.Join(root, "tile", "0"), 0o755))
	mustNotErr(t, "write tile", os.WriteFile(
		filepath.Join(root, "tile", "0", "x000"), []byte("tile-bytes-A"), 0o644))
	mustNotErr(t, "write checkpoint", os.WriteFile(
		filepath.Join(root, "checkpoint"), []byte("origin\n42\nroot=...\n"), 0o644))

	cdn := NewCDNFileServer(t, root)
	if cdn.BaseURL() == "" {
		t.Fatal("BaseURL empty")
	}

	client := &http.Client{Timeout: 2 * time.Second}

	// Tile happy path → 200, immutable cache, body bytes.
	resp, err := client.Get(cdn.BaseURL() + "/tile/0/x000")
	mustNotErr(t, "GET tile", err)
	if resp.StatusCode != 200 {
		t.Fatalf("tile status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != cdnImmutableCacheControl {
		t.Fatalf("tile Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("CORS header missing: %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	resp.Body.Close()

	// Checkpoint happy path → 200, max-age=1 cache.
	resp, err = client.Get(cdn.BaseURL() + "/checkpoint")
	mustNotErr(t, "GET checkpoint", err)
	if got := resp.Header.Get("Cache-Control"); got != cdnMutableCacheControl {
		t.Fatalf("checkpoint Cache-Control = %q", got)
	}
	resp.Body.Close()

	// 404 for missing tile.
	resp, err = client.Get(cdn.BaseURL() + "/tile/999/missing")
	mustNotErr(t, "GET missing", err)
	if resp.StatusCode != 404 {
		t.Fatalf("missing tile status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 404 for unknown path (not /tile/ and not /checkpoint).
	resp, err = client.Get(cdn.BaseURL() + "/random")
	mustNotErr(t, "GET unknown", err)
	if resp.StatusCode != 404 {
		t.Fatalf("unknown status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Path traversal → 403. The router strips the leading slash
	// so /../etc/passwd becomes ../etc/passwd, which Clean
	// normalises to ../etc/passwd, which fails the prefix check.
	resp, err = client.Get(cdn.BaseURL() + "/tile/../../etc/passwd")
	mustNotErr(t, "GET traversal", err)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("traversal status = %d, want 403 or 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Method gating → 405.
	req, _ := http.NewRequest(http.MethodPost, cdn.BaseURL()+"/tile/0/x000", nil)
	resp, err = client.Do(req)
	mustNotErr(t, "POST tile", err)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", resp.StatusCode)
	}
	resp.Body.Close()

	// HitCount / DistinctPaths.
	if cdn.HitCount("/tile/0/x000") < 1 {
		t.Fatalf("HitCount tile = %d", cdn.HitCount("/tile/0/x000"))
	}
	if cdn.DistinctPaths() < 2 { // tile + checkpoint at least
		t.Fatalf("DistinctPaths = %d", cdn.DistinctPaths())
	}
	if cdn.LastServedAt("/tile/0/x000").IsZero() {
		t.Fatal("LastServedAt zero for served path")
	}
	if !cdn.LastServedAt("/never-served").IsZero() {
		t.Fatal("LastServedAt non-zero for unserved path")
	}
}
