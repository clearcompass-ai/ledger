//go:build scenarios

/*
FILE PATH:
    tests/scenarios_p2_cdn_test.go

DESCRIPTION:
    Layer 0 — Persona 2 (Browser-Class Auditor, CDN conformance).
    Two sub-scenarios that drive the LIVE production-stack CDN
    after a real submission, asserting browser-class consumers
    can:

      1. Fetch /tile/... and /checkpoint with stdlib HTTP, observe
         Cache-Control headers exactly matching c2sp.org/tlog-tiles
         + the SDK's published immutable / mutable cache policy.

      2. Issue a "simple request" (CORS-spec terminology: GET / HEAD
         with no custom request headers) and observe
         Access-Control-Allow-Origin: * — the minimum a browser-
         class auditor running at any origin needs to read the log.

KEY ARCHITECTURAL DECISIONS:
    - Live stack, not synthetic root. tests/scenarios_cdn_test.go
      already covers the synthetic-fixture conformance; what's new
      here is asserting the headers on tiles the production stack
      actually wrote. A regression where the CDN fixture stays
      conformant but the production-stack tile path drifts would
      pass the synthetic test and fail Persona 2 — exactly the
      point.
    - Cache-Control values pinned to the exact bytes
      cdnImmutableCacheControl / cdnMutableCacheControl. Drift in
      either direction is a wire-format regression for downstream
      consumers (CDN edge nodes, browser cache).
    - CORS check is the "simple request" path. Persona 2 explicitly
      does not test the OPTIONS preflight path: the current CDN
      fixture is GET/HEAD-only by design, and a browser-class
      auditor that only fetches static tiles (GET, default headers)
      does not require preflight. A future Persona that issues
      authenticated-fetch will need OPTIONS conformance and a
      separate test file.
    - Path traversal regression. Even on a live stack, malicious
      `..` in the URL must not escape the Tessera POSIX root. The
      synthetic test covers this; we re-assert here against the
      live root because traversal defense is the kind of bug that
      hides in path normalization differences between the fixture
      and the production tree.

OVERVIEW:
    runP2CDNHeadersConformant — submit one entry, wait for the
        tile to flush, fetch /tile/0/<encoded> + /checkpoint,
        assert Cache-Control + Content-Type + Access-Control-
        Allow-Origin headers match the SDK's published policy.

    runP2CORSAllowsBrowserFetch — issue a "simple request" GET
        from a fake Origin: https://auditor.example, observe
        the * CORS allow header. Then assert HEAD also carries
        the same header (some CDNs forget HEAD).

KEY DEPENDENCIES:
    - tests/scenarios_p2_minimal_auditor_test.go: TestPersona2_
      MinimalAuditor umbrella, persona1Submit (admissible-wire
      builder).
    - tests/scenarios_p2_proof_verify_test.go: p2HashTilePath,
      p2EncodeTileIndex (computed inline rather than imported).
    - tests/scenarios_cdn_test.go: cdnImmutableCacheControl /
      cdnMutableCacheControl constants — the bytes the CDN
      fixture published, which a browser-class auditor must
      observe verbatim.
*/
package tests

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// -------------------------------------------------------------------------------------------------
// 1) CDNHeadersConformant
// -------------------------------------------------------------------------------------------------

// runP2CDNHeadersConformant submits one entry, waits for the tile
// to flush via WaitForCheckpoint, fetches the level-0 tile + the
// checkpoint over plain HTTP, and asserts every documented header
// (Cache-Control, Content-Type, CORS) matches the published SDK
// policy bytes verbatim.
func runP2CDNHeadersConformant(t *testing.T, stack *scenariosStack) {
	t.Helper()
	if stack.CDNBaseURL() == "" {
		t.Fatal("runP2CDNHeadersConformant: CDN not mounted (test misconfigured)")
	}

	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   "did:example:p2-cdn-headers",
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, []byte("p2-cdn-headers"), stack.LogDID(), difficulty)
	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if sct.CanonicalHash != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch")
	}
	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mustNotErr(t, "WaitForCheckpoint", stack.WaitForCheckpoint(ctx, seq+1))

	tileIdx := seq / p2EntriesPerTile
	tileURL := stack.CDNBaseURL() + "/" + p2HashTilePath(0, tileIdx)
	tileResp := p2HEAD(t, tileURL)
	defer tileResp.Body.Close()

	// /tile/... → immutable cache, octet-stream content type, CORS *.
	if got := tileResp.Header.Get("Cache-Control"); got != cdnImmutableCacheControl {
		t.Fatalf("/tile Cache-Control = %q, want %q", got, cdnImmutableCacheControl)
	}
	if got := tileResp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("/tile Content-Type = %q, want application/octet-stream", got)
	}
	if got := tileResp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("/tile CORS allow = %q, want *", got)
	}

	// /checkpoint → max-age=1 cache, CORS *.
	cpURL := stack.CDNBaseURL() + "/checkpoint"
	cpResp := p2HEAD(t, cpURL)
	defer cpResp.Body.Close()
	if got := cpResp.Header.Get("Cache-Control"); got != cdnMutableCacheControl {
		t.Fatalf("/checkpoint Cache-Control = %q, want %q", got, cdnMutableCacheControl)
	}
	if got := cpResp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("/checkpoint CORS allow = %q, want *", got)
	}

	// Path traversal — even on a live root, a browser-class auditor
	// that fat-fingers a relative path must NOT escape the Tessera
	// POSIX root.
	bad := stack.CDNBaseURL() + "/tile/../../etc/passwd"
	resp, err := http.Get(bad)
	mustNotErr(t, "GET traversal", err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("traversal status = %d, want 403 or 404", resp.StatusCode)
	}
}

// -------------------------------------------------------------------------------------------------
// 2) CORSAllowsBrowserFetch
// -------------------------------------------------------------------------------------------------

// runP2CORSAllowsBrowserFetch issues a "simple request" GET (and
// HEAD) from a fake Origin: https://auditor.example, observes the
// * CORS allow header on both. Persona 2 does not exercise OPTIONS
// preflight: the current CDN fixture rejects OPTIONS with 405 (by
// design — see the docstring at scenarios_cdn_test.go), and a
// browser-class auditor that issues only stdlib GETs / HEADs is
// not required to preflight.
func runP2CORSAllowsBrowserFetch(t *testing.T, stack *scenariosStack) {
	t.Helper()
	if stack.CDNBaseURL() == "" {
		t.Fatal("runP2CORSAllowsBrowserFetch: CDN not mounted (test misconfigured)")
	}

	// We reach the checkpoint (always present after WaitForCheckpoint
	// of any seq) rather than a tile — the checkpoint exists on every
	// non-empty tree, no submission needed.
	difficulty := persona1Difficulty(t, stack.LedgerBaseURL())
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID:   "did:example:p2-cors",
		Destination: stack.LogDID(),
		EventTime:   time.Now().UTC().UnixMicro(),
	}, []byte("p2-cors"), stack.LogDID(), difficulty)
	canonical := persona1HashWire(wire)
	sct := persona1Submit(t, stack.LedgerBaseURL(), wire)
	if sct.CanonicalHash != hex.EncodeToString(canonical[:]) {
		t.Fatalf("SCT.CanonicalHash mismatch")
	}
	seq := persona1WaitForSequence(t, stack.LedgerBaseURL(), canonical, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mustNotErr(t, "WaitForCheckpoint", stack.WaitForCheckpoint(ctx, seq+1))

	cpURL := stack.CDNBaseURL() + "/checkpoint"

	// Simple GET with Origin header — what a browser fetch() does
	// for a same-shape request.
	getResp := p2GETWithOrigin(t, cpURL, "https://auditor.example")
	defer getResp.Body.Close()
	if got := getResp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("GET /checkpoint CORS allow = %q, want *", got)
	}

	// HEAD too — some CDNs forget HEAD; the SDK's spec mandates
	// both. Persona 2 enforces.
	headResp := p2HEADWithOrigin(t, cpURL, "https://auditor.example")
	defer headResp.Body.Close()
	if got := headResp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("HEAD /checkpoint CORS allow = %q, want *", got)
	}

	// Body must still be served on GET (CORS header should not
	// suppress payload). Read up to the c2sp tile-bundle ceiling
	// even though /checkpoint is much smaller.
	body, err := io.ReadAll(io.LimitReader(getResp.Body, scenarioTileMaxBytes))
	mustNotErr(t, "read /checkpoint body", err)
	if len(body) == 0 {
		t.Fatal("/checkpoint body empty")
	}
	// Tessera checkpoints start with the origin string per
	// c2sp.org/tlog-checkpoint; we don't validate the parse here
	// (Persona 4 does), but a non-empty body is the floor.
	if !strings.HasPrefix(string(body), stack.LogDID()) {
		t.Fatalf("/checkpoint body does not begin with origin LogDID; got prefix %q",
			truncate(string(body), 64))
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Helpers — stdlib HEAD / GET with optional Origin
// -------------------------------------------------------------------------------------------------

// p2HEAD issues a HEAD request. Body is empty by HTTP semantics;
// caller must still Close. Fatals on non-200.
func p2HEAD(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, url, nil)
	mustNotErr(t, "new HEAD", err)
	resp, err := http.DefaultClient.Do(req)
	mustNotErr(t, "HEAD "+url, err)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		t.Fatalf("HEAD %s status=%d body=%s", url, resp.StatusCode, body)
	}
	return resp
}

// p2HEADWithOrigin issues a HEAD with a browser-style Origin
// header. Same fatal-on-non-200 contract.
func p2HEADWithOrigin(t *testing.T, url, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, url, nil)
	mustNotErr(t, "new HEAD", err)
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	mustNotErr(t, "HEAD "+url, err)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		t.Fatalf("HEAD %s status=%d body=%s", url, resp.StatusCode, body)
	}
	return resp
}

// p2GETWithOrigin issues a GET with a browser-style Origin header.
func p2GETWithOrigin(t *testing.T, url, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	mustNotErr(t, "new GET", err)
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	mustNotErr(t, "GET "+url, err)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		t.Fatalf("GET %s status=%d body=%s", url, resp.StatusCode, body)
	}
	return resp
}

// truncate is a UTF-8-safe truncator used for diagnostic prints.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
