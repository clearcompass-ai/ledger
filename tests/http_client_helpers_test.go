/*
FILE PATH: tests/http_client_helpers_test.go

Shared HTTP-client helpers for tests that drive sustained load
against a local listener. No build tag — visible to every test
build (default + scale + soak), so the tuning lives in one place.

# WHY THIS EXISTS

Go's http.DefaultTransport caps MaxIdleConnsPerHost at 2 by default.
That ceiling is invisible in single-shot tests but lethal under
sustained concurrent load (8+ workers each running tight
submit/poll loops):

  - Excess in-flight connections close after each request.
  - The kernel parks the closed sockets in TIME_WAIT (~15-30s on
    macOS, ~60s on Linux).
  - Each TIME_WAIT socket holds one ephemeral port hostage.
  - macOS ephemeral range is 49152-65535 (~16,384 ports).
  - At ~800 closing conns/sec (a modest scale-test rate) the pool
    drains in ~20s and every subsequent connect fails with
    "dial tcp: connect: can't assign requested address"
    (EADDRNOTAVAIL).

Evidence of this in the wild: at
  scale_determinism_test.go @ 8 workers × 1000 pairs × ~36 pairs/sec
the bulk-default-client path produced 635 EADDRNOTAVAIL failures
mid-run despite zero contract violations. Tuning fixes it.

# WHAT NOT TO DUPLICATE

newTunedHTTPClient and newTunedNoRedirectClient previously lived
inside tests/soak_test.go behind //go:build soak — invisible to
scale tests. Pulling them here removes the duplication temptation:
any future heavy-HTTP test imports the same tuning from one place.

# WHEN NOT TO USE

Light tests (single-shot E2E, scenario tests, integration tests
that submit fewer than ~50 requests total) can keep using
http.DefaultClient. The tuning is harmless at low load but
unnecessary overhead.
*/
package tests

import (
	"net/http"
	"time"
)

// newTunedHTTPClient returns an *http.Client whose Transport is
// keep-alive-friendly under sustained concurrent load.
//
// Tuning rationale (matches the soak observations documented above):
//
//   - MaxIdleConnsPerHost = 256 — lets 8-128 worker pools fully
//     reuse connections to a single test server without churning
//     the pool.
//   - MaxIdleConns        = 512 — global ceiling well above the
//     per-host setting so headroom for any future multi-host shape.
//   - IdleConnTimeout stays at the default 90s so idle conns are
//     reaped on natural cadence without thrashing.
//   - Timeout — caller-supplied per-request budget; surfaces
//     ledger-side slowdowns as test failures instead of
//     indefinite hangs.
func newTunedHTTPClient(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 512
	t.MaxIdleConnsPerHost = 256
	return &http.Client{Transport: t, Timeout: timeout}
}

// newTunedNoRedirectClient mirrors newTunedHTTPClient but disables
// auto-follow on redirects, so verify-side passes that inspect
// Location headers don't burn an extra request on the redirect
// target. Used by the soak's /raw → 302 → bytestore verify loop.
func newTunedNoRedirectClient(timeout time.Duration) *http.Client {
	c := newTunedHTTPClient(timeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}
