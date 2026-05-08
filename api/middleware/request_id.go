/*
FILE PATH:

	api/middleware/request_id.go

DESCRIPTION:

	Per-request correlation ID middleware. Reads an inbound
	X-Request-ID header (administrator-supplied or proxy-injected) or
	generates a fresh UUIDv4 when absent. The ID is echoed in the
	response header AND stitched into the request context so
	downstream handlers + structured logs carry the same ID end-to-
	end.

KEY ARCHITECTURAL DECISIONS:
  - Header-name + max length are constants. A hostile caller
    cannot supply an unbounded ID — values longer than
    MaxRequestIDLength are rejected and a fresh ID is generated.
  - UUIDv4 generation goes through crypto/rand. No predictable
    counter or wall-clock-derived ID — defends against forensic
    ID-collision and against an attacker correlating IDs across
    concurrent unrelated requests.
  - context.Value uses an unexported sentinel type to prevent
    cross-package collisions (Go idiom; the auth middleware
    already uses the same pattern).
  - Pure middleware: no logging, no metrics. Logging is the
    handler's responsibility (slog.With("request_id", ...)).
    Logging here would double-emit on every request and obscure
    the per-handler vocabulary.

OVERVIEW:

	Wrap any http.Handler. On entry, read the X-Request-ID header.
	Validate (non-empty, length-bounded, printable-ASCII). If
	invalid OR absent, generate a UUIDv4. Set the context key.
	Echo the ID in the response header so callers can correlate
	their client-side logs against the ledger's logs by literal
	string match. Call the wrapped handler.

KEY DEPENDENCIES:
  - crypto/rand: cryptographically-strong UUIDv4 generation.
  - encoding/hex: efficient byte-to-string formatting (UUIDv4
    uses canonical 8-4-4-4-12 hex form).
  - github.com/google/uuid (already in go.sum): standardized
    UUIDv4 generation matching the wider Go ecosystem so
    downstream tools (tracing, log aggregation) parse the form
    without bespoke regex.
*/
package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants + Context Key
// -------------------------------------------------------------------------------------------------

// HeaderRequestID is the canonical correlation-ID header name.
// Echo on response is the contract a forward proxy + a CDN +
// most observability stacks already speak.
const HeaderRequestID = "X-Request-ID"

// MaxRequestIDLength caps inbound header values. 128 bytes is
// generous (UUIDv4 canonical is 36, OpenTelemetry trace-id is 32);
// anything beyond is treated as caller error and replaced with a
// freshly-generated UUIDv4. The cap defends against a hostile peer
// supplying a megabyte header that the Go runtime would otherwise
// allocate.
const MaxRequestIDLength = 128

// contextKey for the request-id slot. Reuses the typed sentinel
// pattern auth.go uses (unexported type prevents collision with
// other packages' context keys).
const ctxRequestID contextKey = "request_id"

// -------------------------------------------------------------------------------------------------
// 2) Public surface
// -------------------------------------------------------------------------------------------------

// RequestID extracts the correlation ID from context. Empty string
// when the middleware has not run (e.g., direct unit tests calling
// a handler without the middleware chain).
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

// WithRequestID returns the middleware wrapper. Every request
// that flows through gets a non-empty correlation ID in context
// AND echoed in the response header.
func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := normalizeInbound(r.Header.Get(HeaderRequestID))
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set(HeaderRequestID, id)
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// -------------------------------------------------------------------------------------------------
// 3) Validation
// -------------------------------------------------------------------------------------------------

// normalizeInbound returns the inbound header value if it is
// non-empty, length-bounded, and contains only printable ASCII.
// Otherwise returns "" so the caller mints a fresh UUIDv4. The
// printable-ASCII check defends against header-injection (CR/LF)
// and against control characters that would corrupt downstream
// log-shipping (slog newline-splits on "\n").
func normalizeInbound(in string) string {
	if in == "" || len(in) > MaxRequestIDLength {
		return ""
	}
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c < 0x20 || c > 0x7E {
			return ""
		}
	}
	return in
}
