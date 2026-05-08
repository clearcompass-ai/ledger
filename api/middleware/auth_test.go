/*
FILE PATH: api/middleware/auth_test.go

Tests the SessionLookup-driven Auth middleware. Pins:

  - No token → unauthenticated (Mode B); next handler invoked,
    ctx carries authenticated=false.
  - nil lookup → unauthenticated regardless of token (test/dev
    convenience).
  - Valid token + future expiry → authenticated; ctx carries the
    exchangeDID; next handler invoked.
  - Token-not-found → 401 (next handler NOT invoked).
  - Lookup transient error → 500.
  - Expired token → 401.
*/
package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeSessions struct {
	exchangeDID string
	expiresAt   time.Time
	err         error
}

func (f *fakeSessions) LookupSession(_ context.Context, _ string) (string, time.Time, error) {
	return f.exchangeDID, f.expiresAt, f.err
}

func nextEcho(called *bool, captured *context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		ctxCopy := r.Context()
		*captured = ctxCopy
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuth_NoToken_PassesThroughUnauthenticated(t *testing.T) {
	called := false
	var captured context.Context
	h := Auth(&fakeSessions{}, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("next handler not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if IsAuthenticated(captured) {
		t.Error("expected unauthenticated context")
	}
}

func TestAuth_NilLookup_AlwaysUnauthenticated(t *testing.T) {
	called := false
	var captured context.Context
	h := Auth(nil, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("next handler not called")
	}
	if IsAuthenticated(captured) {
		t.Error("nil lookup should always yield unauthenticated")
	}
}

func TestAuth_ValidToken_AuthenticatedContext(t *testing.T) {
	called := false
	var captured context.Context
	lookup := &fakeSessions{
		exchangeDID: "did:test:exchange",
		expiresAt:   time.Now().Add(time.Hour),
	}
	h := Auth(lookup, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("next handler not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if !IsAuthenticated(captured) {
		t.Error("expected authenticated context")
	}
	if got := ExchangeDID(captured); got != "did:test:exchange" {
		t.Errorf("ExchangeDID = %q", got)
	}
}

func TestAuth_TokenNotFound_Returns401(t *testing.T) {
	called := false
	var captured context.Context
	lookup := &fakeSessions{err: ErrSessionNotFound}
	h := Auth(lookup, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("next handler should not be called on 401")
	}
}

func TestAuth_LookupTransientError_Returns500(t *testing.T) {
	called := false
	var captured context.Context
	lookup := &fakeSessions{err: errors.New("connection refused")}
	h := Auth(lookup, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer x")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if called {
		t.Error("next handler should not be called on 500")
	}
}

func TestAuth_ExpiredToken_Returns401(t *testing.T) {
	called := false
	var captured context.Context
	lookup := &fakeSessions{
		exchangeDID: "did:test:exchange",
		expiresAt:   time.Now().Add(-time.Hour), // already expired
	}
	h := Auth(lookup, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer expired")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("next handler should not be called on 401")
	}
}

func TestAuth_TokenWithoutBearer_PassesThroughUnauthenticated(t *testing.T) {
	called := false
	var captured context.Context
	h := Auth(&fakeSessions{}, nextEcho(&called, &captured))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic abc")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("next handler not called")
	}
	if IsAuthenticated(captured) {
		t.Error("non-Bearer auth should be treated as no token")
	}
}
