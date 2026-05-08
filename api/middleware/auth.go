/*
FILE PATH: api/middleware/auth.go

Exchange session authentication. Validates Bearer tokens against
the sessions table. Sets authenticated + exchangeDID in context.

KEY ARCHITECTURAL DECISIONS:
  - Missing token → unauthenticated (Mode B). No error.
  - Invalid/expired token → HTTP 401 (not silent fallthrough to Mode B).
  - Valid token → context carries exchangeDID + authenticated=true.

— Pure CQRS:

	Auth takes a SessionLookup interface (NOT *pgxpool.Pool). The
	production wiring in cmd/ledger/main.go constructs a thin
	adapter over store/'s sessions surface that satisfies
	SessionLookup. This keeps the api/middleware package free of
	pgx imports — the load-bearing piece of the api/ pgx-purge.
*/
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const (
	ctxAuthenticated contextKey = "authenticated"
	ctxExchangeDID   contextKey = "exchange_did"
)

// ErrSessionNotFound is the sentinel a SessionLookup returns when
// the supplied token does not match any row in the sessions
// table. The middleware maps this to HTTP 401 (invalid token).
//
// Wrapped errors from the impl ("connection refused", etc.)
// surface as HTTP 500.
var ErrSessionNotFound = errors.New("middleware: session not found")

// SessionLookup resolves a Bearer token to its (exchangeDID,
// expiresAt) tuple. Implementations MUST return ErrSessionNotFound
// (or an error wrapping it) when no row matches; any other error
// is treated as a transient failure (HTTP 500).
//
// Production: wired via a thin adapter over store/'s sessions
// surface in cmd/ledger/main.go.
type SessionLookup interface {
	LookupSession(ctx context.Context, token string) (exchangeDID string, expiresAt time.Time, err error)
}

// IsAuthenticated extracts the authentication flag from context.
func IsAuthenticated(ctx context.Context) bool {
	v, _ := ctx.Value(ctxAuthenticated).(bool)
	return v
}

// ExchangeDID extracts the exchange DID from context.
func ExchangeDID(ctx context.Context) string {
	v, _ := ctx.Value(ctxExchangeDID).(string)
	return v
}

// Auth validates Bearer tokens. Missing token → unauthenticated
// (Mode B). Invalid/expired token → HTTP 401 (rejected, not
// Mode B fallthrough).
//
// nil lookup is treated as "always unauthenticated" — Mode B
// only. Useful for test/dev wiring where the sessions table
// isn't initialized.
func Auth(lookup SessionLookup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := extractBearerToken(r)
		if token == "" || lookup == nil {
			// No token (or no lookup wired): proceed as
			// unauthenticated (Mode B).
			ctx = context.WithValue(ctx, ctxAuthenticated, false)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		exchangeDID, expiresAt, err := lookup.LookupSession(ctx, token)
		if errors.Is(err, ErrSessionNotFound) {
			http.Error(w, `{"error":"invalid session token"}`, http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, `{"error":"session lookup failed"}`, http.StatusInternalServerError)
			return
		}
		if time.Now().After(expiresAt) {
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, ctxAuthenticated, true)
		ctx = context.WithValue(ctx, ctxExchangeDID, exchangeDID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
