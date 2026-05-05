/*
FILE PATH: store/session_lookup.go

PostgresSessionLookup — Postgres-backed implementation of
api/middleware.SessionLookup. Resolves a Bearer token to its
(exchangeDID, expiresAt) tuple via a single point lookup against
the sessions table.

# WHY THIS EXISTS

PT-7 — Pure CQRS: api/middleware/auth.go used to take a
*pgxpool.Pool and inline the SELECT directly, which made
api/middleware (and transitively api/) import pgx. The middleware
now takes a SessionLookup interface; this file is the production
adapter that bridges it to Postgres.

# ERROR CONTRACT

Returns middleware.ErrSessionNotFound (wrapped) when no row
matches — the middleware maps that sentinel to HTTP 401. Any
other error is a transient infrastructure issue and surfaces as
HTTP 500.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
)

// PostgresSessionLookup satisfies api/middleware.SessionLookup
// against a *pgxpool.Pool. Construct once at startup and pass to
// middleware.Auth.
type PostgresSessionLookup struct {
	db *pgxpool.Pool
}

// NewPostgresSessionLookup constructs the adapter. Panics on nil
// pool — the operator should refuse to start without sessions
// access.
func NewPostgresSessionLookup(db *pgxpool.Pool) *PostgresSessionLookup {
	if db == nil {
		panic("store: NewPostgresSessionLookup: nil pool")
	}
	return &PostgresSessionLookup{db: db}
}

// LookupSession implements middleware.SessionLookup.
func (s *PostgresSessionLookup) LookupSession(
	ctx context.Context, token string,
) (string, time.Time, error) {
	var exchangeDID string
	var expiresAt time.Time
	err := s.db.QueryRow(ctx,
		"SELECT exchange_did, expires_at FROM sessions WHERE token = $1",
		token,
	).Scan(&exchangeDID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, middleware.ErrSessionNotFound
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store/session_lookup: query: %w", err)
	}
	return exchangeDID, expiresAt, nil
}

// Static interface check.
var _ middleware.SessionLookup = (*PostgresSessionLookup)(nil)
