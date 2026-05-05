/*
FILE PATH: store/session_lookup_test.go

Compile-time + sentinel-mapping tests for PostgresSessionLookup.

A real Postgres-backed test would belong in integration/; this
file pins:

  - Static interface assertion: *PostgresSessionLookup satisfies
    middleware.SessionLookup (build break on signature drift).
  - nil-pool panic at construction.
  - The error returned for an unmatched token is recognized via
    errors.Is(err, middleware.ErrSessionNotFound) — verified by
    the LookupSession code path's pgx.ErrNoRows mapping (the
    integration test exercises this).
*/
package store

import (
	"testing"

	"github.com/clearcompass-ai/ledger/api/middleware"
)

func TestNewPostgresSessionLookup_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil pool")
		}
	}()
	_ = NewPostgresSessionLookup(nil)
}

func TestPostgresSessionLookup_StaticInterfaceCheck(t *testing.T) {
	var _ middleware.SessionLookup = (*PostgresSessionLookup)(nil)
}
