/*
FILE PATH: store/test_isolation.go

IsolatedDB — per-test PostgreSQL schema namespace.

Each call creates a fresh `test_<sanitized name>_<pid>_<rand>` schema,
applies all migrations into it, returns a pool whose default
search_path is that schema, and registers a cleanup that drops the
schema CASCADE when the test ends.

# Why this exists

The repo's integration tests share a single Postgres instance
(ATTESTA_TEST_DSN). Default `go test ./...` runs packages in
parallel up to GOMAXPROCS, so two packages writing to the same
`entry_index` table concurrently produce 'duplicate entry seq=N' /
'got [], want [...]' / 'Count = 18, want 16' interference. The
historical workaround is `make test` (= `-p 1`, serial package
execution), which costs ~3× CI wall-clock.

Per-package schema isolation removes the shared-state coupling
structurally: each test sees an empty database it set up itself,
and no other test can write into that namespace. Packages
parallelize at full GOMAXPROCS.

# Postgres schemas vs. databases

Schemas are O(ms) to create and drop. Databases are O(s) (catalog
copy). Same Postgres instance, same connection, just a different
search_path. The standard Postgres test-isolation pattern (Boulder,
github.com/jackc/tern, ory/dockertest).

# Migration application

RunMigrations creates schema_migrations + every table in the
search_path's first schema (postgres default behaviour for
unqualified DDL). Setting search_path before RunMigrations means
all tables land inside the isolated schema. Each isolated schema
gets its own migration history — fast (~150ms total) and idempotent.
*/
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IsolatedDB returns a *pgxpool.Pool bound to a fresh, migrated
// PostgreSQL schema unique to this test. The schema is dropped
// (with all its tables) when t finishes.
//
// Skips when ATTESTA_TEST_DSN is unset (same convention as
// requireDB) — consumers that need a real PG should call this;
// pure-unit tests that don't need PG keep skipping cleanly.
//
// Concurrency: multiple tests can call IsolatedDB(t) in parallel.
// Each gets its own schema; the only contention is the schema-
// creation DDL on the root pool, which is fast.
func IsolatedDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset; skipping PG-backed test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// (1) Root pool — only used to CREATE / DROP the per-test
	// schema. Connection back to the default `public` schema so
	// CREATE SCHEMA is unambiguous.
	rootCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("IsolatedDB: parse root DSN: %v", err)
	}
	rootCfg.MaxConns = 2 // schema admin only
	rootPool, err := pgxpool.NewWithConfig(ctx, rootCfg)
	if err != nil {
		t.Fatalf("IsolatedDB: open root pool: %v", err)
	}
	// Defer root close until cleanup — we need it again for the
	// DROP SCHEMA call.

	schema := isolatedSchemaName(t)
	if _, err := rootPool.Exec(ctx,
		fmt.Sprintf("CREATE SCHEMA %q", schema),
	); err != nil {
		rootPool.Close()
		t.Fatalf("IsolatedDB: CREATE SCHEMA %q: %v", schema, err)
	}

	// (2) Test pool — same DSN but with search_path pinned to the
	// isolated schema via RuntimeParams. All unqualified DDL/DML
	// runs inside this schema.
	testCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("IsolatedDB: parse test DSN: %v", err)
	}
	if testCfg.ConnConfig.RuntimeParams == nil {
		testCfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	testCfg.ConnConfig.RuntimeParams["search_path"] = schema
	testPool, err := pgxpool.NewWithConfig(ctx, testCfg)
	if err != nil {
		rootPool.Close()
		t.Fatalf("IsolatedDB: open test pool with search_path=%q: %v", schema, err)
	}

	// (3) Apply migrations into the isolated schema.
	if err := RunMigrations(ctx, testPool); err != nil {
		testPool.Close()
		_, _ = rootPool.Exec(context.Background(),
			fmt.Sprintf("DROP SCHEMA IF EXISTS %q CASCADE", schema))
		rootPool.Close()
		t.Fatalf("IsolatedDB: RunMigrations into %q: %v", schema, err)
	}

	// (4) Cleanup: close pool, drop schema, close root.
	t.Cleanup(func() {
		testPool.Close()
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelCleanup()
		if _, err := rootPool.Exec(cleanupCtx,
			fmt.Sprintf("DROP SCHEMA IF EXISTS %q CASCADE", schema),
		); err != nil {
			t.Logf("IsolatedDB cleanup: DROP SCHEMA %q: %v (non-fatal; schema may leak)", schema, err)
		}
		rootPool.Close()
	})

	return testPool
}

// isolatedSchemaName produces a Postgres-identifier-safe, per-test
// unique schema name. Postgres identifiers cap at 63 bytes, so we
// truncate aggressively while keeping enough of the test name for
// audit / debugging when DROP fails.
func isolatedSchemaName(t *testing.T) string {
	// 4 random bytes → 8 hex chars. Plus os.Getpid (up to 7 chars
	// on Linux) keeps cross-process collisions impossible across
	// concurrent `go test -p N`.
	var randBytes [4]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		t.Fatalf("isolatedSchemaName: rand: %v", err)
	}
	randHex := hex.EncodeToString(randBytes[:])

	clean := sanitizeForPGIdent(t.Name())
	// Reserve room for prefix + pid + rand + separators.
	const reserveBytes = len("test_") + 1 + 7 + 1 + 8
	if maxName := 63 - reserveBytes; len(clean) > maxName {
		clean = clean[:maxName]
	}
	return fmt.Sprintf("test_%s_%d_%s", clean, os.Getpid(), randHex)
}

// sanitizeForPGIdent maps the Go test name (which contains '/',
// '#', etc. from subtests) to a string safe for use inside a
// quoted Postgres identifier. Lowercase a-z, 0-9, underscore; '/'
// from subtest paths becomes '_'.
func sanitizeForPGIdent(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
