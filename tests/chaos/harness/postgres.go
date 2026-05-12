/*
FILE PATH: tests/chaos/harness/postgres.go

Per-test Postgres database isolation for chaos tests. Each test
gets a freshly-created DATABASE inside the shared Postgres
instance (ATTESTA_TEST_DSN). The ledger subprocess connects to
that database; migrations run on first boot via
LEDGER_DB_MIGRATE_MODE=apply. On cleanup the database is dropped.

WHY DATABASE-PER-TEST vs SCHEMA-PER-TEST

The ledger's migration runner expects to own the `public`
schema. Multi-schema per-database setups require coordinating
search_path across pgx pool connections and don't compose
cleanly with the SDK's expectations. A fresh database per test
is heavier (~150ms creation overhead) but eliminates cross-test
contamination and lets us run a SIGKILL-restart cycle against
the same DB without worrying about lingering state.

ENV VAR CONTRACT

  ATTESTA_TEST_DSN must point at a Postgres instance the test
  user has CREATEDB privilege on. The soak's run-soak.sh
  provisions this; chaos tests inherit the same env.

CONCURRENCY

  Test database names embed t.Name() + a process-unique counter
  so parallel test runs don't collide. Drop is best-effort on
  cleanup; lingering test databases are an operational cleanup
  task (DROP DATABASE WITH (FORCE) on a sweep job).
*/
package harness

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Counter for chaos-test DB names. Atomic so parallel tests
// produce non-colliding names without coordination.
var dbCounter atomic.Int64

// Postgres is an isolated Postgres database created for one chaos
// test. The DSN field is what gets passed to the ledger via
// LEDGER_DATABASE_URL. Close drops the database (best-effort).
type Postgres struct {
	// DSN to pass to LEDGER_DATABASE_URL. Includes the
	// per-test database name.
	DSN string

	// Pool is a connection to the test database. Used by the
	// harness's invariant helpers (gap/leapfrog queries, SMT
	// reconstruction). The ledger subprocess uses its own pool.
	Pool *pgxpool.Pool

	// adminDSN is the connection string to the parent database
	// (postgres or attesta_test). Used to issue DROP DATABASE
	// on cleanup since you can't drop the DB you're connected to.
	adminDSN string

	// dbName is the per-test database name (also embedded in
	// DSN). Captured separately so we can DROP it without
	// re-parsing the DSN.
	dbName string
}

// NewPostgres creates a fresh Postgres database for the calling
// test. The new database is empty — the ledger subprocess will
// run migrations on its first boot. Registers cleanup via
// t.Cleanup to DROP the database after the test exits.
//
// On any failure, t.Fatalf is called.
func NewPostgres(t *testing.T) *Postgres {
	t.Helper()
	adminDSN := os.Getenv("ATTESTA_TEST_DSN")
	if adminDSN == "" {
		t.Skip("ATTESTA_TEST_DSN not set — chaos harness needs a Postgres instance")
	}

	dbName := makeDBName(t)

	// CREATE DATABASE requires a connection to the parent (not
	// the target). Open the admin connection, issue CREATE,
	// close.
	adminCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConn, err := pgx.Connect(adminCtx, adminDSN)
	if err != nil {
		t.Fatalf("NewPostgres: connect admin DSN: %v", err)
	}
	defer adminConn.Close(adminCtx)

	// Quote the dbname defensively — t.Name() can contain
	// punctuation that breaks an unquoted identifier.
	_, err = adminConn.Exec(adminCtx,
		fmt.Sprintf(`CREATE DATABASE "%s"`, dbName))
	if err != nil {
		t.Fatalf("NewPostgres: CREATE DATABASE %q: %v", dbName, err)
	}

	// Build the per-test DSN by swapping the database in the
	// admin DSN's URL path.
	testDSN, err := rewriteDSNDatabase(adminDSN, dbName)
	if err != nil {
		// Database was created; drop it before failing.
		_, _ = adminConn.Exec(adminCtx,
			fmt.Sprintf(`DROP DATABASE "%s"`, dbName))
		t.Fatalf("NewPostgres: rewrite DSN: %v", err)
	}

	// Open a pool against the new database for the harness's
	// own diagnostic queries.
	poolCtx, poolCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer poolCancel()
	pool, err := pgxpool.New(poolCtx, testDSN)
	if err != nil {
		_, _ = adminConn.Exec(adminCtx,
			fmt.Sprintf(`DROP DATABASE "%s"`, dbName))
		t.Fatalf("NewPostgres: pgxpool.New: %v", err)
	}

	p := &Postgres{
		DSN:      testDSN,
		Pool:     pool,
		adminDSN: adminDSN,
		dbName:   dbName,
	}
	t.Cleanup(p.Close)
	return p
}

// Close drops the test database (best-effort). Errors logged via
// t.Log; not fatal — lingering test databases are operational
// cleanup, not a correctness issue.
func (p *Postgres) Close() {
	if p.Pool != nil {
		p.Pool.Close()
		p.Pool = nil
	}
	if p.dbName == "" || p.adminDSN == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	adminConn, err := pgx.Connect(ctx, p.adminDSN)
	if err != nil {
		// Best-effort; let operator sweep.
		return
	}
	defer adminConn.Close(ctx)
	// FORCE terminates lingering connections (ours or the
	// subprocess ledger's that didn't close cleanly under SIGKILL).
	_, _ = adminConn.Exec(ctx,
		fmt.Sprintf(`DROP DATABASE IF EXISTS "%s" WITH (FORCE)`, p.dbName))
	p.dbName = ""
}

// makeDBName produces a Postgres-identifier-safe, unique name
// embedding the test name + a process counter. Truncated to
// Postgres's 63-byte identifier limit.
func makeDBName(t *testing.T) string {
	t.Helper()
	n := dbCounter.Add(1)
	// Sanitize t.Name() for Postgres identifier syntax — keep
	// alphanumerics and underscores, replace others with '_'.
	var clean strings.Builder
	for _, r := range t.Name() {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			clean.WriteRune(r)
		default:
			clean.WriteByte('_')
		}
	}
	full := fmt.Sprintf("chaos_%s_%d_%d",
		clean.String(), os.Getpid(), n)
	// Postgres identifier limit.
	if len(full) > 63 {
		full = full[:63]
	}
	return full
}

// rewriteDSNDatabase replaces the database portion of a Postgres
// DSN with name. Handles both URL-style (postgres://user:pw@host/db?...)
// and keyword-style ("host=... dbname=...") DSNs.
func rewriteDSNDatabase(dsn, name string) (string, error) {
	// URL-style: postgres://...
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("parse DSN: %w", err)
		}
		u.Path = "/" + name
		return u.String(), nil
	}
	// Keyword style: replace dbname= or append.
	parts := strings.Fields(dsn)
	var out []string
	dbnameSet := false
	for _, p := range parts {
		if strings.HasPrefix(p, "dbname=") {
			out = append(out, "dbname="+name)
			dbnameSet = true
			continue
		}
		out = append(out, p)
	}
	if !dbnameSet {
		out = append(out, "dbname="+name)
	}
	return strings.Join(out, " "), nil
}
