/*
FILE PATH: store/test_isolation_test.go

Tests for the IsolatedDB helper. Verify the schema is fresh,
migrations are applied inside it, and a sibling pool against the
same DSN does NOT see this pool's rows (the load-bearing isolation
property).
*/
package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestIsolatedDB_FreshSchemaPerCall pins that every IsolatedDB
// invocation gives the caller a fresh, empty entry_index — the
// property that lets parallel test packages share one Postgres
// instance without interfering.
func TestIsolatedDB_FreshSchemaPerCall(t *testing.T) {
	pool := IsolatedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int64
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM entry_index").Scan(&count); err != nil {
		t.Fatalf("count entry_index: %v", err)
	}
	if count != 0 {
		t.Errorf("entry_index has %d rows in fresh schema; want 0", count)
	}
}

// TestIsolatedDB_MigrationsAreAppliedIntoSchema confirms RunMigrations
// ran inside the isolated schema by checking that schema_migrations
// contains entries.
func TestIsolatedDB_MigrationsAreAppliedIntoSchema(t *testing.T) {
	pool := IsolatedDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var migrationCount int64
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if migrationCount == 0 {
		t.Error("schema_migrations is empty; RunMigrations did not apply into the isolated schema")
	}
}

// TestIsolatedDB_PoolsAreIsolated is the load-bearing test for the
// helper's structural purpose. Two pools, two schemas, the same DSN.
// Writes in pool A MUST NOT be visible to pool B.
func TestIsolatedDB_PoolsAreIsolated(t *testing.T) {
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset")
	}

	// Two sibling sub-tests, each gets its own IsolatedDB.
	t.Run("first_writer", func(t *testing.T) {
		first := IsolatedDB(t)
		second := IsolatedDB(t)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Write a row into FIRST pool's schema.
		var hash [32]byte
		hash[0] = 0xAB
		tx, err := first.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		store := NewEntryStore(first)
		if err := store.Insert(ctx, tx, EntryRow{
			SequenceNumber: 7,
			CanonicalHash:  hash,
			LogTime:        time.Now().UTC(),
			SignerDID:      "did:web:isolation-test",
			Status:         StatusLive,
		}); err != nil {
			t.Fatalf("insert into first: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		// SECOND pool must NOT see the row (different schema).
		var count int64
		if err := second.QueryRow(ctx,
			"SELECT COUNT(*) FROM entry_index WHERE sequence_number = 7").Scan(&count); err != nil {
			t.Fatalf("query second pool: %v", err)
		}
		if count != 0 {
			t.Errorf("second pool saw %d rows from first pool's schema; isolation broken", count)
		}
	})
}

// TestIsolatedDB_SchemaDroppedOnCleanup spot-checks that the schema
// is gone after t.Cleanup fires. Uses a wrapper test so we observe
// the cleanup from outside the helper's t lifetime.
func TestIsolatedDB_SchemaDroppedOnCleanup(t *testing.T) {
	dsn := os.Getenv("ATTESTA_TEST_DSN")
	if dsn == "" {
		t.Skip("ATTESTA_TEST_DSN unset")
	}

	var capturedSchema string

	t.Run("inner", func(inner *testing.T) {
		pool := IsolatedDB(inner)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Read current_schema to capture which schema the helper assigned.
		if err := pool.QueryRow(ctx,
			"SELECT current_schema()").Scan(&capturedSchema); err != nil {
			inner.Fatalf("current_schema: %v", err)
		}
	}) // inner.Cleanup fires here; schema should be dropped.

	if capturedSchema == "" {
		t.Fatal("did not capture schema name")
	}

	// Confirm the schema is gone via a sibling root pool.
	rootCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	rootCfg.MaxConns = 2
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rootPool, err := pgxpool.NewWithConfig(ctx, rootCfg)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer rootPool.Close()
	var exists bool
	if err := rootPool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)",
		capturedSchema,
	).Scan(&exists); err != nil {
		t.Fatalf("check schema existence: %v", err)
	}
	if exists {
		t.Errorf("schema %q still exists after cleanup", capturedSchema)
	}
}
