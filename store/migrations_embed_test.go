// Tests for the migration loader's embed contract.
//
// FILE PATH: store/migrations_embed_test.go
//
// The embedded migration files are load-bearing: every Postgres-backed
// test, every production binary boot, every CI gate flows through
// loadMigrations(). A regression that drops a file from the embed
// directive (e.g., renaming a .sql to .sqL, or moving the dir under
// store/sql/migrations) is silent — RunMigrations would happily report
// "0 pending" against a brand-new schema and the next query would fail
// with "relation does not exist".
//
// These tests pin the contract by going directly through loadMigrations
// (no DB dependency, no go:embed magic to inspect).
package store

import (
	"strings"
	"testing"
)

func TestLoadMigrations_EmbedsAtLeastInitialSchema(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("loadMigrations returned 0 migrations; expected at least 0001_initial.sql")
	}
	if migs[0].version != 1 {
		t.Errorf("first migration version = %d, want 1", migs[0].version)
	}
	if migs[0].description != "initial" {
		t.Errorf("first migration description = %q, want \"initial\"", migs[0].description)
	}
	// The initial schema MUST contain at least the hand-rolled
	// schema_migrations + entry_index tables; if the file shrank to
	// near-empty something dropped the load-bearing DDL.
	if len(migs[0].sql) < 1024 {
		t.Errorf("first migration SQL length = %d bytes, want > 1024 (file looks truncated)", len(migs[0].sql))
	}
	for _, table := range []string{"schema_migrations", "entry_index", "smt_leaves", "smt_nodes"} {
		if !strings.Contains(migs[0].sql, table) {
			t.Errorf("first migration missing reference to table %q", table)
		}
	}
}

func TestLoadMigrations_VersionsAreAscending(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for i := 1; i < len(migs); i++ {
		if migs[i].version <= migs[i-1].version {
			t.Errorf("migrations[%d].version=%d <= migrations[%d].version=%d (must be strictly ascending)",
				i, migs[i].version, i-1, migs[i-1].version)
		}
	}
}
