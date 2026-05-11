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
	// Migration 0001 creates the load-bearing initial schema. We
	// only assert tables that PERSIST through later migrations —
	// jellyfish_nodes is added in 0003, not 0001, so it is checked
	// separately below.
	for _, table := range []string{"schema_migrations", "entry_index", "smt_leaves"} {
		if !strings.Contains(migs[0].sql, table) {
			t.Errorf("first migration missing reference to table %q", table)
		}
	}
	// Migration 0003 (Jellyfish SMT) must be embedded and create the
	// content-addressed jellyfish_nodes table. Walking the embed
	// guards against the file being dropped from the //go:embed
	// directive on a future restructure.
	found0003 := false
	for _, m := range migs {
		if m.version == 3 {
			found0003 = true
			if !strings.Contains(m.sql, "jellyfish_nodes") {
				t.Errorf("migration 0003 missing CREATE TABLE jellyfish_nodes")
			}
			break
		}
	}
	if !found0003 {
		t.Errorf("migration 0003 (Jellyfish SMT) missing from embedded migration set")
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
