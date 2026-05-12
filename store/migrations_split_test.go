// FILE PATH: store/migrations_split_test.go
//
// Unit tests for the no-tx migration runner's SQL statement
// splitter. The splitter is load-bearing: PostgreSQL treats a
// multi-statement Query message as a single implicit transaction
// block, which CREATE INDEX CONCURRENTLY rejects with SQLSTATE
// 25001. Migrations marked `-- migrate:no-transaction` rely on
// the splitter to fan each statement out as its own Exec call.
//
// A regression in splitSQLStatements would silently break every
// future no-tx migration. The cases below pin every shape the
// splitter is documented to support and the documented
// non-supported edge cases that the runner FAILS LOUDLY on.
package store

import (
	"reflect"
	"testing"
)

func TestSplitSQLStatements_Empty(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\n\n", "\t  \n"} {
		got := splitSQLStatements(in)
		if len(got) != 0 {
			t.Errorf("splitSQLStatements(%q) = %v, want empty slice",
				in, got)
		}
	}
}

func TestSplitSQLStatements_OnlyComments(t *testing.T) {
	in := "-- just a comment\n-- another\n/* block comment */\n"
	got := splitSQLStatements(in)
	if len(got) != 0 {
		t.Errorf("comments-only input must yield zero statements; got %v", got)
	}
}

func TestSplitSQLStatements_SingleStatement(t *testing.T) {
	for name, in := range map[string]string{
		"with trailing semicolon":    "ALTER TABLE foo DROP COLUMN bar;",
		"without trailing semicolon": "ALTER TABLE foo DROP COLUMN bar",
		"with leading whitespace":    "\n\n  ALTER TABLE foo DROP COLUMN bar;\n",
		"with trailing whitespace":   "ALTER TABLE foo DROP COLUMN bar;\n\n   ",
	} {
		t.Run(name, func(t *testing.T) {
			got := splitSQLStatements(in)
			want := []string{"ALTER TABLE foo DROP COLUMN bar"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestSplitSQLStatements_MultipleStatements(t *testing.T) {
	in := `
		ALTER TABLE foo DROP COLUMN bar;
		ALTER TABLE foo ADD COLUMN baz INT;
		CREATE INDEX CONCURRENTLY idx_foo_baz ON foo (baz);
	`
	got := splitSQLStatements(in)
	want := []string{
		"ALTER TABLE foo DROP COLUMN bar",
		"ALTER TABLE foo ADD COLUMN baz INT",
		"CREATE INDEX CONCURRENTLY idx_foo_baz ON foo (baz)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
}

func TestSplitSQLStatements_StripsLineComments(t *testing.T) {
	in := `
		-- migrate:no-transaction
		-- This is the file header.
		--
		ALTER TABLE foo DROP COLUMN bar;   -- inline trailing comment
		-- standalone comment between statements
		CREATE INDEX idx_foo ON foo (bar);
	`
	got := splitSQLStatements(in)
	want := []string{
		"ALTER TABLE foo DROP COLUMN bar",
		"CREATE INDEX idx_foo ON foo (bar)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
}

func TestSplitSQLStatements_StripsBlockComments(t *testing.T) {
	in := `
		/* file-level block comment
		   spanning multiple lines */
		ALTER TABLE foo DROP COLUMN bar; /* inline */
		/* leading block */ CREATE INDEX idx ON foo (bar);
	`
	got := splitSQLStatements(in)
	want := []string{
		"ALTER TABLE foo DROP COLUMN bar",
		"CREATE INDEX idx ON foo (bar)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
}

// TestSplitSQLStatements_UnterminatedBlockComment pins the
// documented behavior: an unterminated `/*` drops to end-of-string
// (matches PG). This is unlikely in practice but the splitter
// must not crash.
func TestSplitSQLStatements_UnterminatedBlockComment(t *testing.T) {
	in := "ALTER TABLE foo DROP COLUMN bar; /* unterminated"
	got := splitSQLStatements(in)
	want := []string{"ALTER TABLE foo DROP COLUMN bar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

// TestSplitSQLStatements_Migration0006Shape exercises the EXACT
// shape of the migration-0006 file (the file whose mis-split
// triggered this whole code path). If this regresses, the chaos
// test's pre_commit_post_pg path falls apart at boot — pin it
// against drift.
func TestSplitSQLStatements_Migration0006Shape(t *testing.T) {
	in := `-- migrate:no-transaction
--
-- File-level header comment block.

-- ── Phase 1 — extend the status enum to admit ghost (2) ────────────────
ALTER TABLE entry_index
    DROP CONSTRAINT IF EXISTS entry_index_status_check;
ALTER TABLE entry_index
    ADD CONSTRAINT entry_index_status_check CHECK (status IN (0, 1, 2));

-- ── Phase 2 — build the new partial unique index ───────────────────────
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS
    entry_index_canonical_hash_primary_idx
    ON entry_index (canonical_hash)
    WHERE status <> 2;

-- ── Phase 3 — drop the old blanket UNIQUE constraint ───────────────────
ALTER TABLE entry_index
    DROP CONSTRAINT IF EXISTS entry_index_canonical_hash_key;

-- ── Phase 4 — supporting partial index for ghost-row audit ─────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS
    entry_index_canonical_hash_ghost_idx
    ON entry_index (canonical_hash)
    WHERE status = 2;
`
	got := splitSQLStatements(in)
	if len(got) != 5 {
		t.Fatalf("migration 0006 must split into exactly 5 statements; got %d:\n%#v",
			len(got), got)
	}
	// Smoke-check each statement starts with the expected DDL verb.
	prefixes := []string{
		"ALTER TABLE entry_index",
		"ALTER TABLE entry_index",
		"CREATE UNIQUE INDEX CONCURRENTLY",
		"ALTER TABLE entry_index",
		"CREATE INDEX CONCURRENTLY",
	}
	for i, want := range prefixes {
		if !startsWithIgnoreWhitespace(got[i], want) {
			t.Errorf("stmt[%d] = %q, want prefix %q", i, got[i], want)
		}
	}
}

func startsWithIgnoreWhitespace(s, prefix string) bool {
	for i := 0; i < len(s) && i < len(prefix); i++ {
		if s[i] != prefix[i] {
			return false
		}
	}
	return len(s) >= len(prefix)
}

// TestStripSQLLineComments pins the `--` stripping behavior in
// isolation, separate from the full splitter.
func TestStripSQLLineComments(t *testing.T) {
	in := "SELECT 1; -- trailing\nSELECT 2;\n-- standalone\nSELECT 3;"
	got := stripSQLLineComments(in)
	// Newlines preserved; comment text replaced with nothing.
	want := "SELECT 1; \nSELECT 2;\n\nSELECT 3;\n"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// TestStripSQLBlockComments pins the `/* */` stripping behavior in
// isolation.
func TestStripSQLBlockComments(t *testing.T) {
	in := "SELECT 1; /* a */ SELECT 2 /* multi\nline */; SELECT 3;"
	got := stripSQLBlockComments(in)
	want := "SELECT 1;  SELECT 2 ; SELECT 3;"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestTruncateForLog(t *testing.T) {
	t.Run("below cap", func(t *testing.T) {
		got := truncateForLog("short", 100)
		if got != "short" {
			t.Errorf("got %q, want %q", got, "short")
		}
	})
	t.Run("at cap", func(t *testing.T) {
		got := truncateForLog("12345", 5)
		if got != "12345" {
			t.Errorf("got %q, want %q", got, "12345")
		}
	})
	t.Run("over cap", func(t *testing.T) {
		got := truncateForLog("1234567890", 5)
		if got != "12345..." {
			t.Errorf("got %q, want %q", got, "12345...")
		}
	})
	t.Run("strips newlines", func(t *testing.T) {
		got := truncateForLog("a\n  b\nc", 100)
		if got != "a   b c" {
			t.Errorf("got %q, want %q", got, "a   b c")
		}
	})
}
