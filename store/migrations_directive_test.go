// FILE PATH: store/migrations_directive_test.go
//
// Unit tests for the `-- migrate:no-transaction` directive parser.
//
// The directive is the load-bearing knob that lets a migration
// declare "I need to run outside a BEGIN/COMMIT wrapper" — required
// for CREATE INDEX CONCURRENTLY and a handful of other DDL forms
// PostgreSQL refuses inside an explicit transaction. The detector
// scans only the leading bytes of the file and uses the FIRST
// non-empty line as the discriminator, so an audit grep for the
// directive at the top of any .sql file is sufficient to classify
// the migration's transaction mode.
package store

import "testing"

func TestDetectNoTransactionDirective_TopOfFile(t *testing.T) {
	body := []byte("-- migrate:no-transaction\nCREATE INDEX CONCURRENTLY foo ON bar(baz);\n")
	if !detectNoTransactionDirective(body) {
		t.Fatal("directive at top of file must be detected")
	}
}

func TestDetectNoTransactionDirective_AfterLeadingWhitespace(t *testing.T) {
	body := []byte("   \t-- migrate:no-transaction\nCREATE INDEX CONCURRENTLY foo ON bar(baz);\n")
	if !detectNoTransactionDirective(body) {
		t.Fatal("directive after leading whitespace must be detected")
	}
}

func TestDetectNoTransactionDirective_AfterBlankLines(t *testing.T) {
	body := []byte("\n\n\n-- migrate:no-transaction\nCREATE INDEX CONCURRENTLY foo ON bar(baz);\n")
	if !detectNoTransactionDirective(body) {
		t.Fatal("directive after blank lines (still the first non-empty line) must be detected")
	}
}

func TestDetectNoTransactionDirective_NotPresent(t *testing.T) {
	body := []byte("-- ordinary migration\nALTER TABLE foo ADD COLUMN bar TEXT;\n")
	if detectNoTransactionDirective(body) {
		t.Fatal("plain comment must not be misread as the directive")
	}
}

func TestDetectNoTransactionDirective_OnlyTopLineCounts(t *testing.T) {
	// The directive's POSITION matters: only the first non-empty
	// line is considered. A directive buried in the middle of the
	// file is ignored — by design, so a glance at the top of any
	// .sql tells the audit reader the transaction mode.
	body := []byte("ALTER TABLE foo ADD COLUMN bar TEXT;\n-- migrate:no-transaction\nCREATE INDEX CONCURRENTLY baz ON foo(bar);\n")
	if detectNoTransactionDirective(body) {
		t.Fatal("directive past the first non-empty line must NOT be detected (audit rule)")
	}
}

func TestDetectNoTransactionDirective_EmptyFile(t *testing.T) {
	if detectNoTransactionDirective([]byte("")) {
		t.Error("empty file must not register the directive")
	}
	if detectNoTransactionDirective([]byte("\n\n\n")) {
		t.Error("whitespace-only file must not register the directive")
	}
}

func TestDetectNoTransactionDirective_CaseSensitive(t *testing.T) {
	// The directive string is protocol-permanent; case drift
	// would let two near-identical files diverge silently. Pin
	// the exact byte sequence.
	bodies := [][]byte{
		[]byte("-- MIGRATE:NO-TRANSACTION\nCREATE INDEX foo ON bar(baz);\n"),
		[]byte("-- Migrate:No-Transaction\nCREATE INDEX foo ON bar(baz);\n"),
		[]byte("--migrate:no-transaction\nCREATE INDEX foo ON bar(baz);\n"), // missing leading space
	}
	for i, body := range bodies {
		if detectNoTransactionDirective(body) {
			t.Errorf("case-drift body %d must NOT register the directive: %q",
				i, body[:32])
		}
	}
}

func TestLoadMigrations_ParsesDirectiveOnEmbeddedFile(t *testing.T) {
	// Migration 0006 is the canonical use case: it ships with the
	// directive on the first non-empty line. Loading it must
	// surface noTransaction=true.
	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	var found *migration
	for i := range all {
		if all[i].version == 6 {
			found = &all[i]
			break
		}
	}
	if found == nil {
		t.Fatal("migration 0006 not embedded — file missing?")
	}
	if !found.noTransaction {
		t.Errorf("0006 must be classified as no-transaction (CREATE INDEX CONCURRENTLY); got noTransaction=false")
	}
}

func TestLoadMigrations_TransactionalMigrationsStayTransactional(t *testing.T) {
	// Pre-0006 migrations have no directive. They must NOT be
	// reclassified as no-transaction by the new detector.
	all, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range all {
		if m.version < 6 && m.noTransaction {
			t.Errorf("v%d (%s) must remain transactional (no directive); got noTransaction=true",
				m.version, m.description)
		}
	}
}
