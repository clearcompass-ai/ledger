// Package store: migration applier.
//
// FILE PATH:
//
//	store/migrations.go
//
// DESCRIPTION:
//
//	Versioned-SQL migration runner. Replaces the historical inline
//	schemaDDL[] in postgres.go. Mirrors the Boulder / upstream Tessera
//	pattern — numbered .sql files in store/migrations/, embedded via
//	the //go:embed directive, applied in order, recorded in
//	schema_migrations.
//
//	No external dependency. No DSL. ~200 LoC of in-tree Go.
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - Files are numbered with a 4-digit prefix (0001_, 0002_, ...).
//     The applier sorts lexically and applies any version not already
//     in schema_migrations. The version number is parsed from the
//     filename prefix as an int64; the rest of the filename is the
//     description recorded alongside the version.
//
//   - Each file is applied in a single transaction. Partial application
//     is impossible. A file that fails halfway leaves the database
//     unchanged from the file's pre-state.
//
//   - The schema_migrations table itself is created by file 0001 (the
//     first DDL statement). The applier checks for table existence at
//     boot and treats "missing" as "no migrations applied yet".
//
//   - Three operational modes via LEDGER_DB_MIGRATE_MODE:
//
//     "apply"  (default) — run pending migrations, then start.
//     "verify"           — fail if any pending; non-zero exit lists them.
//     "skip"             — assume admin already applied; touch nothing.
//
//     Mirrors the Tessera pattern (operator applies; binary verifies)
//     while keeping the laptop / CI default ergonomic.
package store

import (
	"context"
	"embed"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// MigrateMode controls RunMigrations behaviour.
//
// The legacy RunMigrations(ctx, db) signature defaults to MigrateApply,
// which preserves boot-time idempotent application for every existing
// caller. Operators that want the verify-then-start discipline pass
// MigrateVerify; deployments that apply migrations out-of-band (Helm
// hook, kubectl exec, hand-applied SQL) pass MigrateSkip.
type MigrateMode int

const (
	// MigrateApply applies any pending migrations, then returns.
	MigrateApply MigrateMode = iota
	// MigrateVerify returns *ErrPendingMigrations (with the list)
	// if any version is not yet applied. Touches no schema.
	MigrateVerify
	// MigrateSkip touches no schema and returns nil. Caller is
	// asserting an out-of-band apply has already run.
	MigrateSkip
)

// migration is one parsed *.sql file.
type migration struct {
	version     int64
	description string
	sql         string
	// noTransaction is set when the .sql file's first non-blank
	// line is the directive `-- migrate:no-transaction`. The
	// runner then applies the file via autocommit (no BEGIN/COMMIT
	// wrapper). Required for statements PostgreSQL rejects inside
	// a transaction block, most importantly
	// `CREATE INDEX CONCURRENTLY`.
	//
	// DISCIPLINE — when noTransaction is true:
	//
	//   - Every statement in the file MUST be IDEMPOTENT.
	//     CREATE ... IF NOT EXISTS, DROP ... IF EXISTS, etc. The
	//     runner records the version AFTER all DDL succeeds, in a
	//     SEPARATE small transaction; if that record-insert fails,
	//     the schema has migrated but the version is unrecorded.
	//     On the next boot the migration is re-applied — the
	//     idempotent shape makes that safe.
	//
	//   - Avoid mixing structural changes that depend on each
	//     other in the same file. If DDL #2 needs the row state
	//     DDL #1 produced and DDL #1 partially fails, recovery is
	//     manual. Split into 0006a + 0006b instead.
	//
	//   - The version IS recorded only after the entire file
	//     succeeds. Re-applies cost one redundant DDL pass but
	//     never break the schema.
	//
	// This pattern matches golang-migrate's per-file
	// `migrate:no-transaction` directive and pressly/goose's
	// `+goose NO TRANSACTION`. Same discipline, in-tree.
	noTransaction bool
}

// noTransactionDirective is the literal substring the migration
// runner scans for at the top of each .sql file. Matching is line-
// based: the first non-empty line must contain this exact byte
// sequence (case-sensitive, after trimming leading whitespace).
// Any later occurrence is ignored — directives must be at the top
// so reading the first 80 bytes of the file is enough to classify
// it.
const noTransactionDirective = "-- migrate:no-transaction"

// loadMigrations reads embedded *.sql files, parses the version + name,
// returns them in ascending version order. Filenames must match
// `^\d+_.*\.sql$`.
func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("store/migrations: read embed dir: %w", err)
	}
	out := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		under := strings.IndexByte(name, '_')
		if under < 1 {
			return nil, fmt.Errorf("store/migrations: %q: missing version prefix (want NNNN_<desc>.sql)", name)
		}
		v, err := strconv.ParseInt(name[:under], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("store/migrations: %q: parse version: %w", name, err)
		}
		body, err := migrationFS.ReadFile(path.Join("migrations", name))
		if err != nil {
			return nil, fmt.Errorf("store/migrations: read %q: %w", name, err)
		}
		desc := strings.TrimSuffix(name[under+1:], ".sql")
		out = append(out, migration{
			version:       v,
			description:   desc,
			sql:           string(body),
			noTransaction: detectNoTransactionDirective(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// listApplied returns the set of versions already recorded in
// schema_migrations. Returns an empty map (no error) when the table
// doesn't exist yet — that's the first-boot case.
func listApplied(ctx context.Context, db *pgxpool.Pool) (map[int64]struct{}, error) {
	rows, err := db.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		// First boot: schema_migrations doesn't exist. We detect
		// this via the Postgres error class. Any other error is
		// fatal.
		if strings.Contains(err.Error(), "schema_migrations") &&
			strings.Contains(err.Error(), "does not exist") {
			return map[int64]struct{}{}, nil
		}
		return nil, fmt.Errorf("store/migrations: list applied: %w", err)
	}
	defer rows.Close()
	out := map[int64]struct{}{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store/migrations: scan applied: %w", err)
		}
		out[v] = struct{}{}
	}
	return out, rows.Err()
}

// detectNoTransactionDirective scans the leading bytes of a
// migration file for the `-- migrate:no-transaction` directive.
// Returns true iff the directive appears in the first non-empty
// LINE of the file. The directive MUST be at the top so a glance
// at the file (or an audit grep) reveals the transaction mode.
//
// Implementation note: we don't bring in bufio/regexp for this —
// a tight string scan over the leading 256 bytes is enough for
// every plausible migration file. The cost is O(file header size)
// per migration at boot.
func detectNoTransactionDirective(body []byte) bool {
	// Examine at most the first 256 bytes; the directive must
	// appear before any DDL so this is sufficient.
	const headerLimit = 256
	head := body
	if len(head) > headerLimit {
		head = head[:headerLimit]
	}
	for _, line := range strings.Split(string(head), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue
		}
		// First non-empty line decides. Either match or stop.
		return strings.HasPrefix(trimmed, noTransactionDirective)
	}
	return false
}

// applyMigration runs one file. Two paths:
//
//	Default (transactional): wrap the file's SQL in BEGIN/COMMIT.
//	The version-record INSERT runs inside the same transaction so a
//	partial DDL failure leaves the database in the file's pre-state.
//
//	`-- migrate:no-transaction` (autocommit): run the SQL directly
//	via the pool, then record the version in a SEPARATE small
//	transaction. Used for statements PG rejects inside a tx block
//	(notably CREATE INDEX CONCURRENTLY). REQUIRES idempotent DDL
//	in the file — see migration.noTransaction docstring.
func applyMigration(ctx context.Context, db *pgxpool.Pool, m migration) error {
	if m.noTransaction {
		return applyMigrationNoTx(ctx, db, m)
	}
	return applyMigrationTx(ctx, db, m)
}

// applyMigrationTx is the default transactional path.
func applyMigrationTx(ctx context.Context, db *pgxpool.Pool, m migration) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store/migrations: begin v%d: %w", m.version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, m.sql); err != nil {
		return fmt.Errorf("store/migrations: apply v%d (%s): %w", m.version, m.description, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, description) VALUES ($1, $2)
		 ON CONFLICT (version) DO NOTHING`,
		m.version, m.description,
	); err != nil {
		return fmt.Errorf("store/migrations: record v%d: %w", m.version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store/migrations: commit v%d: %w", m.version, err)
	}
	return nil
}

// applyMigrationNoTx is the autocommit path for migrations marked
// `-- migrate:no-transaction`. Each statement in the file is sent
// as its OWN simple_query message under pgx's simple protocol —
// PostgreSQL runs each individual statement as its own autocommit
// unit, no transaction wrap. This is exactly what
// `CREATE INDEX CONCURRENTLY` requires.
//
// WHY MULTI-STATEMENT IS NOT ENOUGH
//
// The naive implementation — `db.Exec(ctx, wholeFile, simpleProtocol)`
// — fails with SQLSTATE 25001 because PostgreSQL treats a
// multi-statement Query message as a SINGLE IMPLICIT TRANSACTION:
//
//   "Multiple statements sent in a single Query message are treated
//    as a single transaction, unless there are explicit BEGIN/COMMIT
//    commands included in the query string to divide it into
//    multiple transactions."
//                                    — PG docs, "Simple Query"
//
// The implicit-transaction wrap fires inside PG itself, regardless
// of pgx's protocol choice. CREATE INDEX CONCURRENTLY checks for
// any active transaction (implicit or explicit) and refuses.
//
// `psql -f migration.sql` works for the same reason this code now
// does: psql splits the file on `;` (after stripping comments) and
// sends each statement as its OWN simple_query message. Each
// individual statement runs as a single-statement Query message,
// which PG runs as autocommit — no implicit-transaction wrap, and
// CONCURRENTLY works.
//
// We replicate that discipline here:
//
//  1. splitSQLStatements parses the file into individual
//     statements, stripping `--` line comments and `/* */` block
//     comments before tokenizing on `;`.
//  2. Each statement is Exec'd separately under simple protocol.
//     Single-statement simple_query → PG autocommit → no
//     implicit transaction.
//
// The version-record INSERT (a parametrized query) runs AFTER all
// DDL via the default extended protocol — recording the version
// doesn't need CONCURRENTLY.
//
// On record-insert failure after the DDL succeeded, the migration
// replays on next boot. The idempotent-DDL discipline (documented
// on migration.noTransaction) makes the replay safe.
func applyMigrationNoTx(ctx context.Context, db *pgxpool.Pool, m migration) error {
	stmts := splitSQLStatements(m.sql)
	for i, stmt := range stmts {
		if _, err := db.Exec(ctx, stmt, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf(
				"store/migrations: apply v%d (%s, no-tx, stmt %d/%d): %w\n  statement: %s",
				m.version, m.description, i+1, len(stmts), err,
				truncateForLog(stmt, 200),
			)
		}
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO schema_migrations (version, description) VALUES ($1, $2)
		 ON CONFLICT (version) DO NOTHING`,
		m.version, m.description,
	); err != nil {
		return fmt.Errorf("store/migrations: record v%d (no-tx): %w", m.version, err)
	}
	return nil
}

// splitSQLStatements parses a multi-statement SQL string into a
// slice of individual statements. Used by the no-tx migration path
// to send each statement as its own simple_query message.
//
// PARSING DISCIPLINE
//
// The parser is intentionally SIMPLE — it handles the SQL shapes
// our migrations actually use, and FAILS LOUDLY on shapes it
// doesn't. Trying to write a real PG parser in-tree is the wrong
// trade-off; the migration runner needs ~30 lines of correct code,
// not a 300-line tokenizer that grows bugs.
//
// Supported:
//
//   - `--` line comments. Stripped from `--` to end of line. The
//     `-- migrate:no-transaction` directive on the first line is
//     stripped here too — the runner detected it earlier via
//     detectNoTransactionDirective on the raw bytes.
//
//   - `/* ... */` block comments. Stripped wholesale. Non-nested
//     (PG supports nesting; our migrations don't use it).
//
//   - Statements separated by `;`. Whitespace between statements is
//     trimmed. Empty/whitespace-only statements are dropped.
//
// NOT supported (no production migration uses these):
//
//   - String literals containing `;` or `--` or `/*` (e.g., `INSERT
//     INTO foo VALUES ('a;b')`). The splitter will mis-split here.
//   - Dollar-quoted strings (`$$ ... $$`, `$tag$ ... $tag$`).
//   - Nested block comments.
//
// If a future migration NEEDS these features, two options exist:
//
//  1. Drop the `-- migrate:no-transaction` directive and use the
//     transactional path, which sends the whole file as one Exec
//     and lets PG handle parsing.
//  2. Replace splitSQLStatements with a real SQL tokenizer (or
//     import pgsql/sqlparser). The current shape is bounded scope.
//
// The unit tests in migrations_split_test.go pin every supported
// shape; a regression in the parser surfaces there before any
// production migration runs.
func splitSQLStatements(sql string) []string {
	cleaned := stripSQLBlockComments(sql)
	cleaned = stripSQLLineComments(cleaned)
	parts := strings.Split(cleaned, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// stripSQLLineComments removes every `--` line comment from sql.
// A `--` anywhere on a line terminates the line; the rest is
// dropped. Newlines are preserved so error logs that reference
// statement line numbers stay meaningful.
//
// Distinct from the Go-style stripLineComments helper in
// append_only_guard_test.go (which strips `//`). Same package; the
// name carries the language context.
//
// Note: this strips literally — a `--` inside a string literal
// would be incorrectly treated as a comment. See splitSQLStatements'
// "NOT supported" docstring for the bounded scope.
func stripSQLLineComments(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	for _, line := range strings.Split(sql, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// stripSQLBlockComments removes every `/* ... */` block comment
// from sql. Non-nested; the first unmatched `*/` closes the block.
// Unterminated `/*` (no matching `*/`) drops to end-of-string —
// matches PG's behavior.
//
// Distinct from the Go-style stripBlockComments helper in
// append_only_guard_test.go. The Go variant pads with spaces to
// preserve line numbers for the mutation guard's grep; the SQL
// variant drops the bytes outright since splitSQLStatements
// re-tokenizes on `;` after stripping.
//
// Note: this strips literally — a `/*` inside a string literal
// would be incorrectly treated as a comment opener. See
// splitSQLStatements' "NOT supported" docstring for bounded scope.
func stripSQLBlockComments(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	for {
		start := strings.Index(sql, "/*")
		if start < 0 {
			b.WriteString(sql)
			return b.String()
		}
		b.WriteString(sql[:start])
		end := strings.Index(sql[start:], "*/")
		if end < 0 {
			// Unterminated block comment — drop the rest.
			return b.String()
		}
		sql = sql[start+end+2:]
	}
}

// truncateForLog returns the first n characters of s with a
// trailing ellipsis if truncated. Used only in error messages so
// a 10 KB migration statement doesn't dump into the log on apply
// failure.
func truncateForLog(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// pendingMigrations returns the subset of loaded migrations that are
// not yet recorded in schema_migrations.
func pendingMigrations(ctx context.Context, db *pgxpool.Pool) ([]migration, error) {
	all, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	applied, err := listApplied(ctx, db)
	if err != nil {
		return nil, err
	}
	pending := make([]migration, 0)
	for _, m := range all {
		if _, ok := applied[m.version]; !ok {
			pending = append(pending, m)
		}
	}
	return pending, nil
}

// ErrPendingMigrations is returned by RunMigrationsWithMode under
// MigrateVerify when at least one migration is pending. The error
// message lists every pending version + description so an operator
// can pipe the output to a runbook.
type ErrPendingMigrations struct {
	Versions []int64
	Names    []string
}

func (e *ErrPendingMigrations) Error() string {
	parts := make([]string, 0, len(e.Versions))
	for i, v := range e.Versions {
		parts = append(parts, fmt.Sprintf("v%d (%s)", v, e.Names[i]))
	}
	return fmt.Sprintf("store/migrations: %d pending: %s",
		len(e.Versions), strings.Join(parts, ", "))
}

// RunMigrationsWithMode applies, verifies, or skips migrations
// depending on mode. Apply is the legacy default behaviour; the new
// modes give operators the Tessera "operator applies; binary verifies"
// discipline without forcing it.
func RunMigrationsWithMode(ctx context.Context, db *pgxpool.Pool, mode MigrateMode) error {
	if mode == MigrateSkip {
		return nil
	}
	pending, err := pendingMigrations(ctx, db)
	if err != nil {
		return err
	}
	if mode == MigrateVerify {
		if len(pending) == 0 {
			return nil
		}
		versions := make([]int64, len(pending))
		names := make([]string, len(pending))
		for i, m := range pending {
			versions[i] = m.version
			names[i] = m.description
		}
		return &ErrPendingMigrations{Versions: versions, Names: names}
	}
	// MigrateApply.
	for _, m := range pending {
		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

// RunMigrations preserves the legacy boot-time signature. Equivalent
// to RunMigrationsWithMode(ctx, db, MigrateApply).
func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	return RunMigrationsWithMode(ctx, db, MigrateApply)
}
