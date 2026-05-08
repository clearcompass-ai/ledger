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
//	go:embed, applied in order, recorded in schema_migrations.
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
}

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
		out = append(out, migration{version: v, description: desc, sql: string(body)})
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

// applyMigration runs one file in a single transaction. The version
// + description are recorded in schema_migrations as the final
// statement of the transaction so a partial failure leaves the
// database in the file's pre-state.
func applyMigration(ctx context.Context, db *pgxpool.Pool, m migration) error {
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
