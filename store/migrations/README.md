# Schema migrations

Versioned SQL files. No migration framework, no DSL — just numbered
`*.sql` files applied in order at boot.

## Files

```
0001_initial.sql        Initial schema (everything from the historical schemaDDL[])
000N_<description>.sql  Each subsequent change
```

Filenames MUST match `^\d+_[a-z0-9_]+\.sql$`. The 4-digit prefix is
parsed as the version number; the rest is recorded as the description
in `schema_migrations`.

## Discipline

| Allowed | Forbidden |
|---|---|
| `CREATE TABLE IF NOT EXISTS …` | `DROP TABLE …` |
| `CREATE INDEX IF NOT EXISTS …` | `DROP INDEX …` |
| `ALTER TABLE … ADD COLUMN IF NOT EXISTS …` | `ALTER TABLE … DROP COLUMN …` |
| `ALTER TABLE … ALTER COLUMN … SET DEFAULT …` | `ALTER TABLE … RENAME COLUMN …` |
| `INSERT INTO … ON CONFLICT DO NOTHING` | `UPDATE` / `DELETE` of pre-existing rows |
| New tables, new columns, new indexes | Anything destructive or renaming |

The transparency log is **append-only**. Schema must be too. A column
that's no longer used is left in place — it costs a few bytes per row
and a query that ignores it. Renaming a column risks breaking
in-flight rolling deploys; add the new column and dual-write instead.

## Applying

The applier is `store/migrations.go`. Three modes selected by
`LEDGER_DB_MIGRATE_MODE`:

| Mode | Behaviour |
|---|---|
| `apply` (default) | Apply pending migrations, then start. |
| `verify` | Fail at boot if any migration is pending; list them in the error log. |
| `skip` | Touch nothing. Caller asserts an out-of-band apply has run. |

## Adding a migration

1. Pick the next number: `ls store/migrations/` and add 1.
2. Create `store/migrations/000N_descriptive_name.sql`.
3. Use `IF NOT EXISTS` everywhere — re-runs must be idempotent.
4. Each statement runs inside a single transaction the applier wraps
   around the whole file. Group related changes in one file.
5. Update `tests/soak_test.go::assertEntryIndexSchema` if the change
   touches any column the soak verifies.
6. Run the integration tests against a fresh DSN:
   `ATTESTA_TEST_DSN=… go test -count=1 ./store/...`.

## Rollback

There isn't one. Forward-only. To undo a column add: write a new
migration that nulls / ignores it; never delete it from the schema.
This is the same discipline transparency-log software (Trillian,
Tessera, Boulder) uses — destructive rollbacks against an append-only
log are a foot-gun, not a feature.

## Operator workflow examples

**Default — laptop / dev / CI:**
```
LEDGER_DB_MIGRATE_MODE=apply ./ledger    # or unset; same default
```

**Production with out-of-band SQL apply:**
```
# 1. ops applies migrations manually:
psql "$DSN" -f store/migrations/0001_initial.sql
psql "$DSN" -f store/migrations/0002_add_foo.sql
# 2. binary verifies on boot:
LEDGER_DB_MIGRATE_MODE=verify ./ledger
```

**Cluster upgrade with pre-flight verify:**
```
# Init container:
LEDGER_DB_MIGRATE_MODE=verify ./ledger || ./apply-migrations.sh
# Main container:
LEDGER_DB_MIGRATE_MODE=skip ./ledger
```
