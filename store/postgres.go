/*
Package store provides Postgres persistence for the Ortholog operator.

FILE PATH: store/postgres.go

Connection pool, embedded DDL migrations, transaction manager, and advisory
locking for builder exclusivity. Single source of truth for the database schema.

KEY ARCHITECTURAL DECISIONS:
  - pgxpool for connection pooling: native Postgres wire protocol, no CGo.
  - Migrations embedded as Go constants: single-binary deployment.
  - Advisory lock prevents concurrent builder instances per log.
  - All schema changes additive (new tables/columns only).

INVARIANTS:
  - BuilderLockID ensures exactly one builder per database.
  - Migrations are idempotent and ordered.
  - WithTransaction uses Serializable for builder commits, ReadCommitted
    for admission (configurable via TxOptions parameter).

CHANGES:
  - v0.3.0-tessera: Added derivation_commitments table + index.
  - v7.75 Wave 1 (C3): Added commitment_split_id table + index for
    cryptographic-commitment lookup; BTREE not UNIQUE per Decision 3
    (equivocation evidence preservation).
  - v7.75 Wave 1 (S2): Added commitment_equivocation_proofs table for
    persisting cryptographic evidence of dealer equivocation
    (multiple commitment entries under one SplitID, ADR-005 §3).
*/
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Connection Pools
// ─────────────────────────────────────────────────────────────────────────────

// Pool wraps pgxpool.Pool with operator lifecycle.
type Pool struct {
	DB  *pgxpool.Pool
	cfg PoolConfig
}

// PoolConfig configures the Postgres connection.
type PoolConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// InitPool creates and validates the connection pool.
func InitPool(ctx context.Context, cfg PoolConfig) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: invalid DSN: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	db, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: pool creation failed: %w", err)
	}

	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: database unreachable: %w", err)
	}

	return &Pool{DB: db, cfg: cfg}, nil
}

// Close shuts down the pool.
func (p *Pool) Close() { p.DB.Close() }

// Pools holds separate write and read connection pools.
type Pools struct {
	Write *pgxpool.Pool
	Read  *pgxpool.Pool
}

// InitPools creates write and read pools.
func InitPools(ctx context.Context, writeCfg PoolConfig, replicaDSN string) (*Pools, error) {
	writePool, err := InitPool(ctx, writeCfg)
	if err != nil {
		return nil, fmt.Errorf("store: write pool: %w", err)
	}

	if replicaDSN == "" {
		return &Pools{Write: writePool.DB, Read: writePool.DB}, nil
	}

	readCfg := writeCfg
	readCfg.DSN = replicaDSN
	readPool, err := InitPool(ctx, readCfg)
	if err != nil {
		writePool.Close()
		return nil, fmt.Errorf("store: read pool (replica): %w", err)
	}

	return &Pools{Write: writePool.DB, Read: readPool.DB}, nil
}

// Close shuts down both pools.
func (p *Pools) Close() {
	if p.Read != nil && p.Read != p.Write {
		p.Read.Close()
	}
	if p.Write != nil {
		p.Write.Close()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Schema — single idempotent DDL, no versioned migrations
// ─────────────────────────────────────────────────────────────────────────────

var schemaDDL = []string{
	// ── Entry index (Postgres is an index, not byte storage) ──────────
	`CREATE TABLE IF NOT EXISTS entry_index (
		sequence_number  BIGINT       PRIMARY KEY,
		canonical_hash   BYTEA        NOT NULL UNIQUE,
		log_time         TIMESTAMPTZ  NOT NULL,
		signer_did       TEXT         NOT NULL CHECK (signer_did <> ''),
		target_root      BYTEA,
		cosignature_of   BYTEA,
		schema_ref       BYTEA
	)`,
	`CREATE INDEX IF NOT EXISTS idx_signer_did ON entry_index (signer_did)`,
	`CREATE INDEX IF NOT EXISTS idx_target_root ON entry_index (target_root) WHERE target_root IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_cosignature_of ON entry_index (cosignature_of) WHERE cosignature_of IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_schema_ref ON entry_index (schema_ref) WHERE schema_ref IS NOT NULL`,

	// ── SMT state ────────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS smt_leaves (
		leaf_key      BYTEA    PRIMARY KEY,
		origin_tip    BYTEA    NOT NULL,
		authority_tip BYTEA    NOT NULL,
		updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS smt_nodes (
		path_key   BYTEA    PRIMARY KEY,
		hash       BYTEA    NOT NULL,
		depth      INT      NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Credits ──────────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS credits (
		exchange_did    TEXT    PRIMARY KEY,
		balance         BIGINT NOT NULL DEFAULT 0,
		total_purchased BIGINT NOT NULL DEFAULT 0,
		total_consumed  BIGINT NOT NULL DEFAULT 0,
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Tree heads (normalized: one row per attestation) ─────────────
	`CREATE TABLE IF NOT EXISTS tree_heads (
		tree_size    BIGINT      NOT NULL,
		root_hash    BYTEA       NOT NULL,
		hash_algo    SMALLINT    NOT NULL DEFAULT 1,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (tree_size, hash_algo)
	)`,
	`CREATE TABLE IF NOT EXISTS tree_head_sigs (
		tree_size    BIGINT      NOT NULL,
		hash_algo    SMALLINT    NOT NULL DEFAULT 1,
		signer       TEXT        NOT NULL,
		sig_algo     SMALLINT    NOT NULL,
		signature    BYTEA       NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (tree_size, hash_algo, signer, sig_algo),
		FOREIGN KEY (tree_size, hash_algo) REFERENCES tree_heads (tree_size, hash_algo)
	)`,

	// ── Delta buffer ─────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS delta_window_buffers (
		leaf_key    BYTEA   PRIMARY KEY,
		tip_history BYTEA   NOT NULL,
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Builder cursor (CT-native log-tailing follower) ──────────────
	//
	// One-row table holding the highest sequence number the builder
	// has fully processed. The cursor reader (builder/cursor_reader.go)
	// tails entry_index by sequence_number > cursor. Admission writes
	// only entry_index — the log itself is the queue.
	//
	// At 10B+ scale this avoids per-entry MVCC thrash entirely:
	// cursor mutation is a single-row UPDATE per builder batch inside
	// the builder's atomic commit transaction, so dead-tuple
	// pressure is bounded by batches/sec, not entries/sec.
	//
	// id = 1 invariant: the table holds exactly one row, primary
	// key fixed at 1. INSERT...ON CONFLICT(id) DO NOTHING keeps it
	// idempotent on bootstrap.
	`CREATE TABLE IF NOT EXISTS builder_cursor (
		id                      SMALLINT    PRIMARY KEY DEFAULT 1
		                                    CONSTRAINT builder_cursor_singleton CHECK (id = 1),
		last_processed_sequence BIGINT      NOT NULL DEFAULT 0,
		updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	// Seed the singleton row so SELECT FOR UPDATE always finds
	// something to lock. ON CONFLICT keeps reruns of RunMigrations
	// safe — the row may already exist from a prior boot.
	`INSERT INTO builder_cursor (id, last_processed_sequence)
	 VALUES (1, 0)
	 ON CONFLICT (id) DO NOTHING`,

	// ── Witness sets ─────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS witness_sets (
		version     SERIAL   PRIMARY KEY,
		set_hash    BYTEA    NOT NULL,
		keys_json   BYTEA    NOT NULL,
		scheme_tag  SMALLINT NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Equivocation proofs (tree-head fork; v0.3.0-tessera) ────────
	`CREATE TABLE IF NOT EXISTS equivocation_proofs (
		id         SERIAL      PRIMARY KEY,
		head_a     BYTEA       NOT NULL,
		head_b     BYTEA       NOT NULL,
		tree_size  BIGINT      NOT NULL,
		detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Sessions ─────────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS sessions (
		token       TEXT        PRIMARY KEY,
		exchange_did TEXT       NOT NULL,
		expires_at  TIMESTAMPTZ NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Derivation commitments (fraud proof lookup index) ────────────
	// Post-commit persistence: crash between atomic commit and this
	// insert loses the row. Acceptable — reconstructable from entries.
	// See store/derivation_commitments.go for full crash recovery
	// semantics.
	`CREATE TABLE IF NOT EXISTS derivation_commitments (
		id              SERIAL      PRIMARY KEY,
		range_start_seq BIGINT      NOT NULL,
		range_end_seq   BIGINT      NOT NULL,
		prior_smt_root  BYTEA       NOT NULL,
		post_smt_root   BYTEA       NOT NULL,
		mutations_json  BYTEA       NOT NULL,
		commentary_seq  BIGINT,
		created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_commitment_range
		ON derivation_commitments (range_start_seq, range_end_seq)`,

	// ── Commitment SplitID index (v7.75 — Wave 1 C3) ─────────────────
	// Maps the 32-byte SplitID embedded in pre-grant-commitment-v1 and
	// escrow-split-commitment-v1 entry payloads to the entry's sequence
	// number, enabling the SDK lookup primitives FetchPREGrantCommitment
	// and FetchEscrowSplitCommitment per ADR-005 §6.2.
	//
	// Equivocation evidence preservation (Wave 1 v3 Decision 3): the
	// (schema_id, split_id) index is BTREE, NOT UNIQUE. A malicious
	// dealer publishing two distinct commitment entries under the same
	// SplitID produces two rows here under the same key tuple; both
	// MUST persist so the SDK can return *CommitmentEquivocationError
	// to verifiers. Rejecting the second row on a UNIQUE constraint
	// would silently destroy the cryptographic evidence the SDK's
	// equivocation detection depends on.
	//
	// PRIMARY KEY on sequence_number is correct — two equivocating
	// entries have distinct sequence numbers (each has its own admission)
	// and the (schema_id, split_id) tuple is the lookup key, not the
	// uniqueness key.
	`CREATE TABLE IF NOT EXISTS commitment_split_id (
		sequence_number BIGINT NOT NULL,
		schema_id       TEXT   NOT NULL,
		split_id        BYTEA  NOT NULL,
		PRIMARY KEY (sequence_number),
		FOREIGN KEY (sequence_number) REFERENCES entry_index (sequence_number)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_commitment_split_id
		ON commitment_split_id (schema_id, split_id)`,

	// ── Commitment equivocation proofs (v7.75 — Wave 1 S2) ───────────
	// Persists cryptographic evidence of dealer equivocation: when
	// two or more pre-grant-commitment-v1 or escrow-split-commitment-v1
	// entries are admitted under the same (schema_id, split_id) tuple,
	// the witness/commitment_equivocation_monitor.go background loop
	// detects the collision via the commitment_split_id index and
	// records evidence here for downstream governance action
	// (ADR-005 §3 + Wave 1 v3 §S2).
	//
	// Schema rationale:
	//
	//   - One row per (schema_id, split_id) incident. The UNIQUE
	//     constraint makes the upsert pattern safe: when a 3rd or 4th
	//     equivocating entry shows up, the monitor uses
	//     ON CONFLICT (schema_id, split_id) DO UPDATE to append the
	//     new sequence to entry_seqs rather than inserting a duplicate
	//     evidence row.
	//
	//   - entry_seqs is a Postgres BIGINT[] holding every sequence
	//     number that has been seen under this SplitID. Encoded as
	//     a typed array so order and uniqueness can be enforced at
	//     the application layer without splitting the row.
	//
	//   - first_detected_at / last_observed_at distinguish "when the
	//     monitor first noticed equivocation" from "when the most
	//     recent equivocating entry landed", supporting forensics
	//     across long-lived incidents.
	//
	//   - alert_dispatched_at is nullable — set by the S3 alert
	//     callback when the webhook publication succeeds, so the
	//     S3 publisher can be re-run safely (alerted incidents
	//     skip republishing) and operators can audit which incidents
	//     have been escalated to governance.
	//
	// Append-only invariant: rows are NEVER deleted. Equivocation
	// evidence is permanent — even after governance resolution, the
	// historical record stays so future audits can reconstruct what
	// the operator observed.
	`CREATE TABLE IF NOT EXISTS commitment_equivocation_proofs (
		id                  SERIAL      PRIMARY KEY,
		schema_id           TEXT        NOT NULL,
		split_id            BYTEA       NOT NULL,
		entry_seqs          BIGINT[]    NOT NULL,
		first_detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_observed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		alert_dispatched_at TIMESTAMPTZ,
		UNIQUE (schema_id, split_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_commitment_equivocation_unalerted
		ON commitment_equivocation_proofs (first_detected_at)
		WHERE alert_dispatched_at IS NULL`,

	// ── Sequence ─────────────────────────────────────────────────────
	`CREATE SEQUENCE IF NOT EXISTS entry_sequence START 1 NO CYCLE`,
}

// RunMigrations creates the schema. Fully idempotent.
func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	for i, stmt := range schemaDDL {
		if _, err := db.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store: schema stmt %d failed: %w", i, err)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Advisory Lock — builder exclusivity
// ─────────────────────────────────────────────────────────────────────────────

// BuilderLockID is the Postgres advisory lock key for builder exclusivity.
const BuilderLockID int64 = 0x4F5254484F4C4F47 // "ORTHOLOG" in hex

// AcquireBuilderLock takes the advisory lock.
func AcquireBuilderLock(ctx context.Context, db *pgxpool.Pool) (release func(), err error) {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquiring connection for builder lock: %w", err)
	}
	_, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", BuilderLockID)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("store: advisory lock failed: %w", err)
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", BuilderLockID)
		conn.Release()
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Transaction Manager
// ─────────────────────────────────────────────────────────────────────────────

// TxFunc is a function executed within a transaction.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTransaction executes fn within a transaction.
func WithTransaction(ctx context.Context, db *pgxpool.Pool, iso pgx.TxIsoLevel, fn TxFunc) error {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}

	if err := fn(ctx, tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("store: tx error: %w (rollback also failed: %v)", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit tx: %w", err)
	}
	return nil
}

// WithSerializableTx is a convenience for Serializable isolation.
func WithSerializableTx(ctx context.Context, db *pgxpool.Pool, fn TxFunc) error {
	return WithTransaction(ctx, db, pgx.Serializable, fn)
}

// WithReadCommittedTx is a convenience for ReadCommitted isolation.
func WithReadCommittedTx(ctx context.Context, db *pgxpool.Pool, fn TxFunc) error {
	return WithTransaction(ctx, db, pgx.ReadCommitted, fn)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Errors
// ─────────────────────────────────────────────────────────────────────────────

// ErrInsufficientCredits signals balance = 0.
var ErrInsufficientCredits = fmt.Errorf("store/credits: insufficient credits")

// ErrDuplicateEntry signals a UNIQUE constraint violation on canonical_hash.
var ErrDuplicateEntry = fmt.Errorf("store/entries: duplicate entry")
