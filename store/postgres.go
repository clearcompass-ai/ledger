/*
Package store provides Postgres persistence for the Attesta ledger.

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

SCHEMA:
  - derivation_commitments: SMT-batch derivation pins.
  - commitment_split_id: secondary index from (schema_id, split_id)
    to sequence_number; BTREE (not UNIQUE) so multiple admissions
    at the same key persist as evidence rather than getting rejected
    — equivocation detection requires both rows.
  - Entry-level equivocation evidence lives in the gossipstore
    BadgerDB projection 0x0B; the gossipnet equivocation scanner
    detects + projects + publishes, and FetchEquivocationByBinding
    serves zero-trust reads.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/apitypes"
	"github.com/clearcompass-ai/ledger/lifecycle"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Connection Pools
// ─────────────────────────────────────────────────────────────────────────────

// Pool wraps pgxpool.Pool with ledger lifecycle.
type Pool struct {
	DB *pgxpool.Pool
	cfg PoolConfig
}

// PoolConfig configures the Postgres connection.
type PoolConfig struct {
	DSN string
	MaxConns int32
	MinConns int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration

	// StatementTimeout, when > 0, is applied via the connection-
	// level `SET statement_timeout` so every query through the pool
	// is bounded at the Postgres side. Defense-in-depth on top of
	// per-call-site context.WithTimeout discipline. A misconfigured
	// or runaway query that escapes the application-side budget
	// still gets cancelled by the DB. 0 disables the DB-side cap.
	StatementTimeout time.Duration
}

// InitPool creates and validates the connection pool.
//
// Boot-time pool warmup: after constructing the pool, eagerly opens
// MinConns connections via Acquire/Release so the first
// admission request doesn't pay the TCP+TLS+startup-message
// handshake latency. At MinConns=8 against a same-region Postgres
// instance the warmup is ~50-100 ms total; without it, the
// admission p99 spikes for the first ~30s after boot until the
// pool fills naturally.
func InitPool(ctx context.Context, cfg PoolConfig) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: invalid DSN: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	// Per-statement statement_timeout via the AfterConnect hook so
	// EVERY query through the pool inherits the DB-side bound. This
	// is the load-bearing protection against runaway queries (defense
	// in depth on application-side context.WithTimeout discipline).
	// 0 disables the DB-side bound; the application is then sole
	// authority on per-query budgets.
	if cfg.StatementTimeout > 0 {
		stmt := fmt.Sprintf("SET statement_timeout = %d",
			int64(cfg.StatementTimeout/time.Millisecond))
		poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("store: AfterConnect SET statement_timeout: %w", err)
			}
			return nil
		}
	}

	db, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: pool creation failed: %w", err)
	}

	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: database unreachable: %w", err)
	}

	// Boot-time warmup: pre-establish MinConns connections so
	// admission p99 doesn't spike on the first cold requests.
	// Bounded fan-out (MinConns is small, typically ≤16) and bounded
	// budget (per-acquire ctx applies). Failures at warmup are NOT
	// fatal — the pool stays valid; subsequent acquisitions will
	// reconnect lazily. Log the failure and continue.
	if cfg.MinConns > 0 {
		warmCtx, warmCancel := context.WithTimeout(ctx, 10*time.Second)
		defer warmCancel()
		warmPool(warmCtx, db, int(cfg.MinConns))
	}

	return &Pool{DB: db, cfg: cfg}, nil
}

// warmPool eagerly opens n connections then releases them so the
// pool's idle pool is populated before the first user request.
// Best-effort: errors per-connection are swallowed (pgx logs them
// itself), and a partially-warmed pool is fine — the pool still
// works, the application just pays handshake on the first
// previously-unwarmed slot.
func warmPool(ctx context.Context, db *pgxpool.Pool, n int) {
	conns := make([]*pgxpool.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := db.Acquire(ctx)
		if err != nil {
			break
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.Release()
	}
}

// Close shuts down the pool.
func (p *Pool) Close() { p.DB.Close() }

// Pools holds separate write and read connection pools.
type Pools struct {
	Write *pgxpool.Pool
	Read *pgxpool.Pool
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
		sequence_number BIGINT PRIMARY KEY,
		canonical_hash BYTEA NOT NULL UNIQUE,
		log_time TIMESTAMPTZ NOT NULL,
		signer_did TEXT NOT NULL CHECK (signer_did <> ''),
		target_root BYTEA,
		cosignature_of BYTEA,
		schema_ref BYTEA
	)`,
	`CREATE INDEX IF NOT EXISTS idx_signer_did ON entry_index (signer_did)`,
	`CREATE INDEX IF NOT EXISTS idx_target_root ON entry_index (target_root) WHERE target_root IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_cosignature_of ON entry_index (cosignature_of) WHERE cosignature_of IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_schema_ref ON entry_index (schema_ref) WHERE schema_ref IS NOT NULL`,

	// ── SMT state ────────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS smt_leaves (
		leaf_key BYTEA PRIMARY KEY,
		origin_tip BYTEA NOT NULL,
		authority_tip BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS smt_nodes (
		path_key BYTEA PRIMARY KEY,
		hash BYTEA NOT NULL,
		depth INT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Credits ──────────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS credits (
		exchange_did TEXT PRIMARY KEY,
		balance BIGINT NOT NULL DEFAULT 0,
		total_purchased BIGINT NOT NULL DEFAULT 0,
		total_consumed BIGINT NOT NULL DEFAULT 0,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Tree heads (normalized: one row per attestation) ─────────────
	`CREATE TABLE IF NOT EXISTS tree_heads (
		tree_size BIGINT NOT NULL,
		root_hash BYTEA NOT NULL,
		hash_algo SMALLINT NOT NULL DEFAULT 1,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (tree_size, hash_algo)
	)`,
	`CREATE TABLE IF NOT EXISTS tree_head_sigs (
		tree_size BIGINT NOT NULL,
		hash_algo SMALLINT NOT NULL DEFAULT 1,
		signer TEXT NOT NULL,
		sig_algo SMALLINT NOT NULL,
		signature BYTEA NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (tree_size, hash_algo, signer, sig_algo),
		FOREIGN KEY (tree_size, hash_algo) REFERENCES tree_heads (tree_size, hash_algo)
	)`,

	// ── Delta buffer ─────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS delta_window_buffers (
		leaf_key BYTEA PRIMARY KEY,
		tip_history BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
		id SMALLINT PRIMARY KEY DEFAULT 1
		                                    CONSTRAINT builder_cursor_singleton CHECK (id = 1),
		last_processed_sequence BIGINT NOT NULL DEFAULT 0,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	// Seed the singleton row so SELECT FOR UPDATE always finds
	// something to lock. ON CONFLICT keeps reruns of RunMigrations
	// safe — the row may already exist from a prior boot.
	`INSERT INTO builder_cursor (id, last_processed_sequence)
	 VALUES (1, 0)
	 ON CONFLICT (id) DO NOTHING`,

	// ── Witness sets ─────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS witness_sets (
		version SERIAL PRIMARY KEY,
		set_hash BYTEA NOT NULL,
		keys_json BYTEA NOT NULL,
		scheme_tag SMALLINT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Equivocation proofs (tree-head fork) ────────────────────────
	`CREATE TABLE IF NOT EXISTS equivocation_proofs (
		id SERIAL PRIMARY KEY,
		head_a BYTEA NOT NULL,
		head_b BYTEA NOT NULL,
		tree_size BIGINT NOT NULL,
		detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Sessions ─────────────────────────────────────────────────────
	`CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		exchange_did TEXT NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// ── Derivation commitments (fraud proof lookup index) ────────────
	// Post-commit persistence: crash between atomic commit and this
	// insert loses the row. Acceptable — reconstructable from entries.
	// See store/derivation_commitments.go for full crash recovery
	// semantics.
	`CREATE TABLE IF NOT EXISTS derivation_commitments (
		id SERIAL PRIMARY KEY,
		range_start_seq BIGINT NOT NULL,
		range_end_seq BIGINT NOT NULL,
		prior_smt_root BYTEA NOT NULL,
		post_smt_root BYTEA NOT NULL,
		mutations_json BYTEA NOT NULL,
		commentary_seq BIGINT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_commitment_range
		ON derivation_commitments (range_start_seq, range_end_seq)`,

	// ── Commitment SplitID index ───────────────────────────────────
	// Maps the 32-byte SplitID embedded in pre-grant-commitment-v1 and
	// escrow-split-commitment-v1 entry payloads to the entry's sequence
	// number, enabling the SDK lookup primitives FetchPREGrantCommitment
	// and FetchEscrowSplitCommitment.
	//
	// Equivocation evidence preservation: the (schema_id, split_id)
	// index is BTREE, NOT UNIQUE. A malicious dealer publishing two
	// distinct commitment entries under the same SplitID produces two
	// rows here under the same key tuple; both MUST persist so the SDK
	// can return *CommitmentEquivocationError to verifiers. Rejecting
	// the second row on a UNIQUE constraint would silently destroy the
	// cryptographic evidence the SDK's equivocation detection depends on.
	//
	// PRIMARY KEY on sequence_number is correct — two equivocating
	// entries have distinct sequence numbers (each has its own admission)
	// and the (schema_id, split_id) tuple is the lookup key, not the
	// uniqueness key.
	`CREATE TABLE IF NOT EXISTS commitment_split_id (
		sequence_number BIGINT NOT NULL,
		schema_id TEXT NOT NULL,
		split_id BYTEA NOT NULL,
		PRIMARY KEY (sequence_number),
		FOREIGN KEY (sequence_number) REFERENCES entry_index (sequence_number)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_commitment_split_id
		ON commitment_split_id (schema_id, split_id)`,

	// Equivocation evidence persistence lives in the gossipstore
	// BadgerDB projection (prefix 0x0B). Detection runs in
	// gossipnet.EquivocationScanner (independent goroutine subscribed
	// to the splitid index 0x0A); verified findings are persisted as
	// KindEntryCommitmentEquivocation gossip events + projected to
	// 0x0B for O(1) /by-binding lookup. No Postgres surface owns
	// equivocation evidence
	// anymore.

	// Sequence numbers are assigned by the embedded Tessera library
	// (the c2sp.org/tlog-tiles integrator), not by Postgres. The
	// entry_sequence SEQUENCE that lived here in v1 was dropped in
	// the WAL-first admission migration: admission now blocks on
	// wal.Submit (durable bytes), then tessera.AppendLeaf (Tessera-
	// assigned seq), then INSERTs the resulting (seq, hash, ...) row
	// into entry_index. Postgres only records what Tessera already
	// committed to.
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
const BuilderLockID int64 = 0x4F5254484F4C4F47 // "ATTESTA" in hex

// DefaultBuilderLockAcquireTimeout caps how long a fresh boot will
// wait for the advisory lock before failing fast. Operators on a
// rolling-update should see the new pod fail within this budget if
// the previous pod still holds the lock — it surfaces the rolling-
// update misconfiguration immediately instead of letting the new
// pod hang.
const DefaultBuilderLockAcquireTimeout = 30 * time.Second

// DefaultBuilderLockHeartbeatInterval is how often the heartbeat
// goroutine pings the holding connection. Every 10 s is a good
// balance: long enough to be cheap (one round-trip per check),
// short enough to detect a stale lock within a single readiness-
// probe window.
const DefaultBuilderLockHeartbeatInterval = 10 * time.Second

// ErrAdvisoryLockLost surfaces from the heartbeat when the holding
// connection's liveness check fails — the connection was killed
// (TCP reaper, server restart, network partition) and the lock has
// auto-released. The supervisor MUST treat this as fatal and exit
// so the orchestrator restarts the pod, which then either re-
// acquires the lock or refuses to boot if another pod claimed it.
var ErrAdvisoryLockLost = errors.New("store: builder advisory lock lost")

// BuilderLock holds the Postgres advisory lock that gates writer
// exclusivity. Acquire wires a heartbeat goroutine that surfaces
// ErrAdvisoryLockLost via fatalCh on connection-liveness failure.
type BuilderLock struct {
	conn   *pgxpool.Conn
	cancel context.CancelFunc // stops the heartbeat goroutine on Release
	done   chan struct{}
}

// AcquireBuilderLock takes the advisory lock with a bounded
// timeout, then spawns a heartbeat goroutine that surfaces
// ErrAdvisoryLockLost via fatalCh if the holding connection dies.
//
// fatalCh and logger are required (nil fatalCh means "I'll
// catch the loss but won't surface it" — usable in tests but a
// production misconfig). Production callers MUST pass the
// supervisor's fatal channel.
func AcquireBuilderLock(
	ctx context.Context,
	db *pgxpool.Pool,
	fatalCh chan<- error,
	logger *slog.Logger,
) (*BuilderLock, error) {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquiring connection for builder lock: %w", err)
	}

	// Bounded acquisition: rolling-update with the previous pod
	// still alive should surface a clean error within
	// DefaultBuilderLockAcquireTimeout instead of hanging forever.
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, DefaultBuilderLockAcquireTimeout)
	defer cancelAcquire()
	_, err = conn.Exec(acquireCtx, "SELECT pg_advisory_lock($1)", BuilderLockID)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("store: advisory lock failed within %s "+
			"(another writer may hold the lock — check rolling-update or zombie pod): %w",
			DefaultBuilderLockAcquireTimeout, err)
	}

	hbCtx, hbCancel := context.WithCancel(ctx)
	bl := &BuilderLock{
		conn:   conn,
		cancel: hbCancel,
		done:   make(chan struct{}),
	}

	// Heartbeat goroutine. Wrapped in lifecycle.SafeRun so a panic
	// surfaces via fatalCh too — same supervisor signal as a lock
	// loss. The goroutine ALWAYS closes bl.done on exit so Release
	// can wait deterministically.
	go func() {
		defer close(bl.done)
		_ = lifecycle.SafeRun(hbCtx, "builder-lock-heartbeat", logger, fatalCh, func() error {
			bl.heartbeatLoop(hbCtx, fatalCh, logger)
			return nil
		})
	}()

	return bl, nil
}

// Release unlocks the advisory lock and stops the heartbeat. Safe
// to call once. Idempotent on connection error — a connection
// that's already dead has already released the lock server-side.
func (bl *BuilderLock) Release() {
	if bl == nil || bl.conn == nil {
		return
	}
	bl.cancel()
	<-bl.done
	// Best-effort unlock. Use background ctx because the parent
	// ctx is likely already cancelled at shutdown.
	relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = bl.conn.Exec(relCtx, "SELECT pg_advisory_unlock($1)", BuilderLockID)
	bl.conn.Release()
	bl.conn = nil
}

// heartbeatLoop periodically pings the holding connection. A
// failed ping means the connection is dead, which means the
// advisory lock has been auto-released server-side. We surface
// ErrAdvisoryLockLost via fatalCh so the supervisor exits.
func (bl *BuilderLock) heartbeatLoop(
	ctx context.Context,
	fatalCh chan<- error,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(DefaultBuilderLockHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			var x int
			err := bl.conn.QueryRow(pingCtx, "SELECT 1").Scan(&x)
			cancel()
			if err == nil {
				continue
			}
			// Liveness failed → lock is gone. Don't try to
			// re-acquire here — the supervisor will exit the
			// process and the orchestrator will restart it; the
			// new pod will go through a clean Acquire path with
			// the bounded timeout above.
			if logger != nil {
				logger.ErrorContext(ctx,
					"builder advisory lock heartbeat failed; lock presumed lost",
					"error", err)
			}
			if fatalCh != nil {
				select {
				case fatalCh <- fmt.Errorf("%w: ping failed: %v", ErrAdvisoryLockLost, err):
				default:
				}
			}
			return
		}
	}
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

// ErrInsufficientCredits signals balance = 0. Lives in apitypes/
// so api/ can errors.Is against it without importing store/
// (— Pure CQRS). Re-exported here for backwards compatibility
// with existing in-package call sites + integration tests.
var ErrInsufficientCredits = apitypes.ErrInsufficientCredits

// ErrDuplicateEntry signals a UNIQUE constraint violation on canonical_hash.
var ErrDuplicateEntry = fmt.Errorf("store/entries: duplicate entry")
