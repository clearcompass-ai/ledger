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
// 2) Schema — versioned migrations under store/migrations/
// ─────────────────────────────────────────────────────────────────────────────
//
// The schema lives in numbered SQL files at store/migrations/. The
// applier (store/migrations.go) embeds them via go:embed, applies
// pending versions in order, and records each in schema_migrations.
//
// RunMigrations / RunMigrationsWithMode live in store/migrations.go.
// The historical inline schemaDDL[] array is gone — every change is
// a new numbered file in the migrations directory. See
// store/migrations/README.md for the policy.
//

// ─────────────────────────────────────────────────────────────────────────────
// 3) Advisory Lock — builder exclusivity
// ─────────────────────────────────────────────────────────────────────────────

// BuilderLockID is the Postgres advisory lock key for builder exclusivity.
const BuilderLockID int64 = 0x4F5254484F4C4F47 // "ATTESTA" in hex

// DefaultBuilderLockAcquireTimeout caps how long a fresh boot will
// wait for the advisory lock before failing fast. Administrators on a
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
// 4) Transaction Manager + per-query timeout discipline
// ─────────────────────────────────────────────────────────────────────────────

// DefaultQueryTimeout is the application-side per-query budget
// applied when the caller's ctx has no deadline. Defense-in-depth
// on top of the DB-side `statement_timeout` from F3 (the pgxpool
// AfterConnect hook). Either layer fires first, but having both
// means a runaway query is bounded even if one layer is mis-
// configured.
//
// 5 seconds matches the F3 default (LEDGER_PG_STATEMENT_TIMEOUT).
// Callers that need a tighter budget pass an explicit
// context.WithTimeout into the store function.
const DefaultQueryTimeout = 5 * time.Second

// WithQueryTimeout returns a derived context bounded by
// DefaultQueryTimeout if the input ctx has no deadline. Callers
// that already passed a ctx with a deadline get back the same ctx
// + a no-op cancel. Either way the returned cancel MUST be called
// (use defer immediately).
//
// Use this at the entry of public Store methods so every Postgres
// query is application-side timeout-bounded — even when an HTTP
// handler forgot to set a request budget. The DB-side
// statement_timeout (F3) is still the load-bearing protection;
// this is the application-side belt to F3's suspenders.
func WithQueryTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, DefaultQueryTimeout)
}

// TxFunc is a function executed within a transaction.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTransaction executes fn within a transaction. If the input
// ctx has no deadline, applies DefaultQueryTimeout so every query
// inside fn is bounded — defense-in-depth on the F3 DB-side cap.
func WithTransaction(ctx context.Context, db *pgxpool.Pool, iso pgx.TxIsoLevel, fn TxFunc) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()

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
