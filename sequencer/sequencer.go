/*
FILE PATH: sequencer/sequencer.go

Sequencer — the asynchronous pipeline worker that drains
StatePending entries from the WAL into Tessera + Postgres
entry_index. The companion to the Shipper:

  Shipper:    StateSequenced → bytestore.WriteEntry → StateShipped
  Sequencer:  StatePending   → tessera.AppendLeaf  → StateSequenced

Together they keep entries flowing from "durable in WAL" all the
way through to "served via 302 redirect" without blocking the
HTTP admission path.

ROLE IN THE SCT/MMD ARCHITECTURE:

  POST /v1/entries returns a SignedCertificateTimestamp (SCT)
  immediately after wal.Submit fsync. The Sequencer is what
  redeems that promise — it pulls each pending entry, calls
  tessera.AppendLeaf (antispam-idempotent), INSERTs the
  metadata into entry_index, and transitions the WAL state to
  Sequenced. The Maximum Merge Delay (OPERATOR_MMD, default 24h)
  is the SLA on Sequencer drain latency.

WHY A SEPARATE PACKAGE:

  - Pipeline shape mirrors shipper/. Symmetric APIs, symmetric
    metrics, symmetric supervisor wiring.
  - Boot recovery: on restart, the Sequencer's first drain catches
    every entry left in StatePending — replacing the deleted
    integrity.Reasserter.
  - Single writer to Postgres entry_index. v1 admission used to
    INSERT inline; with the SCT/MMD model the v1 handler is now
    a polling facade and the Sequencer is the sole inserter.
    Eliminates the UNIQUE-on-canonical_hash race.

INTERFACES:

  WAL          — minimal surface needed for drain (IterateInflight,
                 Read, MetaState, Sequence, MarkRetry, MarkManual).
                 *wal.Committer satisfies it.
  Tessera      — AppendLeaf only. *tessera.EmbeddedAppender's
                 backend satisfies it.
  EntryInserter — INSERTs the entry_index row inside a Postgres
                 transaction. *store.EntryStore satisfies it.

CONFIG:

  PollInterval  — drain wakeup cadence (default 1s, override via
                  OPERATOR_SEQUENCER_INTERVAL).
  MaxInFlight   — bounded concurrency for per-entry processing
                  (default 4, override via
                  OPERATOR_SEQUENCER_MAX_INFLIGHT).
  MaxAttempts   — per-entry retry cap before transition to
                  StateManual (default 10).
  BackoffBase   — initial backoff between retries (default 1s).
  BackoffMax    — backoff ceiling (default 60s).

The drain itself lives in loop.go.
*/
package sequencer

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/wal"
)

// WAL is the minimal WAL surface the Sequencer depends on.
// *wal.Committer satisfies this structurally.
type WAL interface {
	IterateInflight(ctx context.Context, fn func(wal.PendingHash) error) error
	Read(ctx context.Context, hash [32]byte) ([]byte, error)
	MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error)
	Sequence(ctx context.Context, hash [32]byte, seq uint64) error
	MarkRetry(ctx context.Context, hash [32]byte) error
	MarkManual(ctx context.Context, hash [32]byte) error
}

// Tessera is the append-side surface. The integration backend on
// *tessera.EmbeddedAppender satisfies this; tests inject fakes.
type Tessera interface {
	AppendLeaf(data []byte) (uint64, error)
}

// Config tunes Sequencer behaviour. Zero-valued fields fall back
// to package defaults.
type Config struct {
	PollInterval time.Duration
	MaxInFlight  int
	MaxAttempts  uint32
	BackoffBase  time.Duration
	BackoffMax   time.Duration
	Logger       *slog.Logger
}

// Defaults applied to a zero-valued Config.
const (
	DefaultPollInterval = 1 * time.Second
	DefaultMaxInFlight  = 4
	DefaultMaxAttempts  = 10
	DefaultBackoffBase  = 1 * time.Second
	DefaultBackoffMax   = 60 * time.Second
)

// Metrics is the atomic counter snapshot the supervisor scrapes.
// Concurrency-safe: every field is touched only via sync/atomic.
type Metrics struct {
	drainCycles  atomic.Uint64
	processed    atomic.Uint64
	failures     atomic.Uint64
	manualCount  atomic.Uint64
	currentLag   atomic.Int64 // pending entries observed at last drain
}

// MetricsSnapshot is a non-atomic view for callers (Prometheus
// exposition, log lines).
type MetricsSnapshot struct {
	DrainCycles uint64
	Processed   uint64
	Failures    uint64
	ManualCount uint64
	CurrentLag  int64
}

// Snapshot returns a non-atomic copy of the current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		DrainCycles: m.drainCycles.Load(),
		Processed:   m.processed.Load(),
		Failures:    m.failures.Load(),
		ManualCount: m.manualCount.Load(),
		CurrentLag:  m.currentLag.Load(),
	}
}

// SplitIDIndexWriter is the operator-internal hook the
// Sequencer invokes after a successful Phase 2 commit to
// populate the splitid index (Badger prefix 0x0A) — the
// gossipnet.EquivocationScanner subscribes to this index and
// detects collisions on the same (schema_id, split_id) tuple.
//
// nil receiver is allowed: when no writer is wired, the
// Sequencer skips the splitid write entirely (test mode + the
// transitional state where gossip is disabled). The Postgres
// commitment_split_id INSERT is unaffected; only the Badger
// index population is gated.
type SplitIDIndexWriter interface {
	WriteSplitIDIndexEntry(
		ctx context.Context,
		schemaID string,
		splitID [32]byte,
		seq uint64,
		entry SplitIDIndexEntry,
	) error
}

// SplitIDIndexEntry mirrors gossipstore.SplitIDIndexEntry —
// the value side of one splitid index row. Defined here so the
// sequencer doesn't import gossipstore (the dependency arrow
// is sequencer → gossipstore via main.go's wiring, not via
// type imports).
type SplitIDIndexEntry struct {
	EquivocatorDID string
	CanonicalHash  [32]byte
	SigBytes       []byte
}

// Sequencer is the WAL → Tessera → entry_index pipeline worker.
type Sequencer struct {
	wal          WAL
	tessera      Tessera
	db           *pgxpool.Pool
	store        *store.EntryStore
	splitIDIndex SplitIDIndexWriter
	cfg          Config
	logger       *slog.Logger

	metrics Metrics

	// attempts tracks per-hash retry counts in memory across
	// drain cycles. On crash + restart the counter resets to 0
	// — acceptable, MaxAttempts is a soft ceiling not a hard
	// guarantee against retry storms.
	attemptsMu sync.Mutex
	attempts   map[[32]byte]uint32
}

// NewSequencer wires the Sequencer with normalized config.
// All four dependencies are required; pass nils only in tests
// that drive a single drain cycle deterministically.
func NewSequencer(
	w WAL,
	t Tessera,
	db *pgxpool.Pool,
	es *store.EntryStore,
	cfg Config,
) *Sequencer {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = DefaultMaxInFlight
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = DefaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Sequencer{
		wal:      w,
		tessera:  t,
		db:       db,
		store:    es,
		cfg:      cfg,
		logger:   cfg.Logger,
		attempts: make(map[[32]byte]uint32),
	}
}

// WithSplitIDIndex wires the gossipstore-backed splitid index
// writer. Optional; called once at startup by cmd/operator/main.go
// after the gossipstore is constructed. When nil, the Sequencer
// runs without the splitid write.
//
// Returns the receiver for fluent wiring. Idempotent against a
// nil writer. Race-free against drain cycles only when called
// before Run starts; the v0.9.6 wiring respects that.
func (s *Sequencer) WithSplitIDIndex(w SplitIDIndexWriter) *Sequencer {
	s.splitIDIndex = w
	return s
}

// Metrics returns a snapshot of the Sequencer's atomic counters.
// Safe to call concurrently with Run.
func (s *Sequencer) Metrics() MetricsSnapshot {
	return s.metrics.Snapshot()
}

// Run starts the pipeline and blocks until ctx is cancelled.
//
// Boot drain: the first cycle catches every entry left in
// StatePending across operator restarts. There is no separate
// "Reconcile" entry point — the polling loop IS the
// reconciliation, and on a quiet log it idles cheaply.
//
// Returns ctx.Err() on graceful shutdown.
func (s *Sequencer) Run(ctx context.Context) error {
	if s.wal == nil || s.tessera == nil {
		return errors.New("sequencer: WAL and Tessera both required")
	}

	// First drain immediately on Run start so a freshly-booted
	// operator picks up crash-recovered entries before the first
	// tick. The PollInterval gates only steady-state pacing.
	s.drainOnce(ctx)

	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.drainOnce(ctx)
		}
	}
}

// recordAttempt increments the per-hash attempt counter and
// returns the new value. Used by the drain loop to decide
// retry-vs-manual.
func (s *Sequencer) recordAttempt(hash [32]byte) uint32 {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	s.attempts[hash]++
	return s.attempts[hash]
}

// resetAttempts clears the in-memory retry counter for a hash.
// Called after successful processing.
func (s *Sequencer) resetAttempts(hash [32]byte) {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	delete(s.attempts, hash)
}

