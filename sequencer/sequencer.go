/*
FILE PATH: sequencer/sequencer.go

Sequencer — the asynchronous pipeline worker that drains
StatePending entries from the WAL into Tessera + Postgres
entry_index. The companion to the Shipper:

	Shipper:    StateSequenced → bytestore.WriteEntry → StateShipped
	Sequencer:  StatePending → tessera.AppendLeaf → StateSequenced

Together they keep entries flowing from "durable in WAL" all the
way through to "served via 302 redirect" without blocking the
HTTP admission path.

ROLE IN THE SCT/MMD ARCHITECTURE:

	POST /v1/entries returns a SignedCertificateTimestamp (SCT)
	immediately after wal.Submit fsync. The Sequencer is what
	redeems that promise — it pulls each pending entry, calls
	tessera.AppendLeaf (antispam-idempotent), INSERTs the
	metadata into entry_index, and transitions the WAL state to
	Sequenced. The Maximum Merge Delay (LEDGER_MMD, default 24h)
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

	WAL — minimal surface needed for drain (IterateInflight,
	               Read, MetaState, Sequence, MarkRetry, MarkManual).
	               *wal.Committer satisfies it.
	Tessera — AppendLeaf only. *tessera.EmbeddedAppender's
	               backend satisfies it.
	EntryInserter — INSERTs the entry_index row inside a Postgres
	               transaction. *store.EntryStore satisfies it.

CONFIG:

	PollInterval — drain wakeup cadence (default 1s, override via
	                LEDGER_SEQUENCER_INTERVAL).
	MaxInFlight — bounded concurrency for per-entry processing
	                (default 4, override via
	                LEDGER_SEQUENCER_MAX_INFLIGHT).
	MaxAttempts — per-entry retry cap before transition to
	                StateManual (default 10).
	BackoffBase — initial backoff between retries (default 1s).
	BackoffMax — backoff ceiling (default 60s).

The drain itself lives in loop.go.
*/
package sequencer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ledger/lifecycle"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/wal"
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
//
// L4 — ctx propagation: AppendLeaf accepts the caller's context
// so a sequencer drain that hits a SIGTERM mid-batch can cancel
// the in-flight Tessera Add. Without this, Tessera's batcher
// would continue trying to integrate after the rest of the
// process has unwound.
type Tessera interface {
	AppendLeaf(ctx context.Context, data []byte) (uint64, error)
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

	// MaxBuilderLag is the cursor-lag ceiling — the maximum number
	// of admitted entries the sequencer is allowed to drain ahead
	// of the builder. When a drain cycle observes
	//   MAX(entry_index.sequence_number) − builder_cursor.last_processed_sequence
	// >= MaxBuilderLag the cycle returns immediately (no WAL drain).
	// Because the sequencer stops draining the WAL Committer, the
	// in-memory WAL queue saturates to wal.QueueSize. wal.Submit
	// surfaces ErrQueueFull and the HTTP admission path returns
	// 503 Service Unavailable with a Retry-After. This is the
	// physical wire that turns a stalled builder (e.g., witness
	// quorum failure) into honest backpressure on the public API.
	//
	// 0 disables the gate (legacy behaviour). Production wiring
	// MUST set DefaultMaxBuilderLag (4096) — the same bound as
	// wal.QueueSize so admission backpressure and builder lag
	// share one knob.
	MaxBuilderLag uint64

	// MaxEntriesPerCycle bounds the work performed by a single
	// drainOnce invocation. After dispatching this many entries to
	// the worker pool, the iterator stops; drainOnce waits for the
	// dispatched workers to complete, then returns. The next
	// PollInterval tick re-enters drainOnce for the next batch.
	//
	// Why it must be bounded:
	//   - Without a bound, a single drainOnce iterates the entire
	//     inflight queue. Under load (60K+ pending), drainOnce
	//     blocks for minutes while workers complete. During that
	//     time the drainCycles metric reports 0 increments — it
	//     becomes useless as a liveness signal. Shutdown latency
	//     equals the cycle's wg.Wait duration. Memory pressure
	//     scales with queue size, not concurrency.
	//   - With a bound, drainCycles increments at predictable
	//     cadence (one per ~MaxEntriesPerCycle/MaxInFlight ×
	//     per-entry-latency). Operators get a real liveness
	//     signal; shutdown is bounded; memory is bounded.
	//
	// 0 disables the bound (legacy behaviour for tests that
	// deliberately drain the entire queue in one call). Production
	// wiring SHOULD set DefaultMaxEntriesPerCycle.
	MaxEntriesPerCycle int

	// CommitChannelBuffer caps the staged-entry channel that stage-1
	// workers emit into and the committer drains. Acts as
	// backpressure: when the committer is slower than stage-1, the
	// channel fills, stage-1 workers block on send, the drain
	// iterator blocks on the semaphore, the WAL queue saturates,
	// admission 503s. Recommended sizing: 4 × MaxInFlight (gives
	// the committer headroom to flush one full batch while stage-1
	// is preparing the next).
	//
	// 0 → DefaultCommitChannelBuffer (= 4 × MaxInFlight after
	// MaxInFlight normalization).
	CommitChannelBuffer int

	// CommitMaxBatchSize caps how many entries the committer
	// aggregates into one entry_index transaction. Smaller batches
	// → lower per-entry latency, more PG fsyncs. Larger batches
	// → fewer fsyncs (better throughput), longer tail latency for
	// the first entries in a batch.
	//
	// Recommended default: 256, which:
	//   - matches Postgres's optimal unnest() array size for the
	//     INSERT path,
	//   - aligns with Tessera's tile boundary (256 leaves per
	//     tile), so committer cadence tracks the underlying
	//     storage's physical block boundaries.
	//
	// 0 → DefaultCommitMaxBatchSize.
	CommitMaxBatchSize int

	// CommitMaxWait is the tail-flush deadline — if a batch hasn't
	// reached CommitMaxBatchSize within this duration of the first
	// entry being added, the committer flushes whatever it has.
	// Prevents low-traffic stragglers from sitting in the staged
	// buffer indefinitely.
	//
	// Recommended default: 50ms — under a 5K TPS spike the batch
	// fills (256 entries / 5K = 51ms) before the timer fires; under
	// idle traffic the timer caps entry-to-visible latency at 50ms.
	//
	// 0 → DefaultCommitMaxWait.
	CommitMaxWait time.Duration
}

// Defaults applied to a zero-valued Config.
const (
	DefaultPollInterval  = 1 * time.Second
	DefaultMaxInFlight   = 4
	DefaultMaxAttempts   = 10
	DefaultBackoffBase   = 1 * time.Second
	DefaultBackoffMax    = 60 * time.Second
	DefaultMaxBuilderLag = 4096

	// DefaultMaxEntriesPerCycle bounds the per-cycle work so the
	// drainCycles metric is a useful liveness signal under load.
	//
	// Sizing: per-entry latency is dominated by Tessera AppendLeaf
	// (~5ms in steady state). With MaxInFlight=16 workers, 256
	// entries per cycle = 16 entries per worker × 5ms ≈ 80ms cycle
	// latency → ~12 cycles/sec metric updates. At smaller MaxInFlight
	// values cycle latency scales linearly (MaxInFlight=4 → ~320ms,
	// ~3 cycles/sec) — still meaningful.
	DefaultMaxEntriesPerCycle = 256

	// DefaultCommitMaxBatchSize aligns with Tessera's 256-leaf tile
	// boundary AND with Postgres's optimal unnest() array size for
	// the entry_index INSERT path. See Config.CommitMaxBatchSize.
	DefaultCommitMaxBatchSize = 256

	// DefaultCommitMaxWait — 50ms tail-flush deadline. See
	// Config.CommitMaxWait.
	DefaultCommitMaxWait = 50 * time.Millisecond
)

// LagReader returns the current builder lag (admitted minus
// committed sequences). *store.SequenceCursor satisfies it via
// SequenceCursor.Lag(ctx).
//
// When wired (via WithLagReader) and Config.MaxBuilderLag > 0,
// the Sequencer's drainOnce gates on Lag before consuming from
// the WAL. A nil reader disables the gate.
type LagReader interface {
	Lag(ctx context.Context) (int64, error)
}

// Metrics is the atomic counter snapshot the supervisor scrapes.
// Concurrency-safe: every field is touched only via sync/atomic.
type Metrics struct {
	drainCycles        atomic.Uint64
	processed          atomic.Uint64
	failures           atomic.Uint64
	manualCount        atomic.Uint64
	currentLag         atomic.Int64 // pending entries observed at last drain
	backpressureStalls atomic.Uint64

	// Committer (staged pipeline) metrics. See committer.go.
	committedBatches    atomic.Uint64 // batches committed by the committer
	committedEntries    atomic.Uint64 // total entries (live + tombstone) committed
	commitWaitOnGap     atomic.Uint64 // committer received a tuple but heap head != nextExpectedSeq
	commitBatchFailures atomic.Uint64 // batch tx failed (re-pushed to heap)

	// staleDuplicatesDiscarded — duplicate stagedEntry tuples (seq <
	// nextExpectedSeq) whose WAL state had already advanced past
	// Pending by the time the committer saw them. Normal-race
	// outcome (drainOnce cycle N+1 spawned a stage-1 worker for a
	// hash that cycle N's committer was already mid-commit on).
	// Expected to be small but non-zero under burst load. Watch
	// the ratio committedEntries / staleDuplicatesDiscarded for
	// scale-budget tuning.
	staleDuplicatesDiscarded atomic.Uint64
	// staleCrashRecoveries — duplicate tuples whose WAL state was
	// still Pending when the committer saw them. Indicates the
	// rare path where the original commit's WAL.Sequence call
	// failed; the duplicate is what unblocks the entry. Should be
	// ~zero in steady state; non-zero implies Badger / WAL pressure.
	staleCrashRecoveries atomic.Uint64

	// tesseraLatency — per-call AppendLeaf timing histogram. Populated
	// by stage-1 workers in loop.go::processOne. Initialized in
	// NewSequencer; never nil after construction. Exists to answer
	// the scale question "does Tessera saturate at MaxInFlight=N" with
	// evidence rather than guesswork — the soak's end-of-run summary
	// prints a snapshot.
	tesseraLatency *LatencyHistogram
}

// MetricsSnapshot is a non-atomic view for callers (Prometheus
// exposition, log lines).
type MetricsSnapshot struct {
	DrainCycles              uint64
	Processed                uint64
	Failures                 uint64
	ManualCount              uint64
	CurrentLag               int64
	BackpressureStalls       uint64
	CommittedBatches         uint64
	CommittedEntries         uint64
	CommitWaitOnGap          uint64
	CommitBatchFailures      uint64
	StaleDuplicatesDiscarded uint64
	StaleCrashRecoveries     uint64
	TesseraLatency           LatencyHistogramSnapshot
}

// Snapshot returns a non-atomic copy of the current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	snap := MetricsSnapshot{
		DrainCycles:              m.drainCycles.Load(),
		Processed:                m.processed.Load(),
		Failures:                 m.failures.Load(),
		ManualCount:              m.manualCount.Load(),
		CurrentLag:               m.currentLag.Load(),
		BackpressureStalls:       m.backpressureStalls.Load(),
		CommittedBatches:         m.committedBatches.Load(),
		CommittedEntries:         m.committedEntries.Load(),
		CommitWaitOnGap:          m.commitWaitOnGap.Load(),
		CommitBatchFailures:      m.commitBatchFailures.Load(),
		StaleDuplicatesDiscarded: m.staleDuplicatesDiscarded.Load(),
		StaleCrashRecoveries:     m.staleCrashRecoveries.Load(),
	}
	if m.tesseraLatency != nil {
		snap.TesseraLatency = m.tesseraLatency.Snapshot()
	}
	return snap
}

// SplitIDIndexWriter is the ledger-internal hook the
// Sequencer invokes after a successful commit to populate the
// splitid index (Badger prefix 0x0A) — the
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

// EntryLookupWriter is the ledger-internal hook the Sequencer
// invokes after a successful commit to populate the entry-lookup
// projection (Badger prefix 0x0C) that backs
// /v1/commitments/by-split-id under the pure CQRS discipline.
//
// CQRS DISCIPLINE: the sequencer is the ONLY writer of 0x0C.
// The api/ read-path consumes it via types.CommitmentFetcher (a
// pure SDK interface) — api/'s transitive imports do not include
// pgx. Verifiable: go list -deps ./api/ | grep pgx == 0.
//
// nil receiver is allowed: when no writer is wired (test mode
// + the transitional state before gossip is enabled), the
// sequencer skips the lookup write entirely. Postgres entry_index
// + commitment_split_id INSERTs are unaffected; only the Badger
// projection write is gated.
type EntryLookupWriter interface {
	WriteEntryLookupEntry(
		ctx context.Context,
		schemaID string,
		splitID [32]byte,
		seq uint64,
		entry EntryLookupIndexEntry,
	) error
}

// EntryLookupIndexEntry mirrors gossipstore.EntryLookupIndexEntry —
// the value side of one 0x0C row. Defined here for the same reason
// SplitIDIndexEntry is: the sequencer does not import gossipstore.
type EntryLookupIndexEntry struct {
	CanonicalBytes []byte
	LogTimeMicros  int64
	LogDID         string
}

// Sequencer is the WAL → Tessera → entry_index pipeline worker.
type Sequencer struct {
	wal          WAL
	tessera      Tessera
	db           *pgxpool.Pool
	store        *store.EntryStore
	splitIDIndex SplitIDIndexWriter
	entryLookup  EntryLookupWriter
	lagReader    LagReader
	replayer     *Replayer
	logDID       string
	cfg          Config
	logger       *slog.Logger

	metrics Metrics

	// attempts tracks per-hash retry counts in memory across
	// drain cycles. On crash + restart the counter resets to 0
	// — acceptable, MaxAttempts is a soft ceiling not a hard
	// guarantee against retry storms.
	attemptsMu sync.Mutex
	attempts   map[[32]byte]uint32

	// Staged commit pipeline. Stage-1 workers (loop.go::processOne)
	// emit stagedEntry tuples to commitCh; the committer goroutine
	// (committer.go::committerLoop) drains them via min-heap into
	// contiguous-prefix batches and runs one atomic entry_index
	// INSERT per batch. See committer.go for the full architecture
	// rationale.
	commitCh        chan stagedEntry
	committerHeap   *committerHeap
	nextExpectedSeq atomic.Uint64
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
	if cfg.MaxBuilderLag == 0 {
		cfg.MaxBuilderLag = DefaultMaxBuilderLag
	}
	if cfg.MaxEntriesPerCycle == 0 {
		cfg.MaxEntriesPerCycle = DefaultMaxEntriesPerCycle
	}
	if cfg.CommitMaxBatchSize <= 0 {
		cfg.CommitMaxBatchSize = DefaultCommitMaxBatchSize
	}
	if cfg.CommitMaxWait <= 0 {
		cfg.CommitMaxWait = DefaultCommitMaxWait
	}
	if cfg.CommitChannelBuffer <= 0 {
		// Headroom for the committer to flush one full batch while
		// stage-1 prepares the next. MaxInFlight has been normalized
		// above; 4× gives 16 entries of slack at the default
		// MaxInFlight=4, plenty to absorb single-batch commit jitter.
		cfg.CommitChannelBuffer = 4 * cfg.MaxInFlight
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Sequencer{
		wal:           w,
		tessera:       t,
		db:            db,
		store:         es,
		cfg:           cfg,
		logger:        cfg.Logger,
		attempts:      make(map[[32]byte]uint32),
		committerHeap: &committerHeap{},
	}
	s.metrics.tesseraLatency = newLatencyHistogram()
	return s
}

// WithSplitIDIndex wires the gossipstore-backed splitid index
// writer. Optional; called once at startup by cmd/ledger/main.go
// after the gossipstore is constructed. When nil, the Sequencer
// runs without the splitid write.
//
// Returns the receiver for fluent wiring. Idempotent against a
// nil writer. Race-free against drain cycles only when called
// before Run starts; the wiring respects that.
func (s *Sequencer) WithSplitIDIndex(w SplitIDIndexWriter) *Sequencer {
	s.splitIDIndex = w
	return s
}

// WithEntryLookup wires the gossipstore-backed entry-lookup
// projection writer (Badger prefix 0x0C). The ledger's log DID
// is captured at wiring time and stamped into every 0x0C row so
// the read endpoint can return it verbatim.
//
// Optional; nil writer is a no-op. Race-free against drain cycles
// only when called before Run starts.
func (s *Sequencer) WithEntryLookup(w EntryLookupWriter, logDID string) *Sequencer {
	s.entryLookup = w
	s.logDID = logDID
	return s
}

// WithLagReader wires the builder-lag reader (typically a
// *store.SequenceCursor) used by drainOnce to gate WAL drains
// when the builder falls too far behind. Passing nil disables
// the gate; the sequencer drains as before.
//
// Optional; nil receiver is a no-op (test mode + transitional
// state). Race-free against drain cycles only when called before
// Run starts.
func (s *Sequencer) WithLagReader(r LagReader) *Sequencer {
	s.lagReader = r
	return s
}

// WithReplayer wires the boot replayer that back-populates
// 0x0A + 0x0C from Postgres above the persisted HWM. Run starts
// the replayer on a child goroutine; ctx cancellation propagates
// and Run waits for the replayer to drain before returning
// (graceful teardown).
//
// Optional; nil receiver is a no-op (test mode + transitional
// state where Postgres / bytestore aren't fully wired).
func (s *Sequencer) WithReplayer(r *Replayer) *Sequencer {
	s.replayer = r
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
// StatePending across ledger restarts. There is no separate
// "Reconcile" entry point — the polling loop IS the
// reconciliation, and on a quiet log it idles cheaply.
//
// Boot replay: when WithReplayer is wired, Run spawns the
// replayer on a child goroutine that scans Postgres above the
// HWM and back-populates 0x0A + 0x0C. The replayer runs in
// parallel with the drain loop — admission is never blocked.
// On ctx cancellation, Run waits for the replayer to drain
// before returning (graceful teardown).
//
// Returns ctx.Err() on graceful shutdown.
func (s *Sequencer) Run(ctx context.Context) error {
	if s.wal == nil || s.tessera == nil {
		return errors.New("sequencer: WAL and Tessera both required")
	}

	// Initialize the staged-commit pipeline state from Postgres
	// BEFORE spawning any goroutines. The committer's
	// nextExpectedSeq must reflect entry_index's current high-water
	// mark — otherwise on a restart after crash-recovery the
	// committer would wait indefinitely for seqs that are already
	// committed.
	nextSeq, err := s.readNextExpectedSeq(ctx)
	if err != nil {
		return fmt.Errorf("sequencer: initialize committer state: %w", err)
	}
	s.nextExpectedSeq.Store(nextSeq)
	s.commitCh = make(chan stagedEntry, s.cfg.CommitChannelBuffer)

	// Goroutines spawned in this method drain via wg.Wait below —
	// guarantees clean teardown even on abrupt ctx cancellation.
	// All goroutines see ctx.Done() at the same instant the
	// for-select loop does; the deferred wg.Wait then collects them.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Committer goroutine — the staged-commit consumer. MUST be
	// running before stage-1 workers emit any tuples (otherwise
	// commitCh fills up and stage-1 blocks).
	lifecycle.SafeRunInWG(ctx, &wg, "sequencer-committer", s.logger, nil, func() error {
		s.committerLoop(ctx)
		return nil
	})

	// Replay goroutine. Wrapped in lifecycle.SafeRun so a panic in
	// Replay logs + exits the goroutine cleanly without crashing
	// the supervisor. Replay is best-effort — boot replay failure
	// is logged but not fatal; the steady-state drain loop catches
	// up later.
	if s.replayer != nil {
		lifecycle.SafeRunInWG(ctx, &wg, "sequencer-replay", s.logger, nil, func() error {
			if err := s.replayer.Replay(ctx); err != nil &&
				!errors.Is(err, context.Canceled) &&
				!errors.Is(err, context.DeadlineExceeded) {
				s.logger.Error("sequencer: boot replay failed",
					"error", err)
			}
			return nil
		})
	}

	// First drain immediately on Run start so a freshly-booted
	// ledger picks up crash-recovered entries before the first
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
