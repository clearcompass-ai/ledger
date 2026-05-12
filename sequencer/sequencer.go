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

	sdkschema "github.com/clearcompass-ai/attesta/schema"

	"github.com/clearcompass-ai/ledger/latency"
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

	// MaxCommitterHeapSize bounds the staged-entry min-heap the
	// committer drains. When the heap depth reaches this ceiling,
	// drainOnce returns without dispatching new stage-1 workers —
	// the WAL queue then saturates and admission returns 503.
	//
	// Why bound the heap at all: a poison-pill anomaly (e.g., a
	// permanently-lost contiguous-prefix seq) would otherwise
	// queue every subsequent seq in the heap waiting for the gap
	// to fill, exhausting Go's heap until the kernel OOMs the
	// process. A finite ceiling forces the failure mode to
	// "admission stops accepting" instead of "process disappears".
	//
	// Sizing rationale: CommitMaxBatchSize (256) × MaxInFlight (4)
	// × 4 = 4096 covers the steady-state worst case of 4× batch
	// depth ahead of the committer. Matches DefaultMaxBuilderLag /
	// wal.QueueSize so the three backpressure gates share one
	// budget. 0 disables (legacy / test fixtures).
	MaxCommitterHeapSize int

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

	// DefaultMaxCommitterHeapSize bounds the staged-entry heap.
	// See Config.MaxCommitterHeapSize for the rationale.
	DefaultMaxCommitterHeapSize = 4096

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

	// committerHeapStalls — drainOnce cycles that bailed because the
	// committer heap was at MaxCommitterHeapSize. Strictly the
	// "committer can't keep up" failure mode; distinct from
	// backpressureStalls (the builder-cursor gate). Both saturate
	// admission to 503, but they answer different operator
	// questions: a builder-lag stall means cosignature pressure;
	// a heap stall means PG write pressure.
	committerHeapStalls atomic.Uint64

	// Committer (staged pipeline) metrics. See committer.go.
	committedBatches    atomic.Uint64 // batches committed by the committer
	committedEntries    atomic.Uint64 // total entries (live + tombstone) committed
	commitWaitOnGap     atomic.Uint64 // committer received a tuple but heap head != nextExpectedSeq
	commitBatchFailures atomic.Uint64 // batch tx failed (re-pushed to heap)

	// staleDuplicatesDiscarded — total duplicate stagedEntry tuples
	// (seq < expected) that were silently discarded. Sum of the two
	// split counters below, kept for back-compat with existing log
	// surfaces (scaling_evidence committer{stale_discarded=…}).
	staleDuplicatesDiscarded atomic.Uint64
	// staleInBatchDuplicates — sub-case A of drainHeapInto: dup's
	// Seq is in [nextExpectedSeq, expected), meaning the original is
	// still in `pending` and will be flushed momentarily. The
	// committer detects this BEFORE the original's commit completes
	// — discriminating purely on the committer's own state (Seq <
	// expected) without touching the WAL. The dominant population
	// under normal burst load; rate is driven by drainOnce cadence
	// × commitRaceWindow.
	staleInBatchDuplicates atomic.Uint64
	// staleCrossBatchDuplicates — sub-case B silent-discard from
	// committerStaleRecover: dup's Seq < nextExpectedSeq AND
	// MetaState shows state != Pending, meaning the original was
	// committed in a PRIOR batch and WAL state has already advanced.
	// Pure dup-after-commit race. Expected to be a small minority of
	// total stales — non-zero only when drainOnce N+1 fires AFTER
	// cycle N's committer has fully flushed.
	staleCrossBatchDuplicates atomic.Uint64
	// staleCrashRecoveries — duplicate tuples whose WAL state was
	// still Pending when the committer saw them in the cross-batch
	// branch. Indicates the rare path where the original commit's
	// WAL.Sequence call failed; the duplicate is what unblocks the
	// entry. Should be ~zero in steady state; non-zero implies
	// Badger / WAL pressure.
	staleCrashRecoveries atomic.Uint64

	// staleCrashRecoveriesAfterPGCollision — strictly the subset of
	// staleCrashRecoveries that surfaced through the PG canonical_hash
	// unique-constraint path. Distinguishes "Tessera dedup gap across
	// a crash boundary" (PG was the oracle that caught it) from
	// "stage-1 in-flight race within one process lifetime" (the
	// pre-existing cross-batch path).
	//
	// SRE alert: sustained non-zero values mean either (a) Tessera's
	// antispam follower can't keep up with the AppendLeaf rate, or
	// (b) a hostile actor is replaying canonical hashes across a
	// kill cycle. Both warrant operator attention; the dimensional
	// label separates them.
	staleCrashRecoveriesAfterPGCollision atomic.Uint64

	// staleAgeHistogram — time from stage-1 emit (stagedEntry.emittedAt)
	// to stale-discard, observed for every dup that hits either
	// sub-case A or sub-case B silent-discard. The "how old was the
	// dup when the committer rejected it" distribution. Pairs with
	// commitRaceWindow: if the two distributions overlap, dups are
	// being produced inside the original's race window, which is
	// the hypothesis we're trying to test (vs. some other
	// mechanism).
	staleAgeHistogram *latency.Histogram

	// commitRaceWindow — time from stage-1 emit to successful commit
	// (applyPostCommitForOne entry), observed per committed tuple.
	// The "how long does the original take to commit" distribution.
	// drainOnce cycle N+1 catches the hash still Pending if
	// PollInterval + cycle_N_duration < commitRaceWindow for a given
	// entry. So commitRaceWindow p99 vs. effective drainOnce period
	// is the structural relationship that drives in-batch-dup rate.
	commitRaceWindow *latency.Histogram

	// tesseraLatency — per-call AppendLeaf timing histogram. Populated
	// by stage-1 workers in loop.go::processOne. Initialized in
	// NewSequencer; never nil after construction. Exists to answer
	// the scale question "does Tessera saturate at MaxInFlight=N" with
	// evidence rather than guesswork — the soak's end-of-run summary
	// prints a snapshot.
	tesseraLatency *latency.Histogram

	// tesseraInFlight — live count of stage-1 workers currently
	// blocked inside Tessera.AppendLeaf. Diagnostic for the
	// silent-stall failure mode where Tessera's internal integration
	// future never resolves: a saturated histogram is useless when
	// no observations are being recorded, but
	// tesseraInFlight==MaxInFlight across many drain cycles is
	// unambiguous evidence that the workers are wedged on Tessera.
	// Incremented on AppendLeaf entry, decremented on return (both
	// happy and error paths).
	tesseraInFlight atomic.Int64

	// tesseraInFlightHighWater — the maximum value tesseraInFlight
	// has ever reached. Maintained via CAS so concurrent stage-1
	// workers compose correctly. Surfaces "we touched the ceiling"
	// even after the system recovers; the live count alone would
	// drop back to zero and obscure the peak.
	tesseraInFlightHighWater atomic.Int64
}

// MetricsSnapshot is a non-atomic view for callers (Prometheus
// exposition, log lines).
type MetricsSnapshot struct {
	DrainCycles                          uint64
	Processed                            uint64
	Failures                             uint64
	ManualCount                          uint64
	CurrentLag                           int64
	BackpressureStalls                   uint64
	CommitterHeapStalls                  uint64
	CommittedBatches                     uint64
	CommittedEntries                     uint64
	CommitWaitOnGap                      uint64
	CommitBatchFailures                  uint64
	StaleDuplicatesDiscarded             uint64 // sum (in-batch + cross-batch), back-compat
	StaleInBatchDuplicates               uint64 // sub-case A
	StaleCrossBatchDuplicates            uint64 // sub-case B silent-discard
	StaleCrashRecoveries                 uint64
	StaleCrashRecoveriesAfterPGCollision uint64
	StaleAgeHistogram                    latency.Snapshot
	CommitRaceWindow                     latency.Snapshot
	TesseraLatency                       latency.Snapshot
	TesseraInFlight                      int64
	TesseraInFlightHighWater             int64
}

// Snapshot returns a non-atomic copy of the current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	snap := MetricsSnapshot{
		DrainCycles:                          m.drainCycles.Load(),
		Processed:                            m.processed.Load(),
		Failures:                             m.failures.Load(),
		ManualCount:                          m.manualCount.Load(),
		CurrentLag:                           m.currentLag.Load(),
		BackpressureStalls:                   m.backpressureStalls.Load(),
		CommitterHeapStalls:                  m.committerHeapStalls.Load(),
		CommittedBatches:                     m.committedBatches.Load(),
		CommittedEntries:                     m.committedEntries.Load(),
		CommitWaitOnGap:                      m.commitWaitOnGap.Load(),
		CommitBatchFailures:                  m.commitBatchFailures.Load(),
		StaleDuplicatesDiscarded:             m.staleDuplicatesDiscarded.Load(),
		StaleInBatchDuplicates:               m.staleInBatchDuplicates.Load(),
		StaleCrossBatchDuplicates:            m.staleCrossBatchDuplicates.Load(),
		StaleCrashRecoveries:                 m.staleCrashRecoveries.Load(),
		StaleCrashRecoveriesAfterPGCollision: m.staleCrashRecoveriesAfterPGCollision.Load(),
	}
	if m.staleAgeHistogram != nil {
		snap.StaleAgeHistogram = m.staleAgeHistogram.Snapshot()
	}
	if m.commitRaceWindow != nil {
		snap.CommitRaceWindow = m.commitRaceWindow.Snapshot()
	}
	if m.tesseraLatency != nil {
		snap.TesseraLatency = m.tesseraLatency.Snapshot()
	}
	snap.TesseraInFlight = m.tesseraInFlight.Load()
	snap.TesseraInFlightHighWater = m.tesseraInFlightHighWater.Load()
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

// GhostLeafEvent mirrors gossipnet.GhostLeafEvent. Defined here so
// the sequencer does not import gossipnet (preserves the no-
// gossip-deps invariant used by SplitIDIndexEntry +
// EntryLookupIndexEntry).
//
// Field set is byte-aligned with the gossipnet type so a concrete
// gossipnet.LoggingGhostLeafEmitter satisfies GhostLeafEmitter
// below structurally without an explicit converter — the same
// pattern the splitid + entry-lookup interfaces use today.
//
// ObservedAtUnixNano is a uint64 (never time.Time) so the
// downstream cryptographic-bytes path is deterministic across
// every plausible producer/consumer boundary. See
// gossipnet/ghost_leaf_emitter.go for the full rationale.
type GhostLeafEvent struct {
	GhostSeq           uint64
	CanonicalSeq       uint64
	CanonicalHash      [32]byte
	LogDID             string
	ObservedAtUnixNano uint64
}

// Validate enforces the same structural invariants the SDK's
// findings.GhostLeafFinding constructor enforces (verified by
// reading attesta v0.5.0 gossip/findings/ghost_leaf.go:Validate).
// Defense-in-depth: the committer always populates every field
// correctly today, but a future refactor that leaves a field
// zero would otherwise surface as an SDK-side error deep in
// the gossip Sign pipeline. Calling Validate at the sequencer
// boundary attributes the misuse to the right callsite.
//
// Invariants (1:1 with SDK):
//
//   - LogDID non-empty
//   - CanonicalHash non-zero
//   - GhostSeq > CanonicalSeq (Tessera assigns seqs monotonically;
//     a ghost cannot predate its primary)
//   - ObservedAtUnixNano > 0 (zero is the uninitialized sentinel)
//
// Returns nil on success, a non-nil descriptive error otherwise.
// Errors are not wrapped sentinels — callers log + drop the
// event rather than branching on error identity.
func (ev *GhostLeafEvent) Validate() error {
	if ev.LogDID == "" {
		return errGhostLeafEventEmptyLogDID
	}
	if ev.CanonicalHash == ([32]byte{}) {
		return errGhostLeafEventZeroHash
	}
	if ev.GhostSeq <= ev.CanonicalSeq {
		return errGhostLeafEventSeqOrder
	}
	if ev.ObservedAtUnixNano == 0 {
		return errGhostLeafEventZeroObservedAt
	}
	return nil
}

// Sentinel errors for GhostLeafEvent.Validate. Exported as
// values rather than types so callers can errors.Is the
// specific failure mode. Not wrapped with the "sequencer:"
// prefix because the SEQUENCER doesn't surface these — the
// EMITTER does, with its own prefix in the log line.
var (
	errGhostLeafEventEmptyLogDID    = ghostLeafErr("empty log_did")
	errGhostLeafEventZeroHash       = ghostLeafErr("zero canonical_hash")
	errGhostLeafEventSeqOrder       = ghostLeafErr("ghost_seq must be > canonical_seq")
	errGhostLeafEventZeroObservedAt = ghostLeafErr("zero observed_at_unix_nano")
)

// ghostLeafErr is a tiny stringer error used only by the
// sentinels above. Keeps the sentinels comparable + their
// messages stable for log greps.
type ghostLeafErr string

func (e ghostLeafErr) Error() string {
	return "sequencer: GhostLeafEvent invalid: " + string(e)
}

// GhostLeafEmitter is the sequencer's local surface to the
// gossip-side ghost-leaf publisher. The committer's hot path
// calls Emit after each successful ghost row insert; the
// concrete implementation (in gossipnet/) constructs a signed
// gossip event and broadcasts it for offline-auditor visibility.
//
// Emit MUST be non-blocking and MUST NOT return an error: the
// commit path treats emission as fire-and-forget. The PG ghost
// row is the authoritative record; gossip is broadcast
// amplification only.
//
// nil-safe at the sequencer level: WithGhostLeafEmitter ignores
// a nil argument and dispatchGhostLeaf short-circuits when
// ghostEmitter is nil. Used by test fixtures that don't care
// about emission and by deployments running without gossip.
type GhostLeafEmitter interface {
	Emit(ctx context.Context, ev GhostLeafEvent)
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

	// schemaRegistry, when non-nil, is the v0.4.0 DI schema
	// admission registry built by cmd/ledger/boot/schemareg.
	// dispatchCommitmentSchema consults it: if Has(schema-id)
	// returns false the entry is treated as schema-less; if true
	// ValidateEntry runs as the admission gate before the parse
	// step that extracts the SplitID. nil → fall back to the
	// legacy hard-coded switch (preserves test fixtures that
	// don't build a registry).
	schemaRegistry *sdkschema.Registry

	// ghostEmitter, when non-nil, receives a GhostLeafEvent after
	// each successful canonical_hash-collision recovery (the
	// committer's Ghost Leaf path). Best-effort emission only;
	// failure here NEVER blocks the commit path. Nil is the
	// gossip-disabled deployment mode (matches the LoggingGhost-
	// LeafEmitter behavioural contract — no broadcast, no panic).
	//
	// Production wiring threads a concrete gossipnet.GhostLeafEmitter
	// from cmd/ledger/boot/wire/wire.go. When SDK v0.5.0 ships
	// findings.GhostLeafFinding, the wiring layer swaps the logging
	// emitter for the SDK adapter; the sequencer does not change.
	ghostEmitter GhostLeafEmitter

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
	// fatalCh is the lifecycle.SafeRun-wired fatal channel. When
	// the identical-batch circuit breaker trips (3 consecutive
	// failures on the same first_seq), a sentinel error is sent
	// here so the supervisor terminates the process rather than
	// looping the failed batch forever. nil-safe — see
	// raiseFatal for the guard.
	fatalCh chan<- error

	// identicalBatchTracker holds the (first_seq, error-fingerprint)
	// of the most recent failed flush, plus a streak count. Three
	// consecutive failures with identical fingerprint trip the
	// breaker. Mutex-guarded because flushPending runs on the
	// committer goroutine but raiseFatal may need to log from
	// another path. See checkIdenticalBatchBreaker for the
	// full semantics.
	identicalBatchMu      sync.Mutex
	identicalBatchSeq     uint64
	identicalBatchErrFP   string
	identicalBatchStreak  int
	identicalBatchTripped atomic.Bool

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
	if cfg.MaxCommitterHeapSize == 0 {
		cfg.MaxCommitterHeapSize = DefaultMaxCommitterHeapSize
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
	s.metrics.tesseraLatency = latency.New()
	s.metrics.staleAgeHistogram = latency.New()
	s.metrics.commitRaceWindow = latency.New()
	return s
}

// WithGhostLeafEmitter wires the gossip-side ghost-leaf
// publisher. The committer calls Emit after each successful
// ghost-row insert; the emitter constructs + signs +
// broadcasts the corresponding KindGhostLeaf event so offline
// auditors can correlate the duplicate Tessera leaf with the
// ledger's public confession.
//
// Optional. nil leaves the field unset; dispatchGhostLeaf
// short-circuits and the ghost row remains an in-PG record
// only (still routed correctly by the API's 308 redirect, but
// not announced to peers). The gossip-disabled deployment mode
// uses nil; production wiring always installs a concrete
// emitter (LoggingGhostLeafEmitter pre-v0.5.0, SDK adapter
// post-v0.5.0).
//
// Race-free against drain cycles only when called before Run
// starts; the wiring respects that.
func (s *Sequencer) WithGhostLeafEmitter(e GhostLeafEmitter) *Sequencer {
	s.ghostEmitter = e
	return s
}

// WithFatalChannel wires the supervisor's fatal channel into the
// sequencer. The identical-batch circuit breaker uses it to
// terminate the process when a flush deterministically fails on
// the same (first_seq, error-fingerprint) three consecutive
// times — that signature indicates a non-retriable PG constraint
// failure or malformed data in the batch, NOT transient network
// jitter, and the only correct disposition is process-level
// termination so the supervisor can restart with a clean slate.
//
// Optional; nil-safe. When unwired, breaker trips log at ERROR
// level but do not terminate the process — appropriate for unit
// tests that exercise the breaker without spawning a supervisor.
func (s *Sequencer) WithFatalChannel(fc chan<- error) *Sequencer {
	s.fatalCh = fc
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

// WithSchemaRegistry wires the v0.4.0 DI schema admission registry
// produced by cmd/ledger/boot/schemareg.BuildLedgerSchemaRegistry.
// When set, dispatchCommitmentSchema consults the registry to
// decide whether a SchemaID is admitted and runs the registry's
// EntryValidator before the SplitID-extraction parse. nil →
// legacy hard-coded switch (preserves test fixtures that don't
// build a registry).
//
// Optional; nil receiver is a no-op (intended for unit-test
// fixtures that exercise dispatch via the legacy path).
// Race-free against drain cycles only when called before Run starts.
func (s *Sequencer) WithSchemaRegistry(r *sdkschema.Registry) *Sequencer {
	s.schemaRegistry = r
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
