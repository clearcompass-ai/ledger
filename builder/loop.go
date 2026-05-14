/*
Package builder — loop.go

DESCRIPTION:

	The continuous builder loop — THE core operational loop of the ledger.
	Dequeues admitted entries, calls SDK ProcessBatch, commits state atomically,
	appends entry identities to the Merkle tree, publishes commitments, and
	requests witness cosignatures.

KEY ARCHITECTURAL DECISIONS:
  - Single goroutine: determinism requires exactly one builder per log.
    Advisory lock prevents concurrent instances.
  - Atomic commit: leaf mutations + delta buffer + queue status in ONE
    Postgres transaction. No partial state on crash.
  - Overlay SMT Store: SDK ProcessBatch runs against an in-memory overlay
    to guarantee functional purity. If batch validation fails, the overlay
    is discarded and Postgres remains completely untouched.
  - Entry-identity Merkle tree:
    Step 6 sends envelope.EntryIdentity(entry) — SHA-256 of the entry's
    canonical bytes, NOT the wire-bytes-including-signature hash — to
    the Tessera personality, which wraps it with RFC 6962's 0x00 leaf
    prefix internally. Full wire bytes (canonical + sig_envelope) stay
    in the ledger's own storage. Tessera never sees full entry data.
    Critical: do NOT use envelope.EntryLeafHash here — that would double-
    apply the RFC 6962 prefix because tessera-personality's NewEntry
    already applies it.
  - SDK MerkleTree interface: builder touches only the MerkleAppender
    interface, never tessera/client.go directly. Swappable backend.
  - Idempotent: replaying the same batch produces identical state.
  - Context-aware: every Postgres call checks ctx.Done() first.

SDK ALIGNMENT:
  - Read-side abstraction is types.EntryFetcher with the
    Fetch(pos LogPosition) (*EntryWithMetadata, error) signature.
    sdkbuilder.ProcessBatch accepts types.EntryFetcher.

OVERVIEW:

	Run loop: dequeue → fetch → split → ProcessBatch → atomic commit →
	Merkle append (entry-identity hash) → commitment → witness cosig.

	Step 6 (Merkle append) is POST-COMMIT and best-effort. Crash between
	commit and append → re-append on restart is safe (Tessera deduplicates
	by identity hash). The ledger's atomic state is in Postgres.

CONSUMER VERIFICATION FLOW:
 1. Fetch wire bytes from ledger's byte store.
 2. envelope.Deserialize(canonical) → entry (signatures inline).
 3. envelope.EntryIdentity(entry) → 32-byte hash.
 4. Fetch inclusion proof for position N, verify path hashes to the
    tree head published in the signed checkpoint.

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/attesta/builder: ProcessBatch, BatchResult,
    SchemaResolver, DeltaWindowBuffer.
  - github.com/clearcompass-ai/attesta/core/envelope: EntryIdentity.
  - github.com/clearcompass-ai/attesta/types: EntryFetcher (read-side
    abstraction, moved from builder/ in ).
  - tessera/proof_adapter.go: TesseraAdapter implements MerkleAppender.
  - store/smt_state.go: PostgresLeafStore.SetTx for atomic leaf writes.
  - store/entries.go: PostgresEntryFetcher implements types.EntryFetcher.
*/
package builder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Configuration
// -------------------------------------------------------------------------------------------------

// LoopConfig configures the builder loop.
type LoopConfig struct {
	LogDID       string
	BatchSize    int
	PollInterval time.Duration
	DeltaWindow  int
}

// DefaultLoopConfig returns production defaults.
func DefaultLoopConfig(logDID string) LoopConfig {
	return LoopConfig{
		LogDID:       logDID,
		BatchSize:    1000,
		PollInterval: 100 * time.Millisecond,
		DeltaWindow:  10,
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Interfaces
// -------------------------------------------------------------------------------------------------

// MerkleAppender is the subset of the Merkle tree interface used by the builder.
//
// AppendLeaf takes a 32-byte SHA-256 entry identity (envelope.EntryIdentity).
// Tessera stores this hash in its entry tiles and computes the Merkle leaf
// hash as H(0x00 || hash_bytes) per RFC 6962. The ledger does NOT apply
// the RFC 6962 prefix here — that's Tessera's job.
//
// Full entry bytes (canonical + signature envelope) stay in the ledger's
// own storage. Tessera never sees them.
//
// PublishCosignedCheckpoint writes the K-of-N cosigned tree head to the
// public publication path (CDN-fronted file). Called by the builder
// AFTER the atomic commit and AFTER witness quorum has been collected.
// Implementations MUST write atomically (write-tmp + rename) so partial
// state is never visible to auditors. Empty publication path on the
// concrete implementation is a graceful no-op so dev / test runs that
// don't set a public path still work.
type MerkleAppender interface {
	AppendLeaf(ctx context.Context, data []byte) (uint64, error)
	Head() (types.TreeHead, error)
	PublishCosignedCheckpoint(ctx context.Context, head types.CosignedTreeHead) error
}

// WitnessCosigner requests cosignatures on tree heads. On success
// returns the assembled CosignedTreeHead so the builder can pass
// it to MerkleAppender.PublishCosignedCheckpoint.
//
// Strict STH Finality: the builder MUST NOT advance Postgres state
// (SMT mutations, builder_cursor) until this returns nil. A non-nil
// return aborts the batch; the next builder cycle re-fetches and
// retries the exact same sequences.
type WitnessCosigner interface {
	RequestCosignatures(ctx context.Context, head types.TreeHead) (types.CosignedTreeHead, error)
}

// -------------------------------------------------------------------------------------------------
// 3) BuilderLoop
// -------------------------------------------------------------------------------------------------

// BuilderLoop is the continuous builder goroutine.
//
// V0.3.0 ARCHITECTURE
//
// Each cycle wraps the persistent leafStore + nodeStore in overlays
// (smt.OverlayLeafStore + smt.OverlayNodeStore), runs the SDK's
// ProcessBatch against an overlay-backed Tree seeded with priorRoot,
// then commits the overlay's leaf + node mutations transactionally
// alongside the cursor advance and the new SMT root. Failure at any
// pre-commit step discards the overlays — the persistent state is
// untouched.
//
// The persistent `tree` field is the read-side handle shared with
// API handlers. After a successful commit the builder calls
// `tree.SetRoot(newRoot)` so handlers observe the new root without
// going through Postgres for every request.
type BuilderLoop struct {
	cfg       LoopConfig
	db        *pgxpool.Pool
	tree      *smt.Tree
	leafStore *store.PostgresLeafStore
	nodeStore *store.PostgresNodeStore
	// reader is the CT-native log-tailing follower that reads new
	// sequences from entry_index and advances builder_cursor in the
	// builder's atomic commit. See builder/cursor_reader.go.
	reader      BatchReader
	fetcher     types.EntryFetcher
	schema      sdkbuilder.SchemaResolver
	buffer      *sdkbuilder.DeltaWindowBuffer
	bufferStore *DeltaBufferStore
	commitPub   *CommitmentPublisher
	merkle      MerkleAppender
	witness     WitnessCosigner
	logger      *slog.Logger

	// rootStore is OPTIONAL but production-required. It holds the
	// authoritative smt_root_state.current_root that the builder
	// advances each batch. /v1/smt/root reads it in O(1). When nil,
	// the builder still runs but advances only the in-memory
	// tree.rootHash — useful for tests that don't bootstrap the
	// singleton row.
	rootStore *store.SMTRootStateStore

	// Observability counters (atomic, lock-free).
	totalBatches   atomic.Int64
	totalEntries   atomic.Int64
	totalErrors    atomic.Int64
	consecutiveErr atomic.Int32

	// Shutdown-evidence instrumentation. currentPhase records the
	// step the loop is currently executing along with the timestamp
	// it entered the phase. The shutdown watchdog (spawned in Run on
	// ctx.Done) reads this atomic every 2s and re-emits a WARN log
	// so post-hoc analysis can point at the exact step that didn't
	// honor ctx cancellation within budget.
	//
	// WHY this exists: the prior 30s hang on
	// TestE2E_V1_HappyPath_ReturnsValidSCT manifested as
	//   "shutdownchain: goroutine did not drain in budget index=0
	//    budget=30s"
	// — index 0 is this loop. The error message had no evidence about
	// WHICH step inside processBatch was the blocker. Phase tracking
	// closes that observability gap so the next regression can be
	// triaged from a single test invocation.
	currentPhase atomic.Pointer[builderPhase]
}

// builderPhase captures what the builder loop was doing at a given
// instant. Stored under BuilderLoop.currentPhase as an
// atomic.Pointer[builderPhase] so the watchdog can read it without
// locks. Allocations are cheap (one pointer per phase transition);
// the GC pressure under load is dominated by per-batch allocations
// in processBatch itself.
type builderPhase struct {
	name      string
	enteredAt time.Time
}

// NewBuilderLoop creates a builder loop with all dependencies.
func NewBuilderLoop(
	cfg LoopConfig,
	db *pgxpool.Pool,
	tree *smt.Tree,
	leafStore *store.PostgresLeafStore,
	nodeStore *store.PostgresNodeStore,
	reader BatchReader,
	fetcher types.EntryFetcher,
	schema sdkbuilder.SchemaResolver,
	buffer *sdkbuilder.DeltaWindowBuffer,
	bufferStore *DeltaBufferStore,
	commitPub *CommitmentPublisher,
	merkle MerkleAppender,
	witness WitnessCosigner,
	logger *slog.Logger,
) *BuilderLoop {
	return &BuilderLoop{
		cfg:         cfg,
		db:          db,
		tree:        tree,
		leafStore:   leafStore,
		nodeStore:   nodeStore,
		reader:      reader,
		fetcher:     fetcher,
		schema:      schema,
		buffer:      buffer,
		bufferStore: bufferStore,
		commitPub:   commitPub,
		merkle:      merkle,
		witness:     witness,
		logger:      logger,
	}
}

// setPhase records the builder loop's current activity along with
// the timestamp it entered the phase. Called at every step transition
// in Run + processBatch; cost is a single pointer store under no
// contention (each loop iteration touches it ~10 times). The matching
// reader is the shutdown watchdog in Run.
func (bl *BuilderLoop) setPhase(name string) {
	bl.currentPhase.Store(&builderPhase{name: name, enteredAt: time.Now()})
}

// loadPhase returns the most recently recorded phase, or nil if no
// phase has been set yet (loop has not entered Run). The watchdog
// uses this to surface "stuck in phase X" evidence at shutdown.
func (bl *BuilderLoop) loadPhase() *builderPhase {
	return bl.currentPhase.Load()
}

// WithRootStore wires the SMTRootStateStore that holds the
// authoritative current SMT root + committed-through-seq. When set,
// processBatch reads priorRoot from it, computes newRoot
// incrementally via Tree.ComputeDirtyRoot, and persists the new
// value inside the same atomic commit transaction that writes the
// batch's leaves + cursor advance.
//
// Returns the receiver for chaining (mirroring the WithReplayer
// pattern used by the sequencer).
func (bl *BuilderLoop) WithRootStore(rs *store.SMTRootStateStore) *BuilderLoop {
	bl.rootStore = rs
	return bl
}

// -------------------------------------------------------------------------------------------------
// 4) Run — main loop with clean shutdown and panic recovery
// -------------------------------------------------------------------------------------------------

// Run executes the builder loop until ctx is cancelled.
// MUST be called from a single goroutine.
func (bl *BuilderLoop) Run(ctx context.Context) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			bl.logger.Error("builder loop panic recovered",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(buf[:n]),
			)
			retErr = fmt.Errorf("builder/loop: panic: %v", r)
		}
	}()

	// Shutdown-evidence defer: when Run returns AFTER ctx was
	// cancelled, log the LAST phase the loop was in along with how
	// long it stayed there. Combined with the watchdog below, this
	// pinpoints the step that didn't honor ctx.Done() in budget.
	defer func() {
		if ctx.Err() != nil {
			if ps := bl.loadPhase(); ps != nil {
				bl.logger.Info("builder loop exit: final phase",
					"phase", ps.name,
					"phase_age", time.Since(ps.enteredAt),
					"ctx_err", ctx.Err(),
				)
			}
		}
	}()

	bl.logger.Info("builder loop started",
		"log_did", bl.cfg.LogDID,
		"batch_size", bl.cfg.BatchSize,
		"poll_interval", bl.cfg.PollInterval,
	)
	bl.setPhase("loop_start")

	// Shutdown watchdog: spawned ONCE on Run entry. Waits for ctx.Done
	// and then re-emits a WARN every 2s reporting which phase the
	// builder loop is currently stuck in. Exits when watchdogDone is
	// closed (deferred below, runs after the loop returns).
	//
	// Designed for evidence collection at shutdown — under normal
	// operation the watchdog sleeps on <-ctx.Done() and consumes no
	// resources. After ctx.Done fires, it logs the stuck phase at
	// 2s intervals; the FIRST stuck report (after 5s) also dumps the
	// full goroutine stack so the operator can pinpoint the blocking
	// call without re-running with a debugger.
	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		select {
		case <-watchdogDone:
			return
		case <-ctx.Done():
		}
		// Initial snapshot — what was the loop doing the instant ctx
		// cancelled? This is the most actionable single piece of
		// evidence.
		if ps := bl.loadPhase(); ps != nil {
			bl.logger.Warn("builder loop: ctx cancelled — current phase",
				"phase", ps.name,
				"phase_age", time.Since(ps.enteredAt),
			)
		}
		// Periodic re-snapshots in case the loop stays stuck. 2s is
		// short enough to produce ~15 samples within a 30s shutdown
		// budget, long enough to not spam the log under normal
		// (fast-drain) shutdowns.
		//
		// At the 5s mark (3rd tick), dump ALL goroutine stacks via
		// runtime.Stack. This is the smoking-gun evidence: if the
		// loop is blocked on, say, an upstream tessera future.Get()
		// or a non-ctx-aware channel receive, the stack trace shows
		// exactly the line. Done ONCE to avoid log spam — subsequent
		// ticks just re-log the phase name.
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		dumped := false
		stuckSince := time.Now()
		for {
			select {
			case <-watchdogDone:
				return
			case <-t.C:
				ps := bl.loadPhase()
				if ps == nil {
					continue
				}
				bl.logger.Warn("builder loop: still in phase after ctx cancel",
					"phase", ps.name,
					"phase_age", time.Since(ps.enteredAt),
					"stuck_for", time.Since(stuckSince),
				)
				if !dumped && time.Since(stuckSince) >= 5*time.Second {
					// Full goroutine dump — 1MB cap is enough for
					// ~200 goroutines × 5KB each. Emit at WARN so
					// it surfaces alongside the phase warning, not
					// buried in DEBUG.
					buf := make([]byte, 1<<20)
					n := runtime.Stack(buf, true /* all goroutines */)
					bl.logger.Warn("builder loop: stuck >5s after cancel — full goroutine dump",
						"phase", ps.name,
						"stack", string(buf[:n]),
					)
					dumped = true
				}
			}
		}
	}()

	if err := ctx.Err(); err != nil {
		return nil
	}
	bl.setPhase("recover_on_startup")
	recovered, err := bl.reader.RecoverOnStartup(ctx)
	if err != nil {
		if isContextError(err) {
			bl.logger.Info("builder loop stopped during recovery")
			return nil
		}
		return fmt.Errorf("builder/loop: recover on startup: %w", err)
	}
	if recovered > 0 {
		bl.logger.Warn("recovered stale queue entries", "count", recovered)
	}

	for {
		if err := ctx.Err(); err != nil {
			bl.logger.Info("builder loop stopped",
				"batches", bl.totalBatches.Load(),
				"entries", bl.totalEntries.Load(),
				"errors", bl.totalErrors.Load(),
			)
			return nil
		}

		bl.setPhase("processBatch")
		processed, err := bl.processBatch(ctx)

		if err != nil {
			if isContextError(err) {
				bl.logger.Info("builder loop stopped",
					"batches", bl.totalBatches.Load(),
					"entries", bl.totalEntries.Load(),
				)
				return nil
			}
			// LIVENESS GUARD — Tessera shutdown is a one-way state
			// transition. Treat the same as ctx-cancel: clean exit,
			// no error log, no consecutive_errors bump. Same restart-
			// recovery story as the sequencer (see
			// sequencer/loop.go::handleEntryError): entries stay in
			// WAL StatePending, antispam dedupes on next-process
			// AppendLeaf. The matching boundary translation lives in
			// tessera/embedded_appender.go::AppendLeaf; the pinning
			// test is TestEmbeddedAppender_AppendLeaf_TypedShutdownError.
			if errors.Is(err, optessera.ErrAppenderShutdown) {
				bl.logger.Info("builder loop stopped — tessera appender shut down",
					"batches", bl.totalBatches.Load(),
					"entries", bl.totalEntries.Load(),
				)
				return nil
			}

			bl.totalErrors.Add(1)
			consecutive := bl.consecutiveErr.Add(1)

			bl.logger.Error("batch processing failed",
				"error", err,
				"consecutive_errors", consecutive,
			)

			backoff := bl.cfg.PollInterval * time.Duration(min(int(consecutive), 10))
			bl.setPhase("error_backoff")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		bl.consecutiveErr.Store(0)

		if processed > 0 {
			bl.totalBatches.Add(1)
			bl.totalEntries.Add(int64(processed))
			continue
		}

		bl.setPhase("idle_wait")
		select {
		case <-ctx.Done():
			bl.logger.Info("builder loop stopped",
				"batches", bl.totalBatches.Load(),
				"entries", bl.totalEntries.Load(),
			)
			return nil
		case <-time.After(bl.cfg.PollInterval):
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 5) processBatch — one builder cycle, fully atomic
// -------------------------------------------------------------------------------------------------

func (bl *BuilderLoop) processBatch(ctx context.Context) (int, error) {
	bl.setPhase("processBatch:read_root")
	var priorRoot [32]byte
	if bl.rootStore != nil {
		// Authoritative path: read priorRoot from smt_root_state.
		// The persisted root is the source of truth across builder
		// restarts; the in-memory tree.rootHash mirrors it after each
		// successful commit.
		st, err := bl.rootStore.Read(ctx)
		if err != nil {
			return 0, fmt.Errorf("read smt root state: %w", err)
		}
		priorRoot = st.CurrentRoot
	} else {
		var err error
		priorRoot, err = bl.tree.Root(ctx)
		if err != nil {
			return 0, fmt.Errorf("prior root: %w", err)
		}
	}

	// ── Step 1: Dequeue batch ─────────────────────────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	bl.setPhase("processBatch:dequeue")
	beginStart := time.Now()
	var seqs []uint64
	dqErr := store.WithReadCommittedTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		var iErr error
		seqs, iErr = bl.reader.BeginBatch(ctx, tx, bl.cfg.BatchSize)
		return iErr
	})
	if dqErr != nil {
		return 0, fmt.Errorf("dequeue: %w", dqErr)
	}
	if len(seqs) == 0 {
		return 0, nil
	}
	beginDur := time.Since(beginStart)

	// Contiguity check on the dequeued seqs. BeginBatch returns
	// `WHERE seq > cursor ORDER BY seq ASC LIMIT N`, so the result
	// should be a contiguous run [cursor+1, cursor+N] when the
	// sequencer has gap-free entry_index visibility. Non-contiguous
	// returns mean entry_index has a transient hole — usually from
	// per-entry-tx commits in sequencer.processOne landing out of
	// order. CommitBatch advances cursor to max(seqs), so any
	// non-contiguous return causes the cursor to LEAPFROG over the
	// missing seqs; once that happens those seqs are skipped
	// forever (the next BeginBatch's `seq > cursor` filter excludes
	// them when they finally commit).
	//
	// firstSeq / lastSeq derived from the ASC-ordered slice; the
	// prior cursor value is implicitly firstSeq-1 because BeginBatch
	// returns rows strictly greater than cursor.
	firstSeq := seqs[0]
	lastSeq := seqs[len(seqs)-1]
	priorCursor := int64(firstSeq) - 1
	expectedIfContiguous := int(lastSeq - firstSeq + 1)
	contiguous := expectedIfContiguous == len(seqs)
	gapsInBatch := expectedIfContiguous - len(seqs)
	if !contiguous {
		// WARN — this is the leapfrog-imminent moment. Surface the
		// first ~16 seqs returned so the operator can correlate the
		// gap pattern with sequencer commit order. The full set is
		// reconstructable from prior commits via firstSeq..lastSeq.
		previewN := len(seqs)
		if previewN > 16 {
			previewN = 16
		}
		bl.logger.Warn("BeginBatch returned non-contiguous seqs — cursor will leapfrog on commit",
			"prior_cursor", priorCursor,
			"first_seq", firstSeq,
			"last_seq", lastSeq,
			"count", len(seqs),
			"expected_if_contiguous", expectedIfContiguous,
			"gaps_in_batch", gapsInBatch,
			"preview_seqs", seqs[:previewN],
		)
	}

	// ── Step 2: Fetch entries in sequence order ───────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	bl.setPhase("processBatch:fetch_entries")
	fetchStart := time.Now()
	metas := make([]*types.EntryWithMetadata, 0, len(seqs))
	for _, seq := range seqs {
		p := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, fetchErr := bl.fetcher.Fetch(ctx, p)
		if fetchErr != nil || meta == nil {
			return 0, fmt.Errorf("fetch seq=%d: not found or error: %w", seq, fetchErr)
		}
		metas = append(metas, meta)
	}
	fetchDur := time.Since(fetchStart)

	// ── Step 3: Split EntryWithMetadata → entries + positions ─────────
	entries := make([]*envelope.Entry, len(metas))
	positions := make([]types.LogPosition, len(metas))
	for i, ewm := range metas {
		entry, desErr := envelope.Deserialize(ewm.CanonicalBytes)
		if desErr != nil {
			return 0, fmt.Errorf("deserialize seq=%d: %w", seqs[i], desErr)
		}
		entries[i] = entry
		positions[i] = ewm.Position
	}

	// ── Step 4: SDK ProcessBatch (overlay-backed) ────────────────────
	//
	// Both stores are wrapped in overlays so pre-commit failures (Tessera
	// AppendLeaf, witness cosignature, downstream PG error) leave the
	// persistent leafStore + nodeStore untouched. On commit success the
	// overlay mutations are extracted and persisted atomically below.
	overlayLeaves := smt.NewOverlayLeafStore(bl.leafStore)
	overlayNodes := smt.NewOverlayNodeStore(bl.nodeStore)
	overlayTree := smt.NewTree(overlayLeaves, overlayNodes)
	overlayTree.SetRoot(priorRoot)

	bl.setPhase("processBatch:sdk_process_batch")
	processStart := time.Now()
	result, err := sdkbuilder.ProcessBatch(
		ctx,
		overlayTree, entries, positions,
		bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer,
	)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}
	processDur := time.Since(processStart)

	// ── Step 5 (PRE-COMMIT): Append entry identities to Tessera ───────
	//
	// SDK alignment: send envelope.EntryIdentity(entry) — the
	// 32-byte SHA-256 of the entry's canonical bytes. Tessera wraps
	// our identity hash with the RFC 6962 leaf prefix (0x00) internally.
	//
	// Tessera is idempotent via antispam: re-Add of the same identity
	// returns the same sequence. So if a later step fails (cosignature,
	// commit) and the builder retries this batch, AppendLeaf produces
	// no duplicate state.
	//
	// Moved BEFORE the Postgres atomic commit so the cosignature step
	// (Step 7) can see the new head and a witness-quorum failure aborts
	// the batch BEFORE non-idempotent Postgres state advances.
	bl.setPhase("processBatch:tessera_append_leaf")
	appendStart := time.Now()
	var lastAppendedIdx uint64
	appendedAtLeastOne := false
	if bl.merkle != nil {
		for i, ewm := range metas {
			identity, idErr := envelope.EntryIdentity(entries[i])
			if idErr != nil {
				return 0, fmt.Errorf("EntryIdentity seq=%d: %w",
					ewm.Position.Sequence, idErr)
			}
			idx, appendErr := bl.merkle.AppendLeaf(ctx, identity[:])
			if appendErr != nil {
				return 0, fmt.Errorf("tessera AppendLeaf seq=%d: %w",
					ewm.Position.Sequence, appendErr)
			}
			lastAppendedIdx = idx
			appendedAtLeastOne = true
		}
	}
	appendDur := time.Since(appendStart)

	// ── Step 6 (PRE-COMMIT): Wait for Tessera Head to reflect batch ──
	//
	// AppendLeaf returns once the integration future resolves with an
	// assigned index, but the signed checkpoint reflecting that index
	// is published asynchronously by upstream Tessera (gated by
	// CheckpointInterval). Cosigning a head that pre-dates this batch
	// would defeat the entire pre-commit gate. Bounded poll bridges
	// the gap between integration and checkpoint publication.
	bl.setPhase("processBatch:wait_for_head")
	headWaitStart := time.Now()
	var head types.TreeHead
	if appendedAtLeastOne && bl.merkle != nil {
		var hErr error
		head, hErr = bl.waitForHeadAtLeast(ctx, lastAppendedIdx+1)
		if hErr != nil {
			return 0, fmt.Errorf("wait for head: %w", hErr)
		}
	}
	headWaitDur := time.Since(headWaitStart)

	// ── Step 6b (PRE-COMMIT): Bind the SMT projection root INTO the
	//                          head before the witness cosignature ──
	//
	// Tessera populates head.RootHash + head.TreeSize from its own
	// RFC 6962 checkpoint; Tessera knows nothing about the ledger's
	// SMT state projection. The cryptographic binding that lets a
	// light client trust the SMT root must be added HERE, before
	// the witnesses sign — otherwise the witness K-of-N quorum
	// signs a head that says nothing about state, and an adversary
	// who can MITM the SMT endpoint can swap a forged root with a
	// membership proof that passes every check we wrote.
	//
	// result.NewRoot is the authoritative SMT root for this batch's
	// committed state, computed by sdkbuilder.ProcessBatch in
	// Step 4 above. The same value is persisted to smt_root_state
	// in Step 8b's atomic commit; the binding here ties the witness-
	// cosigned head to exactly that bytes.
	//
	// SDK contract: types.TreeHead.SMTRoot is a [32]byte field added
	// in attesta v0.8.0. cosign.NewTreeHeadPayload includes the
	// SMT root in the canonical signing bytes (72-byte layout
	// RootHash || SMTRoot || TreeSize_BE).
	head.SMTRoot = result.NewRoot

	// ── Step 6c (PRE-COMMIT): Fail-fast on a zero SMT-root binding ──
	//
	// Defense-in-depth against a future refactor that drops the
	// Step 6b assignment above. attesta v0.8.0+ rejects zero-SMTRoot
	// heads at gossip publish time (CosignedTreeHeadFinding.Validate),
	// but the rejection happens AFTER witness cosignatures are
	// collected — wasting a network round-trip and a quorum vote on
	// a head that will never reach the public CDN.
	//
	// Failing here attributes the bug to the producer (this loop),
	// not the consumer (gossip publisher), so a regression surfaces
	// in the right place and aborts the batch BEFORE the witness
	// HTTP traffic. The check is safe under the SDK contract:
	// result.NewRoot is the SDK-computed SMT root, which is non-zero
	// for any non-empty tree (the empty-tree root is also non-zero
	// per attesta/core/smt.EmptyHash; pre-batch operation always
	// has at least one prior leaf in production).
	//
	// Note: a zero SMTRoot is acceptable for logs that publish no
	// SMT projection (per types.TreeHead.SMTRoot godoc). This ledger
	// DOES publish a projection (smt_root_state), so zero here is
	// always a bug.
	if head.SMTRoot == ([32]byte{}) {
		return 0, fmt.Errorf(
			"builder/loop: head.SMTRoot is zero after Step 6b binding; "+
				"refusing to request witness cosignatures (would be rejected "+
				"at gossip publish time by attesta v0.8.0+ Validate); "+
				"tree_size=%d, root_hash=%x", head.TreeSize, head.RootHash[:8])
	}

	// ── Step 7 (PRE-COMMIT): Request witness cosignatures ────────────
	//
	// HARD STALL: a quorum failure here aborts the batch — the SMT
	// mutations, the buffer save, and the cursor advance are all
	// gated on this returning nil. The builder loop's outer error
	// handler logs + backs off; the next tick re-runs the SAME batch
	// because the cursor hasn't moved. Tessera's antispam dedups the
	// re-AppendLeaf calls.
	//
	// Principle 5 (Melt-Proof) + Principle 12 (Two Clocks): when
	// witnesses are unreachable the builder stops advancing the
	// cursor, the sequencer's MaxBuilderLag gate fires, the WAL
	// saturates, and HTTP admission returns 503 Retry-After. Public
	// API behaviour reflects the network's actual readiness.
	bl.setPhase("processBatch:witness_cosignature")
	cosignStart := time.Now()
	var cosigned types.CosignedTreeHead
	cosignSucceeded := false
	if bl.merkle != nil && bl.witness != nil && head.TreeSize > 0 {
		var cosigErr error
		cosigned, cosigErr = bl.witness.RequestCosignatures(ctx, head)
		if cosigErr != nil {
			if !isContextError(cosigErr) {
				incWitnessQuorumFailures(ctx)
			}
			return 0, fmt.Errorf("witness cosignature: %w", cosigErr)
		}
		cosignSucceeded = true
	}
	cosignDur := time.Since(cosignStart)

	// ── Step 8a: New SMT root (v0.3.0 — produced by ProcessBatch) ────
	//
	// In v0.3.0, ProcessBatch advances the overlay tree's rootHash
	// incrementally via SDK Tree.SetLeaves → jellyfishInsert (O(log N)
	// node writes per leaf, exactly 2N-1 nodes total for N live leaves).
	// result.NewRoot is therefore the committed-after-this-batch root
	// already — no materialisation, no extra walk.
	//
	// The overlay's PostgresNodeStore captured every dirty node along
	// the insert paths; we extract those below and persist them in the
	// same atomic transaction as the leaves, the root, and the cursor.
	newRoot := result.NewRoot
	var maxBatchSeq uint64
	for _, s := range seqs {
		if s > maxBatchSeq {
			maxBatchSeq = s
		}
	}

	// Snapshot the overlay's node mutations BEFORE entering the
	// atomic transaction. Iterating overlay.Mutations() returns a
	// copy keyed by node hash — every entry must be persisted or the
	// committed root will reference a node that doesn't exist on
	// disk, breaking every subsequent proof.
	dirtyNodes := overlayNodes.Mutations()

	// Pre-build the leaf slice and node slice OUTSIDE the atomic tx
	// so the tx's wire critical section is as short as possible (a
	// long-running tx blocks vacuum and inflates dead-tuple bloat on
	// builder_cursor + smt_leaves). All of the serialization /
	// allocation work happens here; the tx body below is just three
	// batched INSERTs + the singleton-row UPDATEs.
	leavesToWrite := make([]types.SMTLeaf, len(result.Mutations))
	for i, mut := range result.Mutations {
		leavesToWrite[i] = types.SMTLeaf{
			Key:          mut.LeafKey,
			OriginTip:    mut.NewOriginTip,
			AuthorityTip: mut.NewAuthorityTip,
		}
	}
	nodesToWrite := make([]smt.Node, 0, len(dirtyNodes))
	for _, n := range dirtyNodes {
		nodesToWrite = append(nodesToWrite, n)
	}

	// ── Step 8: Atomic commit ─────────────────────────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	bl.setPhase("processBatch:atomic_commit")
	var leavesAffected, nodesAffected int64
	commitStart := time.Now()
	commitErr := store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		// Leaves first — every mutation produced by ProcessBatch
		// becomes a row in smt_leaves. SetBatchTx collapses the N
		// row-upserts into ONE round-trip via `unnest($1::bytea[],
		// $2::bytea[], $3::bytea[])`. This is THE per-batch latency
		// fix: the prior `for _, mut := range result.Mutations` loop
		// paid one synchronous PG hop per leaf, capping builder
		// throughput at ~loop-overhead × per-row-rtt ≈ ~200 ent/sec
		// even with cosign fully parallel.
		var setErr error
		leavesAffected, setErr = bl.leafStore.SetBatchTx(ctx, tx, leavesToWrite)
		if setErr != nil {
			return fmt.Errorf("set leaves batch (n=%d): %w", len(leavesToWrite), setErr)
		}
		// Invariant: every input leaf is either inserted (new key)
		// or updated (existing key) — PG counts both as 1 affected
		// row under ON CONFLICT DO UPDATE. A mismatch is pathological
		// and means the in-batch slice had a duplicate leaf_key
		// (which sha256(LogDID||seq) makes near-impossible across
		// distinct seqs). Surface it loudly inside the tx so we see
		// the exact batch.
		if leavesAffected != int64(len(leavesToWrite)) {
			bl.logger.Warn("SetBatchTx rows-affected mismatch — leaves silently collapsed via ON CONFLICT",
				"input_leaves", len(leavesToWrite),
				"rows_affected", leavesAffected,
				"collapsed", int64(len(leavesToWrite))-leavesAffected,
				"first_seq", firstSeq,
				"last_seq", lastSeq,
			)
		}

		// Nodes second — every dirty Jellyfish node captured by the
		// overlay during ProcessBatch is INSERT ON CONFLICT DO NOTHING
		// into jellyfish_nodes. Content-addressed storage means
		// duplicates (same hash, same payload) are no-ops; the
		// transaction is bounded by the number of unique new nodes
		// (~33 per leaf at N=10^10, well within PG's per-tx budget).
		// PutBatchTx collapses the M row-inserts into ONE round-trip.
		var putErr error
		nodesAffected, putErr = bl.nodeStore.PutBatchTx(ctx, tx, nodesToWrite)
		if putErr != nil {
			return fmt.Errorf("put nodes batch (n=%d): %w", len(nodesToWrite), putErr)
		}

		// New root atomic with leaves + nodes so readers never see a
		// {root, store} mismatch.
		if bl.rootStore != nil {
			if rErr := bl.rootStore.SetTx(ctx, tx, newRoot, maxBatchSeq); rErr != nil {
				return fmt.Errorf("set smt root state: %w", rErr)
			}
		}

		if bl.bufferStore != nil && result.UpdatedBuffer != nil {
			if bufErr := bl.bufferStore.SaveTx(ctx, tx, result.UpdatedBuffer); bufErr != nil {
				return fmt.Errorf("save buffer: %w", bufErr)
			}
		}

		// commit_intent — emitted INSIDE the atomic tx, immediately
		// before CommitBatch advances the cursor. Pairs with the
		// BeginBatch-side contiguity log to give end-to-end evidence
		// of every cursor movement. Especially useful at leapfrog
		// time: if `delta > count` the cursor advanced further than
		// the seq count justifies, and the difference is the number
		// of seqs lost.
		bl.logger.Info("commit_intent",
			"prior_cursor", priorCursor,
			"new_cursor", lastSeq,
			"delta", int64(lastSeq)-priorCursor,
			"seqs_count", len(seqs),
			"contiguous", contiguous,
			"leaves_in_tx", len(leavesToWrite),
			"nodes_in_tx", len(nodesToWrite),
		)
		if qErr := bl.reader.CommitBatch(ctx, tx, seqs); qErr != nil {
			return fmt.Errorf("commit batch: %w", qErr)
		}

		return nil
	})
	if commitErr != nil {
		return 0, fmt.Errorf("atomic commit: %w", commitErr)
	}
	commitDur := time.Since(commitStart)

	// Advance the read-side tree's rootHash to match the persisted
	// state. API handlers reading from bl.tree now observe the new
	// root. (The handler's Tree shares the same PostgresNodeStore and
	// PostgresLeafStore; SetRoot is the in-memory cursor.)
	bl.tree.SetRoot(newRoot)

	// ──────────────────────────────────────────────────────────────────
	// POST-COMMIT: best-effort publishing. Failure here doesn't roll
	// back the durable Postgres + Tessera + tree-head-sigs state.
	// ──────────────────────────────────────────────────────────────────

	// ── Step 9: Publish cosigned checkpoint to public CDN ─────────────
	//
	// Strict STH Finality: the public checkpoint file the network
	// reads from CDNs is updated ONLY here, AFTER K-of-N witnesses
	// have signed the head. Before this point, the CDN's cosigned
	// checkpoint reflects the previous quorum-finalized head.
	bl.setPhase("processBatch:publish_checkpoint")
	if cosignSucceeded && bl.merkle != nil {
		if pubErr := bl.merkle.PublishCosignedCheckpoint(ctx, cosigned); pubErr != nil {
			if !isContextError(pubErr) {
				bl.logger.Warn("publish cosigned checkpoint failed",
					"tree_size", cosigned.TreeSize,
					"root_hash", fmt.Sprintf("%x", cosigned.RootHash[:8]),
					"smt_root", fmt.Sprintf("%x", cosigned.SMTRoot[:8]),
					"error", pubErr)
			}
		}
	}

	// ── Step 10: Publish derivation commitment ────────────────────────
	bl.setPhase("processBatch:publish_commitment")
	if bl.commitPub != nil && len(positions) > 0 {
		bl.commitPub.MaybePublish(ctx, len(seqs),
			positions[0], positions[len(positions)-1],
			priorRoot, result)
	}

	if result.UpdatedBuffer != nil {
		bl.buffer = result.UpdatedBuffer
	}

	// Per-stage timing — surfaces which step dominates each batch.
	// Stages match the inline section headers above:
	//   begin     = Step 1  (BeginBatch dequeue)
	//   fetch     = Step 2  (PG entry fetch loop)
	//   process   = Step 4  (SDK ProcessBatch — overlay SMT mutations)
	//   append    = Step 5  (Tessera AppendLeaf loop)
	//   head_wait = Step 6  (Tessera signed-checkpoint catch-up poll)
	//   cosign    = Step 7  (K-of-N witness cosignature collection)
	//   commit    = Step 8  (atomic PG tx: leaves+nodes+root+buffer+cursor+fsync)
	// total = sum of the above; gives the per-batch latency floor.
	//
	// leaves_written / nodes_written verify the N+1 fix landed:
	// every batch must show ONE log line covering leaves_written N
	// AND nodes_written M, NOT N+M separate PG round-trips. Pair
	// this with `commit` duration to compute the effective
	// throughput of SetBatchTx / PutBatchTx; a regression to
	// per-row SetTx / PutTx would show up immediately as commit
	// climbing back into the seconds.
	//
	// process_per_leaf / nodes_per_leaf / cum_seq answer the SCALING
	// question: at 10M leaves, does the SDK's jellyfishInsert path
	// remain constant-time per leaf? The Jellyfish-Patricia tree's
	// theoretical depth is ⌈log2(N)⌉ ≈ 23 at N=10M, so per-leaf node
	// touches should converge to ~24 in steady state regardless of
	// cum_seq. A rising process_per_leaf with cum_seq names PG /
	// LRU cache thrash; a flat curve names "constant per leaf as
	// designed". Either way the decision is data-driven.
	processPerLeafUs := int64(0)
	nodesPerLeaf := float64(0)
	if len(seqs) > 0 {
		processPerLeafUs = processDur.Microseconds() / int64(len(seqs))
		nodesPerLeaf = float64(nodesAffected) / float64(len(seqs))
	}
	// cum_seq = sequences processed before this batch + this batch.
	// Used as a proxy for "cumulative SMT working set"; SMT root is
	// monotonically advancing with seqs so this directly characterises
	// the test's scale axis when comparing log lines across cycles.
	cumSeqs := bl.totalEntries.Load() + int64(len(seqs))
	totalDur := beginDur + fetchDur + processDur + appendDur +
		headWaitDur + cosignDur + commitDur
	bl.logger.Info("batch processed",
		"entries", len(seqs),
		"new_leaves", result.NewLeafCounts,
		"leaves_written", len(leavesToWrite),
		"leaves_affected", leavesAffected,
		"nodes_written", len(nodesToWrite),
		"nodes_affected", nodesAffected,
		"nodes_skipped_existing", int64(len(nodesToWrite))-nodesAffected,
		"process_per_leaf_us", processPerLeafUs,
		"nodes_per_leaf", fmt.Sprintf("%.2f", nodesPerLeaf),
		"cum_seq", cumSeqs,
		"path_a", result.PathACounts,
		"path_b", result.PathBCounts,
		"path_c", result.PathCCounts,
		"path_d", result.PathDCounts,
		"commentary", result.CommentaryCounts,
		"contiguous", contiguous,
		"begin", beginDur.Round(time.Microsecond),
		"fetch", fetchDur.Round(time.Microsecond),
		"process", processDur.Round(time.Microsecond),
		"append", appendDur.Round(time.Microsecond),
		"head_wait", headWaitDur.Round(time.Microsecond),
		"cosign", cosignDur.Round(time.Microsecond),
		"commit", commitDur.Round(time.Microsecond),
		"total", totalDur.Round(time.Microsecond),
	)

	return len(seqs), nil
}

// -------------------------------------------------------------------------------------------------
// 6) Observability
// -------------------------------------------------------------------------------------------------

func (bl *BuilderLoop) Stats() (batches, entries, errs int64) {
	return bl.totalBatches.Load(), bl.totalEntries.Load(), bl.totalErrors.Load()
}

// -------------------------------------------------------------------------------------------------
// 7) Helpers
// -------------------------------------------------------------------------------------------------

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// headWaitInterval and headWaitMax bound waitForHeadAtLeast.
// Tessera's CheckpointInterval default is 1s; we tolerate up to
// 5s of integration-future-resolved-but-checkpoint-not-yet-published
// before failing the batch and letting the builder retry.
const (
	headWaitInterval = 100 * time.Millisecond
	headWaitMax      = 5 * time.Second
)

// waitForHeadAtLeast polls the underlying MerkleAppender's Head()
// until TreeSize >= minSize or the bounded deadline expires. Used
// after a batch of AppendLeaf calls to wait for Tessera's signed
// checkpoint to catch up to the leaves we just added — the head
// the witnesses are asked to cosign MUST cover this batch.
//
// Bounded: returns an error after headWaitMax so a stuck Tessera
// publisher doesn't block the builder forever. The next builder
// cycle retries; AppendLeaf is idempotent.
func (bl *BuilderLoop) waitForHeadAtLeast(ctx context.Context, minSize uint64) (types.TreeHead, error) {
	deadline := time.Now().Add(headWaitMax)
	for {
		head, err := bl.merkle.Head()
		if err == nil && head.TreeSize >= minSize {
			return head, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return types.TreeHead{}, fmt.Errorf(
					"head not at size >= %d after %v: %w",
					minSize, headWaitMax, err)
			}
			return types.TreeHead{}, fmt.Errorf(
				"head not at size >= %d after %v (stuck at %d)",
				minSize, headWaitMax, head.TreeSize)
		}
		select {
		case <-ctx.Done():
			return types.TreeHead{}, ctx.Err()
		case <-time.After(headWaitInterval):
		}
	}
}
