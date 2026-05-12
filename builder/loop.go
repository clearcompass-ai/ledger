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

	bl.logger.Info("builder loop started",
		"log_did", bl.cfg.LogDID,
		"batch_size", bl.cfg.BatchSize,
		"poll_interval", bl.cfg.PollInterval,
	)

	if err := ctx.Err(); err != nil {
		return nil
	}
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

		processed, err := bl.processBatch(ctx)

		if err != nil {
			if isContextError(err) {
				bl.logger.Info("builder loop stopped",
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

	// ── Step 2: Fetch entries in sequence order ───────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

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
		if setErr := bl.leafStore.SetBatchTx(ctx, tx, leavesToWrite); setErr != nil {
			return fmt.Errorf("set leaves batch (n=%d): %w", len(leavesToWrite), setErr)
		}

		// Nodes second — every dirty Jellyfish node captured by the
		// overlay during ProcessBatch is INSERT ON CONFLICT DO NOTHING
		// into jellyfish_nodes. Content-addressed storage means
		// duplicates (same hash, same payload) are no-ops; the
		// transaction is bounded by the number of unique new nodes
		// (~33 per leaf at N=10^10, well within PG's per-tx budget).
		// PutBatchTx collapses the M row-inserts into ONE round-trip.
		if putErr := bl.nodeStore.PutBatchTx(ctx, tx, nodesToWrite); putErr != nil {
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
	if cosignSucceeded && bl.merkle != nil {
		if pubErr := bl.merkle.PublishCosignedCheckpoint(ctx, cosigned); pubErr != nil {
			if !isContextError(pubErr) {
				bl.logger.Warn("publish cosigned checkpoint failed",
					"tree_size", cosigned.TreeSize, "error", pubErr)
			}
		}
	}

	// ── Step 10: Publish derivation commitment ────────────────────────
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
	totalDur := beginDur + fetchDur + processDur + appendDur +
		headWaitDur + cosignDur + commitDur
	bl.logger.Info("batch processed",
		"entries", len(seqs),
		"new_leaves", result.NewLeafCounts,
		"leaves_written", len(leavesToWrite),
		"nodes_written", len(nodesToWrite),
		"path_a", result.PathACounts,
		"path_b", result.PathBCounts,
		"path_c", result.PathCCounts,
		"path_d", result.PathDCounts,
		"commentary", result.CommentaryCounts,
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
