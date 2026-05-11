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
type BuilderLoop struct {
	cfg       LoopConfig
	db        *pgxpool.Pool
	tree      *smt.Tree
	leafStore *store.PostgresLeafStore
	nodeCache *store.PostgresNodeCache
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

	// rootStore is OPTIONAL. When non-nil, the builder reads the
	// current SMT root from it at the start of each batch, computes
	// the new root incrementally via Tree.ComputeDirtyRoot, and
	// persists it in the atomic commit. /v1/smt/root then reads
	// the cached value (O(1)) instead of materializing all leaves
	// (O(N)).
	//
	// nil → builder skips the incremental-root path. The handler-
	// side materialization in api/proofs.go still produces correct
	// roots and proofs; the system is correct but read-side cost
	// is O(N). Production wiring (cmd/ledger/boot/wire/wire.go)
	// MUST call WithRootStore.
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
	nodeCache *store.PostgresNodeCache,
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
		nodeCache:   nodeCache,
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
	var priorRootSeq uint64
	if bl.rootStore != nil {
		// Authoritative path: read priorRoot from smt_root_state.
		// bl.tree.Root would short-circuit to the empty-tree default
		// for any PostgresLeafStore-backed tree (SDK collectLeafHashes
		// limitation — see store/smt_root_state.go for the bug
		// reference) so the persisted value is the only correct
		// source of truth.
		st, err := bl.rootStore.Read(ctx)
		if err != nil {
			return 0, fmt.Errorf("read smt root state: %w", err)
		}
		priorRoot = st.CurrentRoot
		priorRootSeq = st.CommittedThroughSeq
	} else {
		var err error
		priorRoot, err = bl.tree.Root(ctx)
		if err != nil {
			return 0, fmt.Errorf("prior root: %w", err)
		}
	}
	_ = priorRootSeq // reserved for crash-recovery sanity checks; not used in the current flow

	// ── Step 1: Dequeue batch ─────────────────────────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

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

	// ── Step 2: Fetch entries in sequence order ───────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	metas := make([]*types.EntryWithMetadata, 0, len(seqs))
	for _, seq := range seqs {
		p := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, fetchErr := bl.fetcher.Fetch(ctx, p)
		if fetchErr != nil || meta == nil {
			return 0, fmt.Errorf("fetch seq=%d: not found or error: %w", seq, fetchErr)
		}
		metas = append(metas, meta)
	}

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

	// ── Step 4: SDK ProcessBatch ──────────────────────────────────────
	overlayStore := smt.NewOverlayLeafStore(bl.leafStore)
	overlayTree := smt.NewTree(overlayStore, bl.nodeCache)

	result, err := sdkbuilder.ProcessBatch(
		ctx,
		overlayTree, entries, positions,
		bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer,
	)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}

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

	// ── Step 6 (PRE-COMMIT): Wait for Tessera Head to reflect batch ──
	//
	// AppendLeaf returns once the integration future resolves with an
	// assigned index, but the signed checkpoint reflecting that index
	// is published asynchronously by upstream Tessera (gated by
	// CheckpointInterval). Cosigning a head that pre-dates this batch
	// would defeat the entire pre-commit gate. Bounded poll bridges
	// the gap between integration and checkpoint publication.
	var head types.TreeHead
	if appendedAtLeastOne && bl.merkle != nil {
		var hErr error
		head, hErr = bl.waitForHeadAtLeast(ctx, lastAppendedIdx+1)
		if hErr != nil {
			return 0, fmt.Errorf("wait for head: %w", hErr)
		}
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

	// ── Step 8a: Incremental SMT root + node-cache mutations ─────────
	//
	// Only runs when rootStore is wired. Computes newRoot from
	// priorRoot + batch mutations against an OverlayNodeCache so the
	// cache writes are TRAPPED IN MEMORY until the atomic commit
	// promotes them into the durable backing cache. If the commit
	// rolls back, the trapped writes are discarded — no PG / cache
	// state corruption.
	//
	// ComputeDirtyRoot's caller contract (see attesta SMT docs)
	// requires the cache to be warm with respect to priorRoot. We
	// rely on the PostgresNodeCache write-through from prior
	// successful batches to keep smt_nodes populated; PostgresNodeCache.
	// Get falls through to PG on in-memory miss, so a fresh process
	// (cold in-mem cache) still gets correct sibling hashes.
	var newRoot [32]byte
	var nodeCacheMutations map[[32]byte][]byte
	var maxBatchSeq uint64
	if bl.rootStore != nil {
		// Materialize the dirty-writes map from result.Mutations.
		writes := make(map[[32]byte]types.SMTLeaf, len(result.Mutations))
		for _, mut := range result.Mutations {
			writes[mut.LeafKey] = types.SMTLeaf{
				Key:          mut.LeafKey,
				OriginTip:    mut.NewOriginTip,
				AuthorityTip: mut.NewAuthorityTip,
			}
		}

		// OverlayNodeCache wraps bl.nodeCache and buffers writes
		// in memory. Reads fall through to backing (which uses PG on
		// in-memory miss). So ComputeDirtyRoot sees a consistent
		// "priorRoot tree" via PG state for clean subtrees AND its
		// own dirty writes via the overlay buffer.
		overlay := smt.NewOverlayNodeCache(bl.nodeCache)
		dirtyTree := smt.NewTree(bl.leafStore, overlay)

		var rootErr error
		newRoot, rootErr = dirtyTree.ComputeDirtyRoot(ctx, priorRoot, writes)
		if rootErr != nil {
			return 0, fmt.Errorf("compute dirty root: %w", rootErr)
		}

		// Collect the buffered node updates so the atomic commit can
		// promote them into the durable cache via SetWithDepthTx.
		nodeCacheMutations = overlay.Mutations()

		// Track the highest seq this batch reflects for the root's
		// committed_through_seq column.
		for _, s := range seqs {
			if s > maxBatchSeq {
				maxBatchSeq = s
			}
		}
	}

	// ── Step 8: Atomic commit ─────────────────────────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	commitErr := store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		for _, mut := range result.Mutations {
			leaf := types.SMTLeaf{
				Key:          mut.LeafKey,
				OriginTip:    mut.NewOriginTip,
				AuthorityTip: mut.NewAuthorityTip,
			}
			if setErr := bl.leafStore.SetTx(ctx, tx, mut.LeafKey, leaf); setErr != nil {
				return fmt.Errorf("set leaf %x: %w", mut.LeafKey[:8], setErr)
			}
		}

		// Promote the OverlayNodeCache mutations into the durable
		// backing cache (smt_nodes + in-memory) within this tx so a
		// rollback discards them atomically with the leaf writes. The
		// depth is encoded as 0 here — the SDK's NodeCache.Set
		// interface drops the actual depth, and the depth column on
		// smt_nodes is metadata for WarmCache filtering only, not for
		// correctness.
		if bl.rootStore != nil {
			for k, v := range nodeCacheMutations {
				if sErr := bl.nodeCache.SetWithDepthTx(ctx, tx, k, v, 0); sErr != nil {
					return fmt.Errorf("set smt node %x: %w", k[:8], sErr)
				}
			}
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

	bl.logger.Info("batch processed",
		"entries", len(seqs),
		"new_leaves", result.NewLeafCounts,
		"path_a", result.PathACounts,
		"path_b", result.PathBCounts,
		"path_c", result.PathCCounts,
		"path_d", result.PathDCounts,
		"commentary", result.CommentaryCounts,
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
