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
	LogDID string
	BatchSize int
	PollInterval time.Duration
	DeltaWindow int
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
type MerkleAppender interface {
	AppendLeaf(data []byte) (uint64, error)
	Head() (types.TreeHead, error)
}

// WitnessCosigner requests cosignatures on tree heads.
type WitnessCosigner interface {
	RequestCosignatures(ctx context.Context, head types.TreeHead) error
}

// -------------------------------------------------------------------------------------------------
// 3) BuilderLoop
// -------------------------------------------------------------------------------------------------

// BuilderLoop is the continuous builder goroutine.
type BuilderLoop struct {
	cfg LoopConfig
	db *pgxpool.Pool
	tree *smt.Tree
	leafStore *store.PostgresLeafStore
	nodeCache *store.PostgresNodeCache
	// reader is the CT-native log-tailing follower that reads new
	// sequences from entry_index and advances builder_cursor in the
	// builder's atomic commit. See builder/cursor_reader.go.
	reader BatchReader
	fetcher types.EntryFetcher
	schema sdkbuilder.SchemaResolver
	buffer *sdkbuilder.DeltaWindowBuffer
	bufferStore *DeltaBufferStore
	commitPub *CommitmentPublisher
	merkle MerkleAppender
	witness WitnessCosigner
	logger *slog.Logger

	// Observability counters (atomic, lock-free).
	totalBatches atomic.Int64
	totalEntries atomic.Int64
	totalErrors atomic.Int64
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
	priorRoot, err := bl.tree.Root()
	if err != nil {
		return 0, fmt.Errorf("prior root: %w", err)
	}

	// ── Step 1: Dequeue batch ─────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var seqs []uint64
	err = store.WithReadCommittedTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		var dqErr error
		seqs, dqErr = bl.reader.BeginBatch(ctx, tx, bl.cfg.BatchSize)
		return dqErr
	})
	if err != nil {
		return 0, fmt.Errorf("dequeue: %w", err)
	}
	if len(seqs) == 0 {
		return 0, nil
	}

	// ── Step 2: Fetch entries in sequence order ───────────────────────
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	metas := make([]*types.EntryWithMetadata, 0, len(seqs))
	for _, seq := range seqs {
		p := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, fetchErr := bl.fetcher.Fetch(p)
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
		overlayTree, entries, positions,
		bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer,
	)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}

	// ── Step 5: Atomic commit ─────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	err = store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
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
	if err != nil {
		return 0, fmt.Errorf("atomic commit: %w", err)
	}

	// ──────────────────────────────────────────────────────────────────
	// POST-COMMIT: Steps 6-8 are best-effort. The atomic state is safe.
	// ──────────────────────────────────────────────────────────────────

	// ── Step 6: Append to Merkle tree — ENTRY IDENTITY (post-commit) ──
	//
	// SDK alignment: send envelope.EntryIdentity(entry) — the
	// 32-byte SHA-256 of the entry's canonical bytes. This is the
	// Tessera "Entry.Identity()" value. The signature is NOT part of
	// entry identity — multiple valid signatures over the same entry
	// (rare but possible with detached sig schemes) must produce the
	// same Merkle leaf.
	//
	// Tessera then wraps our identity hash with the RFC 6962 leaf prefix
	// (0x00) internally. Do NOT call envelope.EntryLeafHash here — that
	// would double-apply the prefix.
	//
	// Idempotency: same entry identity → same Tessera position.
	// Crash between commit and this append → safe to re-run on restart.
	if bl.merkle != nil {
		for i, ewm := range metas {
			identity := envelope.EntryIdentity(entries[i])
			if _, appendErr := bl.merkle.AppendLeaf(identity[:]); appendErr != nil {
				bl.logger.Error("Tessera append failed",
					"seq", ewm.Position.Sequence, "error", appendErr)
			}
		}
	}

	// ── Step 7: Publish derivation commitment ─────────────────────────
	if bl.commitPub != nil && len(positions) > 0 {
		bl.commitPub.MaybePublish(ctx, len(seqs),
			positions[0], positions[len(positions)-1],
			priorRoot, result)
	}

	// ── Step 8: Request witness cosignatures ──────────────────────────
	if bl.merkle != nil && bl.witness != nil {
		head, headErr := bl.merkle.Head()
		if headErr == nil && head.TreeSize > 0 {
			if cosigErr := bl.witness.RequestCosignatures(ctx, head); cosigErr != nil {
				if !isContextError(cosigErr) {
					bl.logger.Warn("witness cosignature request failed", "error", cosigErr)
				}
			}
		}
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
