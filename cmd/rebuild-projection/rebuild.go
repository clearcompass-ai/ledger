/*
FILE PATH: cmd/rebuild-projection/rebuild.go

Rebuild walks the canonical Static-CT tile store and reconstructs
the Ledger's Postgres projection tables (entry_index, smt_leaves,
smt_root_state, builder_cursor) bit-exact from tiles.

This is the load-bearing implementation behind the
PG-as-projection invariant (docs/production_readiness.md §C2). If
Postgres is wiped — disaster recovery, region migration, schema
rebase — running this against the surviving tile store reconstructs
the read-model projection to the byte. The tile store + the gossip
network are the architecture's actual source of truth; PG is a
high-performance ephemeral cache.

WHAT IT REBUILDS:

  entry_index      — one INSERT per entry, with the same columns
                     the sequencer writes (canonical_hash,
                     log_time, signer_did, target_root,
                     cosignature_of, schema_ref). Bit-exact.
  smt_leaves       — derived via SDK ProcessBatch, replicating the
                     builder loop exactly. Bit-exact in the
                     {LeafKey, OriginTip, AuthorityTip} columns
                     for any deterministic-derivation entry set.
  smt_root_state   — final root computed via materialize-once
                     after all leaves are persisted. Matches the
                     root the live builder maintained at the
                     same tree size.
  builder_cursor   — set to treeSize-1 (the last integrated seq).

WHAT IT DOES NOT REBUILD (PHASE 2):

  tree_heads, tree_head_sigs  — these come from gossiped
                                KindCosignedTreeHead events. The
                                gossip-replay rebuild is a
                                separate concern and tracked in
                                §E2/§C2 of the production-readiness
                                doc.
  witness_sets                — projection of
                                KindOriginatorRotation events on
                                the gossip feed; rebuild from
                                gossip is the §E2 work.
  credits, sessions           — admission-side; not derivable
                                from tiles (they are
                                external-input state).
  commitment_*                — derived inline by the sequencer
                                from each entry; covered by the
                                same SDK ProcessBatch the SMT
                                derivation uses, but this PHASE 1
                                cut does NOT re-populate the
                                commitment indexes.

CORRECTNESS MODEL:

	The SDK's sdkbuilder.ProcessBatch is deterministic per the
	"Forward-Only Protocol Evolution" + "Deterministic Idempotency"
	principles (SDK §7, §8). Re-running it against the same entries
	in the same seq order produces the same Mutations and the same
	Root. We exploit that to validate the rebuild: after Rebuild()
	returns, the test asserts that smt_root_state, smt_leaves, and
	entry_index match a pre-wipe snapshot byte-for-byte.

LIMITS:

	PHASE 1 holds the entire walked entry slice in memory while
	building the SMT. At 1M entries (~256 bytes/entry × 1M = 256
	MB) that's fine; at 100M entries (~25 GB) it isn't. The
	architecture supports streaming — process batches of N seqs
	at a time, advance cursor + persist mutations, continue.
	That extension lives behind the (cursor-driven) BatchSize knob
	but for THIS commit the batched path is exercised by the
	integration test at small scale to prove the invariant. The
	cost analysis + RTO budget for production-scale rebuild is
	§C2 in docs/production_readiness.md.
*/
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	optessera "github.com/clearcompass-ai/ledger/tessera"

	"github.com/transparency-dev/tessera/api/layout"
)

// RebuildDeps captures everything Rebuild needs to walk tiles and
// repopulate Postgres. Construct from the CLI's main; tests pass an
// in-process instance.
//
// SOURCE-OF-TRUTH NOTE (load-bearing for the architecture):
//
//	The ledger's AppendLeaf path is HASH-ONLY — Tessera receives
//	only the 32-byte SHA-256(canonical_bytes) and stores it in
//	tile/entries/{N}. The FULL canonical envelope bytes live in
//	the bytestore (S3/GCS/CDN) keyed by (seq, hash). So neither
//	the tile store NOR the bytestore is the source of truth on
//	its own — BOTH are. The rebuild walks tile/entries to learn
//	the (seq → hash) mapping, then reads canonical bytes from
//	the bytestore at the same coordinates the live shipper
//	writes them to.
type RebuildDeps struct {
	// TileDir is the filesystem path to the Tessera POSIX tile
	// store (the directory that holds checkpoint, tile/entries/...,
	// and tile/{L}/...). Same directory the writer's POSIX driver
	// was configured with.
	TileDir string

	// Bytestore is the canonical-byte store. The shipper writes
	// `entries/<seq16>/<hash64>` blobs here as it advances; the
	// rebuild reads them back to reconstruct the envelope.Entry
	// each tile/entries hash refers to. Any bytestore.Reader
	// (Memory for tests, S3/GCS for production) satisfies this.
	Bytestore bytestore.Reader

	// Pool is the Postgres pool the rebuild writes to. The caller
	// is responsible for ensuring migrations have run (RunMigrations)
	// and that the projection tables are in the expected pre-rebuild
	// state — typically empty (DELETE FROM) or freshly-migrated.
	Pool *pgxpool.Pool

	// LogDID is the log identity that owns these tiles. The SDK
	// uses it to short-circuit PathD on cross-log references; the
	// rebuild uses it as the LogPosition.LogDID for every entry.
	LogDID string

	// BatchSize bounds how many entries are processed per atomic
	// commit. Larger batches amortize PG round-trips; smaller
	// batches bound memory + lock-hold time. 500 is the same
	// default the live builder loop uses.
	BatchSize int

	// Logger.
	Logger *slog.Logger
}

// Stats is returned by Rebuild for observability + assertion.
type Stats struct {
	TreeSize         uint64
	EntriesProcessed uint64
	LeavesWritten    uint64
	Root             [32]byte
	Duration         time.Duration
}

// Rebuild reconstructs Postgres projections from the tile store.
// See file-level comment for the architectural contract.
func Rebuild(ctx context.Context, deps RebuildDeps) (Stats, error) {
	start := time.Now()
	if deps.BatchSize <= 0 {
		deps.BatchSize = 500
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Bytestore == nil {
		return Stats{}, fmt.Errorf("rebuild: Bytestore is required (tile/entries holds 32-byte hashes only; canonical envelope bytes live in the bytestore)")
	}

	// ── Step 1: Open the tile store + read the published checkpoint
	//
	// The checkpoint is the network's commitment to the size+root
	// of the tree we're rebuilding. Its TreeSize is the upper bound
	// for our seq walk; any leaf at seq >= TreeSize is not part of
	// the published log.
	backend, err := optessera.NewPOSIXTileBackend(deps.TileDir)
	if err != nil {
		return Stats{}, fmt.Errorf("rebuild: open tile backend: %w", err)
	}
	tileReader := optessera.NewTileReader(backend, 1024)
	cpBytes, err := backend.ReadCheckpoint(ctx)
	if err != nil {
		return Stats{}, fmt.Errorf("rebuild: read checkpoint: %w", err)
	}
	head, err := optessera.ParseCheckpoint(cpBytes)
	if err != nil {
		return Stats{}, fmt.Errorf("rebuild: parse checkpoint: %w", err)
	}
	treeSize := head.TreeSize
	if treeSize == 0 {
		deps.Logger.Info("rebuild: checkpoint reports empty log; nothing to rebuild")
		return Stats{Duration: time.Since(start)}, nil
	}
	deps.Logger.Info("rebuild: checkpoint",
		"tree_size", treeSize,
		"root_hash", fmt.Sprintf("%x", head.RootHash[:8]))

	// ── Step 2: Wire SDK fetcher + projection stores
	//
	// fetcher is tile-backed so cross-log/intra-log references
	// resolve from the SAME source of truth we're rebuilding from
	// (no chicken-and-egg with entry_index, which doesn't exist
	// yet). deltaBuffer + ProcessBatch produce the canonical
	// mutations the live builder also produced.
	fetcher := &tileFetcher{
		reader:    tileReader,
		bytestore: deps.Bytestore,
		logDID:    deps.LogDID,
		treeSize:  treeSize,
	}
	entryStore := store.NewEntryStore(deps.Pool)
	leafStore := store.NewPostgresLeafStore(deps.Pool)
	nodeStore := store.NewPostgresNodeStore(ctx, deps.Pool, 0) // 0 → default 1M-entry LRU
	rootStore := store.NewSMTRootStateStore(deps.Pool)
	cursorStore := store.NewSequenceCursor(deps.Pool)
	deltaBuffer := sdkbuilder.NewDeltaWindowBuffer(10)

	// Persistent rebuild-time tree. Per-batch overlays wrap this so
	// pre-commit failures don't leak. After each batch's atomic
	// commit we advance the persistent tree's rootHash via SetRoot
	// so the next batch builds on the committed state.
	mainTree := smt.NewTree(leafStore, nodeStore)
	currentRoot := smt.EmptyHash
	mainTree.SetRoot(currentRoot)

	// ── Step 3: Walk seqs 0..treeSize-1 in batches; ProcessBatch
	//            per chunk; persist atomically; advance cursor.
	var entriesProcessed, leavesWritten uint64
	for batchStart := uint64(0); batchStart < treeSize; batchStart += uint64(deps.BatchSize) {
		if err := ctx.Err(); err != nil {
			return Stats{}, fmt.Errorf("rebuild: ctx cancelled: %w", err)
		}
		batchEnd := batchStart + uint64(deps.BatchSize)
		if batchEnd > treeSize {
			batchEnd = treeSize
		}

		entries, positions, rows, err := readBatchFromTiles(ctx, fetcher, deps.LogDID, batchStart, batchEnd)
		if err != nil {
			return Stats{}, fmt.Errorf("rebuild: read batch [%d, %d): %w", batchStart, batchEnd, err)
		}

		// Per-batch overlay tree wrapped over the persistent
		// leafStore + nodeStore. The overlay captures every leaf and
		// every dirty Jellyfish node ProcessBatch produces;
		// pre-commit failures (PG error etc.) discard the overlays
		// and leave the persistent stores untouched. On commit
		// success we extract the overlay mutations and persist them
		// in the same atomic transaction as entry_index + cursor.
		overlayLeaves := smt.NewOverlayLeafStore(leafStore)
		overlayNodes := smt.NewOverlayNodeStore(nodeStore)
		overlayTree := smt.NewTree(overlayLeaves, overlayNodes)
		overlayTree.SetRoot(currentRoot)

		result, err := sdkbuilder.ProcessBatch(ctx, overlayTree,
			entries, positions, fetcher, nil, deps.LogDID, deltaBuffer)
		if err != nil {
			return Stats{}, fmt.Errorf("rebuild: ProcessBatch [%d, %d): %w", batchStart, batchEnd, err)
		}

		dirtyNodes := overlayNodes.Mutations()

		// Atomic commit: entry_index + smt_leaves + jellyfish_nodes
		// + cursor advance. Same atomicity shape as builder/loop.go.
		commitErr := store.WithSerializableTx(ctx, deps.Pool, func(ctx context.Context, tx pgx.Tx) error {
			for _, row := range rows {
				if iErr := entryStore.Insert(ctx, tx, row); iErr != nil {
					return fmt.Errorf("entry_index insert seq=%d: %w", row.SequenceNumber, iErr)
				}
			}
			for _, mut := range result.Mutations {
				leaf := types.SMTLeaf{
					Key:          mut.LeafKey,
					OriginTip:    mut.NewOriginTip,
					AuthorityTip: mut.NewAuthorityTip,
				}
				if lErr := leafStore.SetTx(ctx, tx, mut.LeafKey, leaf); lErr != nil {
					return fmt.Errorf("smt_leaves set %x: %w", mut.LeafKey[:8], lErr)
				}
			}
			for _, node := range dirtyNodes {
				if _, pErr := nodeStore.PutTx(ctx, tx, node); pErr != nil {
					return fmt.Errorf("jellyfish_nodes put: %w", pErr)
				}
			}
			// builder_cursor advances to batchEnd-1: the
			// highest sequence we just committed.
			return cursorStore.AdvanceTx(ctx, tx, batchEnd-1)
		})
		if commitErr != nil {
			return Stats{}, fmt.Errorf("rebuild: atomic commit [%d, %d): %w", batchStart, batchEnd, commitErr)
		}

		// Advance the persistent tree's rootHash so the next batch
		// starts from the just-committed state.
		currentRoot = result.NewRoot
		mainTree.SetRoot(currentRoot)
		if result.UpdatedBuffer != nil {
			deltaBuffer = result.UpdatedBuffer
		}

		entriesProcessed += batchEnd - batchStart
		leavesWritten += uint64(len(result.Mutations))
		deps.Logger.Info("rebuild: batch committed",
			"range", fmt.Sprintf("[%d, %d)", batchStart, batchEnd),
			"new_leaves", len(result.Mutations),
			"total_leaves", leavesWritten,
		)
	}

	// ── Step 4: Persist the final SMT root to smt_root_state.
	//
	// currentRoot already IS the post-final-batch root — every batch
	// commit above advanced it via mainTree.SetRoot. No separate
	// materialisation pass needed; the v0.3.0 Jellyfish tree
	// maintains the root incrementally and the per-batch atomic
	// commits already persisted every node it references.
	finalRoot := currentRoot
	commitErr := store.WithSerializableTx(ctx, deps.Pool, func(ctx context.Context, tx pgx.Tx) error {
		return rootStore.SetTx(ctx, tx, finalRoot, treeSize-1)
	})
	if commitErr != nil {
		return Stats{}, fmt.Errorf("rebuild: persist smt_root_state: %w", commitErr)
	}
	_ = mainTree // kept for future expansion (e.g. rebuild-time read endpoints)

	return Stats{
		TreeSize:         treeSize,
		EntriesProcessed: entriesProcessed,
		LeavesWritten:    leavesWritten,
		Root:             finalRoot,
		Duration:         time.Since(start),
	}, nil
}

// readBatchFromTiles pulls entries for [batchStart, batchEnd) from
// the tile bundles, deserializes each, and returns parallel slices
// of (entry, position, entry_index row).
//
// The deserialization mirrors what the sequencer wrote on the live
// path — same TargetRoot / CosignatureOf / SchemaRef serialization,
// same time.UnixMicro encoding for log_time — so the rebuilt rows
// are bit-exact equal to the originals.
func readBatchFromTiles(ctx context.Context, fetcher *tileFetcher, logDID string, batchStart, batchEnd uint64) (
	entries []*envelope.Entry,
	positions []types.LogPosition,
	rows []store.EntryRow,
	err error,
) {
	count := batchEnd - batchStart
	entries = make([]*envelope.Entry, 0, count)
	positions = make([]types.LogPosition, 0, count)
	rows = make([]store.EntryRow, 0, count)
	for seq := batchStart; seq < batchEnd; seq++ {
		pos := types.LogPosition{LogDID: logDID, Sequence: seq}
		ewm, fErr := fetcher.Fetch(ctx, pos)
		if fErr != nil {
			return nil, nil, nil, fmt.Errorf("fetch seq=%d: %w", seq, fErr)
		}
		entry, dErr := envelope.Deserialize(ewm.CanonicalBytes)
		if dErr != nil {
			return nil, nil, nil, fmt.Errorf("deserialize seq=%d: %w", seq, dErr)
		}
		hash, hErr := envelope.EntryIdentity(entry)
		if hErr != nil {
			return nil, nil, nil, fmt.Errorf("entry_identity seq=%d: %w", seq, hErr)
		}
		entries = append(entries, entry)
		positions = append(positions, pos)
		rows = append(rows, entryRowFor(seq, hash, entry))
	}
	return entries, positions, rows, nil
}

// entryRowFor builds the EntryRow with the SAME extraction logic
// the sequencer uses (sequencer/loop.go:287-304). Any drift here
// produces a non-bit-exact rebuild and the integration test fails.
func entryRowFor(seq uint64, hash [32]byte, entry *envelope.Entry) store.EntryRow {
	var targetRoot, cosigOf, schemaRef []byte
	if entry.Header.TargetRoot != nil {
		targetRoot = store.SerializeLogPosition(*entry.Header.TargetRoot)
	}
	if entry.Header.CosignatureOf != nil {
		cosigOf = store.SerializeLogPosition(*entry.Header.CosignatureOf)
	}
	if entry.Header.SchemaRef != nil {
		schemaRef = store.SerializeLogPosition(*entry.Header.SchemaRef)
	}
	var logTime time.Time
	if entry.Header.EventTime != 0 {
		logTime = time.UnixMicro(entry.Header.EventTime).UTC()
	}
	return store.EntryRow{
		SequenceNumber: seq,
		CanonicalHash:  hash,
		LogTime:        logTime,
		SignerDID:      entry.Header.SignerDID,
		TargetRoot:     targetRoot,
		CosignatureOf:  cosigOf,
		SchemaRef:      schemaRef,
	}
}

// tileFetcher satisfies types.EntryFetcher by combining two
// authoritative read paths:
//
//  1. tile/entries/{N} (via *optessera.TileReader) — yields the
//     32-byte SHA-256(canonical_bytes) for each seq. This is what
//     Tessera's AppendLeaf stored. It is NOT the canonical
//     envelope bytes — the ledger uses a "hash-only" leaf policy
//     so the tile store never sees full entry payloads.
//
//  2. bytestore at key entries/<seq16>/<hash64> — yields the
//     canonical envelope bytes. The shipper writes these as each
//     entry transitions WAL Sequenced → Shipped; for steady-state
//     reads they're served from S3/GCS + CDN.
//
// Both reads are content-addressed (the bytestore key includes
// the hash discovered from the tile), so the fetcher fails closed
// if the two sources disagree.
type tileFetcher struct {
	reader    *optessera.TileReader
	bytestore bytestore.Reader
	logDID    string
	treeSize  uint64
}

func (f *tileFetcher) Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if pos.LogDID != f.logDID {
		// SDK locality check expects foreign-log refs to fail
		// with a not-found-style error; ProcessBatch treats them
		// as PathD.
		return nil, fmt.Errorf("rebuild/tileFetcher: foreign log %q", pos.LogDID)
	}
	if pos.Sequence >= f.treeSize {
		return nil, fmt.Errorf("rebuild/tileFetcher: seq %d >= treeSize %d", pos.Sequence, f.treeSize)
	}

	// Step 1: read the 32-byte hash from tile/entries.
	const entriesPerBundle = uint64(layout.EntryBundleWidth) // 256
	bundleIdx := pos.Sequence / entriesPerBundle
	offset := pos.Sequence % entriesPerBundle
	p := layout.PartialTileSize(0, bundleIdx, f.treeSize)
	bundleBytes, err := f.reader.FetchEntryBundle(ctx, bundleIdx, p)
	if err != nil {
		return nil, fmt.Errorf("fetch entry bundle %d: %w", bundleIdx, err)
	}
	hashBytes, err := optessera.ParseEntryBundle(bundleBytes, offset)
	if err != nil {
		return nil, fmt.Errorf("parse entry bundle %d offset %d: %w", bundleIdx, offset, err)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("rebuild/tileFetcher: tile/entries seq=%d returned %d bytes, want 32 (hash-only Tessera contract violated)",
			pos.Sequence, len(hashBytes))
	}
	var hash [32]byte
	copy(hash[:], hashBytes)

	// Step 2: read canonical bytes from the bytestore at the
	// (seq, hash) coordinates the live shipper writes to.
	canonical, err := f.bytestore.ReadEntry(ctx, pos.Sequence, hash)
	if err != nil {
		return nil, fmt.Errorf("rebuild/tileFetcher: bytestore.ReadEntry seq=%d hash=%x: %w",
			pos.Sequence, hash[:8], err)
	}

	// Step 3: defense in depth — verify the bytestore blob hashes
	// back to the tile's claim. A mismatch means either a corrupt
	// bytestore blob OR a tile/entries entry that was rewritten.
	// Either is a load-bearing integrity failure; surface it.
	recomputed := envelopeIdentityHash(canonical)
	if recomputed != hash {
		return nil, fmt.Errorf("rebuild/tileFetcher: seq=%d hash mismatch — "+
			"tile says %x, bytestore SHA-256(canonical)=%x — corruption detected",
			pos.Sequence, hash[:8], recomputed[:8])
	}

	out := make([]byte, len(canonical))
	copy(out, canonical)
	return &types.EntryWithMetadata{
		Position:       pos,
		CanonicalBytes: out,
	}, nil
}

// envelopeIdentityHash matches envelope.EntryIdentity without
// re-deserializing: per envelope/tessera_compat.go, identity is
// SHA-256(Serialize(entry)) — equivalently, SHA-256 over the raw
// canonical bytes the bytestore stores.
func envelopeIdentityHash(canonical []byte) [32]byte {
	return sha256.Sum256(canonical)
}
