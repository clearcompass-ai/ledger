/*
FILE PATH:

	tessera/proof_adapter.go

DESCRIPTION:

	TesseraAdapter implements the ledger's MerkleAppender interface
	over a Tessera AppenderBackend and generates Merkle inclusion and
	consistency proofs from tiles — the tlog-tiles format has no
	server-side proof endpoints, so the ledger computes them locally.

	The builder depends only on the MerkleAppender interface
	(AppendLeaf, Head). Proof methods are on the concrete type for
	HTTP handler consumption.

KEY ARCHITECTURAL DECISIONS:

  - Hash-only AppendLeaf: receives 32-byte SHA-256(wire_bytes), not
    full entry data. The ledger computes the hash in
    builder/loop.go step 6 and passes only the digest. Tessera
    never sees the full entry data.

  - Canonical proof computation: InclusionProof and
    ConsistencyProof delegate to tessera/client.ProofBuilder,
    which uses transparency-dev/merkle's proof.Inclusion /
    proof.Consistency to build the node list, then resolves each
    node via the standard tlog-tiles (level, index) →
    (tile_level, tile_index, node_level, node_index) coordinate
    mapping. This is the same code path every Tessera consumer
    uses; a hand-rolled algorithm previously lived here and was
    broken in three independent ways (treated RFC 6962 levels as
    tile levels, returned raw entry-tile data instead of leaf
    hashes, and mixed absolute/local coordinates when descending
    into right subtrees), so this file is now a thin adapter and
    NOT a re-implementation of merkle proof math.

  - TileReader.Fetch implements client.TileFetcherFunc with the
    partial-tile fallback semantics the tlog-tiles spec requires.
    See tessera/tile_reader.go.

OVERVIEW:

	AppendLeaf(hash) → backend.AppendLeaf(hash) → assigned index.
	Head()           → backend.Head()           → parsed tree state.
	RawInclusionProof(idx, size)  → tessera/client.ProofBuilder.InclusionProof
	ConsistencyProof(old, new)    → tessera/client.ProofBuilder.ConsistencyProof

KEY DEPENDENCIES:
  - tessera/embedded_appender.go: in-process upstream Tessera
    (AppenderBackend implementation used in production).
  - tessera/tile_reader.go: LRU-cached tile fetching with
    partial-tile fallback (TileReader.Fetch).
  - github.com/transparency-dev/tessera/client: canonical proof
    builder used by every Tessera consumer.
  - builder/loop.go: calls AppendLeaf and Head via the
    MerkleAppender interface.
  - api/tree.go: calls RawInclusionProof and ConsistencyProof for
    HTTP endpoints.
*/
package tessera

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/clearcompass-ai/attesta/types"
	tclient "github.com/transparency-dev/tessera/client"
)

// -------------------------------------------------------------------------------------------------
// 1) TesseraAdapter — core adapter
// -------------------------------------------------------------------------------------------------

// AppenderBackend is the minimal append-side surface TesseraAdapter
// needs. The production implementation is *EmbeddedAppender —
// in-process upstream Tessera over the POSIX storage driver.
//
// The adapter is backend-agnostic: AppendLeaf forwards to the
// backend, Head forwards to the backend, and proof computation
// (Inclusion / Consistency) reads tiles via *TileReader without
// touching the backend at all. This split is the load-bearing
// invariant — proof methods don't care which appender a leaf went
// through, they only care about the immutable tiles those
// integrations produced.
//
// PublishCosignedCheckpoint writes the K-of-N CosignedTreeHead to
// the backend's configured public path (see
// tessera.AppenderOptions.PublicCheckpointPath). Backends MUST
// implement this method (returning a graceful nil when no public
// path is configured) so the builder loop can forward the call
// uniformly across embedded and read-only adapters.
type AppenderBackend interface {
	AppendLeaf(ctx context.Context, data []byte) (uint64, error)
	Head() (types.TreeHead, error)
	PublishCosignedCheckpoint(ctx context.Context, head types.CosignedTreeHead) error
}

// TesseraAdapter implements the ledger's MerkleAppender interface
// over an AppenderBackend and uses tiles for proof computation.
type TesseraAdapter struct {
	backend    AppenderBackend
	tileReader *TileReader
	logger     *slog.Logger

	// ctx is the process-lifetime context bound at construction.
	// The InclusionProver / ConsistencyProver interfaces in
	// api/tree.go (RawInclusionProof, ConsistencyProof,
	// TypedInclusionProof) do not accept a per-request ctx.
	// Binding the process ctx here means tile fetches inside
	// proof computation cancel cleanly on SIGTERM rather than
	// leaking goroutines past shutdown.
	ctx context.Context
}

// NewTesseraAdapter creates an adapter over the supplied backend.
// Production wires *EmbeddedAppender (in-process upstream Tessera);
// tests inject lightweight fakes that satisfy AppenderBackend.
//
// ctx is the process-lifetime context: parent of every internal
// tile fetch issued by the no-ctx prover interface methods. Pass
// the same ctx that gates the builder loop and HTTP server.
func NewTesseraAdapter(ctx context.Context, backend AppenderBackend, tileReader *TileReader, logger *slog.Logger) *TesseraAdapter {
	if ctx == nil {
		ctx = context.Background()
	}
	return &TesseraAdapter{
		backend:    backend,
		tileReader: tileReader,
		logger:     logger,
		ctx:        ctx,
	}
}

// -------------------------------------------------------------------------------------------------
// 2) MerkleAppender Interface — AppendLeaf + Head
// -------------------------------------------------------------------------------------------------

// AppendLeaf forwards a 32-byte SHA-256 hash to the underlying
// AppenderBackend. The hash is the canonical entry identity
// (envelope.EntryIdentity); the builder computes it in loop.go
// step 6 and passes only the digest. Tessera never sees the full
// entry data.
//
// STRICT: returns an error if data is not exactly 32 bytes. This is
// a programming error in the caller, not a runtime condition.
func (a *TesseraAdapter) AppendLeaf(ctx context.Context, data []byte) (uint64, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("tessera/proof_adapter: AppendLeaf requires exactly 32 bytes (SHA-256 hash), got %d — this is a programming error in the caller", len(data))
	}
	return a.backend.AppendLeaf(ctx, data)
}

// Head returns the current Merkle tree head from the underlying
// backend (HTTP checkpoint fetch or LogReader.ReadCheckpoint
// depending on which AppenderBackend implementation was wired).
func (a *TesseraAdapter) Head() (types.TreeHead, error) {
	return a.backend.Head()
}

// PublishCosignedCheckpoint forwards the K-of-N cosigned head to
// the underlying backend's public-checkpoint writer. Builder loop
// uses this only after a successful witness quorum collect.
func (a *TesseraAdapter) PublishCosignedCheckpoint(
	ctx context.Context, head types.CosignedTreeHead,
) error {
	return a.backend.PublishCosignedCheckpoint(ctx, head)
}

// -------------------------------------------------------------------------------------------------
// 3) Inclusion Proofs — delegated to tessera/client.ProofBuilder
// -------------------------------------------------------------------------------------------------

// RawInclusionProof computes a Merkle inclusion proof from tiles and returns
// it as a JSON-serializable structure for api/tree.go to encode.
//
// Implementation delegates to tessera/client.ProofBuilder, which uses the
// canonical transparency-dev/merkle proof algorithm. The returned hashes
// are RFC 6962 sibling hashes (leaf-level hashes are H(0x00 || data),
// internal hashes are H(0x01 || left || right)) and verify against the
// tree-of-size-treeSize root using proof.VerifyInclusion.
func (a *TesseraAdapter) RawInclusionProof(position, treeSize uint64) (any, error) {
	if position >= treeSize {
		return nil, fmt.Errorf("tessera/proof: leaf %d >= tree size %d", position, treeSize)
	}

	siblings, err := a.computeInclusionSiblings(position, treeSize)
	if err != nil {
		return nil, err
	}

	siblingHex := make([]string, len(siblings))
	for i, s := range siblings {
		siblingHex[i] = fmt.Sprintf("%x", s)
	}

	return map[string]any{
		"leaf_index": position,
		"tree_size":  treeSize,
		"hashes":     siblingHex,
	}, nil
}

// TypedInclusionProof computes a Merkle inclusion proof parsed into the SDK's
// types.MerkleProof. Used by cross-log verifiers which call
// smt.VerifyMerkleInclusion(proof, rootHash).
//
// Note: LeafHash is left zeroed — the cross-log verifier already has the
// entry bytes and computes the leaf hash itself before calling
// VerifyMerkleInclusion.
func (a *TesseraAdapter) TypedInclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	if position >= treeSize {
		return nil, fmt.Errorf("tessera/proof: leaf %d >= tree size %d", position, treeSize)
	}

	siblings, err := a.computeInclusionSiblings(position, treeSize)
	if err != nil {
		return nil, err
	}

	// types.MerkleProof carries [32]byte siblings; copy from the []byte
	// hashes returned by the proof builder.
	out := make([][32]byte, len(siblings))
	for i, s := range siblings {
		if len(s) != 32 {
			return nil, fmt.Errorf("tessera/proof: sibling %d has %d bytes, want 32", i, len(s))
		}
		copy(out[i][:], s)
	}

	return &types.MerkleProof{
		LeafPosition: position,
		Siblings:     out,
		TreeSize:     treeSize,
		// LeafHash zeroed — caller sets from entry bytes before verification.
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Consistency Proofs — delegated to tessera/client.ProofBuilder
// -------------------------------------------------------------------------------------------------

// ConsistencyProof computes a consistency proof between two tree sizes.
// Used by api/tree.go and witnesses. The builder never calls this.
func (a *TesseraAdapter) ConsistencyProof(oldSize, newSize uint64) (any, error) {
	if oldSize > newSize {
		return nil, fmt.Errorf("tessera/proof: old %d > new %d", oldSize, newSize)
	}
	if oldSize == 0 || oldSize == newSize {
		// Trivially consistent — proof.Consistency returns an empty list,
		// which we mirror here without spinning up a ProofBuilder.
		return map[string]any{
			"old_size": oldSize,
			"new_size": newSize,
			"hashes":   []string{},
		}, nil
	}

	pb, err := tclient.NewProofBuilder(a.ctx, newSize, a.tileReader.Fetch)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: ProofBuilder(newSize=%d): %w", newSize, err)
	}

	siblings, err := pb.ConsistencyProof(a.ctx, oldSize, newSize)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: ConsistencyProof(old=%d new=%d): %w", oldSize, newSize, err)
	}

	siblingHex := make([]string, len(siblings))
	for i, s := range siblings {
		siblingHex[i] = fmt.Sprintf("%x", s)
	}

	return map[string]any{
		"old_size": oldSize,
		"new_size": newSize,
		"hashes":   siblingHex,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Shared helper — builds a ProofBuilder and returns sibling hashes
// -------------------------------------------------------------------------------------------------

// computeInclusionSiblings is the single sibling-list builder shared by
// RawInclusionProof and TypedInclusionProof. Returns the raw [][]byte
// from tessera/client.ProofBuilder.InclusionProof; callers reshape into
// the JSON or typed-struct forms they need.
func (a *TesseraAdapter) computeInclusionSiblings(position, treeSize uint64) ([][]byte, error) {
	pb, err := tclient.NewProofBuilder(a.ctx, treeSize, a.tileReader.Fetch)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: ProofBuilder(treeSize=%d): %w", treeSize, err)
	}

	siblings, err := pb.InclusionProof(a.ctx, position)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: InclusionProof(idx=%d treeSize=%d): %w", position, treeSize, err)
	}
	return siblings, nil
}
