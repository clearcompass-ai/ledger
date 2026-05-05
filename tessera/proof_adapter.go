/*
FILE PATH:

	tessera/proof_adapter.go

DESCRIPTION:

	TesseraAdapter implements the ledger's MerkleAppender interface
	over a Tessera AppenderBackend and computes Merkle inclusion and
	consistency proofs locally from tiles — the tlog-tiles format has
	no server-side proof endpoints.

	The builder depends only on the MerkleAppender interface
	(AppendLeaf, Head). Proof methods are on the concrete type for
	HTTP handler consumption.

KEY ARCHITECTURAL DECISIONS:
  - Hash-only AppendLeaf: receives 32-byte SHA-256(wire_bytes), not
    full entry data. The ledger computes the hash in
    builder/loop.go step 6 and passes only the digest. Tessera
    never sees the full entry data.
  - Tile-based proof computation: InclusionProof and
    ConsistencyProof fetch tiles via the ledger's TileReader and
    compute proofs locally using the transparency-dev/merkle
    library. No proof endpoints exist in the tlog-tiles format.
  - TileHashReader bridges TileReader → merkle proof library's
    HashReaderFunc. Fetches tiles on demand, extracts the required
    hashes by tile coordinate.
  - TypedInclusionProof parses into SDK types.MerkleProof for
    cross-log verifiers.

OVERVIEW:

	AppendLeaf(hash) → backend.AppendLeaf(hash) → assigned index.
	Head()           → backend.Head()           → parsed tree state.
	InclusionProof(idx, size) → fetch tiles → compute from hash tree.
	ConsistencyProof(old, new) → fetch tiles → compute from hash tree.

KEY DEPENDENCIES:
  - tessera/embedded_appender.go: in-process upstream Tessera
    (AppenderBackend implementation used in production).
  - tessera/tile_reader.go: LRU-cached tile fetching from the
    POSIX-backed Tessera storage directory.
  - github.com/transparency-dev/merkle: proof computation from
    tiles.
  - builder/loop.go: calls AppendLeaf and Head via the
    MerkleAppender interface.
  - api/tree.go: calls InclusionProof and ConsistencyProof for
    HTTP endpoints.
*/
package tessera

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/bits"

	"github.com/clearcompass-ai/attesta/types"
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
type AppenderBackend interface {
	AppendLeaf(data []byte) (uint64, error)
	Head() (types.TreeHead, error)
}

// TesseraAdapter implements the ledger's MerkleAppender interface
// over an AppenderBackend and uses tiles for proof computation.
type TesseraAdapter struct {
	backend    AppenderBackend
	tileReader *TileReader
	logger     *slog.Logger
}

// NewTesseraAdapter creates an adapter over the supplied backend.
// Production wires *EmbeddedAppender (in-process upstream Tessera);
// tests inject lightweight fakes that satisfy AppenderBackend.
func NewTesseraAdapter(backend AppenderBackend, tileReader *TileReader, logger *slog.Logger) *TesseraAdapter {
	return &TesseraAdapter{
		backend:    backend,
		tileReader: tileReader,
		logger:     logger,
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
func (a *TesseraAdapter) AppendLeaf(data []byte) (uint64, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("tessera/proof_adapter: AppendLeaf requires exactly 32 bytes (SHA-256 hash), got %d — this is a programming error in the caller", len(data))
	}
	return a.backend.AppendLeaf(data)
}

// Head returns the current Merkle tree head from the underlying
// backend (HTTP checkpoint fetch or LogReader.ReadCheckpoint
// depending on which AppenderBackend implementation was wired).
func (a *TesseraAdapter) Head() (types.TreeHead, error) {
	return a.backend.Head()
}

// -------------------------------------------------------------------------------------------------
// 3) Inclusion Proofs — tile-based computation
// -------------------------------------------------------------------------------------------------

// RawInclusionProof computes a Merkle inclusion proof from tiles and returns
// it as a JSON-serializable structure. Used by api/tree.go for HTTP passthrough.
//
// The proof is computed locally from Tessera's static tiles — no server-side
// proof endpoint exists in the tlog-tiles API.
func (a *TesseraAdapter) RawInclusionProof(position, treeSize uint64) (any, error) {
	if position >= treeSize {
		return nil, fmt.Errorf("tessera/proof: leaf %d >= tree size %d", position, treeSize)
	}

	proof, err := a.computeInclusionProof(position, treeSize)
	if err != nil {
		return nil, err
	}

	return proof, nil
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

	return &types.MerkleProof{
		LeafPosition: position,
		Siblings:     siblings,
		TreeSize:     treeSize,
		// LeafHash zeroed — caller sets from entry bytes before verification.
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Consistency Proofs — tile-based computation
// -------------------------------------------------------------------------------------------------

// ConsistencyProof computes a consistency proof between two tree sizes.
// Used by api/tree.go and witnesses. The builder never calls this.
func (a *TesseraAdapter) ConsistencyProof(oldSize, newSize uint64) (any, error) {
	if oldSize >= newSize {
		return nil, fmt.Errorf("tessera/proof: old %d >= new %d", oldSize, newSize)
	}
	if oldSize == 0 {
		// A tree of size 0 is trivially consistent with any tree.
		return json.RawMessage(`{"old_size":0,"new_size":` + fmt.Sprintf("%d", newSize) + `,"hashes":[]}`), nil
	}

	siblings, err := a.computeConsistencySiblings(oldSize, newSize)
	if err != nil {
		return nil, err
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
// 5) Tile-Based Proof Computation Engine
// -------------------------------------------------------------------------------------------------

// computeInclusionProof returns a JSON-friendly inclusion proof structure.
func (a *TesseraAdapter) computeInclusionProof(index, treeSize uint64) (any, error) {
	siblings, err := a.computeInclusionSiblings(index, treeSize)
	if err != nil {
		return nil, err
	}

	siblingHex := make([]string, len(siblings))
	for i, s := range siblings {
		siblingHex[i] = fmt.Sprintf("%x", s)
	}

	return map[string]any{
		"leaf_index": index,
		"tree_size":  treeSize,
		"hashes":     siblingHex,
	}, nil
}

// computeInclusionSiblings computes the sibling path for a Merkle inclusion proof.
// Uses the RFC 6962 proof algorithm, fetching node hashes from tiles on demand.
func (a *TesseraAdapter) computeInclusionSiblings(index, treeSize uint64) ([][32]byte, error) {
	ctx := context.TODO()

	// The inclusion proof is the set of sibling hashes along the path from
	// the leaf to the root. We compute this by decomposing the tree into
	// complete subtrees and collecting the necessary nodes.
	var siblings [][32]byte

	// Walk the tree level by level.
	m := index
	n := treeSize
	level := uint64(0)

	for n > 1 {
		// Size of the left subtree (largest power of 2 < n).
		k := uint64(1) << (bits.Len64(n-1) - 1)

		if m < k {
			// Leaf is in the left subtree. Sibling is the right subtree hash.
			rightHash, err := a.computeSubtreeHash(ctx, k, n, level)
			if err != nil {
				return nil, fmt.Errorf("tessera/proof: right subtree hash at level %d: %w", level, err)
			}
			siblings = append(siblings, rightHash)
			n = k
		} else {
			// Leaf is in the right subtree. Sibling is the left subtree hash.
			leftHash, err := a.fetchNodeHash(ctx, 0, m-m%2, level)
			if err != nil {
				// Fallback: compute left subtree hash.
				leftHash, err = a.computeSubtreeHash(ctx, 0, k, level)
				if err != nil {
					return nil, fmt.Errorf("tessera/proof: left subtree hash at level %d: %w", level, err)
				}
			}
			siblings = append(siblings, leftHash)
			m -= k
			n -= k
		}
		level++
	}

	return siblings, nil
}

// computeConsistencySiblings computes the sibling path for a consistency proof.
func (a *TesseraAdapter) computeConsistencySiblings(oldSize, newSize uint64) ([][32]byte, error) {
	ctx := context.TODO()

	var siblings [][32]byte

	m := oldSize
	n := newSize
	level := uint64(0)
	reportedOld := false

	for m < n {
		k := uint64(1) << (bits.Len64(n-1) - 1)

		if m <= k {
			rightHash, err := a.computeSubtreeHash(ctx, k, n, level)
			if err != nil {
				return nil, fmt.Errorf("tessera/proof: consistency right at level %d: %w", level, err)
			}
			siblings = append(siblings, rightHash)
			n = k
		} else {
			leftHash, err := a.computeSubtreeHash(ctx, 0, k, level)
			if err != nil {
				return nil, fmt.Errorf("tessera/proof: consistency left at level %d: %w", level, err)
			}
			siblings = append(siblings, leftHash)
			m -= k
			n -= k
			if !reportedOld {
				reportedOld = true
			}
		}
		level++
	}

	return siblings, nil
}

// computeSubtreeHash computes the hash of a subtree rooted at [start, end) at the given level.
// For complete binary subtrees, this is a single tile hash at the appropriate level.
// For incomplete subtrees, this recurses.
func (a *TesseraAdapter) computeSubtreeHash(ctx context.Context, start, end, level uint64) ([32]byte, error) {
	n := end - start
	if n == 0 {
		return [32]byte{}, fmt.Errorf("empty subtree")
	}
	if n == 1 {
		return a.fetchNodeHash(ctx, start, start, 0)
	}

	k := uint64(1) << (bits.Len64(n-1) - 1)

	leftHash, err := a.computeSubtreeHash(ctx, start, start+k, level)
	if err != nil {
		return [32]byte{}, err
	}

	rightHash, err := a.computeSubtreeHash(ctx, start+k, end, level)
	if err != nil {
		return [32]byte{}, err
	}

	// RFC 6962: internal node = H(0x01 || left || right)
	return hashChildren(leftHash, rightHash), nil
}

// fetchNodeHash retrieves a hash from the tile tree.
// Level 0 nodes are leaf hashes from entry tiles.
// Higher level nodes come from hash tiles.
func (a *TesseraAdapter) fetchNodeHash(ctx context.Context, nodeIndex, leafIndex, level uint64) ([32]byte, error) {
	// For level 0: read from entry data tiles (which contain our 32-byte hashes).
	if level == 0 {
		tileIndex := leafIndex / entriesPerHashTile
		offset := leafIndex % entriesPerHashTile

		tileData, err := a.tileReader.ReadEntryTile(ctx, tileIndex)
		if err != nil {
			return [32]byte{}, fmt.Errorf("tessera/proof: read entry tile %d: %w", tileIndex, err)
		}

		return extractHashFromEntryTile(tileData, offset)
	}

	// For higher levels: read from hash tiles.
	tileLevel := level
	tileIndex := nodeIndex / entriesPerHashTile
	offset := nodeIndex % entriesPerHashTile

	tileData, err := a.tileReader.ReadTile(ctx, tileLevel, tileIndex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("tessera/proof: read hash tile L%d/%d: %w", tileLevel, tileIndex, err)
	}

	return extractHashFromHashTile(tileData, offset)
}

// -------------------------------------------------------------------------------------------------
// 6) Hash Computation Helpers
// -------------------------------------------------------------------------------------------------

const entriesPerHashTile = 256

// hashChildren computes RFC 6962 internal node hash: H(0x01 || left || right).
func hashChildren(left, right [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = 0x01
	copy(buf[1:33], left[:])
	copy(buf[33:65], right[:])
	return sha256.Sum256(buf[:])
}

// extractHashFromEntryTile reads a 32-byte hash from an entry data tile.
// Entry tiles contain our SHA-256 hashes packed as uint16-length-prefixed entries
// per the c2sp.org/tlog-tiles spec. Each entry is exactly 32 bytes.
func extractHashFromEntryTile(tileData []byte, offset uint64) ([32]byte, error) {
	// Entry tiles use uint16 length prefix per entry per c2sp.org spec.
	// Our entries are always 32 bytes, so each record is 2 + 32 = 34 bytes.
	pos := 0
	for i := uint64(0); i <= offset; i++ {
		if pos+2 > len(tileData) {
			return [32]byte{}, fmt.Errorf("entry tile truncated at entry %d (pos %d, tile %d bytes)",
				i, pos, len(tileData))
		}
		entryLen := int(tileData[pos])<<8 | int(tileData[pos+1])
		pos += 2
		if pos+entryLen > len(tileData) {
			return [32]byte{}, fmt.Errorf("entry tile data truncated at entry %d", i)
		}
		if i == offset {
			if entryLen != 32 {
				return [32]byte{}, fmt.Errorf("entry at offset %d is %d bytes, expected 32 (hash-only)", offset, entryLen)
			}
			var hash [32]byte
			copy(hash[:], tileData[pos:pos+32])
			return hash, nil
		}
		pos += entryLen
	}
	return [32]byte{}, fmt.Errorf("offset %d not found in entry tile", offset)
}

// extractHashFromHashTile reads a 32-byte hash from a hash tile at the given offset.
// Hash tiles are dense: 256 × 32 = 8192 bytes per full tile.
func extractHashFromHashTile(tileData []byte, offset uint64) ([32]byte, error) {
	start := offset * 32
	if start+32 > uint64(len(tileData)) {
		return [32]byte{}, fmt.Errorf("hash tile too short: need offset %d (byte %d), tile is %d bytes",
			offset, start+32, len(tileData))
	}
	var hash [32]byte
	copy(hash[:], tileData[start:start+32])
	return hash, nil
}
