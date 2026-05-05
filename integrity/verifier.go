/*
FILE PATH: integrity/verifier.go

Verifier — read-only surface that returns the leaf hash at a given
sequence from Tessera's tiles. Used by Detector.SampleVerify.

DESIGN:

	Tile-backed: tessera/tile_reader.go's ReadEntryTile already does
	the heavy lifting (LRU-cached fetch + c2sp.org/tlog-tiles parsing).
	This Verifier wraps it with the seq → (tile, offset) arithmetic
	and the 32-byte hash extractor.

	Hash-only tiles (Phase 1B): each entry tile carries 32-byte SHA-256
	identities, so HashAt is one tile fetch + one slice. No envelope
	deserialization happens at this layer; the ledger only checks
	hashes here.
*/
package integrity

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/ledger/tessera"
)

// EntriesPerEntryTile is the c2sp.org/tlog-tiles entry-tile fanout.
// 256 hashes per tile. Lifted from upstream Tessera so this file
// doesn't import the upstream library directly.
const EntriesPerEntryTile = 256

// Verifier is the read-only Tessera-side check. Implementations
// answer: "what hash did Tessera commit to at sequence seq?"
type Verifier interface {
	HashAt(ctx context.Context, seq uint64) ([32]byte, error)
}

// TileReader is the minimal surface from tessera/tile_reader.go that
// the verifier needs. *tessera.TileReader satisfies it; tests inject
// fakes.
type TileReader interface {
	ReadEntryTile(ctx context.Context, index uint64) ([]byte, error)
}

// tileVerifier satisfies Verifier by reading entry tiles via a
// TileReader and extracting the 32-byte hash at the relevant offset.
type tileVerifier struct {
	tiles TileReader
}

// NewVerifier returns a Verifier rooted at the supplied tile reader.
func NewVerifier(tiles TileReader) Verifier {
	return &tileVerifier{tiles: tiles}
}

// HashAt resolves seq → (tileIndex, offset), reads the entry tile,
// and extracts the 32-byte hash.
func (v *tileVerifier) HashAt(ctx context.Context, seq uint64) ([32]byte, error) {
	if v == nil || v.tiles == nil {
		return [32]byte{}, fmt.Errorf("integrity/verifier: nil reader")
	}
	tileIndex := seq / EntriesPerEntryTile
	offset := seq % EntriesPerEntryTile

	tileData, err := v.tiles.ReadEntryTile(ctx, tileIndex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("integrity/verifier: read entry tile %d: %w", tileIndex, err)
	}

	hashBytes, err := tessera.ParseEntryBundle(tileData, offset)
	if err != nil {
		return [32]byte{}, fmt.Errorf("integrity/verifier: parse tile %d offset %d: %w",
			tileIndex, offset, err)
	}
	if len(hashBytes) != 32 {
		return [32]byte{}, fmt.Errorf("integrity/verifier: hash at seq=%d is %d bytes, want 32",
			seq, len(hashBytes))
	}
	var h [32]byte
	copy(h[:], hashBytes)
	return h, nil
}
