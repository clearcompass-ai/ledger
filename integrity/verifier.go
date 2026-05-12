/*
FILE PATH: integrity/verifier.go

Verifier — read-only surface that returns the leaf hash at a given
sequence from Tessera's tiles. Used by Detector.SampleVerify.

DESIGN — consume the SDK abstraction, do not poke the filesystem:

	The verifier consumes a tessera/client.TileFetcherFunc supplied
	by the composition root. The upstream contract is explicit:
	"when asked to fetch a partial tile (p != 0), fall-back to
	fetching the corresponding full tile if the partial one does
	not exist." Implementations MUST surface os.ErrIsNotExist when
	neither path materializes.

	We ask for the partial count that EXACTLY contains our offset
	— partial = offset + 1 (wrapping to 0 = full-tile request when
	offset == 255). When Tessera's current partial is at a higher
	count (say p=232 while we ask for p=12), both the requested
	.p/12 and the full path are absent, so the fetcher returns
	os.ErrIsNotExist; we translate that to ErrTileNotYetFlushed
	and the Detector skips the sample. Once the tile completes at
	256 entries, the full-tile path resolves cleanly for every
	offset and verification coverage returns to 100%.

	The post-256-entries coverage hole is intentional: it trades
	rightmost-tail verification for a substantially simpler
	verifier — no tree-size plumbing, no adapter wrapper, no
	separate size reader interface. The integrity detector is for
	long-tail divergence detection (10B-scale trees), not for
	freshness checks on the first 256 entries.

	Hash-only tiles: each entry tile carries 32-byte SHA-256
	identities, so HashAt is one bundle fetch + one slice. No
	envelope deserialization happens at this layer.
*/
package integrity

import (
	"context"
	"errors"
	"fmt"
	"os"

	tessera_client "github.com/transparency-dev/tessera/client"

	"github.com/clearcompass-ai/ledger/tessera"
)

// EntriesPerEntryTile is the c2sp.org/tlog-tiles entry-tile fanout.
// 256 hashes per tile. Lifted from upstream Tessera so this file
// doesn't depend on the upstream constant directly.
const EntriesPerEntryTile = 256

// Verifier is the read-only Tessera-side check. Implementations
// answer: "what hash did Tessera commit to at sequence seq?"
type Verifier interface {
	HashAt(ctx context.Context, seq uint64) ([32]byte, error)
}

// tileVerifier satisfies Verifier by reading entry tiles via an
// upstream tessera/client.TileFetcherFunc.
type tileVerifier struct {
	fetcher tessera_client.TileFetcherFunc
}

// NewVerifier returns a Verifier rooted at the supplied fetcher.
// *tessera.TileReader.Fetch satisfies the upstream signature
// (level, index, p) directly — pass it without a wrapper at the
// composition root.
func NewVerifier(fetcher tessera_client.TileFetcherFunc) Verifier {
	return &tileVerifier{fetcher: fetcher}
}

// HashAt resolves seq → (tileIndex, offset), requests the
// minimum partial that contains our offset (= offset + 1, or 0
// for the full tile when offset == 255), and extracts the
// 32-byte hash. Returns ErrTileNotYetFlushed when neither the
// requested partial nor the full tile exists yet — transient by
// construction.
func (v *tileVerifier) HashAt(ctx context.Context, seq uint64) ([32]byte, error) {
	if v == nil || v.fetcher == nil {
		return [32]byte{}, fmt.Errorf("integrity/verifier: nil fetcher")
	}
	tileIndex := seq / EntriesPerEntryTile
	offsetInTile := seq % EntriesPerEntryTile

	// Tessera contract: p=0 means request the full tile; p>0
	// requests the partial tile carrying p entries. We ask for
	// the smallest partial that contains our offset. If the tile
	// is full (offset==255), partial wraps to 0 = full-tile path.
	var p uint8
	if offsetInTile+1 < EntriesPerEntryTile {
		p = uint8(offsetInTile + 1)
	}

	body, err := v.fetcher(ctx, 0, tileIndex, p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return [32]byte{}, fmt.Errorf("seq=%d tile=%d p=%d: %w",
				seq, tileIndex, p, ErrTileNotYetFlushed)
		}
		return [32]byte{}, fmt.Errorf("integrity/verifier: fetch tile %d p=%d: %w",
			tileIndex, p, err)
	}

	hashBytes, err := tessera.ParseEntryBundle(body, offsetInTile)
	if err != nil {
		return [32]byte{}, fmt.Errorf("integrity/verifier: parse tile %d offset %d: %w",
			tileIndex, offsetInTile, err)
	}
	if len(hashBytes) != 32 {
		return [32]byte{}, fmt.Errorf("integrity/verifier: hash at seq=%d is %d bytes, want 32",
			seq, len(hashBytes))
	}
	var h [32]byte
	copy(h[:], hashBytes)
	return h, nil
}
