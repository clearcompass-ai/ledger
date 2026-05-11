/*
FILE PATH:

	tessera/tile_reader.go

DESCRIPTION:

	Tile reader with c2sp.org/tlog-tiles compliant path encoding. Reads immutable
	Merkle tree tiles (hash tiles and entry data tiles) from the Tessera personality's
	HTTP read API. Read-through LRU cache minimizes backend calls.

	Tile paths follow the c2sp.org/tlog-tiles spec:
	  Hash tiles:  tile/{L}/{N}          (e.g., tile/0/x001/x234/067)
	  Entry tiles: tile/entries/{N}      (e.g., tile/entries/x000/042)
	Where {N} uses three-digit path components with 'x' prefix for full tiles.

KEY ARCHITECTURAL DECISIONS:
  - c2sp.org path encoding: three-digit segments, 'x' prefix for full (256-entry)
    tiles, '.p/{count}' suffix for partial tiles. This is the canonical format
    that Tessera's POSIX driver writes and GCS/S3 drivers serve.
  - Dual read methods: ReadTile for hash tiles (level > 0), ReadEntryTile for
    entry data tiles (tile/entries/ path). Both go through the same LRU cache.
  - Tiles are immutable after write — cached indefinitely once read.
  - LRU with access-counter eviction (not random).
  - No write path: Tessera personality manages tile writes. Ledger only reads.

OVERVIEW:

	ReadTile(ctx, level, index) → cache check → fetch via HTTP → cache store → return.
	ReadEntryTile(ctx, index) → same flow but with tile/entries/ path prefix.
	TilePath(level, index) → c2sp.org three-digit path encoding.

KEY DEPENDENCIES:
  - tessera/proof_adapter.go: Reads tiles for proof computation.
  - tessera/entry_reader.go: Reads entry tiles for byte hydration.
  - tessera-personality: The HTTP server serving static tile files.
*/
package tessera

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/transparency-dev/tessera/api/layout"
)

// -------------------------------------------------------------------------------------------------
// 1) Tile Backend Interface
// -------------------------------------------------------------------------------------------------

// TileBackend reads Merkle tree tiles from a storage backend.
type TileBackend interface {
	// ReadTile fetches a tile by its URL path (relative to base URL).
	// The path is c2sp.org encoded (e.g., "tile/0/x001/x234/067").
	ReadTileByPath(ctx context.Context, path string) ([]byte, error)
}

// -------------------------------------------------------------------------------------------------
// 2) TileReader — LRU-cached tile reader
// -------------------------------------------------------------------------------------------------

// TileReader wraps a TileBackend with an in-memory LRU cache.
// Tiles are immutable — once written by Tessera, they never change.
// Cache indefinitely.
type TileReader struct {
	backend TileBackend
	mu      sync.RWMutex
	cache   map[string]tileEntry
	counter int64
	maxSize int
}

type tileEntry struct {
	data   []byte
	access int64
}

// NewTileReader creates a cached tile reader.
func NewTileReader(backend TileBackend, cacheSize int) *TileReader {
	if cacheSize < 100 {
		cacheSize = 10000
	}
	return &TileReader{
		backend: backend,
		cache:   make(map[string]tileEntry, cacheSize),
		maxSize: cacheSize,
	}
}

// ReadTile reads a hash tile at the given level and index.
// Level 0 hash tiles contain the first level of Merkle hashes.
// Higher levels contain internal node hashes.
func (tr *TileReader) ReadTile(ctx context.Context, level, index uint64) ([]byte, error) {
	path := HashTilePath(level, index)
	return tr.readCached(ctx, path)
}

// ReadEntryTile reads an entry data tile at the given index.
// Entry tiles contain the actual entry data (our 32-byte SHA-256 hashes)
// packed per c2sp.org/tlog-tiles format (uint16-length-prefixed entries).
func (tr *TileReader) ReadEntryTile(ctx context.Context, index uint64) ([]byte, error) {
	path := EntryTilePath(index)
	return tr.readCached(ctx, path)
}

// Fetch implements tessera/client.TileFetcherFunc — reads a hash tile
// (level, index) with partial-tile fallback semantics required by the
// tlog-tiles client contract:
//
//   - If p > 0, attempt the partial-tile path tile/{L}/{N}.p/{p} first.
//   - Fall back to the full-tile path tile/{L}/{N} on os.ErrNotExist.
//
// The fallback is required because tessera's POSIX storage driver writes
// frontier tiles as ".p/N" partial files until they fill up; once a tile
// is full (256 hashes) the .p/N path is replaced atomically with the
// full-tile path. Callers that always request full tiles miss the
// frontier and cannot generate proofs that touch the rightmost subtree.
//
// Cache keys are full paths, so partial tiles at different widths each
// get distinct cache entries — safe because the contents at a given
// (level, index, p) are immutable.
func (tr *TileReader) Fetch(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
	if p > 0 {
		partialPath := layout.TilePath(level, index, p)
		data, err := tr.readCached(ctx, partialPath)
		if err == nil {
			return data, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return tr.readCached(ctx, layout.TilePath(level, index, 0))
}

// FetchEntryBundle implements tessera/client.EntryBundleFetcherFunc —
// reads an entry bundle tile with the same partial-fallback semantics
// as Fetch (above). Currently unused by proof generation (which only
// reads hash tiles) but provided for callers that hydrate entry data
// via the canonical tessera/client APIs.
func (tr *TileReader) FetchEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error) {
	if p > 0 {
		partialPath := layout.EntriesPath(index, p)
		data, err := tr.readCached(ctx, partialPath)
		if err == nil {
			return data, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return tr.readCached(ctx, layout.EntriesPath(index, 0))
}

// readCached is the shared cache-through read path.
func (tr *TileReader) readCached(ctx context.Context, path string) ([]byte, error) {
	// Cache read.
	tr.mu.RLock()
	entry, ok := tr.cache[path]
	tr.mu.RUnlock()
	if ok {
		tr.mu.Lock()
		tr.counter++
		entry.access = tr.counter
		tr.cache[path] = entry
		tr.mu.Unlock()
		return entry.data, nil
	}

	// Cache miss — fetch from backend.
	data, err := tr.backend.ReadTileByPath(ctx, path)
	if err != nil {
		return nil, err
	}

	// Cache store.
	tr.mu.Lock()
	if len(tr.cache) >= tr.maxSize {
		tr.evictLRU()
	}
	tr.counter++
	tr.cache[path] = tileEntry{data: data, access: tr.counter}
	tr.mu.Unlock()

	return data, nil
}

// evictLRU removes the least recently accessed 25% of entries. Caller holds mu.
func (tr *TileReader) evictLRU() {
	target := tr.maxSize * 3 / 4
	if len(tr.cache) <= target {
		return
	}
	type kv struct {
		key    string
		access int64
	}
	entries := make([]kv, 0, len(tr.cache))
	for k, v := range tr.cache {
		entries = append(entries, kv{key: k, access: v.access})
	}
	// Sort by access ascending (oldest first).
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].access < entries[i].access {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	toRemove := len(tr.cache) - target
	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(tr.cache, entries[i].key)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) c2sp.org/tlog-tiles Path Encoding
// -------------------------------------------------------------------------------------------------

// HashTilePath returns the c2sp.org/tlog-tiles path for a hash tile.
//
// Format: tile/{L}/{N}
// Where {N} is encoded as three-digit path segments:
//
//	tile/0/x001/x234/067 for tile index 1,234,067 (full tile, 256 entries)
//	tile/0/001/234/067.p/42 for a partial tile with 42 entries
//
// The 'x' prefix indicates a full tile (exactly 256 entries). Partial tiles
// omit the 'x' prefix on the final segment and append '.p/{count}'.
// For simplicity, we always request as full tiles. The server returns
// partial tiles transparently when the tile is at the tree frontier.
func HashTilePath(level, index uint64) string {
	return fmt.Sprintf("tile/%d/%s", level, encodeTileIndex(index))
}

// EntryTilePath returns the c2sp.org/tlog-tiles path for an entry data tile.
//
// Format: tile/entries/{N}
// Same three-digit encoding as hash tiles.
func EntryTilePath(index uint64) string {
	return fmt.Sprintf("tile/entries/%s", encodeTileIndex(index))
}

// encodeTileIndex encodes a tile index using c2sp.org three-digit path segments.
//
// The encoding splits the index into groups of three decimal digits,
// most-significant first, each as a path component. Non-final components
// get the 'x' prefix (indicating they are complete groups). The final
// component has no prefix.
//
// Examples:
//
//	0 → "000"
//	42 → "042"
//	1234 → "x001/234"
//	1234067 → "x001/x234/067"
//	0 → "000"
func encodeTileIndex(index uint64) string {
	if index == 0 {
		return "000"
	}

	// Convert to decimal string.
	s := fmt.Sprintf("%d", index)

	// Pad to multiple of 3.
	for len(s)%3 != 0 {
		s = "0" + s
	}

	// Split into 3-digit groups.
	var parts []string
	for i := 0; i < len(s); i += 3 {
		parts = append(parts, s[i:i+3])
	}

	// Non-final parts get 'x' prefix.
	for i := 0; i < len(parts)-1; i++ {
		parts[i] = "x" + parts[i]
	}

	return strings.Join(parts, "/")
}

// The ledger reads tiles directly from a POSIX directory via
// POSIXTileBackend (defined in posix_tile_backend.go), shared with
// the embedded upstream Tessera writer. See
// tessera/embedded_appender.go for the in-process construction path.
