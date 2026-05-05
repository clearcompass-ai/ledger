/*
FILE PATH:
    lifecycle/archive_reader.go

DESCRIPTION:
    Reads entries from archived (frozen) shards. Resolves shard from sequence
    range, fetches entry hashes from archive tile endpoints (cold storage) for
    proof verification, and full entry bytes from the shard's byte archive.

    With hash-only Tessera tiles (Conflict #1 resolution), entry tiles contain
    32-byte SHA-256 hashes — NOT full wire bytes. Full entry bytes are stored
    in a separate byte archive alongside the tiles. Two-step verification:
      1. Prove hash is in the Merkle tree (tile-based inclusion proof).
      2. Prove entry data hashes to that value (SHA-256 of fetched bytes).

KEY ARCHITECTURAL DECISIONS:
    - Hash-only entry tiles: each entry in a tile is exactly 32 bytes.
      Full wire bytes are in the shard's byte archive (separate endpoint).
    - ArchiveReader implements builder.EntryFetcher — same Fetch(pos) interface
      as the live operator's PostgresEntryFetcher. The caller does not know or
      care if an entry is live or archived.
    - Byte archive endpoint: {archive_endpoint}/bytes/{seq} returns the full
      wire bytes for a given sequence number. This is separate from the tile
      read path.
    - Shard metadata includes both tile and byte archive endpoints.

OVERVIEW:
    Fetch(pos)     → resolve shard → fetch wire bytes from byte archive → return.
    FetchHash(pos) → resolve shard → fetch hash from entry tile → return.

SDK ALIGNMENT:
    - v0.3.0-tessera: envelope.StripSignature split a wire entry into
      (canonical, algoID, sigBytes) so EntryWithMetadata could carry the
      sidecar fields SignatureAlgoID and SignatureBytes.
    - v7.75: signatures live INSIDE the canonical bytes (the v6
      multi-sig section appended by envelope.Serialize). The wire bytes
      ARE the canonical bytes; envelope.StripSignature is removed.
      EntryWithMetadata now exposes only CanonicalBytes, LogTime, and
      Position. Callers that need the primary signature's algoID or raw
      bytes call envelope.Deserialize(meta.CanonicalBytes) and read
      entry.Signatures[0].
    - This file is updated to match: the byte-archive bytes are
      assigned to CanonicalBytes directly without any split call. The
      SignatureAlgoID and SignatureBytes fields are gone from
      EntryWithMetadata so we no longer set them.

KEY DEPENDENCIES:
    - tessera/entry_reader.go: ParseEntryBundle for tile parsing.
    - tessera/tile_reader.go: EntryTilePath for c2sp.org path encoding.
*/
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Shard Metadata
// -------------------------------------------------------------------------------------------------

// ShardMeta describes an archived shard's location and range.
type ShardMeta struct {
	ShardDID            string `json:"shard_did"`
	SequenceStart       uint64 `json:"sequence_start"`
	SequenceEnd         uint64 `json:"sequence_end"`
	TileArchiveEndpoint string `json:"tile_archive_endpoint"` // Static tile files (hash-only).
	ByteArchiveEndpoint string `json:"byte_archive_endpoint"` // Full entry bytes.
	FinalRootHash       string `json:"final_root_hash"`
	FinalTreeSize       uint64 `json:"final_tree_size"`
	ChainPosition       int    `json:"chain_position"`
}

// -------------------------------------------------------------------------------------------------
// 2) Archive Reader
// -------------------------------------------------------------------------------------------------

// ArchiveReader fetches entries from archived shards.
// Implements the same Fetch signature as builder.EntryFetcher.
type ArchiveReader struct {
	mu     sync.RWMutex
	shards map[string]ShardMeta
	client *http.Client
}

// NewArchiveReader creates an archive reader from a shard index.
func NewArchiveReader(shards []ShardMeta) *ArchiveReader {
	index := make(map[string]ShardMeta, len(shards))
	for _, s := range shards {
		index[s.ShardDID] = s
	}
	return &ArchiveReader{
		shards: index,
		// Tier-3 alignment: sdklog.DefaultClient gives connection
		// pooling (100 idle conns/host vs stdlib 2) + 503-Retry-After
		// honoring. Archive endpoints are typically S3-fronted CDNs
		// that surface 503 + Retry-After under burst load; honoring
		// it locally beats the alternative of every reader inventing
		// its own backoff.
		client: sdklog.DefaultClient(30 * time.Second),
	}
}

// LoadShardIndex loads the shard index from a local JSON file or HTTP URL.
func LoadShardIndex(ctx context.Context, source string) ([]ShardMeta, error) {
	var data []byte
	var err error

	if len(source) > 4 && (source[:4] == "http") {
		req, reqErr := http.NewRequestWithContext(ctx, "GET", source, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return nil, doErr
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: read shard index %q: %w", source, err)
	}

	var shards []ShardMeta
	if err := json.Unmarshal(data, &shards); err != nil {
		return nil, fmt.Errorf("lifecycle/archive: parse shard index: %w", err)
	}
	return shards, nil
}

// AddShard adds or updates a shard in the index. Thread-safe.
func (r *ArchiveReader) AddShard(meta ShardMeta) {
	r.mu.Lock()
	r.shards[meta.ShardDID] = meta
	r.mu.Unlock()
}

// -------------------------------------------------------------------------------------------------
// 3) Fetch — full entry bytes from byte archive
// -------------------------------------------------------------------------------------------------

// Fetch retrieves an entry's full bytes from the shard's byte archive.
// Returns the same types.EntryWithMetadata as the live operator's Fetch.
//
// Hash-only architecture: tiles contain hashes only. Full wire bytes
// are in the byte archive at a separate endpoint. Under v7.75 the wire
// bytes ARE the canonical bytes — signatures live in the v6 multi-sig
// section appended inside the canonical form, not as a separate
// envelope. Callers that need the primary signature's algoID or raw
// bytes deserialize CanonicalBytes via envelope.Deserialize and read
// entry.Signatures[0].
//
// LogTime is left at the zero value: the byte archive does not carry
// admission-time metadata, and the live operator's
// PostgresEntryFetcher is the authoritative source for log_time on
// hot-path entries. Archive consumers that need log_time pair this
// fetcher with a separate metadata index (out of scope for the
// archive reader).
func (r *ArchiveReader) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	shard, err := r.resolveShard(pos)
	if err != nil {
		return nil, err
	}

	if shard.ByteArchiveEndpoint == "" {
		return nil, fmt.Errorf("lifecycle/archive: shard %s has no byte archive endpoint", shard.ShardDID)
	}

	// Fetch full wire bytes from the byte archive.
	byteURL := fmt.Sprintf("%s/bytes/%d", shard.ByteArchiveEndpoint, pos.Sequence)
	wireBytes, err := r.fetchBytes(byteURL)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: fetch bytes seq=%d from %s: %w",
			pos.Sequence, shard.ShardDID, err)
	}

	return &types.EntryWithMetadata{
		Position:       pos,
		CanonicalBytes: wireBytes,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 4) FetchHash — entry hash from tile archive (for proof verification)
// -------------------------------------------------------------------------------------------------

// FetchHash retrieves the 32-byte SHA-256 hash for an entry from the shard's
// tile archive. Used for Merkle proof verification against frozen shards.
func (r *ArchiveReader) FetchHash(pos types.LogPosition) ([32]byte, error) {
	shard, err := r.resolveShard(pos)
	if err != nil {
		return [32]byte{}, err
	}

	tileIndex := pos.Sequence / tessera.EntriesPerTile
	offset := pos.Sequence % tessera.EntriesPerTile

	// Fetch entry tile from tile archive.
	tilePath := tessera.EntryTilePath(tileIndex)
	tileURL := fmt.Sprintf("%s/%s", shard.TileArchiveEndpoint, tilePath)
	tileData, err := r.fetchBytes(tileURL)
	if err != nil {
		return [32]byte{}, fmt.Errorf("lifecycle/archive: fetch entry tile %d from %s: %w",
			tileIndex, shard.ShardDID, err)
	}

	// Extract 32-byte hash from entry tile.
	hashBytes, err := tessera.ParseEntryBundle(tileData, offset)
	if err != nil {
		return [32]byte{}, fmt.Errorf("lifecycle/archive: extract hash seq=%d: %w", pos.Sequence, err)
	}
	if len(hashBytes) != 32 {
		return [32]byte{}, fmt.Errorf("lifecycle/archive: entry at seq=%d is %d bytes, expected 32 (hash-only tile)",
			pos.Sequence, len(hashBytes))
	}

	var hash [32]byte
	copy(hash[:], hashBytes)
	return hash, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Batch Operations
// -------------------------------------------------------------------------------------------------

// FetchBatch retrieves multiple entries' full bytes.
func (r *ArchiveReader) FetchBatch(positions []types.LogPosition) ([]*types.EntryWithMetadata, error) {
	results := make([]*types.EntryWithMetadata, len(positions))
	for i, pos := range positions {
		ewm, err := r.Fetch(pos)
		if err != nil {
			return nil, fmt.Errorf("lifecycle/archive: batch fetch pos %d: %w", i, err)
		}
		results[i] = ewm
	}
	return results, nil
}

// ShardFor returns the shard metadata for a given position, or nil if not found.
func (r *ArchiveReader) ShardFor(pos types.LogPosition) *ShardMeta {
	shard, err := r.resolveShard(pos)
	if err != nil {
		return nil
	}
	return shard
}

// Shards returns all known shard metadata.
func (r *ArchiveReader) Shards() []ShardMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ShardMeta, 0, len(r.shards))
	for _, s := range r.shards {
		result = append(result, s)
	}
	return result
}

// -------------------------------------------------------------------------------------------------
// 6) Internal
// -------------------------------------------------------------------------------------------------

func (r *ArchiveReader) resolveShard(pos types.LogPosition) (*ShardMeta, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if shard, ok := r.shards[pos.LogDID]; ok {
		return &shard, nil
	}

	for _, shard := range r.shards {
		if pos.Sequence >= shard.SequenceStart && pos.Sequence <= shard.SequenceEnd {
			return &shard, nil
		}
	}

	return nil, fmt.Errorf("lifecycle/archive: no shard found for %s@%d", pos.LogDID, pos.Sequence)
}

func (r *ArchiveReader) fetchBytes(url string) ([]byte, error) {
	resp, err := r.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	// Cap at 2 MiB (1 MiB max entry + overhead). Tier-2 BUG #3
	// alignment: read cap+1 to detect oversize bodies and surface
	// them as a typed error instead of silently truncating to a
	// downstream parse failure.
	const archiveBodyCap = 2 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, archiveBodyCap+1))
	if err != nil {
		return nil, err
	}
	if len(body) > archiveBodyCap {
		return nil, fmt.Errorf("archive body for %s exceeds %d bytes", url, archiveBodyCap)
	}
	return body, nil
}
