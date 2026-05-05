/*
FILE PATH:

	tessera/entry_reader.go

DESCRIPTION:

	Tessera tile-format helpers retained in the tessera package after
	the byte store was relocated to bytestore/. Wire bytes (entry
	payloads) are no longer this file's concern — see bytestore/ for
	the EntryReader / EntryWriter / Memory / GCS surface.

	What stays here:
	  - EntriesPerTile constant (shard lifecycle, archive reader).
	  - ParseEntryBundle (c2sp.org/tlog-tiles tile body parser, used
	    by the archive reader and proof adapter).

	Everything else moved to bytestore/ in Phase D of the
	WAL/Shipper alignment series.
*/
package tessera

import (
	"encoding/binary"
	"fmt"
)

// EntriesPerTile is the number of entries packed into a single
// Tessera tile. Used by shard lifecycle and the archive reader.
const EntriesPerTile = 256

// ParseEntryBundle extracts the raw data blob for entry at `offset`
// within a Tessera entry tile. The tile format is:
//
//	[uint16 big-endian length][data bytes] × N
//
// With hash-only tiles, each entry is exactly 32 bytes (SHA-256 hash).
// Used by lifecycle/archive_reader.go for frozen shards and by
// proof_adapter.go for hash extraction during proof computation.
//
// Returns the data bytes for the entry at the given offset (0-indexed).
func ParseEntryBundle(tileData []byte, offset uint64) ([]byte, error) {
	pos := 0
	for i := uint64(0); i <= offset; i++ {
		if pos+2 > len(tileData) {
			return nil, fmt.Errorf("tessera/entry_reader: tile truncated at entry %d (need length prefix at byte %d, tile is %d bytes)",
				i, pos, len(tileData))
		}
		entryLen := int(binary.BigEndian.Uint16(tileData[pos : pos+2]))
		pos += 2
		if pos+entryLen > len(tileData) {
			return nil, fmt.Errorf("tessera/entry_reader: tile truncated at entry %d (need %d bytes at offset %d, tile is %d bytes)",
				i, entryLen, pos, len(tileData))
		}
		if i == offset {
			return tileData[pos : pos+entryLen], nil
		}
		pos += entryLen
	}
	return nil, fmt.Errorf("tessera/entry_reader: offset %d not found in tile", offset)
}
