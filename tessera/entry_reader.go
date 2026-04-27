/*
FILE PATH:
    tessera/entry_reader.go

DESCRIPTION:
    Entry byte storage interface. Postgres is an index. The EntryReader is the
    source of truth for entry bytes. Always.

    Tessera-aligned shape: entries are opaque []byte blobs keyed by sequence
    number. The byte store has no knowledge of envelope structure — it
    round-trips whatever is written. Under v7.75 the wire bytes ARE the
    canonical bytes (the multi-sig section is appended INSIDE the canonical
    form by envelope.Serialize), so a single blob carries everything a
    consumer needs; envelope.Deserialize recovers the structure.

    With hash-only Tessera tiles (Conflict #1 resolution), entry data tiles
    contain 32-byte SHA-256 hashes — NOT full entry bytes. Full wire bytes
    live in the operator's own byte store via EntryWriter and are served
    by EntryReader.

KEY ARCHITECTURAL DECISIONS:
    - Single-blob storage: no internal length-prefix codec; the body in
      storage is exactly the bytes passed to WriteEntry. This matches the
      upstream Tessera library's storage shape (entries are []byte) and
      eliminates the v6-era (canonical, sig) sidecar split.
    - EntryReader is the ONLY source of wire bytes.
    - Postgres entry_index stores ONLY queryable metadata (~40 bytes/row).
    - WriteEntry is called at admission time (submission.go step 9).
    - ReadEntryBatch groups reads for efficiency.

OVERVIEW:
    WriteEntry(seq, wireBytes) → store opaque blob in backing map/disk/GCS.
    ReadEntry(seq) → fetch from backing store → []byte.
    ReadEntryBatch(seqs) → batch fetch → [][]byte (parallel order to seqs).

KEY DEPENDENCIES:
    - store/entries.go: PostgresEntryFetcher calls ReadEntry/ReadEntryBatch.
    - store/indexes/query_api.go: scanAndHydrate calls ReadEntryBatch.
    - api/submission.go: Calls WriteEntry at step 9 (atomic persist).
*/
package tessera

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// EntriesPerTile is the number of entries packed into a single Tessera tile.
// Retained as a constant for shard lifecycle and archive reader calculations.
const EntriesPerTile = 256

// -------------------------------------------------------------------------------------------------
// 2) Interfaces
// -------------------------------------------------------------------------------------------------

// EntryReader reads wire bytes from the operator's byte storage.
// This is the ONLY source of entry bytes in the system.
// Postgres stores index metadata only — zero bytes.
//
// The reader is opaque w.r.t. envelope structure: it returns whatever
// bytes were written. Callers that need to inspect the entry (signatures,
// header fields, payload) call envelope.Deserialize on the result.
type EntryReader interface {
	// ReadEntry returns the wire bytes for seq. Returns an error wrapping
	// a not-found sentinel when the entry is absent.
	ReadEntry(seq uint64) ([]byte, error)

	// ReadEntryBatch returns wire bytes for each seq in the same order
	// as the input slice. Any missing sequence is a fatal error for the
	// whole batch (callers don't get a silent short slice).
	ReadEntryBatch(seqs []uint64) ([][]byte, error)
}

// EntryWriter stores wire bytes. Called at admission time.
//
// The writer is opaque w.r.t. envelope structure: whatever bytes are
// passed in are what ReadEntry will return.
type EntryWriter interface {
	WriteEntry(seq uint64, wireBytes []byte) error
}

// -------------------------------------------------------------------------------------------------
// 3) Tile Bundle Parsing (c2sp.org/tlog-tiles format — for archive reader)
// -------------------------------------------------------------------------------------------------

// ParseEntryBundle extracts the raw data blob for entry at `offset` within
// a Tessera entry tile. The tile format is:
//
//	[uint16 big-endian length][data bytes] × N
//
// With hash-only tiles, each entry is exactly 32 bytes (SHA-256 hash).
// This function is used by lifecycle/archive_reader.go for frozen shards
// and by proof_adapter.go for hash extraction during proof computation.
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

// -------------------------------------------------------------------------------------------------
// 4) InMemoryEntryStore — test + local dev implementation
// -------------------------------------------------------------------------------------------------

// InMemoryEntryStore stores wire bytes in memory. Thread-safe.
// Implements both EntryReader and EntryWriter.
//
// Used by tests and local dev; production uses GCSEntryStore.
type InMemoryEntryStore struct {
	mu      sync.RWMutex
	entries map[uint64][]byte
}

// NewInMemoryEntryStore creates an empty in-memory entry store.
func NewInMemoryEntryStore() *InMemoryEntryStore {
	return &InMemoryEntryStore{entries: make(map[uint64][]byte)}
}

// WriteEntry stores wire bytes in memory. The input slice is copied so the
// caller may mutate it after return without corrupting the store.
func (s *InMemoryEntryStore) WriteEntry(seq uint64, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("tessera/entry_reader: WriteEntry seq=%d: empty wire bytes", seq)
	}
	cp := make([]byte, len(wireBytes))
	copy(cp, wireBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[seq] = cp
	return nil
}

// ReadEntry retrieves wire bytes from memory. Returns a copy so callers
// cannot mutate the stored value.
func (s *InMemoryEntryStore) ReadEntry(seq uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[seq]
	if !ok {
		return nil, fmt.Errorf("tessera/entry_reader: seq %d not found in byte store", seq)
	}
	cp := make([]byte, len(e))
	copy(cp, e)
	return cp, nil
}

// ReadEntryBatch retrieves multiple entries from memory.
func (s *InMemoryEntryStore) ReadEntryBatch(seqs []uint64) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([][]byte, len(seqs))
	for i, seq := range seqs {
		e, ok := s.entries[seq]
		if !ok {
			return nil, fmt.Errorf("tessera/entry_reader: seq %d not found in batch", seq)
		}
		cp := make([]byte, len(e))
		copy(cp, e)
		results[i] = cp
	}
	return results, nil
}

// Len returns the number of stored entries.
func (s *InMemoryEntryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Compile-time pins.
var (
	_ EntryReader = (*InMemoryEntryStore)(nil)
	_ EntryWriter = (*InMemoryEntryStore)(nil)
)
