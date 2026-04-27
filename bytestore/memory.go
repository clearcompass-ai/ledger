/*
FILE PATH: bytestore/memory.go

Memory — in-process bytestore.Store implementation. Thread-safe.

Used by tests and local dev. **Production wiring MUST NOT import this
type**: cmd/operator/main.go fails closed when no production-grade
backend (GCS/S3) is configured. Memory exists in a regular .go file
(not _test.go) only because tests across many packages need to
construct one and Go does not let _test.go symbols cross package
boundaries.

Defensive copy on both write and read: callers can mutate their input
buffer after WriteEntry returns and their result slice from ReadEntry
without corrupting the stored value.
*/
package bytestore

import (
	"fmt"
	"sync"
)

// Memory stores wire bytes in memory. Thread-safe. Implements Store.
type Memory struct {
	mu      sync.RWMutex
	entries map[uint64][]byte
}

// NewMemory creates an empty in-memory bytestore.
func NewMemory() *Memory {
	return &Memory{entries: make(map[uint64][]byte)}
}

// WriteEntry stores wire bytes in memory. The input slice is copied
// so the caller may mutate it after return without corrupting the
// store.
func (s *Memory) WriteEntry(seq uint64, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("bytestore/memory: WriteEntry seq=%d: empty wire bytes", seq)
	}
	cp := make([]byte, len(wireBytes))
	copy(cp, wireBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[seq] = cp
	return nil
}

// ReadEntry retrieves wire bytes from memory. Returns a copy so
// callers cannot mutate the stored value.
func (s *Memory) ReadEntry(seq uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[seq]
	if !ok {
		return nil, fmt.Errorf("bytestore/memory: seq %d not found", seq)
	}
	cp := make([]byte, len(e))
	copy(cp, e)
	return cp, nil
}

// ReadEntryBatch retrieves multiple entries in the input order.
// Any missing sequence fails the whole batch.
func (s *Memory) ReadEntryBatch(seqs []uint64) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([][]byte, len(seqs))
	for i, seq := range seqs {
		e, ok := s.entries[seq]
		if !ok {
			return nil, fmt.Errorf("bytestore/memory: seq %d not found in batch", seq)
		}
		cp := make([]byte, len(e))
		copy(cp, e)
		results[i] = cp
	}
	return results, nil
}

// Len returns the number of stored entries.
func (s *Memory) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Compile-time pin: Memory satisfies Store.
var _ Store = (*Memory)(nil)
