/*
FILE PATH: bytestore/memory.go

Memory — in-process bytestore.Store implementation. Thread-safe.

Used by tests and local dev. **Production wiring MUST NOT import
this type**: cmd/ledger/main.go fails closed when no production-
grade backend (gcs/s3) is configured. The factory rejects
Backend="memory" outside of test contexts.

Memory does NOT satisfy PublicURLer — there's no anonymous-read
URL to compose for an in-process map. Tests that need to exercise
the 302-redirect path use the GCS or S3 adapter against
fake-gcs-server / SeaweedFS / RustFS.

Storage layout:

	Keyed by (seq, hash). Two writes with the same seq but different
	hash are stored as distinct entries (last-hash-wins per seq is
	not the model — caller is expected to compute hash deterministically
	from canonical bytes via envelope.EntryIdentity).

Defensive copy on both write and read: callers can mutate their
input buffer after WriteEntry returns and their result slice from
ReadEntry without corrupting the stored value.
*/
package bytestore

import (
	"context"
	"fmt"
	"sync"
)

// Memory stores wire bytes in memory. Thread-safe. Implements Store
// (NOT Backend — no PublicURLer support).
type Memory struct {
	mu      sync.RWMutex
	entries map[string][]byte // key = layoutKey("memory", seq, hash)
}

// NewMemory creates an empty in-memory bytestore.
func NewMemory() *Memory {
	return &Memory{entries: make(map[string][]byte)}
}

// WriteEntry stores wire bytes in memory. Input is copied so callers
// may mutate their buffer after return.
func (s *Memory) WriteEntry(ctx context.Context, seq uint64, hash [32]byte, wireBytes []byte) error {
	if len(wireBytes) == 0 {
		return fmt.Errorf("bytestore/memory: WriteEntry seq=%d: empty wire bytes", seq)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cp := make([]byte, len(wireBytes))
	copy(cp, wireBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[layoutKey("memory", seq, hash)] = cp
	return nil
}

// ReadEntry retrieves wire bytes for (seq, hash). Returns a copy so
// callers cannot mutate the stored value.
func (s *Memory) ReadEntry(ctx context.Context, seq uint64, hash [32]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[layoutKey("memory", seq, hash)]
	if !ok {
		return nil, fmt.Errorf("bytestore/memory: seq=%d hash=%x: %w", seq, hash[:8], ErrNotFound)
	}
	cp := make([]byte, len(e))
	copy(cp, e)
	return cp, nil
}

// ReadEntryBatch retrieves multiple entries in input order. Any
// missing entry fails the whole batch.
func (s *Memory) ReadEntryBatch(ctx context.Context, refs []EntryRef) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([][]byte, len(refs))
	for i, r := range refs {
		e, ok := s.entries[layoutKey("memory", r.Seq, r.Hash)]
		if !ok {
			return nil, fmt.Errorf("bytestore/memory: seq=%d hash=%x: %w", r.Seq, r.Hash[:8], ErrNotFound)
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

// Compile-time pin: Memory satisfies Store but NOT Backend
// (Memory has no PublicURLer — see file docblock).
var _ Store = (*Memory)(nil)
