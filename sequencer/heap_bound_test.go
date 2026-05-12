// FILE PATH: sequencer/heap_bound_test.go
//
// Unit tests for the bounded committer-heap gate in drainOnce.
// When the heap depth is at MaxCommitterHeapSize, drainOnce
// returns immediately without dispatching new stage-1 workers —
// admission backpressure follows via the WAL queue.
//
// Two regressions this file prevents:
//
//	(1) Heap grows unbounded under a poison-pill anomaly,
//	    eventually OOM-killing the process.
//	(2) Default-zero MaxCommitterHeapSize disables the gate
//	    silently (NewSequencer must apply the default).
package sequencer

import (
	"container/heap"
	"context"
	"testing"

	"github.com/clearcompass-ai/ledger/wal"
)

func TestSequencer_DrainOnce_HeapAtCeiling_StallsAndSkipsDispatch(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()

	// Tight heap ceiling so we don't have to push thousands of
	// fake tuples to exercise the gate.
	cfg := Config{MaxCommitterHeapSize: 4}
	s := newTestSequencerNoCommitter(t, w, ts, cfg)

	// Seed an entry in the WAL — drainOnce must NOT dispatch to it
	// while the heap is at the ceiling.
	_, hash := buildEntry(t, "heap-bound")
	w.mu.Lock()
	w.pending = append(w.pending, wal.PendingHash{Hash: hash})
	w.mu.Unlock()

	// Pre-populate the heap to the ceiling. Use distinct seqs so
	// they don't all collapse into one batch.
	for i := uint64(0); i < uint64(cfg.MaxCommitterHeapSize); i++ {
		heap.Push(s.committerHeap, stagedEntry{
			Seq:  i,
			Hash: hash, // hash content irrelevant for this gate test
		})
	}
	if s.committerHeap.Len() != cfg.MaxCommitterHeapSize {
		t.Fatalf("heap precondition violated: len=%d, want %d",
			s.committerHeap.Len(), cfg.MaxCommitterHeapSize)
	}

	beforeStalls := s.metrics.committerHeapStalls.Load()
	s.drainOnce(context.Background())
	afterStalls := s.metrics.committerHeapStalls.Load()

	if afterStalls != beforeStalls+1 {
		t.Errorf("committerHeapStalls = %d, want %d (one stall this cycle)",
			afterStalls, beforeStalls+1)
	}
	// And no stage-1 was dispatched — the WAL Pending hash is still
	// pending (fakeWAL.sequenceCalls would have bumped if any worker
	// reached WAL.Sequence).
	if got := w.sequenceCalls.Load(); got != 0 {
		t.Errorf("WAL.Sequence calls = %d, want 0 (gate must skip dispatch)",
			got)
	}
}

func TestSequencer_NewSequencer_DefaultsMaxCommitterHeapSize(t *testing.T) {
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{
		MaxCommitterHeapSize: 0, // explicit zero — should pick up default
	})
	if got := s.cfg.MaxCommitterHeapSize; got != DefaultMaxCommitterHeapSize {
		t.Errorf("MaxCommitterHeapSize default = %d, want %d",
			got, DefaultMaxCommitterHeapSize)
	}
}

func TestSequencer_DrainOnce_HeapBelowCeiling_NoStall(t *testing.T) {
	w := newFakeWAL()
	ts := newFakeTessera()
	cfg := Config{MaxCommitterHeapSize: 100}
	s := newTestSequencerNoCommitter(t, w, ts, cfg)

	// Heap is well below the ceiling — drainOnce should NOT stall.
	for i := uint64(0); i < 10; i++ {
		heap.Push(s.committerHeap, stagedEntry{Seq: i})
	}

	beforeStalls := s.metrics.committerHeapStalls.Load()
	s.drainOnce(context.Background())
	afterStalls := s.metrics.committerHeapStalls.Load()

	if afterStalls != beforeStalls {
		t.Errorf("committerHeapStalls bumped from %d to %d — gate should not have fired",
			beforeStalls, afterStalls)
	}
}
