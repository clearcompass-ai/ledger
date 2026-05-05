/*
FILE PATH: gossipnet/sequencer_adapter.go

Adapters that let the sequencer publish into the gossipstore-backed
projections without importing gossipstore directly:

  - SequencerSplitIDAdapter        — sequencer.SplitIDIndexWriter (0x0A)
  - SequencerEntryLookupAdapter    — sequencer.EntryLookupWriter (0x0C)
  - SequencerReplayCursorAdapter   — sequencer.SplitIDReplayCursor (0x0D)

# WHY THIS THIN ADAPTER EXISTS

The Sequencer package declares its own SplitIDIndexWriter +
EntryLookupWriter + SplitIDReplayCursor interfaces (with matching
value types where needed) so it doesn't import gossipstore
directly. Each adapter bridges the two-package type system —
mechanical translation, no business logic.

Lives in gossipnet/ (not sequencer/) so the import direction is
gossipnet → sequencer + gossipstore (gossipnet is the highest-
level package), never the reverse.
*/
package gossipnet

import (
	"context"

	"github.com/clearcompass-ai/ortholog-operator/gossipstore"
	"github.com/clearcompass-ai/ortholog-operator/sequencer"
)

// SequencerSplitIDAdapter wraps a *gossipstore.BadgerStore so it
// satisfies sequencer.SplitIDIndexWriter. Construct once at
// startup and pass to sequencer.Sequencer.WithSplitIDIndex.
type SequencerSplitIDAdapter struct {
	store *gossipstore.BadgerStore
}

// NewSequencerSplitIDAdapter constructs the adapter. nil store
// returns nil — the sequencer's nil-tolerant code path handles
// that case (no splitid index population).
func NewSequencerSplitIDAdapter(store *gossipstore.BadgerStore) *SequencerSplitIDAdapter {
	if store == nil {
		return nil
	}
	return &SequencerSplitIDAdapter{store: store}
}

// WriteSplitIDIndexEntry implements sequencer.SplitIDIndexWriter.
func (a *SequencerSplitIDAdapter) WriteSplitIDIndexEntry(
	ctx context.Context,
	schemaID string,
	splitID [32]byte,
	seq uint64,
	entry sequencer.SplitIDIndexEntry,
) error {
	if a == nil || a.store == nil {
		return nil
	}
	return a.store.WriteSplitIDIndexEntry(ctx, schemaID, splitID, seq,
		gossipstore.SplitIDIndexEntry{
			EquivocatorDID: entry.EquivocatorDID,
			CanonicalHash:  entry.CanonicalHash,
			SigBytes:       entry.SigBytes,
		})
}

// SequencerEntryLookupAdapter wraps a *gossipstore.BadgerStore so
// it satisfies sequencer.EntryLookupWriter. Construct once at
// startup and pass to sequencer.Sequencer.WithEntryLookup along
// with the operator's log DID.
type SequencerEntryLookupAdapter struct {
	store *gossipstore.BadgerStore
}

// NewSequencerEntryLookupAdapter constructs the adapter. nil store
// returns nil — the sequencer's nil-tolerant code path handles
// that case (no entry lookup projection population).
func NewSequencerEntryLookupAdapter(store *gossipstore.BadgerStore) *SequencerEntryLookupAdapter {
	if store == nil {
		return nil
	}
	return &SequencerEntryLookupAdapter{store: store}
}

// WriteEntryLookupEntry implements sequencer.EntryLookupWriter.
func (a *SequencerEntryLookupAdapter) WriteEntryLookupEntry(
	ctx context.Context,
	schemaID string,
	splitID [32]byte,
	seq uint64,
	entry sequencer.EntryLookupIndexEntry,
) error {
	if a == nil || a.store == nil {
		return nil
	}
	return a.store.WriteEntryLookupEntry(ctx, schemaID, splitID, seq,
		gossipstore.EntryLookupIndexEntry{
			CanonicalBytes: entry.CanonicalBytes,
			LogTimeMicros:  entry.LogTimeMicros,
			LogDID:         entry.LogDID,
		})
}

// SequencerReplayCursorAdapter wraps a *gossipstore.BadgerStore so
// it satisfies sequencer.SplitIDReplayCursor. Construct once at
// startup and pass to sequencer.NewReplayer via ReplayConfig.Cursor.
//
// Two methods on one tiny adapter — the cursor surface is
// intentionally minimal: read HWM, advance HWM. The replayer's
// SELECT loop and per-row writes go through the SplitIDIndexWriter
// + EntryLookupWriter interfaces (separate adapters above), not
// this one.
type SequencerReplayCursorAdapter struct {
	store *gossipstore.BadgerStore
}

// NewSequencerReplayCursorAdapter constructs the adapter. nil store
// returns nil — the sequencer's nil-tolerant code path handles
// that case (no replayer is wired).
func NewSequencerReplayCursorAdapter(store *gossipstore.BadgerStore) *SequencerReplayCursorAdapter {
	if store == nil {
		return nil
	}
	return &SequencerReplayCursorAdapter{store: store}
}

// SplitIDReplayHWM implements sequencer.SplitIDReplayCursor.
func (a *SequencerReplayCursorAdapter) SplitIDReplayHWM(ctx context.Context) (uint64, error) {
	if a == nil || a.store == nil {
		return 0, nil
	}
	return a.store.SplitIDReplayHWM(ctx)
}

// SetSplitIDReplayHWM implements sequencer.SplitIDReplayCursor.
func (a *SequencerReplayCursorAdapter) SetSplitIDReplayHWM(ctx context.Context, seq uint64) error {
	if a == nil || a.store == nil {
		return nil
	}
	return a.store.SetSplitIDReplayHWM(ctx, seq)
}

// Static interface checks.
var _ sequencer.SplitIDIndexWriter = (*SequencerSplitIDAdapter)(nil)
var _ sequencer.EntryLookupWriter = (*SequencerEntryLookupAdapter)(nil)
var _ sequencer.SplitIDReplayCursor = (*SequencerReplayCursorAdapter)(nil)
