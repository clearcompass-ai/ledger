/*
FILE PATH: gossipnet/sequencer_adapter.go

SequencerSplitIDAdapter — satisfies sequencer.SplitIDIndexWriter
on top of gossipstore.BadgerStore.

# WHY THIS THIN ADAPTER EXISTS

The Sequencer package declares its own SplitIDIndexWriter
interface + matching SplitIDIndexEntry type so it doesn't import
gossipstore directly. The adapter bridges the two type names —
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

// Static interface check.
var _ sequencer.SplitIDIndexWriter = (*SequencerSplitIDAdapter)(nil)
