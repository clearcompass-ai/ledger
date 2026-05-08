/*
FILE PATH: gossipstore/commitment_fetcher.go

BadgerCommitmentFetcher — Postgres-free implementation of the
SDK's types.CommitmentFetcher interface. Reads exclusively from
the 0x0C entry-lookup projection populated by the sequencer at
commit time.

# WHY HERE (NOT store/)

Locating the fetcher in gossipstore (the data's home) keeps api/'s
transitive imports free of github.com/jackc/pgx/v5. The store/
package — where PostgresCommitmentFetcher lives — pulls in pgx
package-wide; importing ANY symbol from store/ transitively
imports pgx. Putting the Badger-backed fetcher here means api/
satisfies its commitment-lookup dependency through gossipstore +
attesta/types only.

Compliance test:

	go list -deps ./api/ | grep -E 'pgx|database/sql' | wc -l == 0

# CONTRACT

FindCommitmentEntries(schemaID, splitID) → []*EntryWithMetadata

  - len = 0 → SDK consumer treats as "no commitment on log"
    (the api handler maps this to 404).
  - len = 1 → normal admission case.
  - len ≥ 2 → cryptographic equivocation: admit both, surface
    as evidence. Returned in seq-ascending order so the SDK's
    CommitmentEquivocationError construction is deterministic.

Every returned EntryWithMetadata is reconstituted from the
sequencer's at-write-time snapshot of canonical bytes + log time
+ log DID — the read path NEVER touches Tessera tiles or Postgres.

# CQRS DISCIPLINE

  - Sequencer is the only writer (gossipstore.WriteEntryLookupEntry).
  - This fetcher is the only reader (gossipstore.ListEntryLookupEntriesAt).
  - Read path holds zero shared mutexes with the write path — they
    contend only on Badger's underlying LSM (which Badger handles
    with its own concurrency control, not a sync.Mutex).
*/
package gossipstore

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/types"
)

// BadgerCommitmentFetcher resolves a (schemaID, splitID) tuple to
// every matching entry on the ledger's log by scanning the
// 0x0C entry-lookup projection in the BadgerStore.
//
// Implements types.CommitmentFetcher. A Postgres-free counterpart
// to store.PostgresCommitmentFetcher; the two satisfy the same SDK
// interface so the api handler is agnostic to which is wired.
type BadgerCommitmentFetcher struct {
	store *BadgerStore
}

// NewBadgerCommitmentFetcher constructs a fetcher reading from
// the supplied BadgerStore. nil store panics — without a store
// the fetcher cannot serve any request, and the ledger should
// refuse to start rather than silently return empty results.
func NewBadgerCommitmentFetcher(store *BadgerStore) *BadgerCommitmentFetcher {
	if store == nil {
		panic("gossipstore: NewBadgerCommitmentFetcher: nil store")
	}
	return &BadgerCommitmentFetcher{store: store}
}

// FindCommitmentEntries implements types.CommitmentFetcher. Scans
// 0x0C for the (schemaID, splitID) tuple and converts every hit
// into an *EntryWithMetadata.
//
// The supplied ctx is threaded into the underlying Badger View;
// SIGTERM cancellation aborts an in-flight scan rather than
// holding the read transaction past shutdown.
func (f *BadgerCommitmentFetcher) FindCommitmentEntries(
	ctx context.Context, schemaID string, splitID [32]byte,
) ([]*types.EntryWithMetadata, error) {
	if schemaID == "" {
		return nil, fmt.Errorf("gossipstore/BadgerCommitmentFetcher: empty schemaID")
	}
	hits, err := f.store.ListEntryLookupEntriesAt(ctx, schemaID, splitID)
	if err != nil {
		return nil, fmt.Errorf("gossipstore/BadgerCommitmentFetcher: list 0x0C: %w", err)
	}
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]*types.EntryWithMetadata, 0, len(hits))
	for _, h := range hits {
		out = append(out, &types.EntryWithMetadata{
			CanonicalBytes: append([]byte(nil), h.Entry.CanonicalBytes...),
			LogTime:        time.UnixMicro(h.Entry.LogTimeMicros).UTC(),
			Position: types.LogPosition{
				Sequence: h.EntrySeq,
				LogDID:   h.Entry.LogDID,
			},
		})
	}
	return out, nil
}

// Compile-time check: BadgerCommitmentFetcher must satisfy the
// SDK's types.CommitmentFetcher interface. A drift in either
// side's signature surfaces as a build failure here — the same
// guarantee store.PostgresCommitmentFetcher has via its
// equivalent assertion.
var _ types.CommitmentFetcher = (*BadgerCommitmentFetcher)(nil)
