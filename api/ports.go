/*
FILE PATH: api/ports.go

api/ side ports (interfaces) for every concrete *store.X type the
HTTP handler layer consumes. Defining the interfaces HERE follows
the Go idiom of "consumer defines the interface" and is the
load-bearing piece of the Pure CQRS closure: the api/ package
imports zero pgx packages because it depends on these interfaces
+ apitypes value types, never on store/ directly.

Compliance test:

	go list -deps ./api/ | grep -E 'pgx|database/sql' | wc -l == 0

# WHY THIS LIVES IN api/

Two reasons:

 1. Each interface lists EXACTLY the methods api/ needs — no more,
    no less. Defining these in store/ would over-expose its public
    API surface (Add/Insert/etc. are write-side concerns api/
    doesn't touch).

 2. The interface set is the api/ "stable contract" — alternate
    read-side implementations (Badger projections, in-memory test
    fakes) plug in via these interfaces without recompiling api/.
    gossipstore.BadgerCommitmentFetcher is the
    canonical example: it implements types.CommitmentFetcher (SDK
    side) and serves /by-split-id with zero pgx in api/.

# DESIGN NOTES

  - Interfaces accept context.Context as the first parameter even
    where the underlying *store.X method does — uniform cancellation
    discipline.
  - Return shapes use *apitypes.X for non-trivial value types,
    plain stdlib types otherwise. No store.X types appear in any
    interface signature.
  - Errors propagated as plain `error`; sentinels exposed via
    apitypes (apitypes.ErrInsufficientCredits) so api/ does
    `errors.Is(err, apitypes.ErrInsufficientCredits)`.
*/
package api

import (
	"context"
	"time"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/ledger/apitypes"
)

// ─────────────────────────────────────────────────────────────────────
// Read-side ports
// ─────────────────────────────────────────────────────────────────────

// EntryStore is the read-side surface api/ consumes for entry-
// metadata lookups. *store.EntryStore satisfies it structurally.
//
// Used by:
//   - api/queries.go (FetchByHash for /v1/query/* endpoints)
//   - api/entries_read.go (FetchHashBySeq for /v1/entries/{seq})
//   - api/submission.go (FetchByHash for early-dup probe)
//   - api/batch.go (FetchByHash for historical-dup probe)
type EntryStore interface {
	// FetchByHash returns the sequence number of the entry with
	// the given canonical hash, or (0, false, nil) if the entry
	// is not on the ledger's log.
	FetchByHash(ctx context.Context, hash [32]byte) (uint64, bool, error)

	// FetchHashBySeq returns the canonical hash, admission
	// log_time, and a ghost-row flag for the entry at the given
	// sequence number. (`isGhost == true` means the row's
	// EntryStatus is StatusGhostLeaf; the caller should resolve
	// the canonical seq via FetchPrimarySeqByHash and redirect.)
	// Returns ([32]byte{}, time.Time{}, false, false, nil) when
	// the sequence is unassigned.
	//
	// The isGhost field is a plain bool to keep this interface
	// independent of the concrete store/ enum type — preserving
	// the CQRS pin (`go list -deps ./api/ | grep pgx == 0`).
	FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, time.Time, bool, bool, error)

	// FetchPrimarySeqByHash returns the canonical (primary) seq
	// for a given canonical_hash — the row with status <> Ghost.
	// Used by the API's ghost-redirect path: a request for
	// GET /v1/entries/{ghost_seq}/raw resolves the underlying
	// canonical_hash and routes to the primary seq so the bytes
	// are served (302 or proxied) regardless of which Tessera seq
	// the auditor asked for.
	//
	// Returns (primarySeq, true, nil) on hit, (0, false, nil) when
	// no non-ghost row exists for the hash, (0, false, err) on
	// transport failure.
	FetchPrimarySeqByHash(ctx context.Context, hash [32]byte) (uint64, bool, error)
}

// CreditDeducter is the api/ → credit-store surface for Mode A
// fiat write-credit accounting. *store.CreditStore satisfies it
// via its self-tx Deduct method (added ).
//
// The api/ side is intentionally given a tx-less surface: the
// store implementation manages its own ReadCommitted transaction
// internally so api/'s transitive imports stay free of pgx.
//
// Used by:
//   - api/submission.go (deductCreditModeA)
//   - api/batch.go (deductCreditModeA, called per-entry)
//
// Returns apitypes.ErrInsufficientCredits when balance is zero;
// the api handler maps that to HTTP 402.
type CreditDeducter interface {
	Deduct(ctx context.Context, exchangeDID string) error
}

// TreeHeadFetcher is the api/ → tree-head surface for the
// /v1/tree/head endpoint. *store.TreeHeadStore satisfies it.
//
// Used by api/tree.go.
type TreeHeadFetcher interface {
	// Latest returns the most recent cosigned tree head.
	Latest(ctx context.Context) (*apitypes.CosignedTreeHead, error)

	// GetBySize returns the cosigned tree head at exactly the
	// supplied tree size. nil + nil error when no head exists at
	// that size (the api handler maps this to 404).
	GetBySize(ctx context.Context, size uint64) (*apitypes.CosignedTreeHead, error)
}

// DerivationCommitmentFetcher is the api/ → derivation-commitment
// surface for the /v1/commitments?seq=N endpoint.
// *store.CommitmentStore satisfies it.
//
// Used by api/derivation_commitments.go.
type DerivationCommitmentFetcher interface {
	// QueryBySequence returns the derivation commitment whose
	// range_start_seq..range_end_seq covers the given sequence.
	// nil + nil error when no commitment covers the range.
	QueryBySequence(ctx context.Context, seq uint64) (*apitypes.CommitmentRow, error)
}

// QueryAPI is the api/ → secondary-index surface for the
// /v1/query/* endpoints. *indexes.PostgresQueryAPI satisfies it.
//
// All methods return SDK shapes (types.EntryWithMetadata) so the
// api/ side never sees a Postgres-tagged value type.
//
// Used by api/queries.go.
//
// CONTEXT: the underlying impl methods are context-free today;
// the interface preserves that signature so api/ doesn't need a
// shim. Threading ctx through these is a separate refactor.
type QueryAPI interface {
	ScanFromPosition(from uint64, count int) ([]types.EntryWithMetadata, error)
	QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)
	QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error)
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
	QueryBySchemaRef(pos types.LogPosition) ([]types.EntryWithMetadata, error)
	// QueryByDelegateDID returns live entries whose
	// Header.DelegateDID matches the given DID, ordered by
	// sequence_number DESC. Backs the L2 read API endpoint
	// /v1/query/delegate_did/{did} used by judicial-network +
	// multi-network shims to build their own delegation
	// projections per the matrix-of-consumers design (each
	// consumer caches independently).
	QueryByDelegateDID(did string) ([]types.EntryWithMetadata, error)
}

// EscrowOverrideProcessor is the api/ → escrow-override flow
// surface. *gossipnet.EscrowOverrideService satisfies it via the
// apitypes.EscrowOverrideResult type alias (gossipnet's
// ProcessOverrideResult is `= apitypes.EscrowOverrideResult`).
//
// Used by api/escrow_override.go to keep api/ free of the
// gossipnet → sequencer → pgx import chain.
type EscrowOverrideProcessor interface {
	ProcessOverride(
		ctx context.Context,
		escrowID, decisionHash [32]byte,
		effective uint64,
	) (apitypes.EscrowOverrideResult, error)
}
