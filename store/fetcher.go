/*
FILE PATH: store/fetcher.go

CompositeByteReader — the read-path coordinator that routes WAL
reads (fast, local NVMe) to bytestore reads (network) based on
where the entry currently lives.

WHY HERE (NOT IN wal/ OR bytestore/):

	Per the locked architectural decision, neither package may import
	the other. wal/ stays a pure local-disk primitive; bytestore/
	stays a pure network primitive. The composite lives at the next
	layer up — store/ owns metadata-aware coordination of the two
	byte sources, mirroring how PostgresEntryFetcher already
	coordinates Postgres metadata with the byte source.

ROUTING RULES:

	Step 1: Try the WAL first.
	  Pending and Sequenced entries always live there. Shipped
	  entries also live there until the GC retention buffer
	  (HWM - retention) kicks in.

	Step 2: On wal.ErrNotFound (the cache-miss signal), fall through
	  to bytestore.
	  This is the post-retention path: the entry has been shipped
	  and the WAL has GC'd its local copy. Fetch from the production
	  byte vault.

	Step 3: Any non-NotFound WAL error short-circuits.
	  Transport / decode failures from Badger are not "ask the
	  network instead" signals; they're operational alarms. Return
	  the error rather than masking it with a bytestore call.

INTERFACE COMPATIBILITY:

	CompositeByteReader satisfies bytestore.Reader so existing
	fetchers (PostgresEntryFetcher, PostgresCommitmentFetcher,
	PostgresQueryAPI) need no signature change — the composition
	root in cmd/ledger/main.go injects a *CompositeByteReader
	where it previously injected a bytestore.GCS / bytestore.S3
	directly. The fetcher code path is untouched.

WIRE FORMAT:

	Both sources return the same wire bytes (single blob,
	signatures section embedded). The composite is opaque w.r.t.
	envelope structure — it just routes byte slices.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/wal"
)

// WALByteReader is the WAL surface the composite needs. *wal.Committer
// satisfies it; tests inject fakes.
type WALByteReader interface {
	Read(ctx context.Context, hash [32]byte) ([]byte, error)
}

// CompositeByteReader satisfies bytestore.Reader by routing reads
// to the WAL first and falling back to a bytestore.Reader on
// wal.ErrNotFound.
//
// Construct via NewCompositeByteReader at the composition root.
// Either wal or bytestore may be nil for tests / degraded modes;
// the composite handles each case.
type CompositeByteReader struct {
	wal       WALByteReader
	bytestore bytestore.Reader
	logger    *slog.Logger
}

// NewCompositeByteReader returns a composite rooted at the supplied
// WAL and bytestore readers. logger may be nil; defaults to slog.Default.
func NewCompositeByteReader(w WALByteReader, bs bytestore.Reader, logger *slog.Logger) *CompositeByteReader {
	if logger == nil {
		logger = slog.Default()
	}
	return &CompositeByteReader{
		wal:       w,
		bytestore: bs,
		logger:    logger,
	}
}

// ReadEntry returns wire bytes for the entry at (seq, hash).
//
// Lookup order:
//  1. WAL (when configured). Returns immediately on hit.
//  2. bytestore (when configured) on wal.ErrNotFound.
//
// Errors:
//   - WAL transport/decode error → returned (do not fall through)
//   - WAL not-found + no bytestore → returned
//   - WAL not-found + bytestore not-found → bytestore.ErrNotFound
//   - bytestore transport error → returned
func (c *CompositeByteReader) ReadEntry(ctx context.Context, seq uint64, hash [32]byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("store/fetcher: nil composite reader")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Step 1: WAL.
	if c.wal != nil {
		wire, err := c.wal.Read(ctx, hash)
		if err == nil {
			return wire, nil
		}
		if !errors.Is(err, wal.ErrNotFound) {
			// Real WAL error — alarm, don't mask with bytestore.
			return nil, fmt.Errorf("store/fetcher: WAL read seq=%d: %w", seq, err)
		}
		c.logger.Debug("store/fetcher: WAL miss, falling through to bytestore",
			"seq", seq,
			"hash", fmt.Sprintf("%x", hash[:8]),
		)
	}

	// Step 2: bytestore fallback.
	if c.bytestore == nil {
		return nil, fmt.Errorf("store/fetcher: WAL miss and no bytestore configured (seq=%d)", seq)
	}
	wire, err := c.bytestore.ReadEntry(ctx, seq, hash)
	if err != nil {
		return nil, fmt.Errorf("store/fetcher: bytestore seq=%d: %w", seq, err)
	}
	return wire, nil
}

// ReadEntryBatch fetches each ref in input order. Per-entry routing
// (WAL → bytestore fallback) is identical to ReadEntry. Any miss
// fails the batch — callers don't get a silent short slice.
//
// Future optimization: group consecutive WAL hits into a single
// Badger txn. The current shape is correctness-first; profile
// before changing.
func (c *CompositeByteReader) ReadEntryBatch(ctx context.Context, refs []bytestore.EntryRef) ([][]byte, error) {
	if c == nil {
		return nil, errors.New("store/fetcher: nil composite reader")
	}
	out := make([][]byte, len(refs))
	for i, r := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wire, err := c.ReadEntry(ctx, r.Seq, r.Hash)
		if err != nil {
			return nil, fmt.Errorf("store/fetcher: batch[%d/%d] seq=%d: %w",
				i, len(refs), r.Seq, err)
		}
		out[i] = wire
	}
	return out, nil
}

// Compile-time pin: CompositeByteReader satisfies bytestore.Reader.
// PostgresEntryFetcher and PostgresCommitmentFetcher take a
// bytestore.Reader; the composite slots in unchanged.
var _ bytestore.Reader = (*CompositeByteReader)(nil)
