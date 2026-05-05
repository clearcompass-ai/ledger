/*
FILE PATH: sequencer/replay.go

Replayer — sequencer-driven boot replay for the 0x0A splitid
detection index + 0x0C entry-lookup projection (PT-4).

# WHY THIS EXISTS

The 0x0A and 0x0C Badger writes are best-effort, AFTER the
Postgres entry_index + commitment_split_id INSERTs commit. If the
operator crashes between the Postgres commit and the Badger
write — or if the Badger DB is restored from a snapshot lagging
Postgres — the projections drift below the source of truth.
Without a replay path, equivocation detection (0x0A → scanner →
0x0B finding) and /by-split-id reads (0x0C) silently miss
historical rows.

The replayer closes that gap on every boot:

  1. Read HWM from Badger 0x0D singleton.
  2. SELECT FROM commitment_split_id ⨝ entry_index WHERE
     sequence_number > HWM ORDER BY sequence_number ASC LIMIT N.
  3. For each row: read canonical bytes from bytestore.Reader,
     deserialize via envelope.Deserialize, extract signer_did +
     signature, write 0x0A + 0x0C (idempotent on identical
     inputs).
  4. Advance HWM = max(seq) in this batch.
  5. Loop until SELECT returns < N rows.

# CQRS DISCIPLINE (P8)

Replay is a write-side concern; it runs on a child goroutine of
the sequencer's Run(), not the HTTP admission goroutine. The
0x0A + 0x0C writes go through the same SplitIDIndexWriter +
EntryLookupWriter interfaces the live admission path uses —
ONE write surface, no duplication.

# I9 IDEMPOTENCY (A13)

Every replay write is a Badger txn.Set on the SAME (key, value)
pairs the live admission path already produced. Re-running the
replayer (e.g., after a crash mid-batch) is a no-op on rows
already present. The HWM is purely an optimization — correctness
holds even if the HWM is lost.

# MELT-PROOF (P3)

The replayer runs on a separate goroutine. drainOnce continues
admitting new entries on its own ticker; replay does not block
admission. ctx cancellation drains both via wg.Wait in Run().

# HOT-PATH ISOLATION (P6)

The HTTP admission path is unmodified. Replay only touches
read-side projections; live admission's WAL fsync + SCT path is
untouched.
*/
package sequencer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"

	"github.com/clearcompass-ai/ortholog-operator/bytestore"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration / interfaces
// ─────────────────────────────────────────────────────────────────────

// DefaultReplayBatchSize bounds the number of rows fetched per
// SELECT. Sized so a single batch fits comfortably in memory at
// 64 KiB canonical bytes per row (the SDK's MaxCanonicalBytes
// cap) — 1000 rows × 64 KiB = ~64 MiB peak per batch.
const DefaultReplayBatchSize = 1000

// SplitIDReplayCursor is the persistence surface the replayer
// uses to advance its high-water-mark. Satisfied by
// gossipstore.BadgerStore via a thin adapter (gossipnet's
// SequencerReplayCursorAdapter).
type SplitIDReplayCursor interface {
	SplitIDReplayHWM(ctx context.Context) (uint64, error)
	SetSplitIDReplayHWM(ctx context.Context, seq uint64) error
}

// ReplayConfig groups Replayer dependencies.
type ReplayConfig struct {
	// DB is the operator's Postgres pool. The replayer SELECTs
	// from commitment_split_id ⨝ entry_index.
	DB *pgxpool.Pool

	// Reader fetches canonical bytes by (seq, hash). Either
	// bytestore.S3, bytestore.GCS, or bytestore.Memory in tests.
	Reader bytestore.Reader

	// SplitIDIndex is the same writer the live admission path
	// uses (sequencer.SplitIDIndexWriter).
	SplitIDIndex SplitIDIndexWriter

	// EntryLookup is the same writer the live admission path
	// uses (sequencer.EntryLookupWriter).
	EntryLookup EntryLookupWriter

	// Cursor reads + advances the HWM.
	Cursor SplitIDReplayCursor

	// LogDID stamps every 0x0C row's LogDID — same value the
	// live admission path uses.
	LogDID string

	// BatchSize bounds per-loop SELECT size. Zero defaults to
	// DefaultReplayBatchSize.
	BatchSize int

	// Logger. nil defaults to slog.Default().
	Logger *slog.Logger
}

// Replayer back-populates 0x0A + 0x0C from Postgres at boot.
type Replayer struct {
	cfg    ReplayConfig
	logger *slog.Logger
}

// NewReplayer validates cfg and constructs the Replayer.
func NewReplayer(cfg ReplayConfig) (*Replayer, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("sequencer/replay: DB required")
	}
	if cfg.Reader == nil {
		return nil, fmt.Errorf("sequencer/replay: Reader required")
	}
	if cfg.SplitIDIndex == nil {
		return nil, fmt.Errorf("sequencer/replay: SplitIDIndex required")
	}
	if cfg.EntryLookup == nil {
		return nil, fmt.Errorf("sequencer/replay: EntryLookup required")
	}
	if cfg.Cursor == nil {
		return nil, fmt.Errorf("sequencer/replay: Cursor required")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("sequencer/replay: LogDID required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultReplayBatchSize
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Replayer{cfg: cfg, logger: cfg.Logger}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Replay loop
// ─────────────────────────────────────────────────────────────────────

// replayRow is the in-memory shape of one Postgres row.
type replayRow struct {
	seq      uint64
	schemaID string
	splitID  [32]byte
	signer   string
	hash     [32]byte
	logTime  int64 // unix-micros
}

// Replay scans Postgres for commitment-schema rows above the
// stored HWM and back-populates 0x0A + 0x0C for each. Returns nil
// when the scan exhausts (caught up). ctx cancellation aborts
// the loop and returns ctx.Err().
//
// On per-row failure (e.g., bytestore read miss, deserialize
// error), the row is logged + skipped and the loop continues.
// Every replay write is idempotent so a future re-run picks up
// the row again. The HWM is only advanced past rows that
// successfully wrote — a bytestore outage on row N pins the HWM
// at N-1 until the row succeeds.
func (r *Replayer) Replay(ctx context.Context) error {
	hwm, err := r.cfg.Cursor.SplitIDReplayHWM(ctx)
	if err != nil {
		return fmt.Errorf("sequencer/replay: read HWM: %w", err)
	}
	r.logger.Info("sequencer replay: starting", "hwm", hwm,
		"batch_size", r.cfg.BatchSize)

	totalRows := 0
	totalSkipped := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := r.fetchBatch(ctx, hwm)
		if err != nil {
			return fmt.Errorf("sequencer/replay: fetch batch (hwm=%d): %w", hwm, err)
		}
		if len(rows) == 0 {
			break
		}

		batchAdvancedTo := hwm
		batchSucceeded := 0
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := r.applyOne(ctx, row); err != nil {
				// Per-row error: log + skip. HWM does NOT
				// advance past this row, so a future replay
				// re-attempts it. Stop the batch here so
				// HWM doesn't leapfrog the failed row.
				r.logger.Warn("sequencer replay: row failed (will retry on next boot)",
					"seq", row.seq, "schema_id", row.schemaID, "error", err)
				totalSkipped++
				break
			}
			batchAdvancedTo = row.seq
			batchSucceeded++
		}
		totalRows += batchSucceeded

		if batchAdvancedTo > hwm {
			if err := r.cfg.Cursor.SetSplitIDReplayHWM(ctx, batchAdvancedTo); err != nil {
				return fmt.Errorf("sequencer/replay: advance HWM to %d: %w",
					batchAdvancedTo, err)
			}
			hwm = batchAdvancedTo
		}

		if batchSucceeded < r.cfg.BatchSize {
			// Exhausted — either fewer rows than BatchSize, or
			// a row failed mid-batch (we stopped to preserve
			// HWM monotonicity).
			break
		}
	}

	r.logger.Info("sequencer replay: caught up",
		"final_hwm", hwm, "rows_replayed", totalRows,
		"rows_skipped", totalSkipped)
	return nil
}

// fetchBatch SELECTs the next batch of (commitment_split_id ⨝
// entry_index) rows above the supplied HWM. Returns rows in
// seq-ascending order so HWM advances monotonically.
//
// Schema-only commitments are filtered upstream by the JOIN —
// only sequences that landed in commitment_split_id are returned,
// and that table only carries v7.75 commitment-schema rows.
func (r *Replayer) fetchBatch(ctx context.Context, hwm uint64) ([]replayRow, error) {
	const q = `
		SELECT
			c.sequence_number,
			c.schema_id,
			c.split_id,
			e.signer_did,
			e.canonical_hash,
			e.log_time
		FROM commitment_split_id c
		JOIN entry_index e ON e.sequence_number = c.sequence_number
		WHERE c.sequence_number > $1
		ORDER BY c.sequence_number ASC
		LIMIT $2`
	rows, err := r.cfg.DB.Query(ctx, q, hwm, r.cfg.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []replayRow
	for rows.Next() {
		var row replayRow
		var splitCol []byte
		var hashCol []byte
		var logTime time.Time
		if err := rows.Scan(
			&row.seq, &row.schemaID, &splitCol,
			&row.signer, &hashCol, &logTime,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if len(splitCol) != 32 {
			return nil, fmt.Errorf("split_id length=%d, want 32 (seq=%d)", len(splitCol), row.seq)
		}
		if len(hashCol) != 32 {
			return nil, fmt.Errorf("canonical_hash length=%d, want 32 (seq=%d)", len(hashCol), row.seq)
		}
		copy(row.splitID[:], splitCol)
		copy(row.hash[:], hashCol)
		// entry_index.log_time is TIMESTAMPTZ; convert to unix-
		// micros to match the format the live admission path
		// stamps into 0x0C (envelope.ControlHeader.EventTime is
		// already unix-micros).
		row.logTime = logTime.UTC().UnixMicro()
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("rows.Err: %w", err)
		}
	}
	return out, nil
}

// applyOne reads canonical bytes from bytestore, extracts the
// operator's entry-signature, and writes both 0x0A + 0x0C.
func (r *Replayer) applyOne(ctx context.Context, row replayRow) error {
	wire, err := r.cfg.Reader.ReadEntry(ctx, row.seq, row.hash)
	if err != nil {
		return fmt.Errorf("bytestore read: %w", err)
	}
	entry, err := envelope.Deserialize(wire)
	if err != nil {
		return fmt.Errorf("envelope deserialize: %w", err)
	}
	if len(entry.Signatures) == 0 {
		return fmt.Errorf("entry has no signatures")
	}

	idxEntry := SplitIDIndexEntry{
		EquivocatorDID: row.signer,
		CanonicalHash:  row.hash,
		SigBytes:       append([]byte{}, entry.Signatures[0].Bytes...),
	}
	if err := r.cfg.SplitIDIndex.WriteSplitIDIndexEntry(
		ctx, row.schemaID, row.splitID, row.seq, idxEntry,
	); err != nil {
		return fmt.Errorf("0x0A write: %w", err)
	}

	lookupEntry := EntryLookupIndexEntry{
		CanonicalBytes: wire,
		LogTimeMicros:  row.logTime,
		LogDID:         r.cfg.LogDID,
	}
	if err := r.cfg.EntryLookup.WriteEntryLookupEntry(
		ctx, row.schemaID, row.splitID, row.seq, lookupEntry,
	); err != nil {
		return fmt.Errorf("0x0C write: %w", err)
	}
	return nil
}
