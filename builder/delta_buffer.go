/*
FILE PATH: builder/delta_buffer.go

Postgres persistence of the delta-window authority history buffer.
Survives operator restarts. Empty on cold start → strict OCC (SDK-D9).

KEY ARCHITECTURAL DECISIONS:
  - Load/Save symmetry: Load → sdk DeltaWindowBuffer, Save → Postgres.
  - SaveTx called INSIDE the atomic commit transaction — buffer and leaf
    mutations are committed together. No partial state.
  - Uses buf.AllKeys() to enumerate all leaves with recorded history.
    AllKeys returns every leaf that has received Path C updates — typically
    under 100 active leaves per batch.
  - Tip history serialized as compact BYTEA: [count][pos1][pos2]...
  - Reconstructable from ScanFromPosition if table is lost.

INVARIANTS:
  - Empty table = cold start = strict OCC (SDK-D9).
  - SaveTx persists all active buffer entries, not just current-batch deltas.
*/
package builder

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/types"
)

// DeltaBufferStore persists the delta-window buffer to Postgres.
type DeltaBufferStore struct {
	db         *pgxpool.Pool
	windowSize int
	logger     *slog.Logger
}

// NewDeltaBufferStore creates a buffer store.
func NewDeltaBufferStore(db *pgxpool.Pool, windowSize int, logger *slog.Logger) *DeltaBufferStore {
	if windowSize < 1 {
		windowSize = 10
	}
	return &DeltaBufferStore{db: db, windowSize: windowSize, logger: logger}
}

// Load reads the persisted buffer into an SDK DeltaWindowBuffer.
// Returns an empty buffer on cold start (SDK-D9: strict OCC).
func (s *DeltaBufferStore) Load(ctx context.Context) (*sdkbuilder.DeltaWindowBuffer, error) {
	buf := sdkbuilder.NewDeltaWindowBuffer(s.windowSize)

	rows, err := s.db.Query(ctx,
		"SELECT leaf_key, tip_history FROM delta_window_buffers",
	)
	if err != nil {
		return buf, fmt.Errorf("builder/delta_buffer: load: %w", err)
	}
	defer rows.Close()

	loaded := 0
	for rows.Next() {
		var keyBytes, histBytes []byte
		if err := rows.Scan(&keyBytes, &histBytes); err != nil {
			return buf, fmt.Errorf("builder/delta_buffer: scan: %w", err)
		}
		if len(keyBytes) != 32 {
			s.logger.Warn("delta_buffer: skipping corrupt key", "len", len(keyBytes))
			continue
		}
		var key [32]byte
		copy(key[:], keyBytes)

		tips, err := deserializeTipHistory(histBytes)
		if err != nil {
			s.logger.Warn("delta_buffer: skipping corrupt history",
				"key", fmt.Sprintf("%x", key[:8]), "error", err)
			continue
		}
		buf.SetHistory(key, tips)
		loaded++
	}
	if err := rows.Err(); err != nil {
		return buf, fmt.Errorf("builder/delta_buffer: rows: %w", err)
	}

	s.logger.Info("delta buffer loaded", "leaves", loaded)
	return buf, nil
}

// SaveTx persists the current buffer state within a transaction.
// Called as part of the builder's atomic commit in loop.go step 5.
//
// Uses buf.AllKeys() to enumerate every leaf with recorded history.
// For each key, persists the tip history via UPSERT. Removes entries
// whose history has been emptied. Trims to windowSize.
func (s *DeltaBufferStore) SaveTx(ctx context.Context, tx pgx.Tx, buf *sdkbuilder.DeltaWindowBuffer) error {
	allKeys := buf.AllKeys()
	if len(allKeys) == 0 {
		return nil
	}

	for _, key := range allKeys {
		tips := buf.History(key)
		if len(tips) == 0 {
			// Remove entries with empty history.
			if _, err := tx.Exec(ctx,
				"DELETE FROM delta_window_buffers WHERE leaf_key = $1", key[:],
			); err != nil {
				return fmt.Errorf("builder/delta_buffer: delete %x: %w", key[:8], err)
			}
			continue
		}

		// Trim to window size.
		if len(tips) > s.windowSize {
			tips = tips[len(tips)-s.windowSize:]
		}

		histBytes := serializeTipHistory(tips)
		if _, err := tx.Exec(ctx, `
			INSERT INTO delta_window_buffers (leaf_key, tip_history, updated_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (leaf_key) DO UPDATE SET
				tip_history = EXCLUDED.tip_history,
				updated_at = NOW()`,
			key[:], histBytes,
		); err != nil {
			return fmt.Errorf("builder/delta_buffer: upsert %x: %w", key[:8], err)
		}
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Tip history serialization: [count uint16][pos1][pos2]...
// Each pos: [didLen uint16][did bytes][seq uint64]
// ─────────────────────────────────────────────────────────────────────────────

func serializeTipHistory(tips []types.LogPosition) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(tips)))
	for _, tip := range tips {
		did := []byte(tip.LogDID)
		dl := make([]byte, 2)
		binary.BigEndian.PutUint16(dl, uint16(len(did)))
		buf = append(buf, dl...)
		buf = append(buf, did...)
		s := make([]byte, 8)
		binary.BigEndian.PutUint64(s, tip.Sequence)
		buf = append(buf, s...)
	}
	return buf
}

func deserializeTipHistory(data []byte) ([]types.LogPosition, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("too short")
	}
	count := binary.BigEndian.Uint16(data[0:2])
	pos := 2
	tips := make([]types.LogPosition, 0, count)
	for i := uint16(0); i < count; i++ {
		if pos+2 > len(data) {
			return nil, fmt.Errorf("truncated at tip %d", i)
		}
		didLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if pos+didLen+8 > len(data) {
			return nil, fmt.Errorf("truncated did at tip %d", i)
		}
		did := string(data[pos : pos+didLen])
		pos += didLen
		seq := binary.BigEndian.Uint64(data[pos : pos+8])
		pos += 8
		tips = append(tips, types.LogPosition{LogDID: did, Sequence: seq})
	}
	return tips, nil
}
