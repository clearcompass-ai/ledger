/*
FILE PATH: api/middleware/rate_limit.go

DifficultyController manages dynamic difficulty for Mode B admission stamps.
Adjusts based on cursor lag — the count of admitted entries the builder has
not yet processed. Higher lag means higher PoW difficulty, which throttles
unauthenticated submissions until the builder catches up.

KEY ARCHITECTURAL DECISIONS:
  - Cursor-lag-based: log-tailing replacement for the legacy queue-depth
    signal. Mathematically identical (MAX(entry_index.seq) - cursor) but
    bounds Postgres MVCC pressure to one row UPDATE per builder batch
    instead of two writes per admitted entry.
  - Floor/ceiling: minimum 8 bits, maximum 24 bits.
  - Recomputed every 30 seconds via background goroutine.
  - CurrentDifficulty() is atomic — safe for per-request reads.
*/
package middleware

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// LagProvider returns the current builder lag (admitted-but-unprocessed
// entries). Implemented by store.SequenceCursor.Lag in production; tests
// inject fakes.
type LagProvider interface {
	Lag(ctx context.Context) (int64, error)
}

// DifficultyController dynamically adjusts Mode B stamp difficulty.
type DifficultyController struct {
	lag           LagProvider
	difficulty    atomic.Uint32
	minDifficulty uint32
	maxDifficulty uint32
	lowThreshold  int64
	highThreshold int64
	hashFunc      string
	logger        *slog.Logger
}

// DifficultyConfig configures the difficulty controller.
type DifficultyConfig struct {
	InitialDifficulty uint32
	MinDifficulty     uint32
	MaxDifficulty     uint32
	LowThreshold      int64
	HighThreshold     int64
	AdjustInterval    time.Duration
	HashFunction      string // "sha256" or "argon2id"
}

// DefaultDifficultyConfig returns production defaults.
func DefaultDifficultyConfig() DifficultyConfig {
	return DifficultyConfig{
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		LowThreshold:      100,
		HighThreshold:     10000,
		AdjustInterval:    30 * time.Second,
		HashFunction:      "sha256",
	}
}

// NewDifficultyController creates a difficulty controller. lag may be nil
// for read-only ledgers that do not run admission; in that case the
// auto-adjust loop runs at static initial difficulty.
func NewDifficultyController(lag LagProvider, cfg DifficultyConfig, logger *slog.Logger) *DifficultyController {
	dc := &DifficultyController{
		lag:           lag,
		minDifficulty: cfg.MinDifficulty,
		maxDifficulty: cfg.MaxDifficulty,
		lowThreshold:  cfg.LowThreshold,
		highThreshold: cfg.HighThreshold,
		hashFunc:      cfg.HashFunction,
		logger:        logger,
	}
	dc.difficulty.Store(cfg.InitialDifficulty)
	return dc
}

// CurrentDifficulty returns the current difficulty. Thread-safe (atomic).
func (dc *DifficultyController) CurrentDifficulty() uint32 {
	return dc.difficulty.Load()
}

// HashFunction returns the configured hash function name.
func (dc *DifficultyController) HashFunction() string {
	return dc.hashFunc
}

// Run starts the adjustment loop. Blocks until ctx cancelled.
func (dc *DifficultyController) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dc.adjust(ctx)
		}
	}
}

func (dc *DifficultyController) adjust(ctx context.Context) {
	if dc.lag == nil {
		return
	}
	depth, err := dc.lag.Lag(ctx)
	if err != nil {
		dc.logger.Error("difficulty: cursor lag query", "error", err)
		return
	}

	current := dc.difficulty.Load()
	var next uint32
	switch {
	case depth < dc.lowThreshold && current > dc.minDifficulty:
		next = current - 1
	case depth > dc.highThreshold && current < dc.maxDifficulty:
		next = current + 1
	default:
		return
	}

	dc.difficulty.Store(next)
	dc.logger.Info("difficulty adjusted",
		"from", current, "to", next, "cursor_lag", depth)
}
