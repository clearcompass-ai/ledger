/*
FILE PATH: cmd/rebuild-projection/main.go

CLI wrapper around Rebuild() (rebuild.go). Operators invoke this in
two disaster-recovery scenarios:

  1. Postgres volume corrupted/wiped. The tile store is intact
     (S3/GCS/CDN); the gossip feed is intact. Re-running migrations
     creates the empty projection schema, then this binary walks
     the tiles and repopulates entry_index, smt_leaves,
     smt_root_state, builder_cursor.

  2. Schema rebase. A migration changes the projection layout. After
     the schema is in place, this binary rebuilds the projection
     content from the immutable tile source.

In both cases the integrity proof is: re-running the live
admission/builder against the same inputs would produce the same
projection rows, byte-for-byte. The integration test
(rebuild_test.go) pins this invariant.

OPERATIONAL NOTES:

  - The binary is idempotent; re-running over a partial rebuild
    overwrites prior rows (entry_index ON CONFLICT, smt_leaves
    UPSERT). A crash mid-rebuild leaves a consistent partial state
    that the next run finishes.
  - Migrations are NOT run by this binary. Operator must run
    schema migrations first; otherwise the INSERTs fail loudly.
  - Tree heads + witness sets are NOT rebuilt here (they come from
    the gossip feed; that path is §E2 in the production-readiness
    doc).
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	var (
		tileDir   = flag.String("tile-dir", "", "filesystem path to the Tessera POSIX tile store (REQUIRED)")
		pgDSN     = flag.String("pg-dsn", "", "Postgres DSN (e.g. postgres://attesta:attesta@host:5432/attesta_test?sslmode=disable) (REQUIRED)")
		logDID    = flag.String("log-did", "", "the log's DID — must match the Origin in the checkpoint (REQUIRED)")
		batchSize = flag.Int("batch-size", 500, "entries processed per atomic commit; bounds memory + lock-hold time")
		verbose   = flag.Bool("verbose", false, "log every batch commit at INFO level (default: warn-only)")
	)
	flag.Parse()
	if *tileDir == "" || *pgDSN == "" || *logDID == "" {
		fmt.Fprintln(os.Stderr, "rebuild-projection: --tile-dir, --pg-dsn, and --log-did are all required")
		flag.PrintDefaults()
		os.Exit(2)
	}

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Honour SIGTERM/SIGINT so a long rebuild can be cancelled
	// cleanly; partial state is consistent (cursor + leaves +
	// entry_index advance together per atomic batch).
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		logger.Error("open postgres pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	logger.Info("rebuild-projection: starting",
		"tile_dir", *tileDir,
		"log_did", *logDID,
		"batch_size", *batchSize,
	)

	start := time.Now()
	stats, err := Rebuild(ctx, RebuildDeps{
		TileDir:   *tileDir,
		Pool:      pool,
		LogDID:    *logDID,
		BatchSize: *batchSize,
		Logger:    logger,
	})
	if err != nil {
		logger.Error("rebuild failed",
			"err", err,
			"elapsed", time.Since(start),
		)
		os.Exit(1)
	}

	fmt.Printf("rebuild-projection: complete\n")
	fmt.Printf("  tree_size:      %d\n", stats.TreeSize)
	fmt.Printf("  entries:        %d\n", stats.EntriesProcessed)
	fmt.Printf("  leaves_written: %d\n", stats.LeavesWritten)
	fmt.Printf("  root:           %x\n", stats.Root)
	fmt.Printf("  duration:       %s\n", stats.Duration.Round(time.Millisecond))
}
