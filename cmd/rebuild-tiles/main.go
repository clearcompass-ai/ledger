/*
FILE PATH: cmd/rebuild-tiles/main.go

DESCRIPTION:

	One-shot utility that rebuilds the Tessera tile store from
	existing admitted entries in Postgres, driving the builder loop
	to completion against a FRESH Tessera personality (empty storage).

	Use this when the on-disk Tessera state is lost or invalidated
	(e.g., volume corruption, leaf-scheme migration). The Postgres
	entry_index is the source of truth for what was admitted; this
	utility replays those entries against a fresh tile store so
	inclusion proofs match the rebuilt tree.

WHY A SEPARATE BINARY:

	The production ledger runs admission, anchor publisher, commitment
	publisher, and witness cosigner concurrently with the builder loop.
	For a tile rebuild we want ONLY the builder loop — no new admissions,
	no anchor publishing, no witness cosig requests. A dedicated binary
	makes the intent explicit.

SAFETY CONTRACT:
 1. Idempotent against its OWN re-runs.
 2. NOT idempotent against the production ledger running
    concurrently. Stop the production binary first.
 3. Point --tessera-url at a FRESH personality with empty storage. If
    the target contains existing tile data, rebuild will APPEND rather
    than replace.
 4. BYTE STORE: uses bytestore.NewMemory() here, which is
    EMPTY at startup. For a real rebuild, the byte store MUST be the
    same persistent backend the production ledger wrote to —
    otherwise the fetcher will find nothing to replay. Wire your
    persistent store at the marked line.

USAGE:

	# 1. Stop the production ledger.
	systemctl stop ledger

	# 2. Back up Postgres.
	pg_dump attesta > /var/backups/ledger-pre-rebuild-$(date -I).sql

	# 3. Start a FRESH Tessera personality on a new port with empty
	#    storage (or wipe the existing personality's storage and restart).

	# 4. Reset cursor + tree state so every admitted entry replays.
	psql attesta <<SQL
	    UPDATE builder_cursor SET last_processed_sequence = 0 WHERE id = 1;
	    DELETE FROM derivation_commitments WHERE true;
	    DELETE FROM smt_leaves WHERE true;
	    DELETE FROM smt_nodes WHERE true;
	    DELETE FROM delta_window_buffers WHERE true;
	SQL

	# 5. Run the rebuild.
	./rebuild-tiles \
	    --database-url="$LEDGER_DATABASE_URL" \
	    --log-did="did:web:your-log.example" \
	    --tessera-url="http://fresh-tessera:8081" \
	    --batch-size=1000

	# 6. Start the production ledger pointing at the new personality.

EXIT CODES:

	0 — rebuild completed cleanly.
	1 — configuration error.
	3 — builder loop failure. Rebuild is in a partial state; investigate.
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

	"github.com/transparency-dev/tessera/storage/posix"

	sdkbuilder "github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"

	"github.com/clearcompass-ai/ledger/builder"
	"github.com/clearcompass-ai/ledger/bytestore"
	"github.com/clearcompass-ai/ledger/store"
	"github.com/clearcompass-ai/ledger/tessera"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var (
		databaseURL = flag.String("database-url", os.Getenv("LEDGER_DATABASE_URL"), "Postgres connection string")
		logDID = flag.String("log-did", os.Getenv("LEDGER_LOG_DID"), "log DID (must match production)")
		tesseraStorageDir = flag.String("tessera-storage-dir", os.Getenv("LEDGER_TESSERA_STORAGE_DIR"), "POSIX directory for the rebuilt Tessera (MUST be empty / fresh)")
		tesseraOrigin = flag.String("tessera-origin", os.Getenv("LEDGER_TESSERA_ORIGIN"), "tlog-tiles origin string for the rebuilt log (defaults to log-did)")
		batchSize = flag.Int("batch-size", 1000, "builder batch size")
		pollInterval = flag.Duration("poll-interval", 10*time.Millisecond, "queue poll interval")
		idleShutdownAfter = flag.Duration("idle-shutdown-after", 30*time.Second, "exit cleanly after this much idle time")
		nodeCacheSize = flag.Int("node-cache-size", 100_000, "SMT node cache max size")
		deltaWindow = flag.Int("delta-window", 10, "delta buffer window size (match production)")
	)
	flag.Parse()

	if *databaseURL == "" || *logDID == "" || *tesseraStorageDir == "" {
		logger.Error("required flags missing",
			"database_url_set", *databaseURL != "",
			"log_did_set", *logDID != "",
			"tessera_storage_dir_set", *tesseraStorageDir != "",
		)
		os.Exit(1)
	}
	if err := envelope.ValidateDestination(*logDID); err != nil {
		logger.Error("invalid log DID", "error", err)
		os.Exit(1)
	}

	logger.Info("tile rebuild starting",
		"log_did", *logDID,
		"tessera_storage_dir", *tesseraStorageDir,
		"batch_size", *batchSize,
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Postgres ──────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		logger.Error("pgxpool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// ── Stores ────────────────────────────────────────────────────────
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool, *nodeCacheSize)

	// CRITICAL: In production, replace NewInMemoryEntryStore with your
	// persistent byte store implementation. The rebuild loop reads entry
	// bytes from here when replaying each sequence through ProcessBatch;
	// if the store is empty the replay produces zero output.
	byteStore := bytestore.NewMemory()
	logger.Warn("byte store is InMemoryEntryStore — rebuild will find no entries to replay unless you wire the production byte store here")

	// ── Embedded Tessera (fresh storage) ──────────────────────────
	// Rebuild boots a fresh in-process Tessera over the supplied
	// (empty) POSIX directory, replays sequenced entries through
	// the builder, and shuts down cleanly. AppendLeaf and Head
	// are the only adapter methods exercised; a nil TileReader is
	// fine because proof methods are not called during rebuild.
	if err := os.MkdirAll(*tesseraStorageDir, 0o755); err != nil {
		logger.Error("tessera storage dir", "error", err, "dir", *tesseraStorageDir)
		os.Exit(1)
	}
	tesseraDriver, err := posix.New(ctx, posix.Config{Path: *tesseraStorageDir})
	if err != nil {
		logger.Error("tessera posix driver", "error", err)
		os.Exit(1)
	}
	origin := *tesseraOrigin
	if origin == "" {
		origin = *logDID
	}
	signer, _, err := tessera.GenerateEphemeralSigner(origin)
	if err != nil {
		logger.Error("tessera signer", "error", err)
		os.Exit(1)
	}
	embeddedAppender, err := tessera.NewEmbeddedAppender(ctx, tesseraDriver, tessera.AppenderOptions{
		Origin: origin,
		Signer: signer,
	}, logger)
	if err != nil {
		logger.Error("tessera embedded appender", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := embeddedAppender.Close(shutdownCtx); err != nil {
			logger.Warn("tessera shutdown", "error", err)
		}
	}()
	merkle := tessera.NewTesseraAdapter(embeddedAppender, nil, logger)

	// ── Builder dependencies ──────────────────────────────────────────
	fetcher := store.NewPostgresEntryFetcher(pool, byteStore, *logDID)
	bufferStore := builder.NewDeltaBufferStore(pool, *deltaWindow, logger)
	buffer, loadErr := bufferStore.Load(ctx)
	if loadErr != nil {
		logger.Warn("delta buffer load — starting cold", "error", loadErr)
		buffer = sdkbuilder.NewDeltaWindowBuffer(*deltaWindow)
	}
	reader := builder.NewCursorReader(store.NewSequenceCursor(pool))
	tree := smt.NewTree(leafStore, nodeCache)

	bl := builder.NewBuilderLoop(
		builder.LoopConfig{
			LogDID:       *logDID,
			BatchSize:    *batchSize,
			PollInterval: *pollInterval,
			DeltaWindow:  *deltaWindow,
		},
		pool, tree, leafStore, nodeCache,
		reader, fetcher,
		nil, // schema resolver
		buffer, bufferStore,
		nil,    // commitPub — no commentary on partial mid-rebuild state.
		merkle, // MerkleAppender
		nil,    // witness cosigner — no one watches partial tree heads.
		logger,
	)

	// ── Idle watchdog: exit when entries counter stops advancing. ────
	go func() {
		lastSeenEntries := int64(-1)
		lastAdvanced := time.Now()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, entries, _ := bl.Stats()
				if entries != lastSeenEntries {
					lastSeenEntries = entries
					lastAdvanced = time.Now()
					continue
				}
				if time.Since(lastAdvanced) >= *idleShutdownAfter {
					logger.Info("idle shutdown threshold reached",
						"total_entries", entries,
						"idle_for", time.Since(lastAdvanced),
					)
					cancel()
					return
				}
			}
		}
	}()

	if err := bl.Run(ctx); err != nil {
		logger.Error("builder loop failed during rebuild", "error", err)
		os.Exit(3)
	}

	head, headErr := merkle.Head()
	if headErr != nil {
		logger.Error("final head fetch", "error", headErr)
		os.Exit(3)
	}
	fmt.Printf("\n=== TILE REBUILD COMPLETE ===\n")
	fmt.Printf("  log_did:     %s\n", *logDID)
	fmt.Printf("  tessera_storage_dir: %s\n", *tesseraStorageDir)
	fmt.Printf("  tree_size:   %d\n", head.TreeSize)
	fmt.Printf("  root_hash:   %x\n", head.RootHash[:])
	batches, entries, errs := bl.Stats()
	fmt.Printf("  batches:     %d\n", batches)
	fmt.Printf("  entries:     %d\n", entries)
	fmt.Printf("  errors:      %d\n", errs)
}
