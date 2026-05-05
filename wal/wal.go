/*
FILE PATH: wal/wal.go

Package wal is the ledger's write-ahead log + byte-of-record store
for entries between admission and shipping. Backed by BadgerDB.

PURPOSE:

	Under admission, the ledger MUST return HTTP 202 only after
	the wire bytes are durable on disk. The legacy code path returned
	202 after a Postgres INSERT, which works at small scale but
	thrashes Postgres autovacuum at 10B+ entries and ties admission
	latency to network-bound network storage. The WAL replaces that:

	  1. Submit blocks until bytes are fsync'd to local NVMe (Badger's
	     WAL on the ledger host).
	  2. Tessera assigns the sequence number.
	  3. Postgres entry_index INSERT records sidecar metadata.
	  4. The Shipper migrates bytes to the production byte store
	     (GCS/S3) asynchronously and advances HWM.
	  5. Reads of pre-shipped entries serve from the WAL; reads of
	     shipped entries 302-redirect to the byte store's presigned URL.

ARCHITECTURE:

  - Committer (committer.go): Submit + group commit + fsync.
  - State machine (meta.go, reader.go): Sequence / MarkShipped /
    MarkRetry / MarkManual transitions.
  - Reader (reader.go): Read / HWM / Iterate*.
  - TesseraDedup (dedup.go): satisfies Tessera's Deduplicator
    interface against the same Badger.
  - Reconciliation (handled by integrity package, not wal): boot-time
    re-Add of inflight entries.

KEYSPACE:

	See keyspace.go for the on-disk layout. All paths use prefix tags
	so a future migration can add or remove a category without
	rewriting existing keys.

OPENING THE DB:

	Open returns a Badger DB configured with SyncWrites=false (the
	Committer manages fsync explicitly via db.Sync()) and tuned for
	the ledger's write-heavy workload. Caller is responsible for
	closing both the Committer and the DB at shutdown.
*/
package wal

import (
	"fmt"
	"log/slog"

	"github.com/dgraph-io/badger/v4"
)

// Open opens (or creates) a BadgerDB at path with options tuned for
// the ledger's write path.
//
// SyncWrites=false: the Committer manages fsync explicitly via
// db.Sync() after each group-commit batch. Passing SyncWrites=true
// here would cause Badger to fsync on every txn commit, defeating
// the purpose of group commit.
//
// path="" → in-memory mode (test/dev only). Production callers MUST
// pass a real on-disk path.
func Open(path string, logger *slog.Logger) (*badger.DB, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var opts badger.Options
	if path == "" {
		opts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		opts = badger.DefaultOptions(path)
	}
	// Group commit invariant: never fsync per-commit. The Committer
	// calls db.Sync() once per batch.
	opts = opts.WithSyncWrites(false)
	// Quiet Badger's stdout chatter; route any errors into our slog.
	opts = opts.WithLogger(badgerLogger{logger: logger})
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("wal: badger.Open(%q): %w", path, err)
	}
	return db, nil
}

// OpenInMemory returns an in-memory Badger DB suitable for tests.
// Identical to Open("", logger).
func OpenInMemory(logger *slog.Logger) (*badger.DB, error) {
	return Open("", logger)
}

// badgerLogger adapts slog.Logger to badger.Logger.
type badgerLogger struct {
	logger *slog.Logger
}

func (b badgerLogger) Errorf(format string, args ...interface{}) {
	b.logger.Error(fmt.Sprintf(format, args...))
}
func (b badgerLogger) Warningf(format string, args ...interface{}) {
	b.logger.Warn(fmt.Sprintf(format, args...))
}
func (b badgerLogger) Infof(format string, args ...interface{}) {
	b.logger.Info(fmt.Sprintf(format, args...))
}
func (b badgerLogger) Debugf(format string, args ...interface{}) {
	b.logger.Debug(fmt.Sprintf(format, args...))
}
