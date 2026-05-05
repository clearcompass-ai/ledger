# Operations

## Boot order

`cmd/operator/main.go` boots in this order. Anything marked **fatal**
exits non-zero before the HTTP server binds.

| Step | Action | Failure mode |
|---|---|---|
| 1 | `loadConfig()` from environment | Fatal — required vars missing |
| 2 | `envelope.ValidateDestination(LogDID)` | Fatal — invalid log DID |
| 3 | `pgxpool.New(DatabaseURL)` | Fatal — DB unreachable |
| 4 | `store.RunMigrations` (idempotent DDL) | Fatal — migration SQL error |
| 5 | Open WAL Badger at `OPERATOR_WAL_PATH` | Fatal — Badger open error |
| 6 | Open Tessera POSIX storage + antispam | Fatal |
| 7 | Construct bytestore (GCS or S3) | Fatal — credentials / bucket invalid |
| 8 | Wire OTel MeterProvider (if enabled) + `api.InstallErrorCounter` | Logs warning if registration fails; continues |
| 9 | Wire gossipstore (BadgerStore on same handle, prefix `0x07`) | Optional — disabled when `OPERATOR_GOSSIP_DISABLE=true` |
| 10 | Wire Sequencer + bind boot replayer (`0x0D` HWM) | Replayer goroutine starts inside `Run()`; failures logged |
| 11 | Wire EquivocationScanner (subscribes to `0x0A`) | Optional — only when gossip enabled |
| 12 | Wire Shipper goroutine | Drains `StateSequenced` → bytestore → `MarkShipped` |
| 13 | Wire HTTP handlers + bind `httpServer.ListenAndServe` | Fatal — bind error |
| 14 | Fatal-channel supervisor goroutines (Loop, Shipper, etc.) | Any send to fatal channel exits the process |

## Graceful shutdown

```
SIGTERM (or SIGINT)
   │
   ▼  ctx cancel propagates to:
   ├─ http.Server.Shutdown — drains in-flight requests
   ├─ Sequencer.Run — stops drain ticker, drains replayer goroutine
   ├─ Shipper — finishes the current upload batch, flushes WAL.MarkShipped
   ├─ EquivocationScanner — Subscribe loop returns ctx.Err()
   ├─ Anti-entropy puller — stops ticker
   ├─ Anchor publisher — stops ticker
   │
   ▼  gossipWG.Wait — every gossip goroutine drained
   ▼  WAL.Close — flushes group-commit batch
   ▼  Tessera.Close — flushes tile writes
   ▼  Bytestore.Close — flushes any in-flight uploads
   ▼  Postgres pool Close
   │
   process exits 0
```

Set `terminationGracePeriodSeconds: 60` in Kubernetes to accommodate
in-flight Tessera flushes + bytestore uploads.

## Kubernetes

| Property | Value | Why |
|---|---|---|
| Replicas | exactly 1 per log DID | Postgres advisory lock prevents concurrent builders (`store/postgres.go: pg_advisory_lock(0x4F5254484F4C4F47)`) |
| Liveness | `GET /healthz` | 200 while process runs |
| Readiness | `GET /readyz` | 200 when ready, 503 during shutdown (atomic bool flips at SIGTERM) |
| Volumes | distinct PVCs for `OPERATOR_WAL_PATH`, `OPERATOR_TESSERA_STORAGE_DIR`, `OPERATOR_TESSERA_ANTISPAM_PATH` | Corruption in one shouldn't force discarding the others |
| Resources | 500m CPU / 512Mi minimum | Sequencer is CPU-bound during batch processing |
| Secrets | `OPERATOR_DATABASE_URL`, signer key files, S3/GCS credentials | Inject via Secret / SOPS |

A read-only sibling (`cmd/operator-reader`) serves the read endpoints
without admission. Run as many replicas as needed for read scaling —
the advisory lock only applies to the writer.

## Repository layout

```
cmd/                    Binaries
  operator/             Main operator binary
  operator-reader/      Read-only replica (no admission, no sequencer)
  submit-stamp/         CLI: build + sign + POST a v7.75 entry
  seed-session/         Dev: insert into sessions table
  rebuild-tiles/        Ops: replay entry_index → Tessera tiles
  bootstrap-v775-schemas/ Ops: load schema definitions

api/                    HTTP handlers (zero pgx imports)
api/middleware/         Auth (SessionLookup), SizeLimit
apitypes/               Leaf package: value types + sentinels (no pgx)

wal/                    Badger WAL
sequencer/              WAL → Tessera → Postgres + Badger projections
shipper/                WAL → bytestore migrator
store/                  Postgres-backed implementations
gossipstore/            Badger-backed gossip Store + read projections
gossipnet/              Gossip handler, sink, scanner, override flow
tessera/                Embedded Tessera appender
bytestore/              GCS / S3 / in-memory backends
admission/              Signature verification, NFC checks
integrity/              Boot reconciliation + sample-verify detector
lifecycle/              Graceful shutdown helpers
witness/                Witness-mode cosign endpoint
anchor/                 External anchor publisher
builder/                Commitment publisher loop

config/                 operator.yaml example
deployment/             Local dev orchestration
docs/                   This documentation
integration/            Postgres-backed integration tests (gated by ORTHOLOG_TEST_DSN)
tests/                  End-to-end test harness
script/, scripts/       Misc developer scripts
```

## Test suite

```sh
# Module-wide short tests (no Postgres required)
go test -count=1 -short ./...
# 20 packages, all green:
#   admission, anchor, api, api/middleware, apitypes, builder,
#   bytestore, cmd/operator, cmd/submit-stamp, gossipnet,
#   gossipstore, integration (skipped without DSN), integrity,
#   lifecycle, sequencer, shipper, store, tessera, tests, wal

# Race detector on the touched packages
go test -count=1 -race -short ./api/ ./api/middleware/ ./apitypes/ \
    ./gossipnet/ ./gossipstore/ ./sequencer/ ./store/

# Static analysis
go vet ./...

# Integration tests (need a live Postgres)
export ORTHOLOG_TEST_DSN="postgres://..."
go test -count=1 ./integration/... ./tests/...
```

## Compliance checks

The architecture invariants are verified at every build:

```sh
# Pure CQRS — api/ has zero Postgres-driver imports
go list -deps ./api/ | grep -E 'pgx|database/sql' | wc -l
# → 0

# apitypes/ leaf has zero deps that pull pgx
go list -deps ./apitypes/ | grep -E 'pgx|database/sql' | wc -l
# → 0

# api/middleware/ leaf is pgx-free (auth uses SessionLookup interface)
go list -deps ./api/middleware/ | grep -E 'pgx|database/sql' | wc -l
# → 0
```

Compile-time interface checks:

```
store/session_lookup.go:75
    var _ middleware.SessionLookup = (*PostgresSessionLookup)(nil)
store/commitment_fetcher.go:208
    var _ types.CommitmentFetcher = (*PostgresCommitmentFetcher)(nil)
gossipstore/commitment_fetcher.go:121
    var _ types.CommitmentFetcher = (*BadgerCommitmentFetcher)(nil)
gossipnet/sequencer_adapter.go:103-105
    var _ sequencer.SplitIDIndexWriter   = (*SequencerSplitIDAdapter)(nil)
    var _ sequencer.EntryLookupWriter    = (*SequencerEntryLookupAdapter)(nil)
    var _ sequencer.SplitIDReplayCursor  = (*SequencerReplayCursorAdapter)(nil)
```

Drift in any side fails the build at boot rather than at first
request.

## Common ops tasks

### Re-key the operator signer

```sh
# Generate new key (operator's secp256k1 ECDSA — signs SCTs + tree heads)
openssl ecparam -name secp256k1 -genkey -noout -out new.key

# Hot-rotate is NOT supported; the operator embeds the DID in every SCT.
# Roll out: update OPERATOR_SIGNER_KEY_FILE + OPERATOR_DID secrets + rolling restart.
```

### Add a new bytestore

```sh
# Update OPERATOR_BYTE_STORE_BACKEND + OPERATOR_BYTE_STORE_*_BUCKET
# Existing entries remain at the old bucket — no automatic migration.
# Run cmd/rebuild-tiles to backfill if needed.
```

### Drain a node before shutdown

```sh
# 1. Flip readiness to NotReady (stops new traffic; existing requests drain)
kubectl annotate pod ortholog-operator-0 ortholog.io/drain=true

# 2. Wait for /readyz to return 503 OR for the WAL queue to drain
curl http://operator/readyz

# 3. SIGTERM
kubectl delete pod ortholog-operator-0 --grace-period=60
```

### Inspect a stuck entry

```sh
# By canonical hash
curl http://operator/v1/entries-hash/<hash_hex>
# Returns {"state":"pending"} | {"state":"manual"} | full metadata

# StateManual means the sequencer gave up after MaxAttempts.
# The bytes are still in the WAL — operator-side intervention to retry
# manually OR mark the entry as drop-and-replace.
```
