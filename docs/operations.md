# Operations

## Boot order

`cmd/ledger/main.go` boots in this order. Anything marked **fatal**
exits non-zero before the HTTP server binds.

| Step | Action | Failure mode |
|---|---|---|
| 1 | `loadConfig()` from environment | Fatal — required vars missing |
| 2 | `envelope.ValidateDestination(LogDID)` | Fatal — invalid log DID |
| 3 | `pgxpool.New(DatabaseURL)` | Fatal — DB unreachable |
| 4 | `store.RunMigrations` (idempotent DDL) | Fatal — migration SQL error |
| 5 | Open WAL Badger at `LEDGER_WAL_PATH` | Fatal — Badger open error |
| 6 | Open Tessera POSIX storage + antispam | Fatal |
| 7 | Construct bytestore (GCS or S3) | Fatal — credentials / bucket invalid |
| 8 | Wire OTel MeterProvider (if enabled) + `api.InstallErrorCounter` | Logs warning if registration fails; continues |
| 9 | Wire gossipstore (BadgerStore on same handle, prefix `0x07`) | Optional — disabled when `LEDGER_GOSSIP_DISABLE=true` |
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
| Volumes | distinct PVCs for `LEDGER_WAL_PATH`, `LEDGER_TESSERA_STORAGE_DIR`, `LEDGER_TESSERA_ANTISPAM_PATH` | Corruption in one shouldn't force discarding the others |
| Resources | 500m CPU / 512Mi minimum | Sequencer is CPU-bound during batch processing |
| Secrets | `LEDGER_DATABASE_URL`, signer key files, S3/GCS credentials | Inject via Secret / SOPS |

A read-only sibling (`cmd/ledger-reader`) serves the read endpoints
without admission. Run as many replicas as needed for read scaling —
the advisory lock only applies to the writer.

## Repository layout

```
cmd/                    Binaries
  ledger/             Main ledger binary
  ledger-reader/      Read-only replica (no admission, no sequencer)
  submit-stamp/       CLI: build + sign + POST an entry
  seed-session/       Dev: insert into sessions table
  rebuild-tiles/      Ops: replay entry_index → Tessera tiles

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

docs/                   This documentation
integration/            Postgres-backed integration tests (gated by ATTESTA_TEST_DSN)
tests/                  End-to-end test harness
scripts/                Runnable developer utilities (run-local, run-gcs-tests, run-soak, ...)
scripts/local/          Docker Compose stacks (local single-op, dev multi-op, integration two-op, test harness)
```

## Test suite

```sh
# Module-wide short tests (no Postgres required)
go test -count=1 -short ./...
# 20 packages, all green:
#   admission, anchor, api, api/middleware, apitypes, builder,
#   bytestore, cmd/ledger, cmd/submit-stamp, gossipnet,
#   gossipstore, integration (skipped without DSN), integrity,
#   lifecycle, sequencer, shipper, store, tessera, tests, wal

# Race detector on the touched packages
go test -count=1 -race -short ./api/ ./api/middleware/ ./apitypes/ \
    ./gossipnet/ ./gossipstore/ ./sequencer/ ./store/

# Static analysis
go vet ./...

# Integration tests (need a live Postgres)
export ATTESTA_TEST_DSN="postgres://..."
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
    var _ sequencer.SplitIDIndexWriter = (*SequencerSplitIDAdapter)(nil)
    var _ sequencer.EntryLookupWriter = (*SequencerEntryLookupAdapter)(nil)
    var _ sequencer.SplitIDReplayCursor = (*SequencerReplayCursorAdapter)(nil)
```

Drift in any side fails the build at boot rather than at first
request.

## Common ops tasks

### Re-key the ledger signer

```sh
# Generate new key (ledger's secp256k1 ECDSA — signs SCTs + tree heads)
openssl ecparam -name secp256k1 -genkey -noout -out new.key

# Hot-rotate is NOT supported; the ledger embeds the DID in every SCT.
# Roll out: update LEDGER_SIGNER_KEY_FILE + LEDGER_DID secrets + rolling restart.
```

### Add a new bytestore

```sh
# Update LEDGER_BYTE_STORE_BACKEND + LEDGER_BYTE_STORE_*_BUCKET
# Existing entries remain at the old bucket — no automatic migration.
# Run cmd/rebuild-tiles to backfill if needed.
```

### Drain a node before shutdown

```sh
# 1. Flip readiness to NotReady (stops new traffic; existing requests drain)
kubectl annotate pod ledger-0 attesta.io/drain=true

# 2. Wait for /readyz to return 503 OR for the WAL queue to drain
curl http://ledger/readyz

# 3. SIGTERM
kubectl delete pod ledger-0 --grace-period=60
```

### Inspect a stuck entry

```sh
# By canonical hash
curl http://ledger/v1/entries-hash/<hash_hex>
# Returns {"state":"pending"} | {"state":"manual"} | full metadata

# StateManual means the sequencer gave up after MaxAttempts.
# The bytes are still in the WAL — ledger-side intervention to retry
# manually OR mark the entry as drop-and-replace.
```

## Static-CT tile serving (c2sp.org/tlog-tiles)

The ledger exposes the c2sp.org/tlog-tiles read surface so external
auditors fetch inclusion + consistency proofs offline using the SDK's
`log/tessera_fetcher` primitive — no per-entry round-trip to the
ledger required, no ledger CPU consumed past one read per tile.

Routes:

```
GET /checkpoint                       — signed root, mutates per integration cycle
GET /tile/{level}/{rest...}           — hash tiles
GET /tile/entries/{rest...}           — entry-bundle tiles
```

The backend that satisfies these reads is selected via
`LEDGER_TILE_BACKEND`:

| Value | Reads from | When to pick |
|---|---|---|
| `posix` (default) | the local `LEDGER_TESSERA_STORAGE_DIR` | single-binary deployment, or zero-trust origin behind a CDN |
| `gcs` | `<bucket>/<prefix>/...` in the same bucket as `LEDGER_BYTE_STORE_GCS_BUCKET` | tiles written directly to GCS, or a sync mirrors POSIX → GCS |

`LEDGER_TILE_BACKEND=gcs` requires `LEDGER_BYTE_STORE_BACKEND=gcs` —
the tile backend reuses the same authenticated bucket handle the
entry bytestore opens, so there is exactly one GCS client per ledger
process regardless of which surfaces are served from GCS.

`LEDGER_TILE_BUCKET_PREFIX` (default `tessera/`) is the GCS key
prefix where Tessera writes tiles. Empty prefix means tiles at
bucket root. Entries (under the entry bytestore's `ObjectPrefix`)
and tiles never collide in the same bucket because the prefixes are
distinct namespaces.

### Lane 1 — POSIX origin, GCS mirror, CDN fronts GCS (recommended)

Tessera writes tiles to a local POSIX directory; a sidecar (e.g.
`gsutil rsync` or `gcloud storage rsync`) mirrors that directory into
a GCS bucket; a generic CDN (CloudFront, Cloud CDN, Fastly) fronts
GCS for auditors. The ledger's `/tile/...` routes serve as a
zero-trust origin from POSIX.

```
       Auditor traffic (99%+ cache hit)
                  │
                  ▼
           ┌─────────────┐
           │     CDN     │   Cache-Control honored:
           └──────┬──────┘     full tile  86400 immutable
                  │            partial    max-age=2
                  ▼            checkpoint max-age=2
           ┌─────────────┐
           │  GCS bucket │   Mirrored from POSIX (gsutil rsync)
           └──────┬──────┘
                  │
                  ▼ (origin pull / direct ledger access)
           ┌─────────────┐
           │   Ledger    │   LEDGER_TILE_BACKEND=posix
           │  POSIX dir  │   /tile/... reads LEDGER_TESSERA_STORAGE_DIR
           └─────────────┘
```

Pros: Tessera write path is unchanged (POSIX-native). CDN absorbs
read load. GCS is read-only from the ledger's perspective.

Cons: rsync lag is the auditor staleness floor (typically <60s with
cron-driven rsync). If the rsync sidecar fails, auditors hit the
ledger directly until it recovers — capacity-plan accordingly.

### Lane 2 — Tessera writes GCS directly (heavier)

Tessera's `tessera/storage/gcp` driver writes tiles directly to GCS
with Spanner-backed coordination. The ledger's `/tile/...` routes
serve from the same GCS bucket via `LEDGER_TILE_BACKEND=gcs`.

```
                  Tessera (cmd/ledger embedded)
                          │
                          ▼  writes
                   ┌─────────────┐
                   │  GCS bucket │
                   └──────┬──────┘
                          ▲
            CDN (auditors)│  Ledger /tile/... (LEDGER_TILE_BACKEND=gcs)
            ──────────────┴──────────────────────────
```

Pros: no sidecar; auditor staleness is bounded by GCS strong
consistency (single-digit ms).

Cons: Tessera's GCP driver requires Spanner, which introduces
additional operational surface beyond Postgres. Requires explicit
opt-in by switching the Tessera storage driver in `tessera/`.

### GCS bucket layout

For Lane 2 (or Lane 1 with POSIX rsync mirror), the bucket is
shared between the entry bytestore and tiles, distinguished by
prefix:

```
gs://<bucket>/
   entries/                            (LEDGER_BYTE_STORE_GCS_OBJECT_PREFIX, default "entries")
       0000000000000001/<hash_hex>
       0000000000000002/<hash_hex>
       ...
   tessera/                            (LEDGER_TILE_BUCKET_PREFIX, default "tessera/")
       checkpoint
       tile/
           0/x000/000              <- hash tiles
           0/x000/001
           ...
           entries/x000/000        <- entry-bundle tiles
           entries/x000/001
           ...
```

Operators can override either prefix:

```sh
export LEDGER_BYTE_STORE_GCS_BUCKET=ledger-prod-bytes
export LEDGER_BYTE_STORE_GCS_OBJECT_PREFIX=entries        # default
export LEDGER_TILE_BACKEND=gcs
export LEDGER_TILE_BUCKET_PREFIX=tessera                  # default ("tessera/" trimmed)
```

### CDN configuration example (Cloud CDN)

```yaml
backendBucket:
  name: ledger-tile-origin
  bucketName: ledger-prod-bytes
  cdnPolicy:
    cacheMode: USE_ORIGIN_HEADERS   # honor Cache-Control from the origin
    defaultTtl: 60                  # safety floor; origin sends per-route TTL
    maxTtl: 86400                   # full tiles cap
    negativeCaching: true           # 404 caching defends origin from probing
    negativeCachingPolicy:
      - code: 404
        ttl: 2                      # match the partial-tile cache window
```

The `Cache-Control` constants in `api/tile_handler.go` are the
single source of truth for CDN behavior. Origin headers:

| Route | Cache-Control |
|---|---|
| Full hash / entry-bundle tile | `public, max-age=86400, immutable` |
| Partial tile (path contains `.p/`) | `public, max-age=2` |
| `/checkpoint` | `max-age=2` |

Full tiles are immutable by spec — once written, the 256-entry
boundary is reached and the tile never changes. CDNs honor
`immutable` by skipping re-validation entirely.

### Scale envelope (1B+ entries, 10M/day)

| Property | Headroom |
|---|---|
| Tile object count at 1B entries | ~8M objects (~4M hash + ~4M entry-bundle) — well under unlimited bucket capacity |
| Tile write rate at 10M entries/day | ~0.5 tiles/sec — 1000× under the 5000 writes/sec/bucket quota |
| Tile read rate (auditor traffic post-CDN) | <100 origin reads/sec at 99% cache hit ratio against 10K req/sec auditor load |
| `MaxTileBytes` ceiling | 16,777,472 bytes (256 entries × (2 + 65535)) — mirrors the SDK's `log/tessera_fetcher.MaxTileBytes` |

The bounded I/O ceiling defends auditors and CDN origin pulls
against a hostile or misbehaving GCS object that streams unbounded
bytes within the 30-second per-request budget. The
`integration-gcs-tile` Makefile target exercises this against a
real bucket.

### Operational verification

```sh
# Real-GCS integration tests (uploads ~16 MiB, deletes its own objects)
export ATTESTA_TEST_GCS_BUCKET=ledger-tile-integration-<your-instance>
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
make integration-gcs-tile

# Smoke check a deployed endpoint
curl -i https://<ledger>/checkpoint                          # → 200, Cache-Control: max-age=2
curl -i https://<ledger>/tile/0/x000/000                     # → 200 (or 404 before first integration)
curl -i https://<ledger>/tile/entries/x000/000               # → 200 (or 404)
curl -i -H "Range: bytes=0-15" https://<ledger>/tile/0/x000/000  # → 206 Partial Content
```

### Disabling tile serving

`LEDGER_TILE_SERVE_DISABLE=true` mounts no tile routes at all. Use
this when a separate read-replica process serves tiles and the
admission node should reject `/tile/...` traffic at the LB layer.
