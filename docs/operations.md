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

Administrators can override either prefix:

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

## Database hardening

The ledger's Postgres surface is tuned for production via four
in-binary mechanisms plus one administrator-applied SQL file. F1
(versioned migrations) is intentionally NOT used: schema changes
remain a single idempotent DDL block in `store/postgres.go::RunMigrations`
to keep boot deterministic.

### F2 — Append-only grants (administrator-applied)

The application connects as a role (typically `ledger_app`).
After `RunMigrations` populates the schema, an administrator runs
`deploy/sql/grants.sql` ONCE to revoke `UPDATE`, `DELETE`,
`TRUNCATE` privileges on the append-only tables. Even a
SQL-injection bug or a buggy ORM cannot mutate the log; the
role lacks the privilege.

```sh
# Once per fresh database, after `cmd/ledger` has booted:
psql "$LEDGER_DATABASE_URL_ADMIN" -v ON_ERROR_STOP=1 \
     -v ledger_app=ledger_app \
     -f deploy/sql/grants.sql
```

Append-only tables (mutation revoked):
`entry_index`, `commitment_split_id`, `derivation_commitments`,
`tree_heads`, `tree_head_sigs`, `equivocation_proofs`.

Mutable tables (intentionally unrevoked):
`builder_cursor`, `credits`, `smt_leaves`, `smt_nodes`,
`delta_window_buffers`, `sessions`.

Verification query (from grants.sql header comment):

```sql
SELECT table_name,
       string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privs
FROM information_schema.table_privileges
WHERE grantee = 'ledger_app'
  AND table_name IN ('entry_index', 'commitment_split_id',
                     'derivation_commitments', 'tree_heads',
                     'tree_head_sigs', 'equivocation_proofs')
GROUP BY table_name
ORDER BY table_name;
```

Expected: each table shows only `INSERT, SELECT` (and `REFERENCES`
if granted at schema level). `UPDATE / DELETE / TRUNCATE` must NOT
appear.

### F3 — Per-statement statement_timeout (in-code)

Every connection acquired from the pool runs `SET statement_timeout`
via the `pgxpool.Config.AfterConnect` hook. A misconfigured or
runaway query that escapes the application's per-call-site
`context.WithTimeout` discipline still gets cancelled at the DB
layer.

```sh
# Default: 5 seconds per query
LEDGER_PG_STATEMENT_TIMEOUT=5s

# Tighten for a quiet read-only deployment:
LEDGER_PG_STATEMENT_TIMEOUT=2s

# Disable (application is sole authority):
LEDGER_PG_STATEMENT_TIMEOUT=0
```

Both `cmd/ledger` (writer) and `cmd/ledger-reader` (read replica)
honor this env. Unparseable values silently fall back to 5 s; the
writer logs the effective value at boot under
`postgres pool ready` so misconfigs are visible.

### F4 — Builder advisory-lock heartbeat (in-code)

`AcquireBuilderLock` takes the Postgres advisory lock at boot
with a bounded timeout (`DefaultBuilderLockAcquireTimeout` = 30 s)
so a rolling-update where the previous pod still holds the lock
fails fast with an explicit error instead of hanging forever:

```
store: advisory lock failed within 30s (another writer may hold
the lock — check rolling-update or zombie pod): ...
```

After acquisition, a heartbeat goroutine pings the holding
connection every `DefaultBuilderLockHeartbeatInterval` (10 s).
If the ping fails — TCP reaper, network partition, server
restart — the connection is dead, the advisory lock has
auto-released server-side, and the heartbeat surfaces
`ErrAdvisoryLockLost` via the supervisor's fatal channel. The
process exits and the orchestrator (k8s/systemd/bare-metal
restart-loop) starts a fresh pod that goes through a clean
`Acquire` path.

This catches the otherwise-silent failure mode where a stale
TCP connection that the kernel hasn't reaped leaves the lock
"held" by a zombie pod — without the heartbeat, the new pod
hangs indefinitely waiting for a lock that the dead one will
never release.

### F5 — Boot-time pool warmup (in-code)

`InitPool` eagerly opens `MinConns` connections via
`Acquire`/`Release` after the pool is constructed and pinged.
Without this warmup, admission p99 spikes during the first ~30 s
after boot as cold connection slots pay the full
TCP+TLS+startup-message handshake cost (~50-200 ms each in
same-region, more across regions).

Failures during warmup are logged but NOT fatal: the pool stays
valid, and the application falls back to lazy connection on the
first request that needs an unwarmed slot.

### Boot order with F changes

`store/postgres.go::InitPool` (warmup) → `RunMigrations` → 
`AcquireBuilderLock` (with heartbeat goroutine) → rest of subsystem
wiring. The lock acquisition fails fast on rolling-update conflict;
the heartbeat starts immediately after acquisition and shares the
supervisor's fatal channel so a lock loss exits the process via the
same path as a sequencer or shipper panic.

## Boot-time integrity + config validation (G category)

The ledger refuses to start on misconfiguration rather than running
in a half-broken state. Every check below is fail-fast at boot;
nothing is "best effort, log and continue".

### G1 — Config validation

`Config.Validate()` runs at the end of `loadConfig()` and rejects
the boot if any cross-field invariant is violated:

| Check | Failure mode |
|---|---|
| `LEDGER_TLS_CERT_FILE` / `LEDGER_TLS_KEY_FILE` both-set or both-unset | Half-configured TLS would silently fall back to plain HTTP |
| Both TLS files exist on disk | Misnamed path surfaces immediately |
| `LEDGER_GOSSIP_PEER_DIDS` and `LEDGER_GOSSIP_PEER_ENDPOINTS` same length | Length mismatch points at a stale env var |
| `LEDGER_TILE_BACKEND=gcs` requires `LEDGER_BYTE_STORE_BACKEND=gcs` | GCSTiles reuses the *GCS bucket handle |
| `LEDGER_TILE_BACKEND` ∈ {posix, gcs} | Typo protection |
| Durations >= 0 (`LEDGER_SEQUENCER_INTERVAL`, `LEDGER_MMD`, `LEDGER_PG_STATEMENT_TIMEOUT`) | Negative values would invert select branches |
| `LEDGER_WITNESS_QUORUM_K > 0` when witnesses configured | 0-of-N would never finalize |
| `LEDGER_WITNESS_QUORUM_K <= len(LEDGER_WITNESS_ENDPOINTS)` | Unreachable quorum |

Pre-existing checks already enforced by `loadConfig`:
`LEDGER_DATABASE_URL`, `LEDGER_LOG_DID`, `LEDGER_BYTE_STORE_BACKEND`,
bytestore-bucket-when-backend-set, `LEDGER_NETWORK_BOOTSTRAP_FILE`
when witness mode active.

### G2 — Boot integrity reconcile

`sequencer.Replayer.Replay(ctx)` runs on every boot via
`Sequencer.Run`. It scans Postgres `entry_index` above the persisted
HWM (gossipstore prefix `0x0D`) and back-populates `0x0A` (splitid
index) + `0x0C` (entry lookup) for any rows missing — closing the
gap between the Postgres source-of-truth and the best-effort Badger
projection writes that happen AFTER the Postgres commit. Idempotent.

Boot logs:

```
{"msg":"sequencer replay: starting","hwm":...}
{"msg":"sequencer replay: caught up","rows_replayed":...}
{"msg":"sequencer ready","boot_replayer":true,...}
```

Gated only on the gossipstore being wired (`LEDGER_GOSSIP_DISABLE`
disables it; without gossip there are no projections to reconcile).

### G3 — Tessera POSIX dir sanity check

`validateTesseraStorageDir` runs immediately after `os.MkdirAll`:

| State | Decision |
|---|---|
| Empty | Fresh init — Tessera will populate |
| Has `checkpoint` file | Healthy — Tessera resumes |
| Has files but no `checkpoint` | Half-initialized → boot fails |

Surfaces the otherwise-silent "partial restore / aborted migration"
class of failure where re-initializing on top of stale tile artifacts
would corrupt the log.

### G5 — `GET /v1/log-info` (public)

The ledger is zero-trust by design (L-1 dumb ledger, T-6
zero-trust dual verification): there is no privileged "admin"
surface. `/v1/log-info` is a PUBLIC, cacheable, auditor-facing
endpoint that pairs with `/checkpoint` and the witness bootstrap
document as the public-truth artifacts of this log.

```sh
curl -s http://ledger:8080/v1/log-info | jq .
```

```json
{
  "byte_store_backend": "gcs",
  "gossip_enabled": true,
  "gossip_peer_count": 3,
  "ledger_did": "did:web:ledger.example",
  "log_did": "did:web:ledger.example",
  "mmd": "24h0m0s",
  "network_id": "0a1b2c3d4e5f6071",
  "sequencer_interval": "1s",
  "server_addr": ":8080",
  "tile_backend": "gcs",
  "tile_bucket_prefix": "tessera/",
  "tile_serve_disable": false,
  "tls_enabled": true,
  "witness_endpoint_count": 7,
  "witness_quorum_k": 4
}
```

`Cache-Control: public, max-age=60`. Witness rotation can change
`witness_quorum_k` and witness set membership; one minute is the
staleness floor an auditor accepts on the public surface.

**Scope discipline:** only fields an external auditor needs to
verify the log's trust posture. Operational tunables (`pg_max_conns`,
`pg_statement_timeout`, internal file paths, WAL path,
`max_concurrent_conns`) are NOT exposed here — they live in the
boot banner log (G7) for administrators reading from their log shipper,
and pprof's private listener (`LEDGER_PPROF_ADDR`) gives administrators
deeper introspection. If a piece of information was sensitive
enough to require auth, it doesn't belong on a runtime endpoint
at all.

### G6 — `GET /version` (public)

Build provenance — which binary served you this proof. Every CT
log monitor expects this surface; auditors verify pod-to-build
correlation.

```sh
curl -s http://ledger:8080/version | jq .
```

```json
{
  "version": "v0.42.1",
  "commit": "abc123def456...",
  "build_time": "2026-05-07T12:34:56Z",
  "sdk_version": "v0.1.2"
}
```

`Cache-Control: public, max-age=3600`. Build is immutable per
pod; the only way the response can change is via a rolling
redeploy.

Populated at build time via `-ldflags`:

```sh
go build \
  -ldflags="-X main.Version=$(git describe --tags --always) \
            -X main.Commit=$(git rev-parse HEAD) \
            -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./cmd/ledger
```

PUBLIC, no auth. Build provenance is fundamentally public
information (this is the same posture every CT log takes —
Sectigo Sabre, Google Argon, Cloudflare Nimbus all expose
unauthenticated version probes).

### G7 — Boot banner

A single Info line at startup carrying the forensic identifiers an
administrator needs to correlate a pod with its source build and
deployment shape. Secrets NEVER logged here; only public identifiers
plus booleans for capability flags.

```json
{
  "msg":"ledger starting (boot banner)",
  "version":"v0.42.1",
  "commit":"abc123def456...",
  "build_time":"2026-05-06T12:34:56Z",
  "sdk_version":"v0.1.2",
  "log_did":"did:web:ledger.example",
  "ledger_did":"did:web:ledger.example",
  "network_id_hex":"0a1b2c3d4e5f6071",
  "addr":":8080",
  "tessera_storage_dir":"/var/lib/attesta/tessera",
  "byte_store_backend":"gcs",
  "tile_backend":"gcs",
  "gossip_enabled":true,
  "gossip_peer_count":3,
  "witness_endpoint_count":7,
  "witness_quorum_k":4,
  "tls_enabled":true,
  "metrics_enabled":true
}
```

## Shutdown ordering (I category)

I1+I2+I3 — Strict-order shutdown via `lifecycle.ShutdownChain`.
Each resource registered at boot has a sync.OnceFunc-protected
close fn that's invoked from BOTH the boot-panic-safety defer
AND the explicit shutdown chain at SIGTERM. Whichever fires
first does the work, the other becomes a no-op.

### I1 — 14-step spec order

```
SIGTERM (or SIGINT)
   │
   ▼
   1. /readyz=503                 (atomic flip; LB removes pod from rotation)
   2. predrain grace              (LEDGER_PREDRAIN_GRACE, default 5s)
   3. http-server                 (Server.Shutdown drains in-flight)
   4. pprof-server                (diagnostic listener close)
   5. background-goroutines       (wg.Wait — sequencer/shipper/builder/etc. drain)
   6. bytestore                   (flush in-flight uploads)
   7. tessera                     (flush tile writes)
   8. wal-committer               (group-commit batch flush; depends on wal-db)
   9. wal-db                      (Badger close)
  10. tessera-antispam            (Badger close)
  11. gossipstore                 (gossip Badger surface close)
  12. builder-advisory-lock       (release lock + drop heartbeat)
  13. pgxpool                     (Postgres pool close — last for in-flight queries)
  14. otel-meter                  (very last so the shutdown event is observable)
   │
   ▼
   process exits 0  (or panic on fatal)
```

### I2 — Per-component timeouts

Each step has its OWN bounded ctx:

| Step | Timeout | Rationale |
|---|---|---|
| http-server | 30 s | matches HTTP request budgets |
| pprof-server | 5 s | no in-flight admission |
| background-goroutines | 30 s | sequencer + shipper drain budget |
| bytestore | 30 s | GCS PUT can be slow |
| tessera | 15 s | tile flush |
| wal-committer | 5 s | group-commit batch finalize |
| wal-db | 10 s | Badger close |
| tessera-antispam | 15 s | antispam Badger close |
| gossipstore | 5 s | Badger close (shared handle, mostly fast) |
| builder-advisory-lock | 5 s | server-side unlock |
| pgxpool | 10 s | drain in-flight queries |
| otel-meter | 5 s | flush metric exports |

Total worst-case shutdown: ~3 minutes if every step times out.
In practice the typical wall time is under 5 s — the budgets are
defense-in-depth, not normal operation.

### I3 — Final summary log

After the chain runs, every step emits a summary line at Info:

```json
{"msg":"shutdown step summary","step":"http-server","status":"ran","duration":"143.2ms","err":""}
{"msg":"shutdown step summary","step":"pprof-server","status":"ran","duration":"1.1ms","err":""}
{"msg":"shutdown step summary","step":"background-goroutines","status":"ran","duration":"812.5ms","err":""}
{"msg":"shutdown step summary","step":"bytestore","status":"ran","duration":"23.4ms","err":""}
... (one line per registered step)
{"msg":"shutdown step summary","step":"otel-meter","status":"ran","duration":"4.2ms","err":""}
{"msg":"ledger stopped","batches":42,"entries":10742,"errors":0}
```

`status` is `ran` (executed) or `skipped` (chain Run never
reached this step — e.g., supervisor exited via panic before
this point). `duration` is per-step wall time. `err` is the
step's error string (empty on success). An SRE post-mortem on
a slow pod-eviction reads these lines to identify which
component stalled.

## Observability (D category)

D1-D7 deliver SRE-grade telemetry:

| # | Item | Anchor |
|---|---|---|
| D1 | `LEDGER_METRICS_ENABLE` defaults to `true`; opt-out via `false` | `cmd/ledger/main.go::loadConfig` |
| D2 | OTel tracing via `LEDGER_OTLP_TRACES_ENDPOINT` ("" / `stdout` / `host:port` / `https://...`) | `lifecycle/tracing.go::NewTracerProvider` |
| D3 | Histograms — `attesta_api_request_duration_seconds`, `_wal_submit_`, `_tessera_append_`, `_postgres_pool_acquire_`, `_bytestore_put_` | one Install per package |
| D4 | Counters — `attesta_witness_quorum_failures_total{network_id}`, `_equivocation_detected_total{kind, originator}` | `gossipnet/instruments.go` |
| D5 | Gauges — `attesta_sequencer_drain_lag_seconds`, `_shipper_pending_total` | `sequencer/instruments.go`, `shipper/instruments.go` |
| D6 | slog redaction helpers: `lifecycle.HashHex`, `PresenceFlag`, `NetworkIDHex`, `HexShort` — never log payloads/sigs/raw | `lifecycle/logsafe.go` |
| D7 | `pprof.Do` labels around every wrapped goroutine — pprof samples carry the supervisor-assigned name | `lifecycle/safe_run.go` |

### Endpoints

```
GET /metrics       Prometheus exposition (when LEDGER_METRICS_ENABLE=true)
GET /version       build provenance (G6) — JSON, public
GET /v1/log-info   public deployment posture (G5) — JSON, public
GET /healthz       liveness — 200 while process runs
GET /readyz        readiness — 503 during shutdown OR when DB breaker is open
GET /debug/pprof/* private listener on LEDGER_PPROF_ADDR (default 127.0.0.1:6060)
```

### LEDGER_OTLP_TRACES_ENDPOINT semantics

| Value | Behavior | Use case |
|---|---|---|
| unset / `""` | NoOp tracer (zero overhead, default) | unit tests, one-shot tools |
| `stdout` | Pretty-print spans to stderr | laptop dev, single administrator |
| `localhost:4318` | OTLP HTTP (insecure) | Jaeger / OTel collector on the same host |
| `http://otel:4318` | OTLP HTTP (insecure, explicit) | sidecar collector |
| `https://otel.example.com` | OTLP HTTP over TLS | hosted Honeycomb / Datadog / Tempo |

## Local-runnable bring-up

The ledger is environment-agnostic (Ledger principle #14). Same
binary + same env contract runs on:

| Target | Orchestrator | Wiring |
|---|---|---|
| Laptop (with Docker) | `scripts/run-local.sh` | docker-compose for Postgres + fake-gcs; ledger as a host process |
| VM / bare-metal | `systemd` | `deploy/systemd/ledger.service`; binary at `/usr/local/bin/ledger`; env at `/etc/ledger/env` |
| Kubernetes | k8s Deployment | `deploy/k8s/ledger.yaml`; ConfigMap + Secret + 3 PVCs + Service |

### Laptop bring-up (5 minutes — REAL GCS required)

`scripts/run-local.sh` requires a real, developer-owned GCS
bucket. Local dev must exercise the same ADC + auth + retry +
GCS-quirks code path that production uses. Fake-gcs-server is
NOT used here because "works locally but breaks on real GCS"
is precisely the surprise we eliminate by always using the
real backend.

For offline / air-gapped runs (e.g., integration tests, CI on
a sandboxed runner), use `make integration-up` which boots the
fake-gcs harness explicitly.

```sh
# Required: Docker + Go 1.21+ + a Google Cloud project
git clone https://github.com/clearcompass-ai/ledger.git
cd ledger

# One-time GCS setup
gcloud auth application-default login
gcloud storage buckets create gs://my-ledger-laptop-bucket
export LEDGER_BYTE_STORE_GCS_BUCKET=my-ledger-laptop-bucket

# Boots Postgres only (no fake-gcs), then runs the ledger
# foreground against the real bucket.
./scripts/run-local.sh

# In a second shell, submit an entry:
go run ./cmd/submit-stamp -log-did did:attesta:ledger:local

# Tear down infra (preserves .run/ data):
./scripts/run-local.sh down
# Wipe state + restart:
./scripts/run-local.sh clean
```

Default observability for laptop dev:
- Metrics: scrape `http://localhost:8080/metrics` (Prometheus exposition format)
- Traces: spans pretty-printed to stderr (`LEDGER_OTLP_TRACES_ENDPOINT=stdout`)
- pprof: `go tool pprof http://localhost:6060/debug/pprof/profile`

### Laptop bring-up — with Prometheus + Jaeger UI

```sh
# Start the observability profile (Prometheus on :9090, Jaeger on :16686):
docker compose -f scripts/local/docker-compose.testharness.yml \
  --profile observability up -d

# Run the ledger with traces pointed at Jaeger:
LEDGER_OTLP_TRACES_ENDPOINT=http://localhost:4318 ./scripts/run-local.sh

# Open the UIs:
open http://localhost:9090     # Prometheus
open http://localhost:16686    # Jaeger
```

Prometheus scrapes `host.docker.internal:8080/metrics` every 5s
(see `scripts/local/prometheus.yml`).

### VM / bare-metal bring-up

```sh
# 1. Build a static binary
go build -o ./bin/ledger ./cmd/ledger
sudo install -o root -g root -m 0755 ./bin/ledger /usr/local/bin/ledger

# 2. Create the ledger user + data dirs
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ledger
sudo mkdir -p /var/lib/attesta/{wal,tessera,antispam}
sudo chown -R ledger:ledger /var/lib/attesta

# 3. Create /etc/ledger/env with LEDGER_* vars (mode 0600)
sudo install -o ledger -g ledger -m 0600 /dev/stdin /etc/ledger/env <<'EOF'
LEDGER_DATABASE_URL=postgres://ledger_app:...@db.example:5432/ledger?sslmode=require
LEDGER_LOG_DID=did:web:ledger.example
LEDGER_BYTE_STORE_BACKEND=gcs
LEDGER_BYTE_STORE_GCS_BUCKET=ledger-prod-bytes
LEDGER_TILE_BACKEND=gcs
LEDGER_METRICS_ENABLE=true
LEDGER_OTLP_TRACES_ENDPOINT=http://otel-collector.example:4318
LEDGER_PG_STATEMENT_TIMEOUT=5s
EOF

# 4. Install + start the systemd unit
sudo install -o root -g root -m 0644 \
    deploy/systemd/ledger.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ledger

# 5. After first boot, apply F2 grants
sudo -u postgres psql ledger -v ledger_app=ledger_app \
    -f /path/to/deploy/sql/grants.sql

# 6. Verify
curl http://localhost:8080/healthz       # → "ok"
curl http://localhost:8080/readyz        # → "ready"
curl http://localhost:8080/version       # → JSON
curl http://localhost:8080/v1/log-info   # → JSON
journalctl -u ledger -f                  # stream logs
```

### Kubernetes bring-up

```sh
# 1. Edit deploy/k8s/ledger.yaml — replace every <SET-AT-DEPLOY>:
#      - log_did
#      - byte_store_gcs_bucket
#      - storageClassName (× 3 PVCs)
#      - container image
#      - DATABASE_URL secret value (use SOPS / Vault / external-secrets)

# 2. Apply
kubectl apply -f deploy/k8s/ledger.yaml

# 3. After first boot, apply F2 grants
kubectl exec -n ledger deploy/ledger -- \
  psql "$LEDGER_DATABASE_URL_ADMIN" -f /etc/ledger/grants.sql

# 4. Verify
kubectl -n ledger logs deploy/ledger -f
kubectl -n ledger port-forward svc/ledger 8080
curl http://localhost:8080/v1/log-info
```

The Deployment uses `strategy: Recreate` (NOT rolling) because
the Postgres advisory lock (F4) enforces singleton-writer; a
rolling-update would race and the new pod would fail-fast within
30s. For zero-downtime read upgrades, run `cmd/ledger-reader`
behind a Service with as many replicas as you need.

## Misc protocol/correctness (L category)

L1-L4 are a mix of code changes and audits. The audits are
captured here so a future review can re-verify the property
holds.

### L1 — Constant-time crypto comparison

**Audit conclusion: structurally clean.**

No production code in the ledger does cryptographic byte
comparison. Verification paths go through:

| Surface | Mechanism |
|---|---|
| Signature verify (ECDSA, Ed25519, BLS) | SDK calls into `crypto/ecdsa`, `crypto/ed25519`, BLS12-381 lib — already constant-time at the library level |
| Session token equality | Postgres-side `WHERE token = $1` — DB-side indexed equality on TEXT, attacker-observable timing leaks "row exists or not", which is presence not content |
| `[32]byte` projection-state comparison | Internal integrity-detector / projection writes — not attacker-observable (no oracle path) |

A `crypto/subtle.ConstantTimeCompare` import is therefore not
needed today. **If a future feature introduces a comparison of
attacker-supplied bytes to a stored secret in-process, that call
site MUST use `subtle.ConstantTimeCompare`** — code review
discipline.

### L2 — Defensive zero-out on shutdown

`zero-key-material` is a step in the shutdown chain (between
`gossipstore` and `otel-meter`). Runs after every signing
goroutine has drained, before OTel shuts down. Zeroes the
authoritative `*ecdsa.PrivateKey.D` field for the ledger
signer.

Caveats:
- Tessera's `note.Signer` doesn't expose its bytes (SDK
  ownership), so it's not zeroable from this layer.
- Go's GC may retain key copies in scratch buffers from prior
  signing operations; this is a defense-in-depth measure
  reducing memory-dump exposure on a subsequent crash, not a
  hard guarantee against post-mortem extraction.

### L3 — NetworkID enforcement

**Audit conclusion: structurally clean + pinned by tests.**

Every gossipnet constructor checks NetworkID FIRST (security-
critical T-9 cryptographic domain separation, ahead of all other
required-field checks):

| Constructor | Check |
|---|---|
| `gossipnet.NewSTHPublisher` | `cfg.NetworkID == zero` → error |
| `gossipnet.NewEquivocationPublisher` | same |
| `gossipnet.Build` (Bundle) | same |

Pinned by `gossipnet/networkid_audit_test.go::TestNetworkIDAudit_*`.
The ledger never bypasses the SDK's NetworkID enforcement
because every cosign payload is signed/verified through SDK
primitives that bind to the publisher/verifier's NetworkID at
construction.

### L4 — ctx propagation

`AppendLeaf` now accepts `ctx` across all four affected
interfaces (`sequencer.Tessera`, `tessera.AppenderBackend`,
`builder.MerkleAppender`, `api.TesseraAppender`) so a sequencer
drain that hits SIGTERM mid-batch cancels the in-flight Tessera
integration future cleanly.

Remaining `context.Background()` call sites in production code,
each documented:

| Site | Rationale |
|---|---|
| `cmd/ledger/main.go` (top-level) | Root ctx for the process |
| `cmd/ledger-reader/main.go`, `cmd/rebuild-tiles/main.go` (top-level) | Same |
| `wal/committer.go::commitLoop` | Lifetime tied to WAL close-channel, not any caller ctx |
| `gossipstore/badger_store.go::runGC` | Internal goroutine; lifetime tied to `gcCancel` |
| `tessera/embedded_appender.go::Head`, `ReadCheckpoint` | Synchronous local-disk reads; fast; threading ctx is a future cleanup |
| `gossipstore/commitment_fetcher.go::FindCommitmentEntries` | SDK interface is ctx-free; documented in code |
| `api/server.go::BaseContext` | Stdlib http.Server requires non-nil; per-request ctx is created by net/http itself |
| Boot-panic close-fns (e.g., `closeOTelMeterOnce`) | Parent ctx already cancelled at shutdown; Background + per-component timeout is the correct shape |

## In-process audit + integrity jobs (H category)

### H1/H2/H3 — Audit + freshness telemetry

A single `audit-telemetry` goroutine emits three observability
lines every 5 minutes, all read-only:

```json
{"msg":"integrity audit","invariant_failures_total":0,"samples_verified_total":42}
{"msg":"checkpoint cosig age","age_seconds":12.3}
{"msg":"gossip store growth","event_count":18742,"originator_count":12}
```

**H1** — `integrity.Detector` exposes
`InvariantFailures()` + `SamplesVerified()` atomic counters.
Sample-verify cycles increment `samples_verified_total` on success
and `invariant_failures_total` on any divergence-detected or
verifier/WAL error path. The metric pair lets SREs compute a
failure rate over a window and alert when invariant_failures
climbs above zero. The future D-category OTel mirror exposes them
as `attesta_audit_invariant_failures_total{}` and
`attesta_audit_samples_verified_total{}`.

**H2** — `gossipnet.STHPublisher.LastCosignedAt()` records the
unix-nanos of every successful PublishCosignedHead.
`CosignAgeSeconds()` returns `now - LastCosignedAt()` in seconds,
or -1 when no cosigned head has been published yet (fresh-boot
disambiguator). Drives the future
`attesta_checkpoint_cosig_age_seconds` gauge consumed by SRE
dashboards to alert when witness fan-out has stalled.

**H3** — `gossipstore.BadgerStore.Stats(ctx)` exposes the
event_count + originator_count growth metric. The audit-telemetry
goroutine logs them at Info every 5 min so administrators see the
gossip-store growth trajectory.

Trim policy is **NOT implemented in this commit**. Trimming gossip
events safely requires a consumer-cursor model (the oldest auditor
cursor any peer might want to fetch from); we don't track that
today. Disk pressure is currently bounded by Badger's value-log
GC at the LSM side. Application-level trim is parked behind a
future `LEDGER_GOSSIP_TRIM_AGE` env once the consumer-cursor
model lands.

### H4 — Append-only build-time guard

`store/append_only_guard_test.go::TestAppendOnlyGuard` walks every
non-test `.go` file in the repo (excluding vendor / .git) and
fails the build if any source file constructs a SQL `UPDATE`,
`DELETE FROM`, or `TRUNCATE` against the append-only tables:

```
entry_index
commitment_split_id
derivation_commitments
tree_heads
tree_head_sigs
equivocation_proofs
```

Block + line comments are stripped before pattern matching so
docstrings + file-header runbooks (which often quote the
administrator-run reset SQL for cmd/rebuild-tiles + similar one-shot
tools) don't trip the guard.

Defense-in-depth on top of F2 (`deploy/sql/grants.sql`):

| Layer | Mechanism |
|---|---|
| F2 — DB role | `REVOKE UPDATE, DELETE, TRUNCATE` from the application role |
| H4 — build time | `go test ./store/` fails the build if mutation SQL appears in source |

A buggy commit can't slip past either layer.

## Build / version / supply-chain (K category)

Pragmatic, transparency-log-shaped supply-chain story. Mirrors the
practices used by Tessera (transparency-dev), Sigstore, and Let's
Encrypt Boulder. Scope is administrator-runnable today + CI-gated; nothing
requires a release pipeline that doesn't exist yet.

### K1 + K2 — Reproducible release builds (`make release-build`)

```sh
make release-build
# → ./bin/ledger
#   version=v0.42.1
#   commit=abc123def456...
#   build_time=2026-05-07T12:34:56Z
```

Flags:
- `-trimpath` — removes absolute paths from the binary (no `/home/$USER/`)
- `-buildvcs=true` — embeds git VCS info in the binary
- `-ldflags="-s -w -buildid="` — strips symbol table, DWARF, and build-ID
- `-ldflags="-X main.Version=... -X main.Commit=... -X main.BuildTime=..."` —
  populates the package vars consumed by `GET /version` (G6)

For byte-reproducible builds, fix `BUILD_TIME` to the commit's
author date so two builders produce identical binaries:

```sh
BUILD_VERSION=v0.42.1 \
  BUILD_TIME=$(git show -s --format=%cI HEAD) \
  make release-build

# Verify byte-identical across two builds:
sha256sum ./bin/ledger
make clean release-build
sha256sum ./bin/ledger
# → same hash
```

### K3 — Module integrity (`make verify-deps`)

```sh
make verify-deps
# go mod verify           — checks go.sum against module cache
# go mod download -x ./... — re-downloads to confirm registry availability
```

Runs on every PR via `.github/workflows/go-test.yml`.

### K4 — Lint + vulnerability scan (`make lint`)

```sh
# Local — install once:
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.4.0
go install golang.org/x/vuln/cmd/govulncheck@latest

make lint
# golangci-lint run ./...        — meta-linter (see .golangci.yml)
# govulncheck ./...              — known-CVE scan
# go vet ./...                   — stdlib's vet pass
```

CI workflows:
- `.github/workflows/lint.yml` — `golangci-lint` on every PR + push
- `.github/workflows/govulncheck.yml` — `govulncheck` on every PR + push + daily cron
- `.github/workflows/go-test.yml` — `go vet`, `go test -short`,
  `audit-sdk`, plus `make test-race` on critical packages

`.golangci.yml` enables: `errcheck`, `govet` (with `shadow`),
`ineffassign`, `staticcheck` (all checks), `unused`, `gosimple`,
`gofmt`, `goimports`, `bodyclose`, `rowserrcheck`, `sqlclosecheck`.

### K5 — SBOM (`make sbom`)

CycloneDX 1.5 JSON SBOM via `cyclonedx-gomod` (pure Go — laptop-runnable,
no Docker / syft dep). Administrators publish this alongside the binary at
release tags so downstream consumers can audit transitive deps.

```sh
# Local — install once:
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

make sbom
# → ./bin/sbom.cdx.json (CycloneDX 1.5 JSON)
```

Inspect:
```sh
jq '.components[] | {name, version, licenses}' ./bin/sbom.cdx.json | head
```

### K6 — Container image signing — DEFERRED

`cosign --keyless` (Sigstore keyless signing via OIDC) is the
industry-standard approach for transparency-log container images.
It is **not implemented in this repo** because there is no
container release pipeline yet (no Dockerfile-based image,
no registry, no GitHub Releases workflow).

When that pipeline lands, the wiring is:

```yaml
# Future .github/workflows/release.yml (illustrative, NOT shipping)
- uses: sigstore/cosign-installer@<pinned>
- run: |
    cosign sign --yes \
      ghcr.io/clearcompass-ai/ledger@${{ steps.build.outputs.digest }}
- run: |
    cosign attest --yes \
      --predicate ./bin/sbom.cdx.json \
      --type cyclonedx \
      ghcr.io/clearcompass-ai/ledger@${{ steps.build.outputs.digest }}
```

This produces a Sigstore Rekor entry binding the image to the
GitHub Actions OIDC identity at release time, plus an SBOM
attestation downstream consumers can `cosign verify-attestation`.

Until the release pipeline exists, K6 is documented but not
wired; `make release-build` + `make sbom` produce the artifacts
a release workflow would consume.

### Supply-chain reference table

| Layer | Mechanism | Owner |
|---|---|---|
| Source integrity | `git` + signed commits | developer |
| Module integrity | `go.sum` + `go mod verify` | K3 |
| Static analysis | golangci-lint + go vet | K4 |
| Dynamic analysis | govulncheck (reachability-aware) | K4 |
| Build determinism | -trimpath + fixed BUILD_TIME + -buildid="" | K2 |
| Build provenance | -ldflags injection of Version/Commit/BuildTime + `GET /version` | K1, G6 |
| Dependency manifest | CycloneDX SBOM | K5 |
| Image signing | cosign --keyless | K6 (deferred) |
| SDK invariant audit | `make audit-sdk` (no muEnable=false) | pre-existing |

The goal is the same as Tessera, Sigstore, and Boulder: every
artifact a consumer can verify back to a source commit, every
dependency they can inspect, every CVE flagged within 24h.
