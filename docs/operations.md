# Operations

Boot order, graceful shutdown, Kubernetes/systemd deployment, tile-
serving lanes, database hardening, and supply-chain story. Owns
runtime ordering and ops tasks; env vars live in
[configuration.md](configuration.md), routes in [api.md](api.md),
metrics in [observability.md](observability.md), storage in
[storage.md](storage.md), tests in [testing.md](testing.md), SDK
contract anchors in [sdk-validation.md](sdk-validation.md).

## Boot order

`cmd/ledger/main.go` boots in the order below. Anything marked
**fatal** exits non-zero before the HTTP server binds.

| Step | Action | Failure mode |
|---|---|---|
| 1 | `loadConfig()` from environment | Fatal — required vars missing |
| 2 | `Config.Validate()` cross-field invariants (G1) | Fatal — see [configuration.md](configuration.md) |
| 3 | `envelope.ValidateDestination(LogDID)` | Fatal — invalid log DID |
| 4 | `pgxpool.New(DatabaseURL)` + `InitPool` warmup (F5) | Fatal — DB unreachable |
| 5 | `store.RunMigrations` (idempotent DDL) | Fatal — migration SQL error |
| 6 | `AcquireBuilderLock` with bounded timeout (F4) | Fatal — another writer holds the advisory lock |
| 7 | Open WAL Badger at `LEDGER_WAL_PATH` | Fatal — Badger open error |
| 8 | `validateTesseraStorageDir` (G3) — empty OR has `checkpoint`; reject half-initialized state | Fatal — partial restore detected |
| 9 | Open Tessera POSIX storage + antispam | Fatal |
| 10 | Construct bytestore (GCS or S3) | Fatal — credentials / bucket invalid |
| 11 | Wire OTel MeterProvider (default ON) + `api.InstallErrorCounter` | Logs warning if registration fails; continues |
| 12 | Wire gossipstore (BadgerStore on same handle, prefix `0x07`) | Optional — disabled when `LEDGER_GOSSIP_DISABLE=true` |
| 13 | Wire Sequencer + bind boot replayer (`0x0D` HWM, G2) | Replayer goroutine starts inside `Run()`; failures logged |
| 14 | Wire EquivocationScanner (subscribes to `0x0A`) | Optional — only when gossip enabled |
| 15 | Wire Shipper goroutine | Drains `StateSequenced` → bytestore → `MarkShipped` |
| 16 | Wire HTTP handlers + bind `httpServer.ListenAndServe` | Fatal — bind error |
| 17 | Boot banner (G7) | Single Info line with forensic identifiers |
| 18 | Fatal-channel supervisor goroutines (Loop, Shipper, etc.) | Any send to fatal channel exits the process |

## Graceful shutdown

I1+I2+I3 — strict-order shutdown via `lifecycle.ShutdownChain`.
Each resource registered at boot has a `sync.OnceFunc`-protected
close fn that's invoked from BOTH the boot-panic-safety defer AND
the explicit shutdown chain at SIGTERM. Whichever fires first
does the work, the other becomes a no-op.

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
Typical wall time is under 5 s — the budgets are defense-in-
depth, not normal operation.

### I3 — Final summary log

After the chain runs, every step emits a summary line at Info:

```json
{"msg":"shutdown step summary","step":"http-server","status":"ran","duration":"143.2ms","err":""}
{"msg":"shutdown step summary","step":"pprof-server","status":"ran","duration":"1.1ms","err":""}
{"msg":"shutdown step summary","step":"background-goroutines","status":"ran","duration":"812.5ms","err":""}
... (one line per registered step)
{"msg":"ledger stopped","batches":42,"entries":10742,"errors":0}
```

`status` is `ran` (executed) or `skipped` (chain Run never
reached this step — supervisor exited via panic before this
point). `duration` is per-step wall time. `err` is the step's
error string (empty on success).

Set `terminationGracePeriodSeconds: 60` in Kubernetes to
accommodate in-flight Tessera flushes + bytestore uploads.

## Kubernetes

| Property | Value | Why |
|---|---|---|
| Replicas | exactly 1 per log DID | Postgres advisory lock prevents concurrent builders (`store/postgres.go:400 BuilderLockID = 0x4F5254484F4C4F47`) |
| Update strategy | `Recreate` (NOT rolling) | Rolling-update would race the lock; new pod fails fast with the F4 conflict message |
| Liveness | `GET /healthz` | 200 while process runs |
| Readiness | `GET /readyz` | 200 when ready, 503 during shutdown (atomic bool flips at SIGTERM); 503 with subsystem error message when the DB circuit breaker is tripped |
| Volumes | distinct PVCs for `LEDGER_WAL_PATH`, `LEDGER_TESSERA_STORAGE_DIR`, `LEDGER_TESSERA_ANTISPAM_PATH` | Corruption in one shouldn't force discarding the others |
| Resources | 500m CPU / 512Mi minimum | Sequencer is CPU-bound during batch processing |
| Secrets | `LEDGER_DATABASE_URL`, signer key files, S3/GCS credentials | Inject via Secret / SOPS |

A read-only sibling (`cmd/ledger-reader`) serves the read
endpoints without admission. Run as many replicas as needed for
read scaling — the advisory lock only applies to the writer.

For a worked Helm overlay see [deploy/helm/ledger/README.md](../deploy/helm/ledger/README.md).
The k8s/ overlay (`deploy/k8s/ledger.yaml`) remains as the
single-file alternative; pick one path per cluster and stay on it.

## Common ops tasks

### Re-key the ledger signer

```sh
# Generate new key (ledger's secp256k1 ECDSA — signs SCTs + tree heads)
openssl ecparam -name secp256k1 -genkey -noout -out new.key

# Hot-rotate is NOT supported; the ledger embeds the DID in every SCT.
# Roll out: update LEDGER_SIGNER_KEY_FILE + LEDGER_DID secrets + recreate.
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
# The bytes are still in the WAL — operator-side intervention to retry
# manually OR mark the entry as drop-and-replace.
```

## Static-CT tile serving (c2sp.org/tlog-tiles)

The ledger exposes the c2sp.org/tlog-tiles read surface so
external auditors fetch inclusion + consistency proofs offline
using the SDK's `log/tessera_fetcher` primitive — no per-entry
round-trip to the ledger required, no ledger CPU consumed past
one read per tile. Routes are listed in [api.md](api.md)
(`GET /checkpoint`, `GET /tile/{level}/{rest...}`).

The backend that satisfies these reads is selected via
`LEDGER_TILE_BACKEND` ([configuration.md](configuration.md)):

| Value | Reads from | When to pick |
|---|---|---|
| `posix` (default) | the local `LEDGER_TESSERA_STORAGE_DIR` | single-binary deployment, or zero-trust origin behind a CDN |
| `gcs` | `<bucket>/<prefix>/...` in the same bucket as `LEDGER_BYTE_STORE_GCS_BUCKET` | tiles written directly to GCS, or a sync mirrors POSIX → GCS |

`LEDGER_TILE_BACKEND=gcs` requires `LEDGER_BYTE_STORE_BACKEND=gcs`
— the tile backend reuses the same authenticated bucket handle
the entry bytestore opens (one GCS client per ledger process
regardless of which surfaces are served from GCS).

`LEDGER_TILE_BUCKET_PREFIX` (default `tessera/`) is the GCS key
prefix where Tessera writes tiles. Empty prefix means tiles at
bucket root. Entries (under the entry bytestore's
`ObjectPrefix`) and tiles never collide in the same bucket
because the prefixes are distinct namespaces.

### Lane 1 — POSIX origin, GCS mirror, CDN fronts GCS (recommended)

Tessera writes tiles to a local POSIX directory; a sidecar
(e.g. `gsutil rsync` or `gcloud storage rsync`) mirrors that
directory into a GCS bucket; a generic CDN (CloudFront, Cloud
CDN, Fastly) fronts GCS for auditors. The ledger's `/tile/...`
routes serve as a zero-trust origin from POSIX.

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

Cons: rsync lag is the auditor staleness floor (typically <60s
with cron-driven rsync). If the rsync sidecar fails, auditors
hit the ledger directly until it recovers — capacity-plan
accordingly.

### Lane 2 — Tessera writes GCS directly (heavier)

Tessera's `tessera/storage/gcp` driver writes tiles directly to
GCS with Spanner-backed coordination. The ledger's `/tile/...`
routes serve from the same GCS bucket via
`LEDGER_TILE_BACKEND=gcs`.

Pros: no sidecar; auditor staleness is bounded by GCS strong
consistency (single-digit ms).

Cons: Tessera's GCP driver requires Spanner, which introduces
additional operational surface beyond Postgres. Requires
explicit opt-in by switching the Tessera storage driver in
`tessera/`.

### GCS bucket layout

For Lane 2 (or Lane 1 with POSIX rsync mirror), the bucket is
shared between the entry bytestore and tiles, distinguished by
prefix:

```
gs://<bucket>/
   entries/                            (LEDGER_BYTE_STORE_PREFIX, default "entries")
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
| Tile object count at 1B entries | ~8M objects (~4M hash + ~4M entry-bundle) |
| Tile write rate at 10M entries/day | ~0.5 tiles/sec — 1000× under the 5000 writes/sec/bucket quota |
| Tile read rate (auditor traffic post-CDN) | <100 origin reads/sec at 99% cache hit ratio against 10K req/sec auditor load |
| `MaxTileBytes` ceiling | 16,777,472 bytes (256 entries × (2 + 65535)) — mirrors the SDK's `log/tessera_fetcher.MaxTileBytes` |

The bounded I/O ceiling defends auditors and CDN origin pulls
against a hostile or misbehaving GCS object that streams
unbounded bytes within the 30-second per-request budget. The
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

`LEDGER_TILE_SERVE_DISABLE=true` mounts no tile routes at all.
Use this when a separate read-replica process serves tiles and
the admission node should reject `/tile/...` traffic at the LB
layer.

## Database hardening

The ledger's Postgres surface is tuned for production via four
in-binary mechanisms plus one administrator-applied SQL file. F1
(versioned migrations) is intentionally NOT used: schema changes
remain a single idempotent DDL block in
`store/postgres.go::RunMigrations` to keep boot deterministic.

### F2 — Append-only grants (administrator-applied)

The application connects as a role (typically `ledger_app`).
After `RunMigrations` populates the schema, an administrator
runs `deploy/sql/grants.sql` ONCE to revoke `UPDATE`, `DELETE`,
`TRUNCATE` privileges on the append-only tables. Even a SQL-
injection bug or a buggy ORM cannot mutate the log; the role
lacks the privilege.

```sh
# Once per fresh database, after `cmd/ledger` has booted:
psql "$LEDGER_DATABASE_URL_ADMIN" -v ON_ERROR_STOP=1 \
     -v ledger_app=ledger_app \
     -f deploy/sql/grants.sql
```

The append-only set and mutable set are listed in
[storage.md](storage.md) `## Postgres schema`.

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

Expected: each table shows only `INSERT, SELECT` (and
`REFERENCES` if granted at schema level). `UPDATE / DELETE /
TRUNCATE` must NOT appear.

### F3 — Per-statement statement_timeout (in-code)

Every connection acquired from the pool runs `SET
statement_timeout` via the `pgxpool.Config.AfterConnect` hook. A
misconfigured or runaway query that escapes the application's
per-call-site `context.WithTimeout` discipline still gets
cancelled at the DB layer.

`LEDGER_PG_STATEMENT_TIMEOUT` defaults to 5 s; `0` disables it
(application is sole authority). Both `cmd/ledger` (writer) and
`cmd/ledger-reader` (read replica) honor this env. Unparseable
values silently fall back to 5 s; the writer logs the effective
value at boot under `postgres pool ready` so misconfigs are
visible.

### F4 — Builder advisory-lock heartbeat (in-code)

`AcquireBuilderLock` takes the Postgres advisory lock at boot
with a bounded timeout
(`DefaultBuilderLockAcquireTimeout = 30 s`) so a rolling-update
where the previous pod still holds the lock fails fast with an
explicit error instead of hanging forever:

```
store: advisory lock failed within 30s (another writer may hold
the lock — check rolling-update or zombie pod): ...
```

After acquisition, a heartbeat goroutine pings the holding
connection every `DefaultBuilderLockHeartbeatInterval` (10 s).
If the ping fails — TCP reaper, network partition, server
restart — the connection is dead, the advisory lock has auto-
released server-side, and the heartbeat surfaces
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
Without this warmup, admission p99 spikes during the first
~30 s after boot as cold connection slots pay the full
TCP+TLS+startup-message handshake cost (~50–200 ms each in
same-region, more across regions).

Failures during warmup are logged but NOT fatal: the pool stays
valid, and the application falls back to lazy connection on the
first request that needs an unwarmed slot.

### Boot order with F changes

`store/postgres.go::InitPool` (warmup) → `RunMigrations` →
`AcquireBuilderLock` (with heartbeat goroutine) → rest of
subsystem wiring. The lock acquisition fails fast on
rolling-update conflict; the heartbeat starts immediately after
acquisition and shares the supervisor's fatal channel so a lock
loss exits the process via the same path as a sequencer or
shipper panic.

## Boot-time integrity (G category)

The ledger refuses to start on misconfiguration rather than
running in a half-broken state.

| # | Check | Failure mode |
|---|---|---|
| G1 | `Config.Validate()` cross-field invariants | Documented in [configuration.md](configuration.md) |
| G2 | `sequencer.Replayer.Replay` boot reconciliation (Badger 0x0D HWM) | Idempotent; gated only on the gossipstore being wired |
| G3 | `validateTesseraStorageDir` — empty OR has `checkpoint` | Half-initialized state fails boot |
| G5 | `GET /v1/log-info` (public deployment posture) | See [api.md](api.md) |
| G6 | `GET /version` (build provenance) | See [api.md](api.md); populated by `-ldflags` |
| G7 | Boot banner (single Info line at startup) | Forensic identifiers; no secrets |

## In-process audit telemetry (H category)

A single `audit-telemetry` goroutine emits three observability
lines every 5 minutes, all read-only:

```json
{"msg":"integrity audit","invariant_failures_total":0,"samples_verified_total":42}
{"msg":"checkpoint cosig age","age_seconds":12.3}
{"msg":"gossip store growth","event_count":18742,"originator_count":12}
```

**H1** — `integrity.Detector` exposes `InvariantFailures()` +
`SamplesVerified()` atomic counters. SREs compute a failure rate
over a window and alert when invariant_failures climbs above
zero.

**H2** — `gossipnet.STHPublisher.LastCosignedAt()` records the
unix-nanos of every successful PublishCosignedHead.
`CosignAgeSeconds()` returns `now - LastCosignedAt()` in
seconds, or `-1` when no cosigned head has been published yet.
Drives dashboards that alert when witness fan-out has stalled.

**H3** — `gossipstore.BadgerStore.Stats(ctx)` exposes the
event_count + originator_count growth metric. Logged at Info
every 5 min.

**H4** — `store/append_only_guard_test.go::TestAppendOnlyGuard`
walks every non-test `.go` file in the repo and fails the build
if any source file constructs a SQL `UPDATE`, `DELETE FROM`, or
`TRUNCATE` against the append-only tables. Defense-in-depth on
top of F2.

Trim policy for the gossip store is **NOT implemented** today —
trimming safely requires a consumer-cursor model (the oldest
auditor cursor any peer might want to fetch from); we don't
track that yet. Disk pressure is currently bounded by Badger's
value-log GC. Application-level trim is parked behind a future
`LEDGER_GOSSIP_TRIM_AGE` env once the consumer-cursor model
lands.

## Local-runnable bring-up

The ledger is environment-agnostic. Same binary + same env
contract runs on:

| Target | Orchestrator | Wiring |
|---|---|---|
| Laptop (with Docker) | `scripts/run-local.sh` | docker-compose for Postgres + GCS; ledger as a host process |
| VM / bare-metal | `systemd` | `deploy/systemd/ledger.service`; binary at `/usr/local/bin/ledger`; env at `/etc/ledger/env` |
| Kubernetes | k8s Deployment | `deploy/k8s/ledger.yaml` OR Helm chart at `deploy/helm/ledger/` |

### Laptop bring-up (REAL GCS required)

`scripts/run-local.sh` requires a real, developer-owned GCS
bucket. Local dev must exercise the same ADC + auth + retry +
GCS-quirks code path that production uses. Fake-gcs-server is
NOT used here because "works locally but breaks on real GCS"
is precisely the surprise we eliminate by always using the
real backend.

For offline / air-gapped runs (e.g., integration tests, CI on
a sandboxed runner), use `make integration-up` which boots the
fake-gcs harness explicitly. Full local-dev topology in
[scripts/local/README.dev.md](../scripts/local/README.dev.md).

## Build / version / supply chain (K category)

Pragmatic, transparency-log-shaped supply-chain story. Mirrors
the practices used by Tessera (transparency-dev), Sigstore, and
Let's Encrypt Boulder. Scope is administrator-runnable today +
CI-gated; nothing requires a release pipeline that doesn't exist
yet.

### K1 + K2 — Reproducible release builds

```sh
make release-build
# → ./bin/ledger
#   version=v0.42.1
#   commit=abc123def456...
#   build_time=2026-05-07T12:34:56Z
```

Flags:

- `-trimpath` — removes absolute paths from the binary (no
  `/home/$USER/`)
- `-buildvcs=true` — embeds git VCS info in the binary
- `-ldflags="-s -w -buildid="` — strips symbol table, DWARF,
  and build-ID
- `-ldflags="-X main.Version=... -X main.Commit=... -X
  main.BuildTime=..."` — populates the package vars consumed by
  `GET /version`

For byte-reproducible builds, fix `BUILD_TIME` to the commit's
author date so two builders produce identical binaries:

```sh
BUILD_VERSION=v0.42.1 \
  BUILD_TIME=$(git show -s --format=%cI HEAD) \
  make release-build

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
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.4.0
go install golang.org/x/vuln/cmd/govulncheck@latest

make lint
# golangci-lint run ./...        — meta-linter (see .golangci.yml)
# govulncheck ./...              — known-CVE scan
# go vet ./...                   — stdlib's vet pass
```

CI workflows (`.github/workflows/`):

- `lint.yml` — `golangci-lint` on every PR + push
- `govulncheck.yml` — `govulncheck` on every PR + push + daily cron
- `go-test.yml` — `go vet`, `go test -short`, `make audit-sdk`,
  `make test-race` on critical packages
- `chaos.yml` — chaos suite
- `fuzz.yml` — fuzz harness

`.golangci.yml` enables: `errcheck`, `govet` (with `shadow`),
`ineffassign`, `staticcheck` (all checks), `unused`, `gosimple`,
`gofmt`, `goimports`, `bodyclose`, `rowserrcheck`,
`sqlclosecheck`.

### K5 — SBOM (`make sbom`)

CycloneDX 1.5 JSON SBOM via `cyclonedx-gomod` (pure Go —
laptop-runnable, no Docker / syft dep). Operators publish this
alongside the binary at release tags so downstream consumers can
audit transitive deps.

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
make sbom
# → ./bin/sbom.cdx.json (CycloneDX 1.5 JSON)
```

### K6 — Container image signing — DEFERRED

`cosign --keyless` (Sigstore keyless signing via OIDC) is the
industry-standard approach for transparency-log container
images. It is **not implemented in this repo** because there is
no container release pipeline yet (no Dockerfile-based image,
no registry, no GitHub Releases workflow). When that pipeline
lands, `make release-build` + `make sbom` already produce the
artifacts the release workflow would consume.

### Supply-chain reference table

| Layer | Mechanism | Owner |
|---|---|---|
| Source integrity | `git` + signed commits | developer |
| Module integrity | `go.sum` + `go mod verify` | K3 |
| Static analysis | golangci-lint + go vet | K4 |
| Dynamic analysis | govulncheck (reachability-aware) | K4 |
| Build determinism | `-trimpath` + fixed `BUILD_TIME` + `-buildid=""` | K2 |
| Build provenance | `-ldflags` injection of Version/Commit/BuildTime + `GET /version` | K1, G6 |
| Dependency manifest | CycloneDX SBOM | K5 |
| Image signing | `cosign --keyless` | K6 (deferred) |
| SDK invariant audit | `make audit-sdk` (no `muEnable=false` in SDK source) | pre-existing |

## L-category invariants (correctness audits)

### L1 — Constant-time crypto comparison

**Audit conclusion: structurally clean.** No production code in
the ledger does cryptographic byte comparison. Verification
paths go through:

| Surface | Mechanism |
|---|---|
| Signature verify (ECDSA, Ed25519, BLS) | SDK calls into `crypto/ecdsa`, `crypto/ed25519`, BLS12-381 lib — already constant-time at the library level |
| Session token equality | Postgres-side `WHERE token = $1` — DB-side indexed equality on TEXT, attacker-observable timing leaks "row exists or not", which is presence not content |
| `[32]byte` projection-state comparison | Internal integrity-detector / projection writes — not attacker-observable (no oracle path) |

If a future feature introduces a comparison of attacker-supplied
bytes to a stored secret in-process, that call site MUST use
`crypto/subtle.ConstantTimeCompare` — code-review discipline.

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
Every gossipnet constructor checks NetworkID FIRST (T-9
cryptographic domain separation, ahead of all other required-
field checks):

| Constructor | Source |
|---|---|
| `gossipnet.NewSTHPublisher` | `gossipnet/publisher.go:133` |
| `gossipnet.NewEquivocationPublisher` | `gossipnet/equivocation_publisher.go:94` |
| `gossipnet.NewEquivocationMonitor` | `gossipnet/equivocation_monitor.go:165` |
| `gossipnet.Build` (Bundle) | bundle ctor |

Pinned by
`gossipnet/networkid_audit_test.go::TestNetworkIDAudit_*`. The
ledger never bypasses the SDK's NetworkID enforcement because
every cosign payload is signed/verified through SDK primitives
that bind to the publisher/verifier's NetworkID at construction.

### L4 — ctx propagation

`AppendLeaf` accepts `ctx` across all four affected interfaces
(`sequencer.Tessera`, `tessera.AppenderBackend`,
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
| `api/server.go::BaseContext` | Stdlib `http.Server` requires non-nil; per-request ctx is created by net/http itself |
| Boot-panic close-fns (e.g., `closeOTelMeterOnce`) | Parent ctx already cancelled at shutdown; Background + per-component timeout is the correct shape |
