# Operations

Day-1 operational surface: how the operator boots, what's in the
repo, how to run the test suite, and what a Kubernetes deployment
looks like. Day-2 (alerts, recovery, volume failure semantics) is in
[`docs/RUNBOOK.md`](../docs/RUNBOOK.md).

## Startup sequence

`cmd/operator/main.go` boots in this order. Anything marked **fatal**
exits the process non-zero before the HTTP server binds.

| Order | Action | Failure mode |
|---|---|---|
| 1 | Load config from environment | **Fatal** — required vars missing |
| 2 | `envelope.ValidateDestination(LogDID)` | **Fatal** — invalid log DID |
| 3 | Open Postgres pool (`pgxpool.New`) | **Fatal** — DB unreachable |
| 4 | `store.RunMigrations` (idempotent DDL) | **Fatal** — migration SQL error |
| 5 | Construct entry / credit / commit / leaf / node-cache stores | — |
| 6 | Open WAL BadgerDB at `OPERATOR_WAL_PATH` | **Fatal** — Badger open error |
| 7 | Construct WAL committer | — |
| 8 | `bytestore.NewFromConfig` (GCS or S3 selected by `OPERATOR_BYTE_STORE_BACKEND`) | **Fatal** — bucket unreachable / creds missing |
| 9 | `mkdir` Tessera storage dir; `posix.New` driver | **Fatal** — directory unwritable |
| 10 | Resolve Tessera signer (file or ephemeral) | **Fatal** — file unreadable / parse error |
| 11 | `mkdir` antispam dir; `posixantispam.NewAntispam` | **Fatal** — Badger open error |
| 12 | `tessera.NewEmbeddedAppender` | **Fatal** — Tessera init error |
| 13 | Construct tile reader + `TesseraAdapter` | — |
| 14 | Composite byte reader (WAL → bytestore fallback) | — |
| 15 | Builder dependencies — fetcher, delta buffer, cursor reader, SMT tree | — |
| 16 | Load delta buffer from Postgres (cold start = strict OCC per SDK-D9) | Warn — non-fatal |
| 17 | Construct commitment publisher, difficulty controller, cosigner (currently nil) | — |
| 18 | Construct builder loop, anchor publisher, submission handler | — |
| 19 | Wire query / tree / SMT / commitment handlers | — |
| 20 | Construct integrity Detector | — |
| 21 | **Boot reconcile** — `detector.Reconcile(ctx)` re-Adds every WAL inflight entry to Tessera (idempotent via antispam) | **Fatal** — transport error |
| 22 | Construct Shipper | — |
| 23 | Construct HTTP server | — |
| 24 | Spawn goroutines: HTTP server, builder loop, difficulty controller, anchor publisher, shipper, integrity detector loop | — |
| 25 | Block on `ctx.Done()` (SIGTERM/SIGINT) **or** the fatal channel | — |
| 26 | `server.Shutdown(30s)`; `wg.Wait`; log batch stats; panic if a fatal-channel error fired | — |

The supervisor at the bottom of `main.go` is the only deliberate
panic site in the codebase. A goroutine returning a non-recoverable
error (Tessera divergence, shipper exhaustion) cancels the context,
drains, and panics — the orchestrator decides what's next.

## Project structure

```
ortholog-operator/
├── cmd/
│   ├── operator/                       Operator binary entry point
│   ├── operator-reader/                Read-only operator (Tessera follower)
│   ├── bootstrap-v775-schemas/         One-shot schema bootstrap utility
│   └── rebuild-tiles/                  Tile rebuild utility
├── api/
│   ├── server.go                       HTTP routes + middleware chain
│   ├── submission.go                   14-step admission pipeline
│   ├── tree.go                         Tree head + Merkle proofs
│   ├── proofs.go                       SMT proof endpoints
│   ├── queries.go                      Query endpoints + difficulty handler
│   ├── entries_read.go                 GET /v1/entries/{seq}{,/raw}
│   ├── batch.go                        Batch read handler
│   ├── smt_read.go                     SMT leaf read handlers
│   ├── commitments.go                  Commitment query handler
│   ├── derivation_commitments.go       Derivation commitment endpoints
│   └── middleware/
│       ├── auth.go                     Bearer-token session validation
│       ├── size_limit.go               http.MaxBytesReader
│       ├── rate_limit.go               DifficultyController
│       └── evidence_cap.go             Decision 51 evidence-pointer cap
├── admission/
│   ├── entry_signature_verifier.go     Wraps SDK signature verification
│   ├── nfc_check.go                    NFC normalization assertion
│   └── bls_quorum_verifier.go          BLS witness-quorum verifier
├── builder/
│   ├── loop.go                         Builder loop (single goroutine)
│   ├── cursor_reader.go                CT-native log-tailing reader
│   ├── delta_buffer.go                 OCC tip history persistence
│   └── commitment_publisher.go         Periodic derivation commitments
├── store/
│   ├── postgres.go                     Pool, idempotent DDL, advisory lock
│   ├── entries.go                      PostgresEntryFetcher
│   ├── smt_state.go                    LeafStore.SetTx + NodeCache.SetWithDepthTx
│   ├── credits.go                      Atomic credit deduction
│   ├── tree_heads.go                   Cosigned head history + cache
│   ├── sequence_cursor.go              Builder cursor (singleton row)
│   ├── derivation_commitments.go       Derivation commitment store
│   ├── commitment_fetcher.go           Commitment lookup by SplitID
│   ├── pre_grant_commitments.go        Pre-grant commitment helpers
│   ├── escrow_split_commitments.go     Escrow-split commitment helpers
│   ├── fetcher.go                      Composite byte reader
│   └── indexes/                        PostgresQueryAPI implementations
├── tessera/
│   ├── embedded_appender.go            In-process upstream Tessera
│   ├── posix_tile_backend.go           POSIX tile reader backend
│   ├── tile_reader.go                  LRU-cached tile reader
│   ├── proof_adapter.go                MerkleAppender adapter + proof methods
│   └── entry_reader.go                 Entry-byte reader for follower mode
├── wal/
│   ├── wal.go                          BadgerDB open / close
│   ├── committer.go                    Group-commit + fsync
│   ├── meta.go                         EntryState constants + meta encoding
│   ├── reader.go                       Iterate-inflight + state reads
│   ├── dedup.go                        Tessera deduplicator backed by WAL
│   ├── keyspace.go                     BadgerDB key prefixes
│   └── errors.go                       WAL error sentinels
├── bytestore/
│   ├── bytestore.go                    Reader / Writer / Presigner / Backend
│   ├── factory.go                      NewFromConfig + per-backend validation
│   ├── memory.go                       In-memory Store (test-only)
│   ├── gcs.go                          GCS Backend
│   └── s3.go                           S3 Backend
├── shipper/
│   ├── shipper.go                      WAL → bytestore migrator
│   └── metrics.go                      Shipper observability
├── integrity/
│   ├── detector.go                     Boot Reconcile + periodic Loop
│   ├── reasserter.go                   Re-Add WAL inflight to Tessera
│   ├── verifier.go                     WAL.HashAt vs Tessera.HashAt
│   ├── tessera_adapter.go              Adapter merging appender + tile reader
│   └── integrity.go                    Shared error types
├── witness/
│   ├── head_sync.go                    K-of-N parallel cosigner client
│   ├── serve.go                        Cosignature server (this operator as witness)
│   ├── equivocation_monitor.go         Tree-head fork detection
│   ├── rotation_handler.go             Witness-set rotation dual-sign
│   ├── commitment_equivocation_monitor.go  Dealer SplitID equivocation
│   └── commitment_equivocation_alert.go    Webhook alerting
├── anchor/
│   └── publisher.go                    Periodic anchor commentary
├── lifecycle/
│   ├── archive_reader.go               Archived-shard reads
│   └── shard_manager.go                Shard lifecycle coordination
├── config/
│   └── operator.yaml                   Reference config (env vars are authoritative)
├── deployment/local/                   Local docker-compose harness
├── docs/
│   ├── ARCHITECTURE.md                 Architectural deep-dive
│   ├── CONFIG.md                       Full env-var reference
│   └── RUNBOOK.md                      Day-2 operations
├── readme/                             This split README
├── scripts/                            Test runners (gcs, s3, soak, cursor)
├── script/                             run.sh helper
├── tests/                              Cross-package e2e + integration tests
├── integration/                        Postgres-backed integration tests
├── go.mod
├── go.sum
├── Makefile
├── CHANGELOG.md
├── README.md                           This file's index
└── ...
```

29 active Go test files, ~327 test functions. The byte-counts above
ignore `*.go.bak` files in `tests/` (legacy snapshots scheduled for
removal).

## Testing

```bash
# Unit-level tests (no Postgres / no cloud required)
go test ./... -count=1

# Skip integration paths gated on ORTHOLOG_TEST_DSN
go test -short ./...

# HTTP integration + e2e (Postgres required)
export ORTHOLOG_TEST_DSN="postgres://user:pass@localhost:5432/ortholog_test?sslmode=disable"
go test ./tests/ -count=1 -v

# Bytestore conformance against fake-gcs-server (Docker required)
./scripts/run-gcs-tests.sh

# Bytestore conformance against real GCS
ORTHOLOG_REAL_GCS_BUCKET=my-bucket ./scripts/run-gcs-tests-real.sh

# Bytestore conformance against RustFS
./scripts/run-bytestore-tests-rustfs.sh

# Operator soak (1M entries against real GCS — minutes, real cloud cost)
ORTHOLOG_TEST_DSN=... ORTHOLOG_TEST_GCS_BUCKET=... ./scripts/run-soak.sh
```

The soak harness is build-tag-isolated under `//go:build soak`; the
default `go test ./...` never invokes it. Test-gating env vars
(`ORTHOLOG_TEST_*`) and soak knobs (`ORTHOLOG_SOAK_*`) are documented
in [`docs/CONFIG.md`](../docs/CONFIG.md).

The `make audit-v775` target enforces the SDK mutation-gate
discipline: every `muEnable*` constant in the SDK must remain `true`
in committed code; CI fails on any flipped to `false`.

## Kubernetes deployment

- **Replicas:** Exactly 1 per log DID. The Postgres advisory lock
  makes a second builder structurally impossible, but you'll waste
  a pod restarting against the lock.
- **Readiness probe:** `GET /readyz` — atomic bool, returns 503
  during shutdown.
- **Liveness probe:** `GET /healthz` — returns 200 while the
  process runs.
- **Graceful shutdown:** `SIGTERM` flips readiness false → 30 s
  drain → `wg.Wait` → exit 0. Set
  `terminationGracePeriodSeconds: 60`.
- **Persistent volumes:** distinct PVCs for
  `OPERATOR_WAL_PATH`, `OPERATOR_TESSERA_STORAGE_DIR`, and
  `OPERATOR_TESSERA_ANTISPAM_PATH`. Mixing them risks correlated
  loss (see [`docs/RUNBOOK.md`](../docs/RUNBOOK.md) for failure
  semantics per volume).
- **Secrets:** inject `OPERATOR_DATABASE_URL` and any S3 static
  credentials via Kubernetes Secret / SOPS. Prefer IAM role / IRSA
  / Workload Identity over static keys on cloud.
- **Resources:** the builder loop is CPU-bound during batch
  processing; admission is WAL-IOPS-bound. Provision NVMe-class
  storage for `OPERATOR_WAL_PATH` — sustained admission throughput
  is bounded by its fsync IOPS. Start at 500m CPU / 512Mi memory
  per pod and tune from observed metrics.

## Invariants enforced by code

These are structural properties code makes structurally impossible to
violate. Not aspirational guidelines.

- **Signature verification before persistence (SDK-D5):** every row
  in `entry_index` has had its signature verified at admission step
  4. The builder trusts this — it never re-verifies.
- **Builder exclusivity:**
  `pg_advisory_lock(0x4F5254484F4C4F47)` in `store/postgres.go`.
  Two builders on the same log is impossible.
- **Atomic commit:** SMT leaves + node cache + delta buffer + cursor
  advance happen in one Serializable Postgres transaction. No
  orphaned entries; no partial state.
- **Gapless sequence:** Tessera owns sequence allocation; admission
  inserts the assigned value into `entry_index`. Antispam dedup
  keeps re-Adds idempotent under concurrent submission of the same
  content.
- **Locality (Decision 47):** `PostgresEntryFetcher.Fetch` returns
  nil for foreign log DIDs. The builder only processes local
  entries.
- **Evidence cap (Decision 51):** enforced at SDK `NewEntry` and at
  admission step 6. Defense in depth.
- **Cold start = strict OCC (SDK-D9):** an empty delta buffer
  triggers strict OCC; commutative widening only kicks in once the
  buffer has tip history.
- **Live difficulty:** `DifficultyController.CurrentDifficulty()`
  is read atomically per request. Not a startup snapshot.
- **Append-only equivocation evidence:** rows in
  `commitment_equivocation_proofs` are never deleted. Historical
  forensics over governance resolution.
