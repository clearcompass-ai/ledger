# Ortholog Operator

Log operator infrastructure for the Ortholog decentralized credentialing protocol. Receives signed entries, runs the four-path builder algorithm via the SDK, persists state atomically to Postgres, distributes cosigned tree heads to witnesses, and serves query/proof endpoints to clients.

Separate deployable from the SDK. Kubernetes target. Single binary.

## Architecture

Phase 3+4 architecture (WAL-first admission, hexagonal bytestore,
async Shipper, integrity Detector, 302-redirect read path) is
documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
                  ┌─────────────┐
                  │   Clients   │
                  └──────┬──────┘
                         │ POST /v1/entries
                         ▼
               ┌───────────────────┐
               │  Admission        │      Middleware chain:
               │  (sequential)     │      SizeLimit → Auth → Handler
               └────────┬──────────┘
                        │ wal.Submit (durable on local NVMe)
                        ▼
               ┌───────────────────┐
               │   WAL (Badger)    │ ← state: pending → sequenced → shipped
               └────────┬──────────┘
                        │
                        │ tessera AppendLeaf (sequence + dedup)
                        ▼
               ┌───────────────────┐       ┌──────────────────┐
               │  entry_index +    │       │   Tessera tiles  │
               │  Postgres         │       │   + antispam     │
               └───────────────────┘       └──────────────────┘
                        │
                        │ Shipper (async migrator)
                        ▼
               ┌───────────────────┐
               │  Bytestore (GCS)  │ ← 302 target for shipped reads
               └───────────────────┘
```

For day-2 operations (alerts, recovery, volume failure semantics)
see [`docs/RUNBOOK.md`](docs/RUNBOOK.md). For environment-variable
configuration see [`docs/CONFIG.md`](docs/CONFIG.md). Phase-3+4
migration notes are in [`CHANGELOG.md`](CHANGELOG.md).

The operator never reimplements builder logic. It calls `sdk builder.ProcessBatch` — the same deterministic function that two independent operators processing the same log must agree on.

## Three-Service Architecture

```
Operator:        Postgres + Tessera credentials. No artifact access. No keys.
Artifact store:  GCS/S3/IPFS credentials. No decryption keys. No log access.
Exchange:        HSM keys + escrow nodes. No storage credentials. No log admin.
```

The CID is the only identifier shared between operator and artifact store. The CID lives in Domain Payload (opaque to operator per SDK-D6). The operator never reads it.

## Requirements

- Go 1.22+ (tested through 1.26)
- PostgreSQL 14+
- [Trillian Tessera](https://github.com/transparency-dev/trillian-tessera) instance
- Ortholog SDK at `../ortholog-sdk` (local replace in go.mod)

## Quick Start

```bash
# 1. Database
createdb ortholog
export OPERATOR_DATABASE_URL="postgres://user:pass@localhost:5432/ortholog?sslmode=disable"

# 2. Required identity + storage env
export OPERATOR_LOG_DID="did:ortholog:operator:001"
export OPERATOR_WAL_PATH="/var/lib/ortholog/wal"
export OPERATOR_TESSERA_STORAGE_DIR="/var/lib/ortholog/tessera"
export OPERATOR_TESSERA_ANTISPAM_PATH="/var/lib/ortholog/tessera-antispam"

# 2a. GCS — pick this OR the S3 block below.
export OPERATOR_BYTE_STORE_BACKEND="gcs"
export OPERATOR_BYTE_STORE_GCS_BUCKET="my-ortholog-bucket"
# GOOGLE_APPLICATION_CREDENTIALS or workload identity for GCS auth.

# 2b. S3 / RustFS / R2 / AWS S3 (alternative to GCS).
# export OPERATOR_BYTE_STORE_BACKEND="s3"
# export OPERATOR_BYTE_STORE_S3_BUCKET="my-ortholog-bucket"
# # AWS production: leave creds empty so the default credential chain
# # (IAM role / IRSA / AWS_* / ~/.aws) is used.
# # RustFS / on-prem:
# # export OPERATOR_BYTE_STORE_S3_ENDPOINT="http://rustfs:9000"
# # export OPERATOR_BYTE_STORE_S3_ACCESS_KEY="..."
# # export OPERATOR_BYTE_STORE_S3_SECRET_KEY="..."
# # export OPERATOR_BYTE_STORE_S3_PATH_STYLE="true"

# 3. Build
go mod tidy
go build -o operator ./cmd/operator

# 4. Run (migrations execute automatically on first start)
./operator

# 5. Verify
curl http://localhost:8080/healthz   # → "ok"
curl http://localhost:8080/readyz    # → "ready"
```

The full env-var reference is in [`docs/CONFIG.md`](docs/CONFIG.md).

## Startup Sequence

`cmd/operator/main.go` executes 16 steps in order. Steps 1–9 are fail-fast: any failure terminates the process immediately.

| Step | Action | Failure mode |
|------|--------|-------------|
| 1 | Load config from env / operator.yaml | Fatal: missing required config |
| 2 | Initialize Postgres pool (pgxpool) | Fatal: database unreachable |
| 3 | Run embedded DDL migrations (6 versions) | Fatal: migration SQL error |
| 4 | Initialize Tessera client | Fatal: invalid URL |
| 5 | Initialize TesseraAdapter (sdk MerkleTree) | — |
| 6 | Initialize SMT with Postgres LeafStore + NodeCache | Fatal: Postgres error |
| 7 | Warm SMT node cache (top N levels into LRU) | Warn: non-fatal, cold cache |
| 8 | Load persisted delta-window buffer | Warn: cold start → strict OCC |
| 9 | Load current witness set from Postgres | Warn: genesis deployment |
| 10 | Acquire advisory lock, start builder loop | Fatal: lock contention |
| 11 | Start equivocation monitor goroutine | — |
| 12 | Start anchor publisher goroutine (if configured) | — |
| 13 | Start difficulty controller goroutine | — |
| 14 | Start HTTP server with middleware chain | Fatal: port bind |
| 15 | Block on SIGTERM / SIGINT | — |
| 16 | Graceful shutdown: drain queue, cancel goroutines, close pool | — |

## API Reference

### Submission

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/entries` | Submit a signed entry for admission |

**Middleware chain:** `SizeLimit(1MB+1KB)` → `Auth(sessions table)` → handler.

**Admission Pipeline** (10 sequential steps, fail-fast):

1. Read raw bytes, validate 6-byte preamble (Protocol_Version must be 3)
2. Strip and verify signature (SDK-D5 contract established here)
3. Entry size check (SDK-D11, default 1MB max canonical bytes)
4. Evidence_Pointers cap (Decision 51, max 10, Authority Snapshots exempt)
5. Admission mode dispatch:
   - Authenticated (Bearer token) → Mode A: credit deduction inside atomic tx
   - Unauthenticated → Mode B: verify compute stamp with **live** difficulty
6. Log_Time assignment (UTC, outside canonical hash — SDK-D1, Decision 50)
7. Compute canonical hash from **raw canonical bytes** (not re-serialized)
8. Atomic persist + enqueue (single Postgres ReadCommitted transaction)
9. HTTP 202 `{ sequence_number, canonical_hash, log_time }`

**Error responses:**

| Status | Condition |
|--------|-----------|
| 401 | Signature verification failed / invalid session token |
| 402 | Insufficient write credits (Mode A) |
| 403 | Invalid compute stamp / wrong log DID (Mode B) |
| 409 | Duplicate entry (canonical hash exists) |
| 413 | Entry exceeds max size |
| 422 | Malformed preamble / unsupported version / Evidence_Pointers cap |

### Tree Head & Merkle Proofs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/tree/head` | Latest cosigned tree head (ETag + Cache-Control: max-age=5) |
| `GET` | `/v1/tree/inclusion/{seq}` | Merkle inclusion proof for sequence number |
| `GET` | `/v1/tree/consistency/{old}/{new}` | Consistency proof between two tree sizes |

### SMT Proofs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/smt/proof/{key}` | Membership or non-membership proof (auto-detected) |
| `POST` | `/v1/smt/batch_proof` | Batch multiproof for up to 1000 keys (SDK-D13 ordering) |
| `GET` | `/v1/smt/root` | Current SMT root hash + leaf count |

### Query Endpoints

All return `[]EntryResponse` JSON with enriched fields. Empty array if no results (never null).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/query/cosignature_of/{pos}` | Entries whose Cosignature_Of matches position (**certification-required**) |
| `GET` | `/v1/query/target_root/{pos}` | Entries targeting a specific root entity |
| `GET` | `/v1/query/signer_did/{did}` | Entries signed by a specific DID |
| `GET` | `/v1/query/schema_ref/{pos}` | Entries governed by a specific schema |
| `GET` | `/v1/query/scan?start=N&count=M` | Sequential scan (default count=100, max 10000, error on >10000) |

**EntryResponse** enriches sdk `EntryWithMetadata` with extracted header fields:

```json
{
  "sequence_number": 42,
  "canonical_hash": "a1b2c3...",
  "log_time": "2024-01-15T10:30:00Z",
  "signer_did": "did:example:alice",
  "target_root": "...",
  "cosignature_of": null,
  "schema_ref": null,
  "canonical_bytes": "00030000..."
}
```

### Admission Info

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/admission/difficulty` | Current Mode B difficulty + hash function (**live**, not cached) |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness probe (always 200 while process runs) |
| `GET` | `/readyz` | Readiness probe (atomic bool, 503 during shutdown) |

## Database Schema

Six migration versions, each statement executed individually. All additive.

**Core tables:**

| Table | Primary Key | Purpose |
|-------|-------------|---------|
| `entries` | `sequence_number BIGINT` | Log entries with canonical bytes, hash, signature, indexed fields |
| `smt_leaves` | `leaf_key BYTEA(32)` | SMT leaf state: origin_tip + authority_tip |
| `smt_nodes` | `path_key BYTEA` | SMT internal node hashes with correct depth tracking |
| `credits` | `exchange_did TEXT` | Mode A write credit balances |
| `tree_heads` | `tree_size BIGINT` | Cosigned tree head history |
| `delta_window_buffers` | `leaf_key BYTEA` | Per-leaf OCC authority tip history |
| `witness_sets` | `version SERIAL` | Witness key set rotation history |
| `equivocation_proofs` | `id SERIAL` | Detected fork evidence (immutable, complete) |
| `sessions` | `token TEXT` | Authenticated exchange sessions |

**Indexes:**

| Index | Column | Condition |
|-------|--------|-----------|
| `idx_signer_did` | `signer_did` | — |
| `idx_target_root` | `target_root` | `WHERE NOT NULL` |
| `idx_cosignature_of` | `cosignature_of` | `WHERE NOT NULL` |
| `idx_schema_ref` | `schema_ref` | `WHERE NOT NULL` |

## Builder Loop

The builder is a single goroutine protected by Postgres advisory lock (`pg_advisory_lock(0x4F5254484F4C4F47)`). Two builders on the same log would produce non-deterministic state — the lock makes this structurally impossible.

Each cycle:

1. **Dequeue** — `SELECT FOR UPDATE SKIP LOCKED` (no contention)
2. **Fetch** — entries in strict sequence order via `PostgresEntryFetcher`
3. **Split** — `EntryWithMetadata` → `[]*envelope.Entry` + `[]LogPosition`
4. **ProcessBatch** — SDK four-path algorithm, deterministic
5. **Atomic commit** — Serializable transaction:
   - Leaf mutations → `smt_leaves` (via `SetTx`)
   - Delta buffer → `delta_window_buffers` (via `SaveTx`)
   - Cursor advance → `builder_cursor` (via `AdvanceTx`)
6. **Tessera append** — `merkleTree.AppendLeaf()` per entry (idempotent)
7. **Commitment** — `MaybePublish()` with frequency control
8. **Cosignatures** — `merkleTree.Head()` → `witness.RequestCosignatures()`

**Crash recovery:** `RecoverStale` resets orphaned `processing` → `pending`. Replay is idempotent: same entries → identical state.

**Key difference from prior implementation:** Steps 5 is a true atomic commit. Previous code wrote leaf mutations outside the transaction (fire-and-forget). Now `PostgresLeafStore.SetTx` and `DeltaBufferStore.SaveTx` write within the same Serializable transaction as queue status updates.

## SDK Interfaces Implemented

```
SDK INTERFACE              OPERATOR IMPLEMENTATION           FILE
────────────────────────────────────────────────────────────────────────
builder.EntryFetcher       PostgresEntryFetcher              store/entries.go
smt.LeafStore              PostgresLeafStore (+SetTx)        store/smt_state.go
smt.NodeCache              PostgresNodeCache (+SetWithDepthTx) store/smt_state.go
smt.MerkleTree             TesseraAdapter                    tessera/proof_adapter.go
log.OperatorQueryAPI       PostgresQueryAPI                  store/indexes/*.go
```

Five SDK interfaces. All read/write for log state. None involve artifacts or decryption.

## Configuration

All settings via environment variables. Config file at `config/operator.yaml` for reference.

**Critical settings:**

| Setting | Default | Description |
|---------|---------|-------------|
| `ORTHOLOG_LOG_DID` | `did:ortholog:operator:001` | This operator's log identity |
| `ORTHOLOG_POSTGRES_DSN` | localhost | Postgres connection string |
| `ORTHOLOG_SERVER_ADDR` | `:8080` | HTTP listen address |
| `ORTHOLOG_TESSERA_URL` | `http://localhost:2024` | Tessera Merkle tree backend |

**Builder tuning:**

| Setting | Default | Impact |
|---------|---------|--------|
| `builder.batch_size` | 1000 | Entries per cycle. Higher = throughput, latency tradeoff. |
| `builder.poll_interval` | 100ms | Delay between empty polls. Zero between non-empty batches. |
| `builder.delta_window_size` | 10 | OCC window depth for commutative schemas. |

**Admission tuning:**

| Setting | Default | Impact |
|---------|---------|--------|
| `admission.initial_difficulty` | 16 | Mode B stamp bits. Read **live** per-request. |
| `admission.min_difficulty` | 8 | Floor. Never below this. |
| `admission.max_difficulty` | 24 | Ceiling. ~16M hashes. |
| `admission.hash_function` | sha256 | `sha256` or `argon2id` for Mode B. |

## Testing

```bash
# Unit-level tests (no Postgres / no cloud required)
go test ./... -count=1

# HTTP integration + e2e tests (Postgres required)
export ORTHOLOG_TEST_DSN="postgres://user:pass@localhost:5432/ortholog_test?sslmode=disable"
go test ./tests/ -count=1 -v

# Bytestore conformance against fake-gcs-server (Docker required)
./scripts/run-gcs-tests.sh

# Bytestore conformance against real GCS bucket
ORTHOLOG_REAL_GCS_BUCKET=my-bucket ./scripts/run-gcs-tests-real.sh

# Operator soak (1M entries against real GCS — minutes, real cloud cost)
ORTHOLOG_TEST_DSN=... ORTHOLOG_TEST_GCS_BUCKET=... ./scripts/run-soak.sh
```

Test gating envs (`ORTHOLOG_TEST_*`) and soak knobs (`ORTHOLOG_SOAK_*`)
are documented in [`docs/CONFIG.md`](docs/CONFIG.md). Soak is
build-tag-isolated under `//go:build soak` — the default
`go test ./...` never invokes it.

**85 tests across 14 categories:**

| Category | Tests | Validates |
|----------|-------|-----------|
| Admission Pipeline | 12 | SDK-D5 sig contract, SDK-D11 size, Decision 51 cap, Mode A/B |
| Builder Determinism | 6 | Root match, all paths, path compression, lane selection, empty batch |
| SMT State Correctness | 8 | Leaf creation, Origin/Authority tip updates, commentary zero impact, Path D |
| Query Index Correctness | 10 | All 5 OperatorQueryAPI methods with pagination |
| Tree Head & Witness | 7 | Assembly, K-of-N threshold, rotation dual-sign, equivocation |
| Log_Time Accuracy | 4 | Assignment, monotonicity, outside hash, in metadata |
| Sequence Integrity | 4 | Monotonic, gapless, cross-restart, queue order |
| Delta Buffer & OCC | 5 | Persistence, cold start, reconstructible, commutative/strict |
| Anchor Publishing | 3 | Commentary entry, payload content, frequency |
| Derivation Commitments | 3 | Matches mutations, is commentary, frequency |
| Crash Recovery | 5 | Mid-batch, queue reclaim, advisory lock, shutdown, retry |
| Governance End-to-End | 7 | Scope creation, amendment, removal, rotation, recovery, delegation, enforcement |
| Judicial End-to-End | 6 | Filing, sealing, evidence grant, relay, bulk import, assignments |
| Multi-Tenant & Operational | 4 | Log isolation, credit isolation, difficulty, health checks |

## Invariants

These are structural properties enforced by code, not guidelines.

**SDK-D5 (signature contract):** Every entry in the `entries` table has had its signature verified at admission. The builder trusts this — it never re-verifies. Established at `api/submission.go` step 2.

**Builder exclusivity:** `pg_advisory_lock(0x4F5254484F4C4F47)` in `store/postgres.go`. Two builders on the same log is impossible.

**Atomic commit:** Leaf mutations + node cache + delta buffer + queue status happen in ONE Serializable Postgres transaction. No orphaned entries. No partial state.

**Gapless sequence:** Tessera owns sequence allocation. Admission obtains the seq from `tessera.AppendLeaf` (the antispam dedup keeps it idempotent under concurrent submissions of the same content) and inserts the assigned value into `entry_index`. The Phase 1/2 `entry_sequence` Postgres SEQUENCE was dropped in commit 10. Builder processes entries in seq order via the cursor reader. Gaps break determinism.

**Decision 47 (locality):** `PostgresEntryFetcher.Fetch` returns nil for foreign log DIDs. The builder only processes local entries.

**Decision 51 (evidence cap):** Enforced at both `sdk envelope.NewEntry` (Phase 1) and `api/submission.go` step 4 (Phase 2). Defense in depth.

**SDK-D9 (cold start):** Empty delta buffer = strict OCC. `DeltaBufferStore.Load` returns empty buffer on first boot.

**Live difficulty:** `DifficultyController.CurrentDifficulty()` read atomically per-request. Not a startup snapshot.

**Middleware chain:** POST /v1/entries passes through `SizeLimit → Auth → handler`. Auth validates session tokens against the `sessions` table; invalid tokens return 401 (not silent Mode B fallthrough).

## Project Structure

```
ortholog-operator/
├── cmd/operator/main.go               16-step startup + graceful shutdown
├── api/
│   ├── server.go                      HTTP routes + middleware chain applied
│   ├── submission.go                  10-step admission pipeline
│   ├── tree.go                        Tree head + Merkle proofs
│   ├── proofs.go                      SMT proof endpoints
│   ├── queries.go                     5 query endpoints + EntryResponse + difficulty
│   └── middleware/
│       ├── auth.go                    Session validation (401 on invalid token)
│       ├── size_limit.go              MaxBytesReader
│       ├── rate_limit.go              DifficultyController (queue-depth-based)
│       └── evidence_cap.go            Decision 51 check function
├── builder/
│   ├── loop.go                        Builder loop → SDK ProcessBatch → atomic commit
│   ├── queue.go                       Postgres FIFO + processed_at + PendingCount
│   ├── commitment_publisher.go        Frequency-controlled commitments
│   └── delta_buffer.go                SaveTx inside atomic commit
├── store/
│   ├── postgres.go                    Pool, migrations (per-stmt), advisory lock, tx manager
│   ├── entries.go                     PostgresEntryFetcher (SDK-D5 + Decision 47)
│   ├── smt_state.go                   LeafStore.SetTx + NodeCache.SetWithDepthTx
│   ├── credits.go                     Atomic credit deduction
│   ├── tree_heads.go                  Cosigned head history + in-memory cache
│   └── indexes/
│       ├── query_api.go               PostgresQueryAPI struct + shared scanner
│       ├── cosignature_of.go          Certification-required index
│       ├── target_root.go
│       ├── signer_did.go
│       ├── schema_ref.go
│       └── scan.go                    MaxScanCount=10000, error on exceed
├── witness/
│   ├── head_sync.go                   K-of-N parallel cosig (builder.WitnessCosigner)
│   ├── equivocation_monitor.go        Fork detection (complete proofs)
│   └── rotation_handler.go            Dual-sign scheme transition
├── tessera/
│   ├── client.go                      Tessera HTTP API (internal)
│   ├── proof_adapter.go               TesseraAdapter (sdk MerkleTree interface)
│   └── tile_reader.go                 LRU-cached tile reader
├── anchor/
│   └── publisher.go                   Periodic anchors to parent log (actually submits)
├── config/
│   └── operator.yaml                  Full config schema
├── tests/
│   └── integration_test.go            85 tests across 14 categories
├── go.mod
└── go.sum
```

32 Go source files. 1 test file. 85 tests. ~5,200 lines.

## Kubernetes Deployment

- **Replicas:** Exactly 1 per log DID. Advisory lock prevents concurrent builders.
- **Readiness probe:** `GET /readyz` — atomic bool, 503 during shutdown.
- **Liveness probe:** `GET /healthz` — 200 while process runs.
- **Graceful shutdown:** `SIGTERM` → readiness false → drain → exit 0. Set `terminationGracePeriodSeconds: 60`.
- **Secrets:** Inject `ORTHOLOG_POSTGRES_DSN` via Kubernetes Secret / SOPS.
- **Resources:** Builder loop is CPU-bound during batch processing. 500m CPU / 512Mi minimum.

## Protocol Decisions Enforced

| Decision | Enforcement point |
|----------|-------------------|
| SDK-D1 | Log_Time assignment at submission step 6 |
| SDK-D5 | Signature verification at submission step 2 |
| SDK-D7 | SchemaResolver → commutative boolean (OCC mode) |
| SDK-D9 | Empty delta buffer → strict OCC |
| SDK-D11 | Entry size check at submission step 3 |
| SDK-D13 | Batch proof canonical ordering in proofs.go |
| Decision 41 | Witness rotation dual-sign detection |
| Decision 44 | Anchor entries as standard commentary |
| Decision 47 | Locality check in PostgresEntryFetcher.Fetch |
| Decision 49 | Protocol version preamble check at submission step 1 |
| Decision 50 | Log_Time outside canonical hash |
| Decision 51 | Evidence_Pointers cap at submission step 4 + SDK NewEntry |

## License

Proprietary. ClearCompass AI.
