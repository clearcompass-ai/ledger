# Ortholog Operator

Log operator infrastructure for the Ortholog decentralized credentialing
protocol. Receives signed entries, sequences them via embedded Tessera,
persists log state to Postgres, distributes cosigned tree heads to
witnesses, and serves query/proof endpoints to clients.

Single binary. Kubernetes target. WAL-first admission for durability
under load. Hexagonal byte storage (GCS or S3-compatible).

## Architecture

The full architecture document is [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
                  ┌─────────────┐
                  │   Clients   │
                  └──────┬──────┘
                         │ POST /v1/entries
                         ▼
               ┌───────────────────┐      Middleware:
               │  Admission        │      SizeLimit → Auth → Handler
               │  (14 steps)       │
               └────────┬──────────┘
                        │ wal.Submit (durable on local NVMe)
                        ▼
               ┌───────────────────┐
               │   WAL (Badger)    │  state: pending → sequenced → shipped
               └────────┬──────────┘
                        │ tessera AppendLeaf (embedded; antispam dedup)
                        ▼
               ┌───────────────────┐       ┌──────────────────┐
               │  entry_index +    │       │  Tessera tiles   │
               │  Postgres         │       │  + antispam      │
               └───────────────────┘       └──────────────────┘
                        │
                        │ Shipper (async migrator)
                        ▼
               ┌───────────────────┐
               │  Bytestore        │  302 target for shipped reads
               │  (GCS or S3)      │
               └───────────────────┘
```

For day-2 operations (alerts, recovery, volume failure semantics) see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md). For environment-variable
configuration see [`docs/CONFIG.md`](docs/CONFIG.md). Release notes
live in [`CHANGELOG.md`](CHANGELOG.md).

The operator never reimplements builder logic. It calls
`sdk.builder.ProcessBatch` — the same deterministic function that two
independent operators processing the same log must agree on.

## Three-Service Architecture

```
Operator:        Postgres + Tessera storage. No artifact access. No keys.
Artifact store:  GCS/S3/IPFS credentials. No decryption keys. No log access.
Exchange:        HSM keys + escrow nodes. No storage credentials. No log admin.
```

The CID is the only identifier shared between operator and artifact
store. The CID lives in Domain Payload (opaque to operator per SDK-D6).
The operator never reads it.

## Requirements

- Go 1.25 (per `go.mod`)
- PostgreSQL 14+
- Embedded Tessera (`github.com/transparency-dev/tessera`) — no
  separate Tessera service to deploy
- Ortholog SDK (configured in `go.mod`)

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

## Local development

`integration/docker-compose.yml` brings up Postgres + fake-gcs +
RustFS for local-dev. After `docker compose -f integration/docker-compose.yml
up -d postgres fake-gcs bucket-init`, set the env above pointing at
`localhost:5544` (Postgres) and `http://localhost:4443/storage/v1/`
(fake-gcs) and `go run ./cmd/operator`.

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/entries` | Submit a signed entry. SizeLimit → Auth → handler. |
| `GET`  | `/v1/entries/{seq}` | JSON metadata for one entry. |
| `GET`  | `/v1/entries/batch?start&count` | JSON metadata list. |
| `GET`  | `/v1/entries/{seq}/raw` | Wire bytes; 200 inline OR 302 to bytestore. |
| `GET`  | `/v1/tree/head` | Latest cosigned tree head (ETag + max-age=5). |
| `GET`  | `/v1/tree/inclusion/{seq}` | Merkle inclusion proof. |
| `GET`  | `/v1/tree/consistency/{old}/{new}` | Consistency proof between sizes. |
| `GET`  | `/v1/smt/proof/{key}` | Membership / non-membership SMT proof. |
| `POST` | `/v1/smt/batch_proof` | Batch multiproof for up to 1000 keys. |
| `GET`  | `/v1/smt/root` | Current SMT root + leaf count. |
| `GET`  | `/v1/smt/leaf/{key}` | Single leaf state. |
| `POST` | `/v1/smt/leaves` | Batch leaf state. |
| `GET`  | `/v1/query/cosignature_of/{pos}` | Certification-required index. |
| `GET`  | `/v1/query/target_root/{pos}` | Entries targeting a root entity. |
| `GET`  | `/v1/query/signer_did/{did}` | Entries signed by DID. |
| `GET`  | `/v1/query/schema_ref/{pos}` | Entries governed by a schema. |
| `GET`  | `/v1/query/scan?start&count` | Sequential scan (count ≤ 10000). |
| `GET`  | `/v1/admission/difficulty` | Live Mode B difficulty. |
| `GET`  | `/v1/commitments?seq=N` | Cryptographic commitment lookup. |
| `POST` | `/v1/cosign` | Witness cosign endpoint (mounted only when this op is a witness). |
| `GET`  | `/healthz` | Liveness. |
| `GET`  | `/readyz` | Readiness (503 during shutdown). |

### Admission pipeline

`api/submission.go` runs 14 sequential steps; any failure aborts:

| Step | Action |
|------|--------|
| 1 | Read raw bytes; validate 6-byte preamble (Protocol_Version checked via `envelope.CurrentProtocolVersion()`). |
| 2 | Deserialize wire bytes; validate algo ID. |
| 3a | `entry.Validate()` re-applies write-time invariants. |
| 3a-NFC | NFC normalization assertion (`admission.CheckNFC`). |
| 3b | Destination binding: `Header.Destination == OPERATOR_LOG_DID`. |
| 3c | Late-replay freshness via `exchange/policy.CheckFreshness`. |
| 4 | Signature verification — `admission.VerifyEntrySignature` over `envelope.SigningPayload`. |
| 4-Schema | Commitment-schema dispatch — peeks `schema_id`, parses recognized commitment payloads to extract SplitID. |
| 5 | Entry size cap (SDK-D11, 1MB default). |
| 6 | Evidence_Pointers cap (Decision 51, max 10; Authority Snapshots exempt). |
| 7 | Mode dispatch: authenticated (Bearer token) → Mode A credit deduction; unauthenticated → Mode B PoW stamp verify. |
| 8 | Canonical hash via `envelope.EntryIdentity`. |
| 8a | Early duplicate check against `entry_index`. |
| 9 | Log_Time assignment (UTC, outside canonical hash). |
| 10 | WAL durability: `wal.Submit` blocks until fsync. |
| 11 | Tessera sequence assignment via `tessera.AppendLeaf` (antispam dedup makes this idempotent under concurrent admission of identical content). |
| 12 | Postgres sidecar — `entry_index` + `commitment_split_id`. |
| 13 | WAL state pending → sequenced. |
| 14 | HTTP 202 `{ sequence_number, canonical_hash, log_time }`. |

Error responses:

| Status | Condition |
|--------|-----------|
| 401 | Signature verification failed / invalid session token |
| 402 | Insufficient write credits (Mode A) |
| 403 | Invalid compute stamp / wrong log DID (Mode B) |
| 409 | Duplicate entry (canonical hash exists) |
| 413 | Entry exceeds max size |
| 422 | Malformed preamble / unsupported version / Evidence_Pointers cap |
| 503 | WAL queue full (back-pressure; client retries) |

`POST /v1/entries` requires either a valid Mode A session token
(rows in the `sessions` and `credits` tables) or a Mode B PoW stamp
inside the entry header. The submission is asynchronous from the
caller's perspective: HTTP 202 is returned after WAL durability
plus Tessera sequencing; bytestore migration runs in the background.

## Database schema

Migrations are embedded in `store/postgres.go` and run automatically
at first boot. Tables:

| Table | Primary key | Purpose |
|-------|-------------|---------|
| `entry_index` | `sequence_number BIGINT` | Sequenced entries; no wire bytes (those live in WAL/bytestore). Indexed on signer_did, target_root, cosignature_of, schema_ref. |
| `smt_leaves` | `leaf_key BYTEA(32)` | SMT leaf state — origin_tip + authority_tip. |
| `smt_nodes` | `path_key BYTEA` | SMT internal node hashes with depth tracking. |
| `credits` | `exchange_did TEXT` | Mode A write-credit balances. |
| `tree_heads` | `tree_size BIGINT` | Cosigned tree head history. |
| `tree_head_sigs` | `(tree_size, signer_id)` | Per-witness signatures over tree heads. |
| `delta_window_buffers` | `leaf_key BYTEA` | Per-leaf OCC authority-tip history. |
| `builder_cursor` | `log_did TEXT` | Builder's current sequence position. |
| `witness_sets` | `version SERIAL` | Witness-key-set rotation history. |
| `equivocation_proofs` | `id SERIAL` | Tree-head fork evidence. |
| `sessions` | `token TEXT` | Authenticated exchange sessions. |
| `derivation_commitments` | `id SERIAL` | Fraud-proof lookup index. |
| `commitment_split_id` | `split_id BYTEA(32)` | Pre-grant + escrow split-commitment index. |
| `commitment_equivocation_proofs` | `id SERIAL` | Commitment-level fork evidence. |

## Builder loop

Single goroutine protected by Postgres advisory lock
(`pg_advisory_lock(0x4F5254484F4C4F47)`). Two builders on the same
log would produce non-deterministic state — the lock makes this
structurally impossible.

Each cycle:

1. **Read** — `cursor_reader` returns the next batch from
   `entry_index` after the persisted cursor.
2. **Fetch** — entries in strict sequence order via
   `PostgresEntryFetcher`.
3. **Split** — `EntryWithMetadata` → `[]*envelope.Entry` +
   `[]LogPosition`.
4. **ProcessBatch** — SDK four-path algorithm, deterministic.
5. **Atomic commit** — Serializable transaction:
   - leaf mutations → `smt_leaves` (`SetTx`)
   - delta buffer → `delta_window_buffers` (`SaveTx`)
   - cursor advance → `builder_cursor` (`AdvanceTx`)
6. **Tessera append (post-commit)** — `merkleTree.AppendLeaf()` per
   entry. Tessera was already called at admission step 11 to
   allocate the seq; this second call is idempotent because
   antispam dedup returns the previously-assigned seq for re-Adds.
   The post-commit append is a belt-and-braces guarantee that
   surviving entries are integrated into the published tree even
   if admission crashed between step 11 and step 12.
7. **Commitment publish** — `MaybePublish()` with frequency control.
8. **Cosignatures** — `merkleTree.Head()` →
   `witness.RequestCosignatures()` (skipped silently when no
   witness endpoints configured).

Crash recovery: cursor is the source of truth. Replay is
idempotent: same entries → identical state.

## SDK interfaces implemented

| SDK interface | Operator implementation | File |
|---|---|---|
| `builder.EntryFetcher` | `PostgresEntryFetcher` | `store/entries.go` |
| `smt.LeafStore` | `PostgresLeafStore` (+ `SetTx`) | `store/smt_state.go` |
| `smt.NodeCache` | `PostgresNodeCache` (+ `SetWithDepthTx`) | `store/smt_state.go` |
| `smt.MerkleTree` | `TesseraAdapter` | `tessera/proof_adapter.go` |
| `log.OperatorQueryAPI` | `PostgresQueryAPI` | `store/indexes/*.go` |

## Testing

```bash
# Unit-level tests (no Postgres / no cloud required)
go test ./... -count=1

# HTTP integration + e2e tests (Postgres required)
export ORTHOLOG_TEST_DSN="postgres://user:pass@localhost:5432/ortholog_test?sslmode=disable"
go test ./tests/ -count=1 -v

# Bytestore conformance against fake-gcs-server
./scripts/run-gcs-tests.sh

# Bytestore conformance against real GCS
ORTHOLOG_REAL_GCS_BUCKET=my-bucket ./scripts/run-gcs-tests-real.sh

# Bytestore conformance against the local RustFS container
./scripts/run-bytestore-tests-rustfs.sh

# Operator soak (1M entries against real GCS — minutes, real cloud cost)
ORTHOLOG_TEST_DSN=... ORTHOLOG_TEST_GCS_BUCKET=... ./scripts/run-soak.sh
```

Test gating envs (`ORTHOLOG_TEST_*`) and soak knobs (`ORTHOLOG_SOAK_*`)
are documented in [`docs/CONFIG.md`](docs/CONFIG.md). Soak is
build-tag-isolated under `//go:build soak` — the default
`go test ./...` never invokes it.

## Project structure

```
ortholog-operator/
├── cmd/
│   ├── operator/main.go              composition root + supervisor
│   ├── operator-reader/main.go       read-only operator
│   ├── bootstrap-v775-schemas/       schema-entry bootstrap
│   └── rebuild-tiles/                tile reconstructor
├── api/                              HTTP server, handlers, middleware
├── admission/                        signature verifier + NFC checker
├── builder/                          builder loop, cursor reader, commitment publisher
├── store/                            Postgres pool, migrations, fetchers, indexes
├── wal/                              BadgerDB WAL with group commit + dedup
├── bytestore/                        hexagonal Backend (GCS + S3) + memory + factory
├── tessera/                          embedded Tessera adapter, posix tile backend, tile reader
├── shipper/                          WAL → bytestore migrator
├── integrity/                        Verifier + Reasserter + Detector (panic on divergence)
├── witness/                          K-of-N cosignature collection + cosign serve endpoint
├── anchor/                           periodic anchor publisher
├── lifecycle/                        boot reconciler
├── tests/                            HTTP + e2e + soak suites
├── integration/                      docker-compose harness
├── scripts/                          test runners
├── docs/                             ARCHITECTURE / CONFIG / RUNBOOK
├── go.mod / go.sum
├── README.md / CHANGELOG.md
```

## Invariants

Structural properties enforced by code, not guidelines.

**SDK-D5 (signature contract):** every entry whose seq is in
`entry_index` had its signature verified at admission step 4.
Builder trusts this — it never re-verifies.

**Builder exclusivity:** `pg_advisory_lock(0x4F5254484F4C4F47)`
in `store/postgres.go`. Two builders on the same log is impossible.

**Atomic commit:** leaf mutations + node cache + delta buffer +
cursor advance happen in ONE Serializable Postgres transaction.

**Gapless sequence:** Tessera owns sequence allocation. Admission
obtains the seq from `tessera.AppendLeaf` (antispam dedup keeps it
idempotent under concurrent admission of identical content) and
inserts the assigned value into `entry_index`. Builder processes
entries in seq order via the cursor reader.

**Decision 47 (locality):** `PostgresEntryFetcher.Fetch` returns nil
for foreign log DIDs. The builder only processes local entries.

**Decision 51 (evidence cap):** enforced at both
`sdk.envelope.NewEntry` and `api/submission.go` step 6.

**SDK-D9 (cold start):** empty delta buffer = strict OCC.
`DeltaBufferStore.Load` returns empty buffer on first boot.

**Live difficulty:** `DifficultyController.CurrentDifficulty()` read
atomically per-request.

**Auth contract:** invalid Bearer token → 401 (never silent Mode B
fallthrough).

**WAL durability:** `wal.Submit` blocks until fsync. HTTP 202 is
returned only after the bytes are on disk.

**Static-verifiability of the redirect:** the bytestore object key
is `<prefix>/<seq:016x>/<hash_hex>`. Presigned URLs contain the
hash hex in the path so consumers can verify a 302 destination
matches the promised bytes before fetching.

**Divergence is fatal:** if the integrity Detector finds Tessera and
WAL disagree on `HashAt(seq)`, the supervisor in
`cmd/operator/main.go` panics with `operator FATAL: integrity
detector: %w`. The only deliberate panic in the codebase.

## Kubernetes

- **Replicas:** exactly 1 per log DID. Advisory lock prevents
  concurrent builders.
- **Readiness:** `GET /readyz` — atomic bool, 503 during shutdown.
- **Liveness:** `GET /healthz` — 200 while process runs.
- **Graceful shutdown:** `SIGTERM` → ctx cancel → server.Shutdown
  drains in-flight requests → builder loop exits → shipper drains
  in-flight uploads → WAL committer drains group-commit batch →
  process exits 0. Set `terminationGracePeriodSeconds: 60`.
- **Volumes:** distinct PersistentVolumeClaims for
  `OPERATOR_WAL_PATH`, `OPERATOR_TESSERA_STORAGE_DIR`,
  `OPERATOR_TESSERA_ANTISPAM_PATH` so corruption in one doesn't
  force discarding the others. See
  [`docs/RUNBOOK.md`](docs/RUNBOOK.md).
- **Secrets:** inject `OPERATOR_DATABASE_URL` and any bytestore
  credentials via Kubernetes Secret / SOPS.
- **Resources:** builder loop is CPU-bound during batch processing.
  500m CPU / 512Mi minimum.

## Protocol decisions enforced

| Decision | Enforcement point |
|----------|-------------------|
| SDK-D1 | Log_Time assignment at admission step 9 |
| SDK-D5 | Signature verification at admission step 4 |
| SDK-D7 | SchemaResolver → commutative boolean (OCC mode) |
| SDK-D9 | Empty delta buffer → strict OCC |
| SDK-D11 | Entry size check at admission step 5 |
| SDK-D13 | Batch proof canonical ordering in `proofs.go` |
| Decision 41 | Witness rotation dual-sign detection |
| Decision 44 | Anchor entries as standard commentary |
| Decision 47 | Locality check in `PostgresEntryFetcher.Fetch` |
| Decision 49 | Protocol version preamble check at admission step 1 |
| Decision 50 | Log_Time outside canonical hash |
| Decision 51 | Evidence_Pointers cap at admission step 6 + SDK NewEntry |

## License

Proprietary. ClearCompass AI.
