# Changelog

## Phase 3+4 — WAL-first admission, hexagonal bytestore, async Shipper

### Required infra additions before deploy

The operator now consults three on-disk volumes plus one cloud
bucket. All four MUST be provisioned before the v0.4 binary boots:

- **`OPERATOR_WAL_PATH`** — BadgerDB directory for the durable WAL.
  Admission writes wire bytes to disk + fsync before returning HTTP
  202. Sustained throughput is bounded by this volume's IOPS;
  provision NVMe-class storage.
- **`OPERATOR_TESSERA_ANTISPAM_PATH`** — Tessera antispam dedup
  directory. Required for idempotent re-Add under concurrent
  admission of the same content.
- **`OPERATOR_TESSERA_STORAGE_DIR`** — Tessera tile + checkpoint
  storage. Existed in earlier phases.
- **`OPERATOR_BYTE_STORE_BACKEND`** — `gcs` or `s3`. Selects the
  production bytestore adapter; the factory enforces per-backend
  required fields.
- **`OPERATOR_BYTE_STORE_GCS_BUCKET`** / **`_S3_BUCKET`** —
  production bucket name (one or the other, matching the
  selected backend). The WAL → bytestore migration is
  asynchronous; the bucket receives every entry's wire bytes
  shortly after sequencing.

See `docs/CONFIG.md` for the full env-var matrix and
`docs/RUNBOOK.md` for per-volume failure semantics.

### Schema changes

- Dropped: `entry_sequence` Postgres SEQUENCE. Tessera owns
  sequence allocation now; admission obtains the seq from
  `tessera.AppendLeaf` and inserts the assigned value into
  `entry_index`.
- Dropped: `builder_queue` table. The entry_index IS the queue
  under cursor-mode builder reads.
- `entry_index` schema: unchanged at the column level; semantic
  change is that the row is created with a Tessera-assigned seq
  rather than a Postgres-allocated seq.

### Wire format

- Wire bytes ARE the canonical bytes (v7.75). The multi-sig section
  is appended INSIDE `envelope.Serialize`'s output; there is no
  separate signature-append step. Consumers feed the wire bytes
  directly to `envelope.Deserialize`.
- `sig_algorithm_id` end-to-end was dropped (Phase 3) — algo IDs
  live inside the multi-sig section.

### Bytestore

- New hexagonal package `bytestore/`:
  - `Reader`, `Writer`, `Presigner` interfaces.
  - `Store = Reader + Writer` (test/dev impls — `Memory`).
  - `Backend = Store + Presigner` (production impls — `GCS`, `S3`).
- Object key shape: `<prefix>/<seq:016x>/<hash_hex>`. The
  hash-suffix shape is the static-verifiability invariant the 302
  redirect path relies on: a consumer can verify that a presigned
  URL points at the bytes the operator promised before fetching.
- Production selects between two adapters via
  `OPERATOR_BYTE_STORE_BACKEND={gcs,s3}`. The composition root
  passes the config through `bytestore.NewFromConfig`, which
  enforces per-backend required fields and rejects anything else.
  RustFS / R2 / AWS S3 / any S3-compatible target is reachable
  via `s3`.
- `Memory` is test-only and does not satisfy `Backend` (no
  Presigner).

### Read path

- `GET /v1/entries/{seq}/raw` is now WAL-aware:
  - Pending / sequenced / manual entries: 200 inline,
    `X-Source: wal`, body = wire bytes.
  - Shipped entries (and post-GC misses): 302 + presigned URL,
    `X-Source: bytestore`. Consumers MUST verify the URL contains
    the hash hex before fetching, and MUST verify the fetched
    bytes hash to the promised value.
- `GET /v1/entries/{seq}` (JSON metadata) is unchanged.

### Integrity Detector

- New package `integrity/`:
  - `Reasserter` — boot-time idempotent re-Add.
  - `Verifier` — point-in-time `WAL.HashAt` vs `Tessera.HashAt`.
  - `Detector.Reconcile` — boot reconciliation (permissive).
  - `Detector.Loop` — periodic sample-verify (fatal on
    mismatch).
- Composition root in `cmd/operator/main.go` PANICS on
  `ErrDiverged` with wrap `operator FATAL: integrity detector: %w`.
  This is the only deliberate panic in the codebase.

### Migration steps from v0.3 (Tessera-aligned vocabulary)

1. Provision the WAL + antispam volumes alongside the existing
   Tessera storage volume.
2. Provision a bucket on the chosen backend:
   - GCS: grant `storage.objects.{create,get,list}` (+ `delete`
     for soak / conformance) to the operator's ADC identity.
   - S3 / RustFS / R2: `s3:PutObject`, `s3:GetObject`,
     `s3:ListBucket` (+ `s3:DeleteObject` for soak /
     conformance). Prefer IAM roles on AWS; static creds for
     RustFS / on-prem.
3. Drain the v0.3 operator (let `builder_queue` empty and Tessera
   integrate the last entries).
4. Update the manifests to set `OPERATOR_WAL_PATH`,
   `OPERATOR_TESSERA_ANTISPAM_PATH`, `OPERATOR_BYTE_STORE_BACKEND`
   (`gcs` or `s3`), and the matching bucket / S3 family vars.
5. Boot the v0.4 binary. Migrations run automatically; the
   `builder_queue` table is left in place but unused — drop it in
   a follow-up maintenance window.

### Test surface additions

- `tests/e2e_shipper_redirect_test.go` — full WAL → Tessera →
  bytestore → 302 redirect happy path.
- `tests/e2e_graceful_shutdown_test.go` — SIGTERM-mid-shipping +
  restart-resume validation.
- `tests/soak_test.go` (`//go:build soak`) — 1M entries against
  real GCS. Opt-in via `scripts/run-soak.sh`.
- `integrity/divergence_panic_test.go` — locks the
  `ErrDiverged → fatal channel → panic` contract.
- `bytestore/conformance_test.go` — shared Backend conformance
  suite covering Memory + GCS + S3 in container + real modes.
