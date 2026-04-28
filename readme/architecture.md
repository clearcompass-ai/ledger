# Architecture

End-to-end flow of a single entry through the operator, the three-service
trust split it sits inside, and the load-bearing components inside the
process. For per-component deep dives see
[`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## End-to-end flow

```
                   ┌─────────────┐
                   │   Clients   │
                   └──────┬──────┘
                          │ POST /v1/entries (canonical bytes)
                          ▼
            ┌─────────────────────────────┐
            │  HTTP middleware            │
            │  SizeLimit → Auth → handler │
            └────────────┬────────────────┘
                         │
                         ▼
            ┌─────────────────────────────┐
            │  Admission pipeline         │
            │  14 numbered steps          │  api/submission.go
            └────────────┬────────────────┘
                         │ wal.Submit (durable on local NVMe, fsynced)
                         ▼
              ┌──────────────────────┐
              │   WAL (BadgerDB)     │  states: pending → sequenced
              └──────────┬───────────┘                  → shipped
                         │                              → manual
                         │ tessera.AppendLeaf
                         │   (sequence assignment + antispam dedup)
                         ▼
              ┌──────────────────────┐    ┌──────────────────────┐
              │  Embedded Tessera    │    │  Postgres            │
              │  POSIX driver:       │    │  entry_index INSERT  │
              │  tiles + checkpoint  │    │  (sidecar metadata)  │
              └──────────┬───────────┘    └──────────────────────┘
                         │ wal.Sequence (pending → sequenced)
                         │
                         │ Shipper goroutine (async)
                         ▼
              ┌──────────────────────┐
              │  Bytestore           │ ← GCS or S3 (factory selects)
              │  <prefix>/<seq>/<h>  │
              └──────────────────────┘
                         │
                         │ MarkShipped (sequenced → shipped)
                         ▼
                       reads:
                         /v1/entries/{seq}     (JSON metadata)
                         /v1/entries/{seq}/raw (200 inline OR 302 redirect)
```

The 202 ACK from `POST /v1/entries` requires three things to be durable:
WAL on disk, a Tessera-assigned sequence number, and the Postgres
`entry_index` row. The shipper migrating bytes from WAL to bytestore
happens asynchronously after the response.

## Three-service trust split

```
Operator:        Postgres + Tessera storage. No artifact access. No keys.
Artifact store:  GCS/S3/IPFS credentials. No decryption keys. No log access.
Exchange:        HSM keys + escrow nodes. No storage credentials. No log admin.
```

The CID is the only identifier shared between the operator and the
artifact store. The CID lives in the entry's Domain Payload (opaque to
the operator); the operator never reads it.

## Components inside the process

The operator is one Go binary. The major subsystems wired in
`cmd/operator/main.go`:

| Subsystem | Package | Purpose |
|---|---|---|
| Admission pipeline | `api` | HTTP entry submission, 14-step validation |
| WAL | `wal` | BadgerDB-backed durability before HTTP 202 |
| Embedded Tessera | `tessera` | In-process upstream Tessera over a POSIX driver |
| Bytestore | `bytestore` | Hexagonal Reader/Writer/Presigner over GCS or S3 |
| Builder loop | `builder` | Single-goroutine deterministic state machine |
| Shipper | `shipper` | WAL → bytestore migration, advances HWM |
| Integrity Detector | `integrity` | Boot reconcile + periodic WAL ↔ Tessera audit |
| Anchor publisher | `anchor` | Periodic commentary anchoring tree heads |
| Witness | `witness` | Equivocation monitor + cosigner serve side |
| Postgres stores | `store`, `store/indexes` | Entry index, SMT, credits, queries |

## Embedded Tessera, not a separate process

The operator runs upstream Tessera in-process via
`github.com/transparency-dev/tessera` over a POSIX storage driver
(`tessera.NewEmbeddedAppender` in `cmd/operator/main.go`). There is no
HTTP-fronted Tessera personality service.

- `tessera/embedded_appender.go` constructs the in-process appender.
- `tessera/posix_tile_backend.go` reads tiles directly off the same
  directory Tessera writes to.
- `tessera/proof_adapter.go` wraps it as the `MerkleAppender` interface
  the builder consumes.

Antispam (deduplication by entry identity) is BadgerDB-backed at
`OPERATOR_TESSERA_ANTISPAM_PATH`. This is the property that makes
re-`AppendLeaf` of the same identity return the previously assigned
sequence number — load-bearing for both admission step 11 and the
post-commit append in `builder/loop.go`.

## Hexagonal bytestore

Three interfaces in `bytestore/bytestore.go`:

```
Reader     ReadEntry, EntryExists
Writer     WriteEntry, DeleteEntry
Presigner  PresignedURL (used for the /v1/entries/{seq}/raw 302 path)

Store      = Reader + Writer            (test/dev impls)
Backend    = Reader + Writer + Presigner (production impls)
```

`bytestore.NewFromConfig` selects the production adapter from
`OPERATOR_BYTE_STORE_BACKEND`:

- `gcs` — Google Cloud Storage. ADC by default; fake-gcs-server
  reachable via `OPERATOR_BYTE_STORE_GCS_ENDPOINT` +
  `OPERATOR_BYTE_STORE_GCS_ANONYMOUS=true`.
- `s3` — any S3-compatible target (AWS S3, RustFS, R2, MinIO).
  Default credential chain on AWS; static creds + endpoint +
  `OPERATOR_BYTE_STORE_S3_PATH_STYLE=true` for on-prem.
- `memory` — explicitly rejected at the composition root. Tests that
  need an in-memory store call `bytestore.NewMemory` directly.

Object key shape is `<prefix>/<seq:016x>/<hash_hex>`. The hash suffix
makes presigned URLs statically verifiable: a consumer can confirm a
URL points at the bytes the operator promised before fetching.

## Read path

`GET /v1/entries/{seq}/raw` is WAL-aware (`api/entries_read.go`):

- Pending / sequenced / manual entries → 200 inline,
  `X-Source: wal`, body is the wire bytes.
- Shipped entries (and post-GC misses) → 302 + presigned bytestore
  URL, `X-Source: bytestore`. Consumers MUST verify the URL contains
  the hash hex and the fetched bytes hash to the promised value.

`GET /v1/entries/{seq}` (JSON metadata) is unchanged across states.

## Single-goroutine builder

The builder is a single goroutine guarded by a Postgres advisory lock
(`pg_advisory_lock(0x4F5254484F4C4F47)` in `store/postgres.go`). Two
builders on the same log would diverge non-deterministically; the lock
makes that structurally impossible.

Each cycle reads admitted entries via the `entry_index` cursor,
calls SDK `ProcessBatch`, commits SMT mutations + delta buffer +
cursor advance in one Serializable Postgres transaction, then
post-commit appends each identity hash to Tessera. See
[readme/storage.md](storage.md) for the full step list.

## Integrity detector

`integrity.Detector` runs at boot (`Reconcile`) and on a loop
(`Loop`):

- `Reconcile` re-`AppendLeaf`s every WAL inflight entry to Tessera —
  idempotent because antispam returns the prior seq.
- `Loop` samples sequences below HWM and compares
  `WAL.HashAt(seq) == Tessera.HashAt(seq)`.

On `ErrDiverged` the supervisor in `cmd/operator/main.go` cancels the
context, drains, and panics. This is the one deliberate panic in the
codebase — process exit so the orchestrator restart-loops or
escalates rather than serving corrupt proofs.
