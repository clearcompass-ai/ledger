# Operator architecture (Phase 3 + 4)

This document is the orientation map for the Phase 3+4 architecture
— the WAL-first admission model, hexagonal bytestore, asynchronous
Shipper, integrity Detector, and 302-redirect read path. For
historical context (the v1 admission model and the migration to
Tessera-aligned vocabulary) see `MIGRATION.md`.

## End-to-end flow

```
                      ┌────────────────────┐
                      │   submitter        │
                      └─────────┬──────────┘
                                │ POST /v1/entries (canonical bytes)
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │                    admission pipeline                      │
   │                                                            │
   │   preamble → Validate → destination → freshness → sig      │
   │      → schema dispatch → size → evidence → mode (A/B)      │
   │      → canonical hash → early-dup check → log_time         │
   │      → wal.Submit (durable on local NVMe; group commit)    │
   │      → tessera AppendLeaf (sequence assignment, dedup)     │
   │      → Postgres entry_index INSERT (sidecar metadata)      │
   │      → wal.Sequence (state: pending → sequenced)           │
   │      → 202 with sequence_number + canonical_hash           │
   └────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼─────────────────────────┐
        ▼                       ▼                         ▼
  local NVMe (WAL)         Tessera tiles +         Postgres
  ─────────────────        antispam dedup         entry_index
  pending / sequenced /    (tile reader gives     (canonical_hash,
  shipped / manual         HashAt for             log_time, signer,
                           Detector)              indexed fields)
        │
        │  Shipper goroutine (async, bounded concurrency)
        │   - reads sequenced entries from WAL
        │   - bytestore.WriteEntry (GCS / S3)
        │   - wal.MarkShipped
        │   - hwmAdvancer: advance HWM through contiguous run
        ▼
  ┌──────────────────┐
  │  bytestore       │   GCS (production) or S3-compatible
  │  Backend         │   (RustFS / R2 / AWS S3)
  └──────────────────┘
        │
        │ GET /v1/entries/{seq}/raw
        │   - Postgres entry_index → canonical_hash
        │   - WAL probe meta state
        │      pending/sequenced/manual → 200 inline (X-Source: wal)
        │      shipped                  → 302 + presigned URL
        │      WAL miss (post-GC)       → 302 + presigned URL
        ▼
   ┌────────────────────┐
   │   consumer / verifier
   └────────────────────┘
```

## Components

### WAL (`wal/`)
Durable bytes-of-record store backed by BadgerDB. Submit blocks
until wire bytes are fsync'd to disk. Group commit amortizes the
fsync cost across concurrent admissions. Tests use
`OpenInMemory` + `DisableSync: true`; production opens an on-disk
path with default sync.

State machine for each entry:
- `Pending` — wal.Submit completed; tessera AppendLeaf has not.
- `Sequenced` — Tessera assigned a seq; bytes still in WAL.
- `Shipped` — Shipper migrated bytes to bytestore; WAL keeps a copy
  until the GC retention buffer.
- `Manual` — Shipper exhausted retries; bytes stay in WAL pending
  operator review.

### Bytestore (`bytestore/`)
Hexagonal `Backend = Reader + Writer + Presigner`. Two production
adapters: `GCS` (workload identity / ADC, V4 signing) and `S3` (AWS
SDK v2; the same wire fits RustFS / R2 / AWS S3). Object
keys use a hash-suffixed layout — `<prefix>/<seq:016x>/<hash_hex>`
— so a presigned URL can be statically verified to point at the
promised bytes before the consumer fetches.

`Memory` is a test-only `Store` (no Presigner). The factory refuses
to construct a memory backend through the production
`NewFromConfig` entry point.

### Composite byte reader (`store/fetcher.go`)
`CompositeByteReader` satisfies `bytestore.Reader` by routing reads
to the WAL first and falling back to bytestore on `wal.ErrNotFound`.
This is the single coordination point for the read path: existing
fetchers (`PostgresEntryFetcher`, `PostgresQueryAPI`,
`PostgresCommitmentFetcher`) take a `bytestore.Reader` and need no
change when the composite is wired in at the composition root.

### Shipper (`shipper/`)
Async migrator: WAL `Sequenced` → bytestore upload → WAL `Shipped`
→ HWM advance through contiguous runs. Single hwmAdvancer goroutine
holds out-of-order completions in an in-memory above-HWM set until
their predecessor lands. Failed uploads enter exponential backoff
and, after `MaxAttempts`, transition to `Manual`.

### Integrity (`integrity/`)
- `Reasserter` — boot-time idempotent re-Add of WAL inflight entries
  to Tessera. Antispam dedup makes this safe.
- `Verifier` — point-in-time `WAL.HashAt` vs `Tessera.HashAt` check.
- `Detector.Reconcile(ctx)` — boot reconciliation. Permissive: per-
  entry failures are logged and reconciliation continues.
- `Detector.Loop(ctx)` — periodic sample-verify. Returns
  `ErrDiverged` on first mismatch.

The composition root in `cmd/operator/main.go` reads from a fatal
channel and **panics** on `ErrDiverged` with the wrap shape
`operator FATAL: integrity detector: <ErrDiverged...>`. CT logs
cannot tolerate divergent state; non-zero exit is the only correct
response. Orchestrators (k8s, systemd, bare metal) decide what
happens next.

### 302 redirect read path (`api/entries_read.go`)
`GET /v1/entries/{seq}/raw` consults Postgres `entry_index` for the
canonical hash, then probes the WAL meta state. Sequenced/manual/
pending entries serve inline (200 + X-Source: wal) from the WAL.
Shipped entries (and post-GC misses) return 302 with a presigned
URL. The hash hex is part of the URL path; consumers verify the
URL shape before fetching, then verify byte content against the
hash on receipt.

## Wire format invariant (v7.75)

Under v7.75 the wire bytes ARE the canonical bytes. The multi-sig
section is appended INSIDE `envelope.Serialize`'s output — there is
no separate signature-append step. Implications:

- `envelope.Serialize(entry)` is the byte sequence that:
  - admission persists in the WAL,
  - the Shipper uploads to the bytestore,
  - the read path returns inline OR via 302.
- `envelope.EntryIdentity(entry)` is `SHA-256(envelope.Serialize(entry))`.
- The bytestore is opaque w.r.t. envelope structure.
- Consumers feed `Deserialize` the wire bytes and recover signatures
  from `entry.Signatures`.

## Sequencing

Tessera is the sole sequence authority. The Phase 1/2 Postgres
`entry_sequence` SEQUENCE was dropped in commit 10. Admission flow:
WAL Submit → Tessera AppendLeaf (assigns seq, dedup via antispam)
→ Postgres `entry_index` INSERT with the assigned seq → WAL
Sequence transition. A failure between any two of these stages is
recoverable via the integrity Reasserter at next boot.

## What's intentionally NOT in this architecture

- **No Postgres sequence allocator** — Tessera owns this.
- **No `builder_queue` / `entry_queue` table** — the entry_index
  IS the queue (the cursor reader tails it).
- **No proxy-mode read path for shipped entries** — 302 cuts the
  operator out of the byte path; egress is consumer-direct.
- **No automatic ErrDiverged recovery** — divergence is a panic.
  Recovery is a manual operator decision, not an automated retry.

For day-2 operational guidance, see `RUNBOOK.md`.
