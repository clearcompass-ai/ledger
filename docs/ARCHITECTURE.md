# Operator architecture

Orientation map for the operator's runtime architecture: the
WAL-first admission model with SCT/MMD return shape, asynchronous
Sequencer + Shipper pipeline, hexagonal bytestore, integrity
Detector, and 302-redirect read path.

## Admission contract: SCT/MMD

POST /v1/entries and POST /v2/entries differ only in their return
shape — both run identical fast-path validation (preamble +
deserialize + Validate + NFC + destination binding + freshness +
signature verification + schema dispatch + size + evidence cap +
mode dispatch + canonical hash + early-dup check + log_time
assignment + Mode A credit deduction + WAL.Submit). What happens
afterwards is the only difference:

- **POST /v2/entries** returns a `SignedCertificateTimestamp`
  (SCT) immediately after WAL fsync. The SCT is a cryptographic
  promise: "I have your bytes, durable, and I will sequence them
  within MMD." Signed with the operator's secp256k1 ECDSA key
  (the same key whose did:key:z… is `cfg.OperatorDID`).
  RFC-6962-aligned semantics, deterministic length-prefixed
  binary signing payload (see `api/sct.go` for the wire format).

- **POST /v1/entries** is a polling facade. The handler waits on
  WAL.MetaState until the background Sequencer transitions the
  entry to StateSequenced or `OPERATOR_V1_TIMEOUT` (default 30s)
  elapses. On success: legacy `{sequence_number, canonical_hash,
  log_time}` JSON. On timeout: HTTP 504 with structured
  `sequencer_lag` payload pointing at GET /v1/entries/hash/{hash}
  for follow-up. Strictly bound to `r.Context().Done()` so client
  TCP disconnect exits within one poll tick.

The Maximum Merge Delay (`OPERATOR_MMD`, default 24h) is the SLA
on Sequencer drain latency. Consumers verify it programmatically
via GET /v1/admission/mmd before trusting an SCT.

### Defenses preserved in the fast path

The asynchronous architecture does NOT weaken replay defenses:

- **Step 3c freshness check** (wall-clock window vs the entry's
  EventTime) is the late-replay defense. A stamp held for weeks
  before submission gets rejected at admission with HTTP 422
  BEFORE WAL fsync — the attacker never gets an SCT.
- **Step 8a early-duplicate check** is the immediate-replay
  defense. Spamming the same canonical bytes returns HTTP 409
  on the second-and-later request without burning WAL slots.

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

### Sequencer (`sequencer/`)
Async pipeline worker: WAL `Pending` → tessera.AppendLeaf
(antispam-idempotent) → Postgres `entry_index` INSERT inside
`WithReadCommittedTx` → WAL `Sequenced`. Drains every
`OPERATOR_SEQUENCER_INTERVAL` (default 1s); first drain on Run
start subsumes boot recovery, replacing the deleted
`integrity.Reasserter`. Per-entry retry counter; after
`MaxAttempts` (default 10) the entry transitions to `Manual`.

The Sequencer is the SOLE writer to `entry_index` — under SCT/MMD
the v1 facade and v2 SCT handlers both stop INSERTing inline.
This eliminates the `UNIQUE(canonical_hash)` race that two
synchronous writers would have created.

### Shipper (`shipper/`)
Async migrator: WAL `Sequenced` → bytestore upload → WAL `Shipped`
→ HWM advance through contiguous runs. Single hwmAdvancer goroutine
holds out-of-order completions in an in-memory above-HWM set until
their predecessor lands. Failed uploads enter exponential backoff
and, after `MaxAttempts`, transition to `Manual`.

### Integrity (`integrity/`)
Read-only verifier surface (post-SCT/MMD cleanup; the Reasserter
package was deleted because the Sequencer now owns boot recovery):

- `Verifier` — point-in-time `WAL.HashAt` vs `Tessera.HashAt`
  check.
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

Tessera is the sole sequence authority — there is no Postgres
SEQUENCE backing entry numbers. Admission flow: WAL Submit →
Tessera AppendLeaf (assigns seq, dedup via antispam) → Postgres
`entry_index` INSERT with the assigned seq → WAL Sequence
transition. A failure between any two of these stages is
sequence allocator. Admission flow:
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
