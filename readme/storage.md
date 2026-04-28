# Storage and the builder loop

The operator has four distinct storage media on the hot path:

1. **WAL** — local BadgerDB at `OPERATOR_WAL_PATH`. Bytes-of-record
   between `wal.Submit` and `MarkShipped`. Source of durability for the
   202 promise.
2. **Tessera POSIX storage** — tile data + checkpoint at
   `OPERATOR_TESSERA_STORAGE_DIR`. Plus `OPERATOR_TESSERA_ANTISPAM_PATH`
   for dedup state.
3. **Postgres** — the entry index, SMT state, credits, witness
   sets, and commitment indices. Authoritative for everything other
   than entry bytes.
4. **Bytestore (GCS or S3)** — long-term entry-byte storage after
   the Shipper has migrated them out of the WAL.

This page covers how each stores what, plus the builder loop that
threads them together.

## WAL states

`wal/meta.go` defines four states each entry passes through:

| State | Meaning |
|---|---|
| `StatePending` | WAL has the bytes durably; `tessera.AppendLeaf` not yet called |
| `StateSequenced` | Tessera assigned a sequence; entry is integrated into the log |
| `StateShipped` | Shipper completed the bytestore upload; bytes durable in GCS/S3 |
| `StateManual` | Shipper retried N times and gave up; bytes still live in the WAL pending operator intervention |

Reads of `/v1/entries/{seq}/raw` consult `CompositeByteReader`
(`store/composite_byte_reader.go`): WAL first for `Pending` /
`Sequenced` / `Manual`, then bytestore fallback. After GC has cleared
shipped entries from the WAL, reads go straight to bytestore via the
302 redirect.

## Bytestore object layout

Object key shape: `<prefix>/<seq:016x>/<hash_hex>`.

The hash suffix is the static-verifiability invariant the 302
redirect path relies on: a consumer can verify that a presigned URL
points at the bytes the operator promised before fetching, and verify
the fetched bytes hash to the promised value before trusting them.

`<prefix>` defaults to `entries` and is configurable via
`OPERATOR_BYTE_STORE_PREFIX` — useful for sharing one bucket across
multiple operator instances.

## Postgres schema

The schema is a single idempotent DDL list in `store/postgres.go`,
applied by `RunMigrations` at startup. There are no versioned
migrations.

### Entry index

| Table | Primary key | Purpose |
|---|---|---|
| `entry_index` | `sequence_number BIGINT` | Sidecar metadata: canonical hash, log time, signer DID, indexed header fields. **Does not store canonical bytes** — those live in the WAL or bytestore. |

Indexes (all conditional on the column being non-null where
applicable): `idx_signer_did`, `idx_target_root`, `idx_cosignature_of`,
`idx_schema_ref`.

The Tessera embedded library is the sole sequence authority. There
is no Postgres `entry_sequence` SEQUENCE — admission obtains the seq
from `tessera.AppendLeaf` and inserts the assigned value.

### SMT state

| Table | Primary key | Purpose |
|---|---|---|
| `smt_leaves` | `leaf_key BYTEA` | Per-leaf state: origin tip + authority tip |
| `smt_nodes` | `path_key BYTEA` | Internal node hashes with depth tracking |

### Credits and sessions

| Table | Primary key | Purpose |
|---|---|---|
| `credits` | `exchange_did TEXT` | Mode A write credit balances |
| `sessions` | `token TEXT` | Authenticated exchange Bearer tokens |

### Tree heads

| Table | Primary key | Purpose |
|---|---|---|
| `tree_heads` | `(tree_size, hash_algo)` | One row per attestation |
| `tree_head_sigs` | `(tree_size, hash_algo, signer, sig_algo)` | Cosigner signatures, FK to `tree_heads` |

### Builder state

| Table | Primary key | Purpose |
|---|---|---|
| `delta_window_buffers` | `leaf_key BYTEA` | Per-leaf OCC authority tip history |
| `builder_cursor` | `id` (singleton, fixed at 1) | Highest sequence number the builder has fully processed |

The cursor is the queue. Admission writes only to `entry_index`; the
builder's cursor reader (`builder/cursor_reader.go`) tails
`entry_index WHERE sequence_number > cursor` and advances
`builder_cursor` in its atomic commit.

### Witness and equivocation

| Table | Primary key | Purpose |
|---|---|---|
| `witness_sets` | `version SERIAL` | Witness key set rotation history |
| `equivocation_proofs` | `id SERIAL` | Detected tree-head fork evidence |

### Commitment indices

| Table | Primary key | Purpose |
|---|---|---|
| `derivation_commitments` | `id SERIAL` | Fraud-proof lookup index. Post-commit persistence; reconstructable from entries on crash. |
| `commitment_split_id` | `sequence_number` (FK to `entry_index`) | Maps the 32-byte SplitID embedded in pre-grant and escrow-split commitments to the entry's sequence number. `(schema_id, split_id)` is intentionally non-unique to preserve dealer-equivocation evidence. |
| `commitment_equivocation_proofs` | `id SERIAL` | One row per `(schema_id, split_id)` incident. Append-only — rows are never deleted. |

## Builder loop

`builder/loop.go` is one goroutine guarded by
`pg_advisory_lock(0x4F5254484F4C4F47)`. Each cycle does:

1. **Cursor read** — `SELECT … FROM entry_index WHERE
   sequence_number > cursor LIMIT batch` via the cursor reader.
2. **Fetch entries** — `PostgresEntryFetcher` reads bytes via the
   composite reader (WAL first, bytestore fallback) and metadata
   from `entry_index`.
3. **Split** — `EntryWithMetadata` → `[]*envelope.Entry` +
   `[]LogPosition`.
4. **`ProcessBatch`** — SDK deterministic algorithm, run against an
   in-memory overlay SMT. If validation fails, the overlay is
   discarded and Postgres is untouched.
5. **Atomic commit** — single Serializable Postgres transaction:
   - SMT leaf mutations (`PostgresLeafStore.SetTx`)
   - SMT node cache updates (`PostgresNodeCache.SetWithDepthTx`)
   - Delta buffer (`DeltaBufferStore.SaveTx`)
   - Cursor advance (`SequenceCursor.AdvanceTx`)
6. **Post-commit Tessera append** — for each entry,
   `merkle.AppendLeaf(envelope.EntryIdentity(entry))`. Idempotent
   via antispam: same identity always returns the same seq. Crash
   between commit and append is safe; integrity reconcile re-Adds
   on next boot.
7. **Commitment publish** — `commitPub.MaybePublish` with
   frequency control.
8. **Witness cosignatures** — `merkle.Head()` →
   `witness.RequestCosignatures` if a cosigner is wired.

`builder/loop.go:411-434` is the post-commit append. The atomic state
in Postgres is the source of truth — Tessera and witness cosignatures
are best-effort restartable extensions.

## Crash recovery

- **Admission crash between WAL submit and Tessera append:**
  integrity `Reconcile` at next boot re-`AppendLeaf`s every WAL
  inflight entry. Antispam dedup returns the prior seq for any that
  already integrated.
- **Admission crash between Tessera append and Postgres INSERT:**
  same path — `Reconcile` re-Adds and the WAL meta picks up the
  same seq. The entry waits for the next admission attempt to
  re-INSERT into `entry_index` (or arrives via builder fetch if
  another writer admitted it first; the canonical_hash UNIQUE on
  `entry_index` resolves the race).
- **Builder crash mid-batch:** the atomic commit wraps everything;
  no partial state. Post-commit Tessera append is replayed
  idempotently on restart.
- **Shipper crash mid-upload:** WAL state is still `Sequenced`;
  Shipper picks the entry up again on next scan. Bytestore
  uploads use deterministic keys, so re-upload is safe.

## SDK interfaces implemented

| SDK interface | Operator implementation | File |
|---|---|---|
| `types.EntryFetcher` | `PostgresEntryFetcher` | `store/entries.go` |
| `smt.LeafStore` | `PostgresLeafStore` (+ `SetTx`) | `store/smt_state.go` |
| `smt.NodeCache` | `PostgresNodeCache` (+ `SetWithDepthTx`) | `store/smt_state.go` |
| `builder.MerkleAppender` | `tessera.TesseraAdapter` | `tessera/proof_adapter.go` |
| `log.OperatorQueryAPI` | `PostgresQueryAPI` | `store/indexes/query_api.go` |
