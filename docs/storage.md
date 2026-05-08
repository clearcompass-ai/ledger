# Storage

The ledger has four distinct storage media. Owns the WAL state
machine, the gossipstore keyspace, the Postgres schema, the
bytestore object layout, and volume failure semantics. Routes that
read these are in [api.md](api.md); env vars driving the paths in
[configuration.md](configuration.md).

## Storage media

| Medium | Path / DSN | Owns | File of record |
|---|---|---|---|
| WAL (Badger) | `LEDGER_WAL_PATH` | Bytes-of-record between `wal.Submit` and `MarkShipped`; admission durability for the 202 promise | `wal/keyspace.go`, `wal/committer.go` |
| Tessera POSIX | `LEDGER_TESSERA_STORAGE_DIR` + `LEDGER_TESSERA_ANTISPAM_PATH` | Tile data + checkpoint + antispam dedup map | `tessera/embedded_appender.go` |
| Postgres | `LEDGER_DATABASE_URL` | `entry_index`, `commitment_split_id`, `sessions`, `credits`, `tree_heads`, `tree_head_sigs`, `derivation_commitments`, `equivocation_proofs`, witness keys, builder cursor, SMT state | `store/*.go` |
| Bytestore (GCS or S3) | `LEDGER_BYTE_STORE_*` | Long-term entry-byte storage after the Shipper migrates them out of the WAL | `bytestore/*.go` |
| Gossipstore (Badger, co-tenant of WAL DB) | same Badger handle, distinct prefix `0x07` | Gossip events + read projections | `gossipstore/keyspace.go` |

## WAL state machine

`wal/meta.go:30+`:

```
StateUnknown = 0  // never written; reading 0 = decode bug
StatePending = 1  // bytes durable; tessera.Add not yet called
StateSequenced = 2 // tessera assigned a sequence number
StateShipped = 3  // bytestore upload complete; WAL bytes safe to GC
StateManual = 4   // sequencer gave up after MaxAttempts
```

Transitions:

```
            wal.Submit
               │
               ▼
         ┌──────────┐  sequencer.Sequence(seq)  ┌─────────────┐
         │ Pending  │─────────────────────────▶│  Sequenced  │
         └────┬─────┘                           └──────┬──────┘
              │                                        │
              │ MaxAttempts exhausted   shipper.MarkShipped
              ▼                                        ▼
         ┌──────────┐                           ┌─────────────┐
         │  Manual  │                           │   Shipped   │
         └──────────┘                           └─────────────┘
```

`wal.Meta` (29 bytes on disk —
`wal/meta.go:82 metaEncodedSize = 1 + 8 + 4 + 8 + 8`):

```
State            uint8   1 byte
Sequence         uint64  8 bytes
Attempts         uint32  4 bytes
LastErrTs        int64   8 bytes (unix nanos)
LogTimeMicros    int64   8 bytes (unix micros — pinned at first Submit)
                         ─────
                         29 bytes total
```

`LogTimeMicros` is the load-bearing field for deterministic
idempotency: a byte-identical resubmission re-issues the SAME SCT
because the `log_time` signed-over field is the persisted value,
not a fresh one. Pinned by
`api/submission_test.go::TestV1Handler_SemanticIdempotency`.

## Gossipstore keyspace

Co-tenants the WAL's Badger handle under root prefix `0x07`. Sub-
prefix layout (`gossipstore/keyspace.go:8–24`):

| Prefix | Layout | Purpose |
|---|---|---|
| `0x07 0x01 <eventID:32>` | → SignedEvent JSON | Event by ID (point read) |
| `0x07 0x02 <olen:2><orig><lamport:8>` | → eventID | Per-originator chain (ordered) |
| `0x07 0x03 <klen:2><kind><lamport:8><olen:2><orig>` | → eventID | Per-kind global index |
| `0x07 0x04 <olen:2><orig>` | → headRecord (40 bytes) | Per-originator chain head |
| `0x07 0x05 <olen:2><orig><lamport:8>` | → eventID | Per-originator STH index |
| `0x07 0x06` | → statsCounter (16 bytes) | Singleton stats |
| `0x07 0x07 <olen:2><orig>` | → empty | Originator existence marker |
| `0x07 0x09 <binding:32><eventID:32>` | → empty | Binding inverted index — powers `/v1/gossip/by-binding` |
| `0x07 0x0A <slen:2><schema><spid:32><seq:8>` | → SplitIDIndexEntry JSON | Splitid detection trigger; EquivocationScanner subscribes |
| `0x07 0x0B <binding:32>` | → SignedEvent JSON | Verified equivocation projection |
| `0x07 0x0C <slen:2><schema><spid:32><seq:8>` | → EntryLookupIndexEntry JSON | Pure-CQRS read backing for `/v1/commitments/by-split-id` |
| `0x07 0x0D` | → uint64 BE | Splitid replay HWM (boot back-population cursor) |

Big-endian integer encoding throughout (Badger sorts keys
lexicographically — BE makes numeric ranges contiguous).

`MaxOriginatorLen = 1024`, `MaxKindLen = 64`
(`gossipstore/keyspace.go:191, 194`).

### Why the projections matter

`0x0A` (splitid index) is the detection trigger. The
`gossipnet.EquivocationScanner` subscribes to writes on this
prefix (`badger.DB.Subscribe`); when it sees ≥ 2 entries at the
same `(schema_id, split_id)` it constructs a verified
`EntryCommitmentEquivocationFinding`, signs it, appends to the
local gossip Store, and broadcasts via the BufferedSink.

`0x0B` (equivocation projection) is keyed by content-derived
binding. Powers `/v1/gossip/by-binding/{hash}` zero-trust audit
pulls. Producer + consumer both compute the binding via the SDK's
`findings.EntryCommitmentBinding(schemaID, splitID)` — drift-free
by construction.

`0x0C` (entry lookup) backs `/v1/commitments/by-split-id`. Holds
the canonical wire bytes + log time + log DID per admission. Read
path serves verbatim — zero Postgres for this endpoint.

`0x0D` (replay HWM) is the singleton high-water-mark used by
`sequencer.Replayer` on boot to back-populate 0x0A + 0x0C from
Postgres above the persisted seq. Monotonic; backwards `Set` is a
silent no-op (`gossipstore/projections.go::SetSplitIDReplayHWM`,
pinned by
`gossipstore/replay_hwm_test.go::TestSplitIDReplayHWM_BackwardsSetIsNoOp`).

## Postgres schema

Schema lives in `store/postgres.go::RunMigrations` (the doc-of-
record for table definitions).  Every `CREATE TABLE IF NOT EXISTS`
in the function:

| Table | store/postgres.go line | Owned by | Purpose |
|---|---|---|---|
| `entry_index` | 203 | sequencer + queries | sequence_number → canonical_hash + signer_did + log_time + control-header field projections |
| `smt_leaves` | 218 | builder | SMT leaf data (OriginTip + AuthorityTip) |
| `smt_nodes` | 224 | builder | SMT internal node cache |
| `credits` | 232 | submission handler | Mode A fiat write-credit accounting |
| `tree_heads` | 241 | witness flow | Cosigned tree heads |
| `tree_head_sigs` | 248 | witness flow | Per-witness signatures over tree heads |
| `delta_window_buffers` | 260 | builder | OCC commit window state |
| `builder_cursor` | 281 | builder | Last-published commitment cursor |
| `witness_sets` | 295 | witness flow | Active witness DIDs + key bytes |
| `equivocation_proofs` | 304 | gossipnet | Verified equivocation findings, append-only |
| `sessions` | 313 | auth middleware | Bearer-token → exchange_did mapping |
| `derivation_commitments` | 325 | builder | SMT batch derivation commitments (range_start_seq..range_end_seq) |
| `commitment_split_id` | 356 | sequencer | Secondary index: (schema_id, split_id) → sequence_number |

The Postgres advisory lock at boot is
`store/postgres.go:400 BuilderLockID = 0x4F5254484F4C4F47`
(`pg_advisory_lock(BuilderLockID)` at line 458) — guarantees a
single builder process per log DID.

Append-only tables (mutation revoked at the role level via
`deploy/sql/grants.sql`):
`entry_index`, `commitment_split_id`, `derivation_commitments`,
`tree_heads`, `tree_head_sigs`, `equivocation_proofs`. See
[operations.md](operations.md) F2 for the grant flow.

## Bytestore object layout

`bytestore/{gcs,s3,memory}.go`:

```
<prefix>/<seq:016x>/<hash_hex>
```

`<prefix>` = `LEDGER_BYTE_STORE_PREFIX` (default `entries`).
`<seq>` is zero-padded to 16 hex characters so lexicographic
ordering matches sequence ordering.
`<hash_hex>` is the canonical hash, 64 hex chars.

The `/v1/entries/{sequence}/raw` redirect 302's to a presigned URL
containing the hash hex in the path so consumers verify the
destination matches the promised bytes before fetching.

## Volume failure semantics

| Volume | What's lost | Recovery |
|---|---|---|
| `LEDGER_WAL_PATH` (post-Submit, pre-Ship) | Wire bytes for in-flight entries; orphan `entry_index` rows | Reads 404 or post-GC redirect to a 404. Sequencer's boot replay catches up via 0x0D HWM cursor |
| `LEDGER_TESSERA_ANTISPAM_PATH` | Hash → seq dedup map | Tessera re-`Add` becomes non-idempotent; boot reconciliation could integrate same entry under fresh seq |
| `LEDGER_TESSERA_STORAGE_DIR` | Tile data + checkpoint | Tessera cannot reconstruct the tree; tree-head signing offline. Use `cmd/rebuild-tiles` |
| Postgres | `entry_index`, etc. | Full ledger outage. Restore from backup |
| Bytestore | Shipped entry bytes | `/raw` redirect targets miss; reads return 404 from the bucket |

Co-tenanting WAL + gossipstore on the same Badger handle means
losing `LEDGER_WAL_PATH` also wipes the 0x0A–0x0D projections.
The sequencer's boot replayer re-builds 0x0A + 0x0C from Postgres
on the next boot (see [architecture.md](architecture.md)
`### Boot replay`).
