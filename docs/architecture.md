# Architecture

End-to-end runtime layout of `cmd/ledger`. Every claim resolves to a
specific file:line in the repo.

## Package layout

```
ledger/
├── cmd/
│   ├── ledger/         # main binary; loadConfig + wiring
│   ├── ledger-reader/  # read-only sibling (no admission)
│   ├── submit-stamp/   # CLI: build + sign + POST an entry
│   ├── seed-session/   # dev: create a sessions row
│   └── rebuild-tiles/  # ops: replay entry_index → Tessera
├── api/                  # HTTP handlers (zero pgx imports)
│   ├── server.go # the route table — single source of truth
│   ├── ports.go # interfaces for store/* and middleware
│   ├── errors.go # writeTypedError + OTel counter
│   ├── submission.go # POST /v1/entries
│   ├── batch.go # POST /v1/entries/batch
│   ├── commitments.go # GET /v1/commitments/by-split-id
│   ├── tree.go # GET /v1/tree/{head,inclusion,consistency}
│   ├── proofs.go # GET /v1/smt/{proof,batch_proof,root}
│   ├── queries.go # GET /v1/query/* + /v1/entries-hash
│   ├── entries_read.go # GET /v1/entries/{seq,batch,raw}
│   ├── escrow_override.go # POST /v1/escrow-override
│   ├── smt_read.go # GET /v1/smt/leaf/{key} + POST /v1/smt/leaves
│   ├── derivation_commitments.go # GET /v1/commitments?seq=N
│   ├── mmd.go # GET /v1/admission/mmd
│   ├── sct.go # SCT signing
│   └── middleware/       # Auth (SessionLookup), SizeLimit, etc.
├── apitypes/             # leaf package — value types + sentinels (no pgx)
├── wal/                  # Badger WAL with state machine
├── sequencer/            # WAL drain + Tessera AppendLeaf + projection writes
├── shipper/              # WAL → bytestore migrator
├── store/                # Postgres-backed store types
├── gossipstore/          # Badger-backed gossip Store + read projections
├── gossipnet/            # gossip handler, sink, scanner, override flow
├── tessera/              # embedded Tessera appender
├── bytestore/            # GCS or S3 long-term entry-byte storage
├── admission/            # signature verification, NFC checks
├── integrity/            # boot reconciliation + sample-verify detector
├── lifecycle/            # graceful shutdown
├── witness/              # witness-mode cosign endpoint
├── anchor/               # external anchor publishing
└── builder/              # commitment-publisher loop
```

## Admission flow

POST /v1/entries (`api/submission.go`):

```
HTTP request
   │
   ▼ middleware.SizeLimit(MaxEntrySize+1024)        (server.go:217)
   │
   ▼ middleware.Auth(SessionLookup)                  (server.go:219)
   │  no token → ctx[authenticated]=false (Mode B)
   │  invalid token → 401
   │  valid token → ctx[authenticated]=true, ctx[exchange_did]=...
   │
   ▼ NewSubmissionHandler.prepareSubmission (submission.go:262)
   │   step 1: read raw bytes + protocol-version preamble
   │   step 2: envelope.Deserialize + ValidateAlgorithmID
   │   step 3: entry.Validate + CheckNFC + destination + freshness
   │   step 4: admission.VerifyEntrySignature
   │   step 4b: BLSQuorumVerifier.VerifyEntry (no-op)
   │   step 5-6: size cap + evidence pointers cap
   │   step 7: Mode B stamp verify (unauthenticated only)
   │   step 8: canonical hash + idempotency probe via wal.MetaState
   │
   ├─ idempotent replay → SignSCT with persisted log_time → 202
   │
   ▼ deductCreditModeA via CreditDeducter.Deduct (submission.go:545)
   │  insufficient credits → 402
   │
   ▼ deps.Storage.WAL.Submit(hash, wire, logTimeMicros)  (submission.go:559)
   │  wal.ErrQueueFull → 503 + Retry-After
   │
   ▼ SignSCT → write 202 + JSON SignedCertificateTimestamp
```

The handler **never blocks on Tessera or Postgres**. Sequence-number
assignment + entry_index INSERT + projection writes happen on the
sequencer goroutine (next section).

## Sequencer pipeline

`sequencer/loop.go` drains the WAL on a ticker (`LEDGER_SEQUENCER_INTERVAL`,
default 1s):

```
ticker tick → drainOnce
   │
   ▼ for each StatePending entry (up to MaxInFlight):
   │
   │   wal.Read → envelope.Deserialize
   │       │
   │       ▼ tessera.AppendLeaf(canonical bytes)
   │       │   (idempotent via Tessera antispam dedup)
   │       │
   │       ▼ insertEntryIndex (Postgres, ReadCommitted txn):
   │       │   - INSERT INTO entry_index
   │       │   - INSERT INTO commitment_split_id (commitment schemas only)
   │       │
   │       ▼ AFTER Postgres commit, best-effort Badger writes:
   │       │   - 0x0A WriteSplitIDIndexEntry (detection trigger)
   │       │   - 0x0C WriteEntryLookupEntry (CQRS read path)
   │       │
   │       ▼ wal.Sequence(hash, seq) → state pending → sequenced
   │
   ▼ on retry: wal.MarkRetry; on fatal: wal.MarkManual
```

### Boot replay

`sequencer/replay.go` runs on a child goroutine inside `Sequencer.Run()`
(`sequencer/sequencer.go:339-356`). It reads the
`SplitIDReplayHWM` (Badger 0x0D) and back-populates 0x0A + 0x0C from
Postgres above the high-water-mark. WaitGroup discipline guarantees
the goroutine drains before `Run()` returns on ctx cancel.

Closes the gap when the sequencer crashes between Postgres commit
and best-effort Badger writes.

## Read paths

### Pure CQRS for `/v1/commitments/by-split-id`

```
GET /v1/commitments/by-split-id/{schema_id}/{hex}
   │
   ▼ NewCommitmentLookupHandler (commitments.go:151)
   │  uses types.CommitmentFetcher (SDK interface)
   │
   ▼ gossipstore.BadgerCommitmentFetcher
   │  ListEntryLookupEntriesAt(schemaID, splitID)    (projections.go:283)
   │
   ▼ Badger 0x0C prefix scan → []EntryLookupHit
   │
   ▼ marshal → JSON {entries: [...]}

  len = 0 → 404
  len = 1 → 200 (normal)
  len ≥ 2 → 200 + multiple entries (cryptographic equivocation)
```

Zero Postgres on this path. Pinned by `api/commitments_test.go`:

```
TestCommitmentLookup_EndToEnd_BadgerCQRS (line 294)
TestCommitmentLookup_EndToEnd_EquivocationCase (line 363)
```

### Other reads

| Endpoint | Backing |
|---|---|
| `/v1/tree/head` | `TreeHeadFetcher` (Postgres) |
| `/v1/tree/inclusion/{seq}` | Tessera tile reader |
| `/v1/tree/consistency/{old}/{new}` | Tessera tile reader |
| `/v1/smt/proof/{key}` | SDK `smt.Tree` |
| `/v1/smt/root` | SDK `smt.Tree` |
| `/v1/smt/leaf/{key}` | `LeafStore` (Postgres) |
| `/v1/entries/{seq}/raw` | WAL inline OR bytestore 302 |
| `/v1/entries-hash/{hashHex}` | WAL meta probe + entry_index lookup |
| `/v1/query/*` | `QueryAPI` (Postgres secondary indexes) |

## Gossip pipeline

`gossipnet/` ties together publish + pull + detection:

```
Sequencer writes 0x0A SplitIDIndex
            │
            ▼  badger.DB.Subscribe(prefix=0x0A)
   ┌────────────────────────────┐
   │ gossipnet.EquivocationScanner │  (equivocation_scanner.go)
   └────────────┬───────────────┘
                │  ≥ 2 entries at same (schema, split_id)?
                ▼
        findings.NewEntryCommitmentEquivocationFinding
                │
                ▼  sign + Append to local gossip Store
                │  + project to 0x0B (equivocation projection)
                │  + Broadcast via BufferedSink
                ▼
        peers pull via /v1/gossip/since (anti-entropy)
```

Pull endpoints (`api/server.go:303-312`):

```
GET /v1/gossip/sth/latest
GET /v1/gossip/since
GET /v1/gossip/by-kind
GET /v1/gossip/event/{eventID}
GET /v1/gossip/by-binding/{hash}     ← zero-trust audit primitive
```

## Trust split

```
Ledger Postgres + Tessera + WAL + bytestore. No artifact decryption keys.
                Signs SCTs + tree heads. Detects equivocation.

Witnesses Hold cosign keys. Sign tree heads (K-of-N). Pull-based: each
                witness scrapes the ledger's /v1/gossip/* feeds independently.

Auditors Pull /v1/gossip/* + Static-CT tiles. Recompute Merkle + SMT
                roots locally. Fetch /v1/gossip/by-binding/{hash} to verify
                equivocation findings without trusting the ledger's word.
```

The Ledger never possesses artifact decryption keys. Domain-level
artifact encryption + key management lives outside this binary.

## What guarantees what

| Property | Where it's enforced |
|---|---|
| Durability before 202 | `wal.Submit` blocks until fsync (`wal/committer.go`) |
| Idempotent admission | WAL.MetaState probe + persisted `LogTimeMicros` (`api/submission.go:432`) |
| Hot-path isolation | HTTP handler is WAL-fsync only; Tessera + Postgres run on sequencer goroutine |
| Zero-pgx read path | `api/commitments.go` consumes `types.CommitmentFetcher`, served by `gossipstore.BadgerCommitmentFetcher` |
| Boot reconciliation | `sequencer.Replayer` back-populates 0x0A + 0x0C from Postgres on every boot |
| Equivocation detection | `gossipnet/equivocation_scanner.go` subscribes to Badger 0x0A |
| Drift-free projection key | `findings.EntryCommitmentBinding` (SDK) used by both producer + consumer |
| Graceful shutdown | `sync.WaitGroup` drains every goroutine (`sequencer/sequencer.go:Run`, `cmd/ledger/main.go gossipWG`) |
| Single-writer invariant | Postgres advisory lock at boot (`store/postgres.go`) |
| OTel error dimensionality | Every `writeTypedError` increments `attesta_api_errors_total{error_class, http_status}` |

## SDK pin

```
go.mod:  github.com/clearcompass-ai/attesta v0.1.1
```

The ledger never re-implements SDK validation logic. Every signed
artifact goes through SDK primitives:

- `envelope.Deserialize` / `envelope.NewEntry` / `envelope.Validate`
- `crypto/admission.VerifyStamp` (Mode B PoW)
- `crypto/sct.SignSCT` (admission promise)
- `crypto/cosign.NewWitnessKeySet` (encapsulated K-of-N topology)
- `crypto/cosign.WitnessCollector` (K-of-N collection)
- `crypto/cosign.Verify(payload, set, algo, sigs)` (single-arg verification)
- `findings.NewEquivocationFinding` + `Verify(set)` (witness-attested gossip events)
- `findings.NewEntryCommitmentEquivocationFinding` (signer-attested gossip events)
- `gossip.FeedHandler` + `BufferedSink` + `MultiSink` (pull-based egress)

### v0.1.1 alignment notes

The v0.1.1 break collapsed the previous `(keys, K, networkID,
blsVerifier)` parameter group into a single `*cosign.WitnessKeySet`
constructed once at boot (`cmd/ledger/main.go`) from
`LEDGER_WITNESS_QUORUM_K` + the genesis witness DIDs. The same
keyset is shared between the admission `BLSQuorumVerifier` and the
gossipnet `EquivocationMonitor` — one source of truth for
witness topology. Phantom-typed `Verified...Finding` wrappers were
removed; the publish gate is now developer discipline at the call
site, enforced by tests in `gossipnet/equivocation_monitor_test.go`
and the contract conformance tests in
`admission/v011_contract_test.go` + `gossipnet/v011_contract_test.go`.
- `types.CommitmentFetcher` (read-side abstraction)
