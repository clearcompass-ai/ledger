# Architecture

End-to-end runtime layout of `cmd/ledger`. Owns the package
boundary map, the admission and sequencer data flows, the
gossip/equivocation pipeline, and the trust split. Routes live in
[api.md](api.md); env vars in [configuration.md](configuration.md);
storage in [storage.md](storage.md); metrics in
[observability.md](observability.md); SDK contract anchors in
[sdk-validation.md](sdk-validation.md).

## Package layout

```
ledger/
├── cmd/
│   ├── ledger/         # main binary; loadConfig + wiring + supervisor
│   ├── ledger-reader/  # read-only sibling (no admission, no sequencer)
│   ├── submit-stamp/   # CLI: build + sign + POST an entry
│   ├── seed-session/   # dev: insert a sessions row
│   ├── rebuild-tiles/  # ops: replay entry_index → Tessera
│   └── init-network/   # local-dev bootstrap-doc + witness-key generator
├── api/                  # HTTP handlers (api/middleware/ holds Auth, SizeLimit, WithRequestID)
│   ├── server.go              # the route table — single source of truth
│   ├── ports.go               # interfaces for store/* and middleware (no pgx)
│   ├── errors.go              # writeTypedError + OTel counter
│   ├── instruments.go         # request-duration histogram
│   ├── body_caps.go           # MaxCosignRequestBytes, MaxGossipPostBytes, etc.
│   ├── submission.go          # POST /v1/entries
│   ├── batch.go               # POST /v1/entries/batch
│   ├── commitments.go         # GET /v1/commitments/by-split-id
│   ├── tree.go                # GET /v1/tree/{head,inclusion,consistency}
│   ├── proofs.go              # GET /v1/smt/{proof,batch_proof,root}
│   ├── queries.go             # GET /v1/query/* + /v1/entries-hash
│   ├── entries_read.go        # GET /v1/entries/{seq,batch,raw}
│   ├── escrow_override.go     # POST /v1/escrow-override
│   ├── smt_read.go            # GET /v1/smt/leaf/{key} + POST /v1/smt/leaves
│   ├── derivation_commitments.go # GET /v1/commitments?seq=N
│   ├── mmd.go                 # GET /v1/admission/mmd
│   ├── tile_handler.go        # GET /checkpoint + GET /tile/{level}/{rest...}
│   ├── info.go                # GET /version + GET /v1/log-info
│   ├── sct.go                 # SignSCT (ledger-owned; the SDK only ships the verifier-side primitives)
│   └── middleware/            # Auth(SessionLookup), SizeLimit, WithRequestID
├── apitypes/             # leaf package — value types + sentinels (no pgx, no SDK)
├── wal/                  # Badger WAL with state machine
├── sequencer/            # WAL drain + Tessera AppendLeaf + projection writes + boot replayer
├── shipper/              # WAL → bytestore migrator
├── store/                # Postgres-backed store types
├── gossipstore/          # Badger-backed gossip Store + read projections
├── gossipnet/            # gossip handler, sink, scanner, override flow
├── tessera/              # embedded Tessera appender
├── bytestore/            # GCS / S3 / in-memory entry-byte storage + GCS tile backend
├── admission/            # signature verification, NFC checks, BLS quorum verifier
├── integrity/            # boot reconciliation + sample-verify detector
├── lifecycle/            # graceful shutdown chain, slog redaction helpers, pprof labels
├── witness/              # witness-mode cosign endpoint
├── anchor/               # external anchor publishing
├── builder/              # commitment-publisher loop
├── integration/          # Postgres-gated integration tests
└── tests/                # End-to-end test harness (Postgres + Badger + bytestore)
```

## Admission flow

`POST /v1/entries` (`api/submission.go`):

```
HTTP request
   │
   ▼ middleware.SizeLimit(MaxEntrySize+1024)        (server.go:284)
   │
   ▼ middleware.Auth(SessionLookup)                  (server.go:286)
   │  no token → ctx[authenticated]=false (Mode B)
   │  invalid token → 401
   │  valid token → ctx[authenticated]=true, ctx[exchange_did]=...
   │
   ▼ NewSubmissionHandler.prepareSubmission         (submission.go:283)
   │   step 1: read raw bytes + protocol-version preamble
   │   step 2: envelope.Deserialize + ValidateAlgorithmID
   │   step 3: entry.Validate + CheckNFC + destination + freshness
   │   step 4: admission.VerifyEntrySignature
   │   step 4b: BLSQuorumVerifier.VerifyEntry        (no-op until
   │            EntryEmbedsTreeHead matches a schema; closed-set
   │            predicate currently empty —
   │            admission/bls_quorum_verifier.go:238)
   │   step 5-6: size cap + evidence pointers cap
   │   step 7: Mode B stamp verify (unauthenticated only)
   │   step 8: canonical hash + idempotency probe
   │            via wal.MetaState                    (submission.go:460)
   │
   ├─ idempotent replay → SignSCT with persisted log_time → 202
   │
   ▼ deductCreditModeA via CreditDeducter.Deduct    (submission.go:586)
   │  insufficient credits → 402
   │
   ▼ deps.Storage.WAL.Submit(hash, wire, logTimeMicros)
   │                                                  (submission.go:599)
   │  wal.ErrQueueFull → 503 + Retry-After
   │
   ▼ SignSCT(api/sct.go:65) → write 202 + JSON SignedCertificateTimestamp
```

The handler **never blocks on Tessera or Postgres**. Sequence-
number assignment + entry_index INSERT + projection writes happen
on the sequencer goroutine (next section).

## Sequencer pipeline

`sequencer/loop.go` drains the WAL on a ticker
(`LEDGER_SEQUENCER_INTERVAL`, default 1s; see
[configuration.md](configuration.md)):

```
ticker tick → drainOnce                        (sequencer/loop.go:75)
   │
   ▼ for each StatePending entry (up to MaxInFlight):
   │
   │   wal.Read → envelope.Deserialize
   │       │
   │       ▼ tessera.AppendLeaf(canonical bytes)
   │       │   (idempotent via Tessera antispam dedup)
   │       │
   │       ▼ insertEntryIndex(...)              (sequencer/loop.go:187)
   │       │   Postgres ReadCommitted txn:
   │       │     INSERT INTO entry_index
   │       │     INSERT INTO commitment_split_id (commitment schemas only)
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

`sequencer/replay.go::Replayer.Replay` runs on a child goroutine
inside `Sequencer.Run` (`sequencer/sequencer.go:340–356`,
`wg.Wait` deferred so the goroutine drains before `Run` returns
on ctx cancel). It reads the `SplitIDReplayHWM` (Badger 0x0D) and
back-populates 0x0A + 0x0C from Postgres above the high-water
mark — closing the gap when the sequencer crashes between
Postgres commit and best-effort Badger writes. Idempotent;
backwards `Set` of the HWM is a silent no-op.

## Read paths

### Pure CQRS for `/v1/commitments/by-split-id`

```
GET /v1/commitments/by-split-id/{schema_id}/{hex}
   │
   ▼ NewCommitmentLookupHandler                  (commitments.go:152)
   │  uses types.CommitmentFetcher (SDK interface)
   │
   ▼ gossipstore.BadgerCommitmentFetcher
   │  ListEntryLookupEntriesAt(schemaID, splitID)  (projections.go:354)
   │
   ▼ Badger 0x0C prefix scan → []EntryLookupHit
   │
   ▼ marshal → JSON {entries: [...]}

  len = 0 → 404
  len = 1 → 200 (normal)
  len ≥ 2 → 200 + multiple entries (cryptographic equivocation)
```

Pure CQRS: zero Postgres on this hot path. The compile-time
interface anchor that pins both implementations against the SDK
contract is documented in
[sdk-validation.md](sdk-validation.md). End-to-end pinned by:

```
api/commitments_test.go::TestCommitmentLookup_EndToEnd_BadgerCQRS
api/commitments_test.go::TestCommitmentLookup_EndToEnd_EquivocationCase
```

### Other reads

| Endpoint | Backing |
|---|---|
| `/v1/tree/head` | `TreeHeadFetcher` (Postgres) |
| `/v1/tree/inclusion/{seq}` | Tessera tile reader |
| `/v1/tree/consistency/{old}/{new}` | Tessera tile reader |
| `/v1/smt/proof/{key}` | SDK `core/smt.Tree` |
| `/v1/smt/root` | SDK `core/smt.Tree` |
| `/v1/smt/leaf/{key}` | `LeafStore` (Postgres) |
| `/v1/entries/{seq}/raw` | WAL inline OR bytestore 302 |
| `/v1/entries-hash/{hashHex}` | WAL meta probe + entry_index lookup |
| `/v1/query/*` | `QueryAPI` (Postgres secondary indexes) |
| `/checkpoint`, `/tile/...` | Tessera POSIX dir or GCS bucket (`LEDGER_TILE_BACKEND`) |

## Gossip pipeline

`gossipnet/` ties together publish + pull + detection:

```
Sequencer writes 0x0A SplitIDIndex
            │
            ▼  badger.DB.Subscribe(prefix=0x0A)
   ┌──────────────────────────────┐
   │ gossipnet.EquivocationScanner │  (equivocation_scanner.go)
   └──────────────┬────────────────┘
                  │  ≥ 2 entries at same (schema, split_id)?
                  ▼
          findings.NewEntryCommitmentEquivocationFinding
                  │
                  ▼  sign + Append to local gossip Store
                  │  + project to 0x0B (equivocation projection)
                  │  + Broadcast via BufferedSink (DropPolicyDropOldest)
                  ▼
          peers pull via /v1/gossip/since (anti-entropy)
```

Pull endpoints are listed in [api.md](api.md). The producer +
consumer compute the same content-derived binding via the SDK
helper `findings.EntryCommitmentBinding(schemaID, splitID)` —
drift-free by construction.

The gossip handler, feed handler, and cosign witness handler are
panic-resilient by SDK construction: each embeds
`defer recoverPanic(...)` as the first statement of `ServeHTTP`,
so the ledger does NOT need to wrap them in any local recovery
middleware. Recovered panics surface a clean 500 carrying the
typed `ErrInternalPanic` sentinel + a `panic_kind` label and
increment `attesta_gossip_panic_total` (full inventory in
[observability.md](observability.md)). `http.ErrAbortHandler` is
re-panicked so stdlib's `TimeoutHandler` integration still works.

## Trust split

```
Ledger    Postgres + Tessera + WAL + bytestore. No artifact decryption keys.
          Signs SCTs + tree heads. Detects equivocation.

Witnesses Hold cosign keys. Sign tree heads (K-of-N). Pull-based: each
          witness scrapes the ledger's /v1/gossip/* feeds independently.

Auditors  Pull /v1/gossip/* + Static-CT tiles. Recompute Merkle + SMT
          roots locally. Fetch /v1/gossip/by-binding/{hash} to verify
          equivocation findings without trusting the ledger's word.
```

The Ledger never possesses artifact decryption keys. Domain-level
artifact encryption + key management lives outside this binary.

## What guarantees what

| Property | Where it's enforced |
|---|---|
| Durability before 202 | `wal.Submit` blocks until fsync (`wal/committer.go`) |
| Idempotent admission | `wal.MetaState` probe + persisted `LogTimeMicros` (`api/submission.go:460`) |
| Hot-path isolation | HTTP handler is WAL-fsync only; Tessera + Postgres run on the sequencer goroutine |
| Zero-pgx read path for commitments | `api/commitments.go` consumes `types.CommitmentFetcher`, served by `gossipstore.BadgerCommitmentFetcher` |
| Boot reconciliation | `sequencer.Replayer` back-populates 0x0A + 0x0C from Postgres on every boot |
| Equivocation detection | `gossipnet/equivocation_scanner.go` subscribes to Badger 0x0A |
| Drift-free projection key | `findings.EntryCommitmentBinding` (SDK) used by both producer + consumer |
| Graceful shutdown | `lifecycle.ShutdownChain` (sync.OnceFunc-protected close fns; full ordering in [operations.md](operations.md)) |
| Single-writer invariant | Postgres advisory lock at boot (`store/postgres.go::BuilderLockID = 0x4F5254484F4C4F47`, line 400) |
| OTel error dimensionality | Every `writeTypedError` increments `attesta_api_errors_total{error_class, http_status}` |

## SDK pin

```
go.mod:  github.com/clearcompass-ai/attesta v0.1.3
```

Verified by `go list -m github.com/clearcompass-ai/attesta`.

The ledger never re-implements SDK validation logic. Every signed
artifact goes through SDK primitives:

- `core/envelope.Deserialize` / `core/envelope.NewEntry` / `(*Entry).Validate`
- `crypto/admission.VerifyStamp` (Mode B PoW)
- `crypto/sct.SigningPayload` + `crypto/sct.Verify` (the SDK only
  ships the verifier-side bytes; SCT signing lives in the ledger
  at `api/sct.go:65` because the ledger's private key never
  leaves the process)
- `crypto/cosign.NewWitnessKeySet(keys, networkID, quorum, blsVerifier)`
- `crypto/cosign.WitnessCollector` (K-of-N collection)
- `crypto/cosign.Verify(payload, set, algo, sigs)` (single-set verification)
- `findings.NewEquivocationFinding` + `Verify(set)` (witness-attested gossip events)
- `findings.NewEntryCommitmentEquivocationFinding` (signer-attested gossip events)
- `findings.EntryCommitmentBinding` (drift-free binding key)
- `gossip.FeedHandler` + `gossip.BufferedSink` + `gossip.MultiSink` (pull-based egress)
- `types.CommitmentFetcher` (read-side abstraction satisfied by both
  the Postgres-backed and Badger-backed implementations)

### Witness keyset wiring

The boot path (`cmd/ledger/main.go::loadOrGenerateWitnessSigner`
+ key-set construction) calls
`cosign.NewWitnessKeySet(witKeys, NetworkID, LEDGER_WITNESS_QUORUM_K,
blsv)` once and shares the resulting `*cosign.WitnessKeySet`
between the admission `BLSQuorumVerifier` and the gossipnet
`EquivocationMonitor` — one source of truth for witness topology
(keys, NetworkID, K-of-N quorum, BLS verifier). The publish gate
on equivocation findings is developer discipline at the call
site, enforced by tests in
`gossipnet/equivocation_monitor_test.go` and the contract
conformance tests in `admission/v011_contract_test.go` +
`gossipnet/v011_contract_test.go`.
