# Changelog

## v0.5 — SCT/MMD architecture (CT-log-aligned admission)

POST /v1/entries used to block on Tessera AppendLeaf + Postgres
INSERT before returning. Throughput was bounded by Tessera's
batching cadence (currently 1s default BatchMaxAge). Under v0.5
the admission boundary moves to WAL fsync only — Tessera and
entry_index INSERT are deferred to a background Sequencer worker.

### Wire-protocol changes

- **NEW: POST /v2/entries.** Returns a `SignedCertificateTimestamp`
  (SCT) — a cryptographic promise that the operator has the
  bytes durably (WAL fsync) and will sequence them within the
  Maximum Merge Delay. RFC-6962-aligned. The SCT is signed with
  the operator's secp256k1 ECDSA key
  (`OPERATOR_SIGNER_KEY_FILE`) and verifiable against the
  operator's public key (reachable via `cfg.OperatorDID`, a
  did:key:z…).
- **POST /v1/entries** keeps its synchronous `{sequence_number,
  canonical_hash, log_time}` JSON contract via a polling facade.
  The handler waits on WAL.MetaState until the background
  Sequencer transitions the entry to StateSequenced or
  `OPERATOR_V1_TIMEOUT` elapses (default 30s). On timeout the
  caller gets HTTP 504 with `{error:"sequencer_lag", hash,
  wal_state, follow_up, timeout_seconds}` pointing at
  GET /v1/entries/hash/{hash} for follow-up. The handler is
  strictly bound to `r.Context().Done()` so a client TCP
  disconnect exits the poll loop within one tick.
- **NEW: GET /v1/admission/mmd.** Publishes the operator's
  promised maximum merge delay (`OPERATOR_MMD`, default 24h) so
  consumers can verify the SLA before trusting an SCT.
- **GET /v1/entries/hash/{hashHex}** is now WAL-aware. Returns
  `{state:"pending"}` for entries durable in WAL but not yet in
  entry_index (the SCT/MMD inflight window) and
  `{state:"manual"}` for entries the Sequencer gave up on. Falls
  through to the existing entry_index lookup for sequenced/shipped
  entries.

### New env vars

- **`OPERATOR_MMD`** — Maximum merge delay published via
  GET /v1/admission/mmd. Default `24h`. The Sequencer must
  drain entries within this window or the SCT promise is
  broken; alert on `sequencer_lag > 0.8 * MMD`.
- **`OPERATOR_V1_TIMEOUT`** — Per-request cap on the v1 facade's
  poll loop. Default `30s`. Set lower for low-latency clients;
  set higher for clients that prefer waiting over the 504+
  follow-up dance.
- **`OPERATOR_SEQUENCER_INTERVAL`** — Background drain cadence.
  Default `1s` in production; tests override to `10ms`.
- **`OPERATOR_SEQUENCER_MAX_INFLIGHT`** — Bounded concurrency in
  the Sequencer. Default 4.

### Architectural changes

- **NEW: `sequencer/` package.** Single writer to entry_index.
  Drains WAL StatePending → tessera.AppendLeaf →
  WithReadCommittedTx{ store.EntryStore.Insert } → wal.Sequence.
  Symmetric to `shipper/` (sequenced→shipped). The sequencer's
  drain on Run start subsumes boot recovery; `integrity/Reasserter`
  is deleted.
- **DELETED: `integrity/reasserter.go`** + `Detector.Reconcile()`
  + `InflightIterator` + `WALReassertSink`. The integrity package
  is now a read-only verifier — it samples random sequences below
  HWM and compares WAL.HashAt to Tessera.HashAt; ErrDiverged still
  panics at the supervisor.
- **REFACTORED: `api/submission.go`.** Steps 1-9 extracted into a
  `prepareSubmission` helper; both v1 (facade) and v2 (SCT) handlers
  share it. Mode A credit deduction moved out of the original
  step-12 entry_index transaction (the Sequencer is now the only
  writer to entry_index) and into its own pre-WAL transaction
  via `deductCreditModeA`. Eager deduction means an SCT is only
  issued to entitled callers; the SCT promise is preserved if
  WAL.Submit succeeds.

### Defenses preserved (per the user's locked design)

- **Step 3c freshness check** stays in the fast path — it's the
  late-replay defense. An attacker sitting on a 3-week-old payload
  can't get an SCT for it; admission rejects with 422 before WAL
  fsync.
- **Step 8a early duplicate check** stays in the fast path — it's
  the immediate-replay defense. Re-submitting the same canonical
  hash returns 409 without burning a WAL fsync slot.

### CLI updates

- **`cmd/submit-stamp`** gains `-v2` (default `true`) and
  `-operator-did`. v2 mode parses the SCT response and, when
  `-operator-did` is supplied, cryptographically verifies the
  signature against the resolved public key. The CLI mirrors
  api.SignedCertificateTimestamp's JSON shape and re-implements
  the canonical packing locally so the binary stays free of an
  api/ import — drift caught by tests.

### Test surface additions

- **`api/sct_test.go`** (13 tests): SCT round-trip + tamper-reject
  on every signed-over field; canonical packing pinned bytewise.
- **`api/submission_v2_test.go`** (9 tests): v2 handler happy
  path, constructor guards, WAL queue full → 503, WAL transport
  error → 500, MMD endpoint.
- **`api/submission_facade_test.go`** (8 tests): pollForSequenced
  unit tests + integration through httptest with a transitioning
  WAL fake; timeout + structured 504 payload + ctx-cancel
  promptness.
- **`api/queries_test.go`** (5 tests): WAL-aware hash lookup —
  pending, manual, bad-hex, transport error, nil-WAL fall-through.
- **`sequencer/sequencer_test.go`** (16 subtests): drain
  semantics, retry/manual transitions, Tessera dedup
  idempotency, isUniqueViolation matcher.
- **`tests/e2e_v2_sct_test.go`** (5 tests): full HTTP round-trip
  through a real harness — SCT verification, hash-lookup
  pending→sequenced, MMD endpoint, multi-entry drain,
  end-to-end tamper resistance.
- **`cmd/submit-stamp/main_test.go`** (8 tests): CLI's apiSCT
  shape vs api.SignedCertificateTimestamp; verifyClientSCT
  matches api.VerifySCT byte-for-byte; tamper rejections.

### Migration steps from v0.4

1. Provision two new env vars with defaults: set
   `OPERATOR_MMD` if the default 24h doesn't fit your SLA;
   `OPERATOR_V1_TIMEOUT` if 30s is too generous or too tight.
2. Update v1 clients that depend on `sequence_number` being
   immediately available — under load + sequencer lag the v1
   path can return 504 sequencer_lag instead. Either retry on
   504 (the WAL is durable; the entry will eventually sequence)
   or migrate to v2 + SCT verification.
3. Migrate latency-sensitive clients to POST /v2/entries.
   Verify SCT signatures against the operator's public key (the
   did:key:z… in cfg.OperatorDID, parsed via did.ParseDIDKey
   from the SDK).

---

## v0.4 — WAL-first admission, hexagonal bytestore, async Shipper

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
  storage. Existed in earlier releases.
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

- Wire bytes ARE the canonical bytes. The multi-sig section is
  appended INSIDE `envelope.Serialize`'s output; there is no
  separate signature-append step. Consumers feed the wire bytes
  directly to `envelope.Deserialize`.
- `sig_algorithm_id` was dropped end-to-end — algo IDs live
  inside the multi-sig section.

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

### Migration steps

1. Provision the WAL + antispam volumes alongside the existing
   Tessera storage volume.
2. Provision a bucket on the chosen backend:
   - GCS: grant `storage.objects.{create,get,list}` (+ `delete`
     for soak / conformance) to the operator's ADC identity.
   - S3 / RustFS / R2: `s3:PutObject`, `s3:GetObject`,
     `s3:ListBucket` (+ `s3:DeleteObject` for soak /
     conformance). Prefer IAM roles on AWS; static creds for
     RustFS / on-prem.
3. Drain the previous operator release (let any pre-existing
   `builder_queue` empty and Tessera integrate the last entries).
4. Update the manifests to set `OPERATOR_WAL_PATH`,
   `OPERATOR_TESSERA_ANTISPAM_PATH`, `OPERATOR_BYTE_STORE_BACKEND`
   (`gcs` or `s3`), and the matching bucket / S3 family vars.
5. Boot the v0.4 binary. Migrations run automatically; any
   pre-existing `builder_queue` table is left in place but unused —
   drop it in a follow-up maintenance window.

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
Pre-release. No tagged versions yet — see `git log` for the full
history. This file will start tracking releases at `v1.0.0`.
