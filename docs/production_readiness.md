# Production Readiness — Ledger

This is the **versioned, canonical plan** for making the Ledger
production-grade. Update this file in the same commit that lands the
work. Pick the next item from here, not from conversation memory.

---

## Scope

| Axis | Target |
|---|---|
| Total entries (lifetime) | **10⁹–10¹⁰** |
| Operational lifetime | **10 years** |
| Write rate (steady state) | **8–12 M entries / day** (~100–140 ent/sec; bursts higher) |
| API consumers | **Hundreds**, mixed read/write profiles |
| Read traffic | **Dominant** — inclusion proofs, entry hydration, SMT proofs, head queries |

This is a **transparency-log scale problem**, not a general-purpose
DB scale problem. The architecture is built on tile-based Static CT
+ pull-based gossip + Postgres-as-projection. SLOs and rebuild
plans below assume that physics.

---

## Architectural invariants (cross-reference the principle docs)

The following invariants are load-bearing. Every item below is
required to respect them; flag a PR if any item appears to violate
one.

### A. Dumb Ledger / Smart SDK — domain agnosticism
*Ledger principle §1, §4 — SDK principle §1, §2.*
The Ledger contains zero domain logic. The SDK is authoritative for
schema validation, signature verification, SMT derivation, and
quorum policy. Items below MUST NOT propose adding domain rules to
the Ledger.

### B. Tiles + Static CT are the source of truth — Postgres is a projection
*Ledger principle §10 — Trust principle §6, §15.*
The authoritative storage is the immutable Static-CT bytestore
(`.p` hash tiles + entry bundles in S3/GCS) combined with the
signed events on the gossip network. **Every Postgres table is a
projection that can be rebuilt by walking tiles + replaying
gossip** (see §C below for the explicit rebuild path per table).
Items below MUST treat PG as ephemeral cache, not authoritative
state.

### C. CQRS, melt-proof, two-clocks
*Ledger principle §5, §7, §8, §12.*
Admission does *nothing* except validate envelopes + WAL append.
Heavy crypto (BLS, SMT walks, tile compaction) runs in bounded
background workers. The **Commit Clock** (witnessing, sync,
strictly blocking) and the **Transparency Clock** (gossip, async,
fire-and-forget) share zero transport semantics.

### D. K-of-N witness quorum is the network's anchor
*Trust principle §2, §3, §4 — Ledger principle §12.*
A tree head is mathematically unfinalized until the
configured-per-deployment `WitnessKeySet` quorum signs it. Witness
set rotation is itself signed by the existing K-of-N quorum
(`KindOriginatorRotation`). The `witness_sets` PG table is a
**projection** of those rotation events, not the source of truth.

### E. Per-originator parallelism, idempotency, fail-closed
*Ledger principle §6, §9 — SDK principle §3, §8.*
Two events from different originators advance fully in parallel.
Resubmissions are content-addressed no-ops. Cryptographic APIs fail
closed by construction, never by caller discipline.

---

## Status legend

- ✅ **Done** — landed + gated by a test on the feature branch.
- 🟡 **In progress** — branch open or partially landed.
- ⬜ **Pending** — not started.

## Scaffolds (shared test infrastructure)

| ID | Scope | Reused by | Status |
|----|-------|-----------|--------|
| **A** | WAL bench harness (in-memory + flake-able Badger) | §C2, §D1, §D3 | ⬜ |
| **B** | Shipper bench harness (`shipper/bench_harness_test.go`) | §A1, §A2, §F1 | ✅ commit `0556d70` |
| **C** | Multi-component soak with fault injection | §D1, §D2, §D3, §E lifecycle | 🟡 soak exists; fault injection doesn't |

---

# Items, organized by structural axis

## §A — Write-path SLOs (admission through ship through tree)

### A1 — Shipper throughput SLO ✅
- **SLO:** `shipper.SLOThroughputEntriesPerSec = 500` (~14% of S3
  single-prefix ceiling; comfortable headroom for the 100–140
  ent/sec steady-state target with burst capacity).
- **Test:** `TestShipperThroughput_MeetsSLO` + negative-control
  `TestShipperThroughput_SLO_DetectsRegression`.
- **Defaults tuned:** `PollInterval` 1s → 100ms, `MaxInFlight` 4 →
  32. Measured 12 → 960 ent/sec (80× improvement).
- **Evidence:** commit `0556d70`.

### A2 — Admit→SCT p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 50ms from request entry to 202 SCT
  response, measured at the API edge with a 1ms-bytestore
  benchmark. This isolates the *admission hot path* (Ledger §7).
- **Plan:** extend Scaffold B with an admission-side timer that
  marks t₀ on request arrival and t₁ on SCT sign+return. Negative
  control: deliberately move PoW verification onto the hot path
  → assert p99 explodes.

### A3 — Admit→Shipped p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 30s under steady-state at the daily
  target rate. End-to-end: t₀ = admission accept, t₁ = bytestore
  PUT confirmed.

### A4 — Admit→TreeHead p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 2 × `CheckpointInterval` under
  steady-state (default 500ms checkpoint → ~1s p99). Subject to
  upstream Tessera batching constraints; this SLO is the
  **operator-visible MMD** (Maximum Merge Delay).

### A5 — WAL backpressure SLO ⬜
- **SLO (proposed):** at sustained admission ≥ 2× sequencing
  drain rate, HTTP 429 returns within p99 ≤ 50ms with a usable
  `Retry-After`; zero panics; zero silent drops.
- **Today:** plumbing exists (`wal/errors.go:13` `ErrQueueFull`;
  `api/submission.go:604` returns 429). No scale test.
- **Plan:** Scaffold A. Load gen exceeds drain rate; assert 429
  latency, WAL counters stay bounded, admission liveness holds.

---

## §B — Read-path SLOs

The user-visible behavior at 10⁹ entries is dominated by read
traffic from hundreds of consumers. Items here gate the **edge-
first, CPU-zero** read model the Ledger principle §10 demands.

### B1 — Tile CDN hit-rate gate ⬜
- **SLO (proposed):** CDN cache hit rate ≥ 99% for hash-tile and
  entry-tile reads under steady-state. Tiles are immutable; misses
  should only happen on first-fetch after publication.
- **Plan:** synthetic read load generator across N consumer
  identities; measure origin-Ledger CPU under load → MUST be
  effectively zero. Validates Ledger §10 ("Static CT API —
  edge-first read offloading").

### B2 — `/v1/tree/inclusion/{seq}` p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 100ms with warm tile cache;
  p99 ≤ 500ms with cold cache.
- **Today:** uses canonical `tessera/client.ProofBuilder` after
  commit `c8324b8`. Correctness verified at 100K leaves
  (100/100 inclusion proofs). Latency not yet gated.
- **Plan:** soak harness measures per-seq proof generation latency
  histogram; assert p99.

### B3 — `/v1/tree/head` p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 10ms. This is a single CDN read of the
  cosigned-checkpoint file (Ledger §10) or a single PG row read
  (`tree_heads` projection). It MUST be O(1).

### B4 — `/v1/smt/proof/{key}` p99 latency SLO 🟡
- **Today:** correctness shipped via materialization
  (commit `b3fd728`, `api/proofs.go:liveTree`). Materialization is
  **O(N) per request** — works at 10⁶ leaves, breaks at 10⁹.
- **Plan (PHASE 2 — load-bearing for 10B scale):** incremental
  proof generation. Cache walk-from-root sibling hashes in
  `smt_nodes` (already write-through). Generate proofs by reading
  the persisted node hashes along the target key's path —
  O(log N), no leaf enumeration. See §C3.

### B5 — `/v1/entries/{seq}/raw` p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 50ms — this is a 302 redirect to the
  bytestore; the Ledger does no I/O. The latency is dominated by
  the PG lookup `seq → hash`.
- **Plan:** index strategy on `entry_index.sequence_number` (PK
  already). Assert latency under concurrent fan-out (100 readers).

### B6 — `/v1/entries-hash/{hex}` p99 latency SLO ⬜
- **SLO (proposed):** p99 ≤ 50ms. Hash-to-seq lookup against
  `entry_index.canonical_hash`. Needs documented unique index +
  benchmark.

### B7 — Multi-consumer concurrent read SLO ⬜
- **SLO (proposed):** with 100 simultaneous read clients each at
  10 RPS, the per-request latencies above hold (no head-of-line
  blocking, no per-consumer interference).

---

## §C — Scale invariants (PG-as-projection; rebuild-from-tiles)

The core principle here: **every PG table is a projection
rebuildable from the canonical tile/entries bundles + gossip
feed**. The SLOs below cap PG size and require a tested rebuild
path within an explicit RTO budget.

### C1 — Memory envelope ⬜
- **SLO (proposed):** RSS sub-linear from 10⁶ → 10¹⁰ entries, with
  an explicit per-process ceiling (proposed 8 GB).
- **Today:** soak caps at 1K entries.
- **Plan:** Scaffold A or C extension. 1M-entry soak first, then
  10M. Track LSM-tree size, tile cache size, in-memory caches.

### C2 — Postgres-as-projection envelope 🟡
- **PG is NOT authoritative.** Every table below is a projection
  with a defined rebuild path:

  | Table | Projection of | Rebuild path |
  |-------|---------------|--------------|
  | `entry_index` | tile/entries bundles | walk `tile/entries/{N}` bundles; SDK parses each entry; re-INSERT rows |
  | `smt_leaves` | log entries + SDK derivation | for each integrated entry, run `sdkbuilder.ProcessBatch`; capture `result.Mutations`; UPSERT leaves |
  | `smt_nodes` | smt_leaves + SDK tree math | walk tree top-down (or bottom-up) over the rebuilt leaves; persist intermediate nodes |
  | `builder_cursor` | the highest seq in `entry_index` (or tile state) | single SELECT MAX after rebuild |
  | `tree_heads` | gossiped `KindCosignedTreeHead` events | replay the gossip feed; one row per published head |
  | `witness_sets` | gossiped `KindOriginatorRotation` events | replay the rotation chain from genesis |

- **SLO (proposed):**
  1. **Bounded PG size:** `entry_index` retains entries within a
     rolling window (proposed: most-recent 30 days, ~360 M rows).
     Older entries are accessible via tile walk + on-demand
     `entry_index` re-projection.
  2. **Provable rebuild RTO:** complete rebuild of a wiped PG from
     tiles + gossip completes within X hours (proposed: 4 h for
     360 M-entry window, scaling linearly). Tested in CI.
- **Plan:** `cmd/rebuild-projection` binary that walks the tile
  store, replays the gossip feed, and reconstructs every table.
  Tested against a known-good snapshot.
- **Phase 1 evidence (this branch):** `cmd/rebuild-projection/`
  (rebuild.go + main.go + rebuild_test.go) rebuilds entry_index,
  smt_leaves, smt_root_state, builder_cursor from the POSIX tile
  store. Integration test
  `TestRebuild_DeterministicProjectionFromTiles` (gated on
  ATTESTA_TEST_DSN) appends 50 entries through upstream Tessera,
  runs Rebuild twice against the same tile dir, and asserts the
  two PG snapshots are bit-exact equal across all four projection
  tables.
- **Phase 2 work pending:** gossip-replay rebuild for tree_heads,
  tree_head_sigs, witness_sets; RTO budget benchmarks at 1M / 10M /
  100M entries; sharded/streamed rebuild for 10⁹+ scale.

### C3 — Sharded / paginated SMT for 10⁹+ scale ⬜
- **Today:** SMT root is maintained via materialize-once-per-batch
  (`builder/loop.go`, commit `0ea1328`). O(N) per batch where N =
  total live leaves. At 10⁷ leaves this is ~100ms/batch; at 10⁹
  it's >10s/batch — unworkable.
- **Plan (load-bearing for 10B scale):**
  1. Persist intermediate node hashes from `ComputeDirtyRoot` into
     `smt_nodes` (already write-through), via a warm
     `PostgresNodeCache`. Cache warmth on cold-start comes from
     PG-fallthrough Get.
  2. With the cache properly warm, `ComputeDirtyRoot` becomes
     O(M log N) per batch (M = batch size, ~256× M cache reads).
  3. /v1/smt/proof/{key} reads sibling hashes from `smt_nodes`
     directly — O(log N), no leaf enumeration. Closes §B4.
- **Why this isn't trivial:** cache-warmth correctness requires
  every node touched during prior batches to be in PG. The
  builder's atomic commit must promote intermediate nodes
  transactionally — the first attempt (commit `ea8f451`, reverted)
  showed the cold-cache PG-roundtrip bottleneck makes naive
  implementations unusable. Needs careful design + benchmarks.

### C4 — Tile cache sizing ⬜
- **SLO (proposed):** tile cache hit rate ≥ 99% under steady-state
  read load; LRU eviction does not thrash under burst proof
  generation. Reuse `tessera/tile_reader.go` LRU; size based on
  working set (proposed: 10 GB).

---

## §D — Correctness under fault

### D1 — Crash recovery correctness ⬜
- **Assertion:** `kill -9` mid-integration. On restart, every
  accepted entry is durable AND every committed seq appears in the
  tree with a valid inclusion proof, with no holes.
- **Today:** `ReconcileHWM` exists at `shipper/shipper.go:192`;
  not fault-tested.
- **Plan:** Scaffold A. Inject crash at: (a) post-WAL pre-sequence,
  (b) post-sequence pre-Tessera-append, (c) post-Tessera-append
  pre-MarkShipped, (d) shipper mid-batch, (e) builder
  mid-atomic-commit, (f) builder post-CommitBatch pre-tx-commit.
  Recent CursorReader fix (commit `3a41d19`) closed a known silent-
  skip; (f) gates that fix.

### D2 — Witness quorum degraded mode ⬜
- **Assertion:** under K-1 witness failure (one short of quorum),
  the Ledger MUST refuse to publish a cosigned checkpoint AND
  surface the degraded state via a counter ops can alert on. Under
  recovery the next checkpoint cycle MUST succeed without manual
  intervention. *(Trust principle §2 — decentralized threshold
  witnessing.)*
- **Today:** `newWitnessFixture(t, netID, N)` already supports
  N-witness fixtures.
- **Plan:** fault injection that closes one witness mid-test;
  assert degraded counter increments, no cosigned checkpoint
  publishes, and recovery is automatic.

### D3 — Equivocation detection at runtime ⬜
- **Assertion:** if a misbehaving Ledger or peer signs two different
  RootHashes at the same TreeSize, the SDK's `DetectEquivocation`
  fires + `VerifiedEquivocationFinding` propagates via gossip.
  Verified by an out-of-band auditor pulling tiles + gossip feed.
  *(Trust principle §7.)*
- **Plan:** test harness with two divergent Ledgers + a shared
  gossip network. Auditor replay-builds the equivocation finding.

### D4 — Chaos / fault-injection coverage ⬜
- **Assertion:** the soak survives bytestore 5xx storms (10% PUT
  failure rate for 30s), WAL `fsync` slowness (200ms p99), Tessera
  batch latency spikes, without missing entries or stuck HWM.
- **Plan:** Scaffold C. Wraps bytestore / WAL / Tessera at the
  interface boundary; existing `benchBytestore.WithFailRate` is
  the seed pattern.

---

## §E — Operational lifecycle (10-year specific)

These are the items that distinguish "works for the demo" from
"runs for 10 years."

### E1 — Tessera signer key rotation ⬜
- **Assertion:** the Tessera signer key can be rotated without
  invalidating any historical inclusion proof or cosigned head.
  Old keys remain verifiable; new heads sign with the new key.
- **Plan:** document the rotation protocol (multi-signer
  checkpoint period; auditor key-set replay); add a test that
  rotates the signer mid-run and asserts continued integration.

### E2 — Witness set rotation via `KindOriginatorRotation` ⬜
- **Assertion:** the active K-of-N quorum signs a
  `WitnessRotation` payload containing the new set + K-of-N
  signatures from the **active** quorum authorizing the handover.
  Once gossiped, the `witness_sets` projection updates; the next
  cosigned head MUST use the new set. *(Trust principle §3.)*
- **Today:** SDK types exist
  (`witnessclient/rotation_handler.go`, `types/witness_rotation.go`,
  gossip kind `KindOriginatorRotation`). Genesis set is loaded from
  a static YAML only at cluster bootstrap.
- **Plan:** integration test that performs a rotation mid-run and
  asserts (a) old set immediately rejects new attestations, (b)
  new set's first checkpoint is accepted, (c) `witness_sets`
  table updates without manual intervention.

### E3 — Schema migration safety ⬜
- **Assertion:** every Postgres migration is zero-downtime:
  add-column-with-default + backfill rather than transformative
  ALTER. CI gate verifies migrations are forward-compatible with
  the previous binary running.
- **Today:** migrations 0001 + 0002 in `store/migrations/`; runner
  in `store/migrations.go` supports `apply` / `verify` / `skip`.
- **Plan:** add a CI check that runs the previous-release binary
  against the new schema (and vice versa).

### E4 — Bytestore provider / region migration ⬜
- **Assertion:** the bytestore can be migrated to a new region or
  provider over a decade without data loss or read-path downtime.
- **Plan:** documented protocol (object-by-object copy + verify +
  cutover); integration test that exercises a dual-write +
  cutover flow.

### E5 — Long-tail data lifecycle ⬜
- **Plan:** retention policies for ancient entries; cold-storage
  tiering; document audit trail accessibility at 10-year horizon
  (S3 Glacier, Deep Archive, IPFS — TBD per deployment).

---

## §F — Fairness + cost envelope

### F1 — Per-consumer rate limit + quota ⬜
- **Assertion:** one fat consumer cannot crowd out the other 99.
  Per-consumer admission credits already exist in `credits`
  table; this item upgrades them to operational SLOs + monitoring.
- **Plan:** per-consumer admission rate (RPS) limit; per-consumer
  read RPS limit; alerting when any consumer exceeds quota.

### F2 — Cost envelope at 10⁹ entries ⬜
- **PG storage (bounded):** with a 30-day rolling window
  (~360 M rows × ~400 B/row × 4 tables) ≈ **600 GB**, not 16 TB.
  This is the *projection-as-cache* dividend.
- **Tile bytestore:** 10⁹ × ~300 B (tile-amortized) ≈ **300 GB**
  primary + replication.
- **WAL Badger:** transient, ≤ 100 GB.
- **Plan:** document expected costs per deployment shape;
  alerting when any axis exceeds budget.

---

## §G — Observability + operability

### G1 — OTel instrumentation completeness audit ⬜
- **Assertion:** every counter/histogram an ops dashboard needs is
  exported via OTel with a documented metric name and stable
  units. No counter exists in code that isn't exposed; no exposed
  counter is undocumented. *(Ledger principle §13 — SRE-grade
  observability.)*
- **Plan:** script that diffs (a) counters in `shipper/instruments.go`,
  `sequencer/instruments.go`, `tessera/embedded_appender.go`,
  `wal/` against (b) documented metrics in
  `docs/observability.md`. CI gate fails on mismatch.

### G2 — Graceful shutdown drain SLO ⬜
- **SLO (proposed):** on `SIGTERM`, all admitted entries reach
  the tree within p99 ≤ 30s OR the binary returns a non-zero exit
  code. Zero entries lost. *(Ledger principle §14.)*
- **Landmine documented:** `tests/testserver_tessera_test.go:159`
  rejects `context.WithoutCancel`. The SLO has to navigate that
  constraint.
- **Plan:** integration test with `goleak` + controlled
  `context.Cancel`.

### G3 — Error dimensionality audit ⬜
- **Assertion:** OTel error counters are partitioned per Trust
  principle §14 — `ErrSignatureInvalid` (active attack) is
  distinct from `ErrChainBreak` (missing event ID) is distinct
  from `ErrLamportRegression` (clock desync). Enables noise-free
  alerting.
- **Plan:** audit existing error sites; add tagged metrics where
  missing.

### G4 — Configuration drift gate ⚪
- **Assertion:** production defaults match `docs/operations.md`.
  CI fails on drift.
- **Plan:** test parses operations.md tunable values + asserts
  equality with code constants.

---

# Recently-landed fixes (provenance trail)

Surfaced during the entry-size-panic branch's debugging sessions.
Documented here so future contributors don't re-hit them.

| Commit | Fix | Why it matters |
|--------|-----|----------------|
| `bbba617` | bytestore: S3 checksum validation | Catches silent corruption at S3 read time. |
| `f42321f` | soak: TreeHead/Inclusion/Consistency handler wiring | Test harness was missing routes the SDK depends on. |
| `afedc0b` | sequencer: per-cycle work bound (`MaxEntriesPerCycle`) | Killed the `cycles=12→13→191` metrics-freshness pathology. |
| `c8324b8` | tessera: hand-rolled proof → `client.ProofBuilder` | Hand-rolled algorithm had three independent bugs at >256 leaves. |
| `0556d70` | shipper: throughput SLO + tuned defaults | 12 → 960 ent/sec (80×). |
| `0879ebd` | soak: builder loop + SMT handlers wired | Without this, soak's SMT validation 404'd. |
| `4ccad14` | tessera: antispam wired | Without it, sequencer + builder both AppendLeaf for the same hash and Tessera assigns distinct seqs → WAL `seqIndex` sparse → Shipper HWM stalls. |
| `7a9ceb4` | tests: reset `builder_cursor` in cleanTables | Previous test runs left cursor advanced; new test ran an empty `entry_index` and the builder skipped all entries. |
| `4c030b5` | shipper: HWM advances past StateManual + bounded `above` set | A single permanent failure stalled HWM and grew the holding set unboundedly (OOMKill within days at production rate). |
| `b3fd728` | smt: materialize PG leaves for `Tree.Root` / `Tree.GenerateMembershipProof` | SDK `collectLeafHashes` type switch doesn't handle PostgresLeafStore — `Tree.Root` returned empty-tree default regardless of leaf count. |
| `ea8f451` (reverted in `0ea1328`) | smt: incremental root via `ComputeDirtyRoot` | First attempt at §C3. Cold-cache PG round-trip bottleneck made batches 13s+ each → soak only committed first ~3 leaves. |
| `0ea1328` | smt: materialize-once-per-batch (replaces `ComputeDirtyRoot`) | O(N) per batch, O(1) per /v1/smt/root. Works to ~10⁷ leaves; §C3 replaces it for 10⁹. |
| `3a41d19` | builder: remove `CursorReader` in-memory cache | A rolled-back atomic tx left the in-memory cursor ahead of PG → silent skip of un-committed seqs. PG is now sole source of truth. |
| `d4a1f31` | tests/soak: poll `/v1/smt/root` until builder catches up | Removed false-negative drift caused by snapshotting the SMT mid-final-batch. |

---

## Working-order recommendation

Once C1 (1M soak) is green, the highest-leverage path is:

1. **C2 (PG-as-projection envelope)** — formalize the rebuild path
   and prove the RTO budget. Unlocks the rest of the scale work
   because it pins what we're allowed to keep in PG.
2. **B1 + B2 + B3 + B4 + B5 + B6 + B7 (read-path SLOs)** in
   parallel. The read API is the user-visible surface at 10B
   scale; each can be benchmarked independently.
3. **C3 (sharded/incremental SMT)** — load-bearing for 10⁹+ leaves.
4. **D1 (crash recovery)** + **D2 (witness degraded mode)** —
   correctness gates before performance.
5. **E1–E5 (lifecycle)** — important for 10-year operation but
   not blocking for first-year scale.
6. **F1 (multi-tenant fairness)** — required before opening the
   API to "hundreds of consumers."
7. **G1–G4 (observability)** — quality-of-life; necessary for ops
   but not structural.

---

## How to use this document

- **Adding an item:** open a section in the appropriate axis (§A–
  §G). Include SLO (or assertion), plan, why, and the test that
  will gate it.
- **Marking an item done:** flip the status, point Evidence at the
  commit and the test name, leave the rest in place.
- **Disagreeing with an item:** propose a replacement in the same
  PR that closes the old one. Don't delete history.
- **Violating an architectural invariant (§A–§E above):** reject
  the PR. Invariants are load-bearing; if you need to change one,
  document why in a separate PR that updates this doc first.
