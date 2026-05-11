# Production Readiness — Ledger

This is the versioned plan for making the Ledger production-grade for a
**10-billion-entry / 10-year deployment** serving **50 exchanges and
500 API clients**. The list is canonical: pick the next item from here,
not from conversation memory.

When status changes, update this file in the same commit that lands the
work. The "Evidence" column for a completed item must point at the
commit or test that locks it in.

---

## Scope and ground rules

**Target:** sustained admission + integration of ~10B entries over 10
years on the published API contract, with operator-observable SLOs
that hold under steady-state load, retry storms, single-node faults,
and graceful shutdown.

**Out of scope here:** multi-region replication, fraud-proof
generation by third parties, SDK ergonomics. These have their own
tracks.

**Ground rules:**
1. Every item is gated by a test. No "fixed it in production, trust
   me" entries.
2. Every SLO is a named constant in the relevant package (see
   `shipper/slo.go` for the pattern), referenced by the test, and
   documented for ops dashboards.
3. Negative-control tests prove the gate has discriminating power:
   the same test with deliberately-pathological config MUST violate
   the SLO.

---

## Status legend

- ✅ **Done** — landed + gated by a test on `main` (or designated
  feature branch).
- 🟡 **In progress** — branch open or commits landed but the gating
  test isn't green yet.
- ⬜ **Pending** — not started.

---

## Scaffolds (shared test infrastructure)

| ID | Scope | Reused by | Status |
|----|-------|-----------|--------|
| **A** | WAL bench harness (in-memory + flake-able Badger) | Items 4, 5, 6, 8 | ⬜ |
| **B** | Shipper bench harness (`shipper/bench_harness_test.go`) | Items 1, 4, 9 | ✅ commit `0556d70` |
| **C** | Multi-component soak with fault injection | Items 7, 8, 10 | 🟡 soak exists; fault injection doesn't |

---

## Top-10 items

### 1 — Shipper throughput SLO ✅

- **SLO:** `shipper.SLOThroughputEntriesPerSec = 500` (~14% of S3
  single-prefix ceiling).
- **Test:** `TestShipperThroughput_MeetsSLO` + negative-control
  `TestShipperThroughput_SLO_DetectsRegression`.
- **Defaults tuned:** `PollInterval` 1s → 100ms,
  `MaxInFlight` 4 → 32.
- **Measured:** 12 ent/sec → 960 ent/sec (80× improvement, 1.9× over SLO).
- **Evidence:** commit `0556d70`.

### 2 — Admit → tree integration p99 latency SLO ⬜

- **SLO (proposed):** p99 of `admit_time → head.TreeSize >= seq` ≤
  2s steady-state with 1ms bytestore, 50ms-per-PUT real S3 equivalent.
- **Plan:** harness measures wall-clock per-entry from POST 202 to
  the seq appearing in `/v1/tree/head`. Reuses Scaffold B + extends
  the bench harness to include sequencer + Tessera.
- **Why next:** highest operator-visible latency; closes the gap
  between "shipper is fast" (item 1) and "user-visible behavior is
  fast."

### 3 — Crash-recovery correctness ⬜

- **Assertion:** kill -9 during integration; on restart, **every
  accepted entry is durable AND every committed sequence appears in
  the tree with a valid inclusion proof, with no holes**.
- **Plan:** Scaffold A (in-memory + flake-able Badger). Inject crash
  at: (a) post-WAL-write pre-sequence, (b) post-sequence
  pre-Tessera-append, (c) post-Tessera-append pre-MarkShipped, (d)
  shipper mid-batch.
- **Why critical:** a 10-year deployment WILL crash. Today
  `ReconcileHWM` exists at `shipper/shipper.go:192` but is not
  fault-tested. Bit-exact recovery is the highest-stakes correctness
  gap.

### 4 — WAL backpressure SLO ⬜

- **SLO (proposed):** under sustained admission at 2× the WAL's
  sequencing rate, the API returns HTTP 429 within p99 ≤ 50ms; **no
  panics, no silent drops**.
- **Plan:** Scaffold A. Load generator exceeds sequencer drain rate;
  measure 429 latency, validate `Retry-After`, validate WAL counters
  stay bounded.
- **Plumbing today:** `ErrQueueFull` (`wal/errors.go:13`) + 429
  return (`api/submission.go:604`). No scale test.

### 5 — Memory envelope SLO at 1M+ entries ⬜

- **SLO (proposed):** at steady-state with N entries, RSS ≤ f(N)
  (specific bound TBD from measurement); zero growth in the post-drain
  quiescent window.
- **Plan:** extend soak (Scaffold C) to 1M and 10M; track RSS,
  Badger LSM size, Tessera tile cache size.
- **Why important:** 10B entries × even 100 bytes per entry of
  resident state = 1TB working set. Must validate sublinear growth.

### 6 — Witness quorum degraded-mode behavior ⬜

- **Assertion:** under K-of-N witness fault (k-1 witnesses fail), the
  log MUST refuse to publish a cosigned checkpoint AND surface the
  degraded state through a counter ops can alert on. Under recovery
  (witness comes back), the next checkpoint cycle MUST succeed.
- **Plan:** existing `newWitnessFixture(t, netID, N)` already
  supports N-witness fixtures; needs fault injection (close one
  witness's listener mid-test) and the assertion suite.

### 7 — Tessera graceful shutdown drain SLO ⬜

- **SLO (proposed):** on `SIGTERM`, all admitted entries reach the
  tree within p99 ≤ 30s OR the binary returns a non-zero exit code.
  Zero entries lost.
- **Plan:** integration test with controlled `context.Cancel` and
  goroutine-leak detection (`uber-go/goleak`).
- **Landmine documented:** `tests/testserver_tessera_test.go:159`
  explicitly rejects `context.WithoutCancel` because it leaks Tessera
  goroutines. The SLO has to navigate that constraint.

### 8 — OTel instrumentation completeness audit ⬜

- **Assertion:** every counter / histogram an ops dashboard needs
  is exported via OTel with a documented metric name and stable
  units. No counter exists in code that isn't exposed; no exposed
  counter is undocumented.
- **Plan:** script that diffs (a) counters in `shipper/instruments.go`,
  `sequencer/instruments.go`, `tessera/embedded_appender.go`,
  `wal/...` against (b) documented metrics in
  `docs/observability.md`. Fail on mismatch.

### 9 — Chaos / fault-injection coverage ⬜

- **Assertion:** the soak survives bytestore 5xx storms (10% PUT
  failure rate for 30s), WAL `fsync` slowness (200ms p99),
  Tessera batch latency spikes, without missing entries or stuck HWM.
- **Plan:** Scaffold C. Adds a fault injector that wraps bytestore /
  WAL / Tessera at the interface boundary; existing `benchBytestore`
  pattern with `WithFailRate` is the seed.

### 10 — Configuration-drift gate ⬜

- **Assertion:** production defaults match what `docs/operations.md`
  documents. If a default in code changes, either the docs change in
  the same commit or CI fails.
- **Plan:** test that parses operations.md tunable values and asserts
  equality with code constants. Catches "shipper.MaxInFlight is 32 in
  code but docs still say 4."

---

## Recent fixes that are NOT in the top-10 (already done)

These were correctness fixes that gate the top-10 work; they're
documented here so the next session has provenance.

| Commit | Fix | Why it's not an "item" |
|--------|-----|------------------------|
| `bbba617` | bytestore: S3 checksum validation | Single config gate; no SLO needed beyond regression test |
| `f42321f` | soak: TreeHead/Inclusion/Consistency handler wiring | Test harness fix |
| `afedc0b` | sequencer: per-cycle work bound | Cycle-budget pathology fix; the SLO it implies (metrics freshness) is implicit in items 2 + 8 |
| `c8324b8` | tessera: hand-rolled proof → `client.ProofBuilder` | Correctness fix, gated by `TestTesseraAdapter_InclusionProof_*` |
| `0879ebd` | soak: builder loop + SMT handlers wired | Test harness completeness; SMT validation in soak is part of scaffold C, but the wiring itself was a 1-commit fix |

---

## Working order recommendation

After the current 100K soak goes green (validates items 1 + the
correctness fixes compose cleanly), the highest-leverage path is:

1. **Item 3 (crash recovery)** — pre-requires Scaffold A. Highest
   correctness stakes for a 10-year deployment.
2. **Item 2 (admit→tree p99)** — extends Scaffold B. Operator-visible.
3. **Items 4, 5, 6** in parallel once scaffolds are seeded.
4. **Items 7, 8, 9, 10** as the long tail.

This order optimizes for **correctness gates before performance
gates** — performance regressions can be tuned; correctness
regressions corrupt the log.

---

## How to use this document

- **Adding an item:** open a section under "Top-10 items" (or extend
  past 10 if needed; the number is not magic). Include SLO (or
  assertion), plan, why, and tests-needed.
- **Marking an item Done:** flip the status, fill the Evidence line
  with the commit and the test name, leave the rest in place.
- **Disagreeing with an item:** propose a replacement in the same PR
  that closes the old one. Don't delete history.
