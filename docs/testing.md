# Test plan

How the ledger is tested today, and how to extend the test surface
cleanly when adding new behavior. Owns: test layout, run modes,
the compliance map, and clean-extension rules. Compile-time
interface anchors live in [sdk-validation.md](sdk-validation.md);
metric/error taxonomy in [observability.md](observability.md).

## Test layout

```
admission/*_test.go        SDK-validation pin tests (NFC, signature, resolver, BLS)
anchor/*_test.go           External anchor publisher
api/*_test.go              HTTP handler tests (routes, idempotency, error_class)
api/middleware/*_test.go   Auth middleware (SessionLookup interface)
apitypes/*_test.go         ErrorClass taxonomy + value-type round-trips
builder/*_test.go          Commitment publisher loop
bytestore/*_test.go        GCS / S3 / memory backend conformance
cmd/ledger/*_test.go       Pool sizing, boot config sanity
cmd/submit-stamp/*_test.go SCT verify path (matches the API path)
gossipnet/*_test.go        Gossip pipeline (scanner, publisher, sink, anti-entropy, override)
gossipstore/*_test.go      Badger keyspace + projections + replay HWM
integration/*_test.go      Postgres-gated integration (skips without ATTESTA_TEST_DSN)
integrity/*_test.go        Boot reconciliation + sample-verify detector
lifecycle/*_test.go        Graceful shutdown chain components
sequencer/*_test.go        WAL drain + boot replayer
shipper/*_test.go          WAL → bytestore migrator
store/*_test.go            Postgres-backed stores (gated by ATTESTA_TEST_DSN)
tessera/*_test.go          Embedded Tessera appender
tests/*_test.go            End-to-end (HTTP + Postgres + Badger) — gated
tests/chaos/*_test.go      Chaos suite (lifecycle, WAL durability, shutdown ordering, inject)
wal/*_test.go              Badger WAL state machine
```

**Total: 703 test functions across 21 packages with `_test.go`.**
Reproduce with:

```sh
grep -rE '^func Test[A-Z]' --include='*_test.go' . | wc -l
find . -name '*_test.go' -not -path './.git/*' -exec dirname {} \; | sort -u | wc -l
```

Per-package breakdown (`grep -hE '^func Test[A-Z]' <pkg>/*_test.go | wc -l`):

| Package | Tests |
|---|---|
| admission | 28 |
| anchor | 3 |
| api | 99 |
| api/middleware | 7 |
| apitypes | 10 |
| builder | 8 |
| bytestore | 79 |
| cmd/ledger | 21 |
| cmd/submit-stamp | 8 |
| gossipnet | 52 |
| gossipstore | 42 |
| integration | 11 |
| integrity | 13 |
| lifecycle | 26 |
| sequencer | 30 |
| shipper | 15 |
| store | 43 |
| tessera | 26 |
| tests | 152 |
| tests/chaos | 10 |
| wal | 20 |

## Run modes

```sh
# Fast — skips anything that needs Postgres / Docker. Default for CI.
go test -count=1 -short ./...

# Full — same gates, but with race detector
go test -count=1 -race -short ./...

# Static analysis
go vet ./...

# Postgres-backed integration tests (needs a live DB)
export ATTESTA_TEST_DSN="postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable"
go test -count=1 ./integration/... ./tests/...

# GCS tests against fake-gcs-server
./scripts/run-gcs-tests.sh

# GCS tests against REAL GCS (validates production code path)
export ATTESTA_TEST_GCS_BUCKET=my-test-bucket
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
./scripts/run-gcs-tests-real.sh

# S3 tests against rustfs (S3-compatible)
./scripts/run-bytestore-tests-rustfs.sh

# S3 tests against REAL S3
export ATTESTA_REAL_S3_BUCKET=my-test-bucket
./scripts/run-bytestore-tests-real-s3.sh

# Soak (24h-style)
./scripts/run-soak.sh
```

## Compliance map

For every named architectural property the ledger advertises in
[architecture.md](architecture.md), this table maps the production
code that implements it to the test that pins the contract.

### Ledger architectural properties

| Property | Production code | Test |
|---|---|---|
| Dumb Ledger (SDK validates) | `api/commitments.go::allowedCommitmentSchemas` (closed-set dispatch at line 167); `api/submission.go` calls only SDK primitives (`envelope.Deserialize`, `entry.Validate`, `admission.CheckNFC`, `admission.VerifyEntrySignature`, `sdkadmission.VerifyStamp`) | `admission/nfc_check_test.go` (multiple sub-tests pinning SDK validation paths); `api/submission_test.go::TestV1Handler_HappyPath_ReturnsValidSCT` |
| Pure SDK (zero tech debt) | `go.mod` pins `attesta v0.1.3`; the 19 compile-time interface anchors in [sdk-validation.md](sdk-validation.md); cross-package contract pinned by `admission/v011_contract_test.go` + `gossipnet/v011_contract_test.go` | `gossipnet/equivocation_binding_pin_test.go::TestEquivocationBinding_LedgerMatchesSDK` (drift pin between ledger code and SDK helper) |
| Melt-Proof admission | `wal/committer.go::Submit` returns `ErrQueueFull`; `api/submission.go` maps to 503 + `Retry-After`; `gossipnet/wiring.go:398 NewBufferedSink` with `DropPolicyDropOldest` | `api/submission_test.go::TestV1Handler_WALQueueFull_Returns503` |
| SCT as SLA | `api/sct.go:65 SignSCT`; `api/submission.go` returns 202 + SCT after WAL fsync | `api/submission_test.go::TestV1Handler_HappyPath_ReturnsValidSCT`; `cmd/submit-stamp/main_test.go::TestVerifyClientSCT_MatchesAPIPath` |
| Deterministic idempotency | `wal/meta.go::LogTimeMicros` (8 bytes inside the 29-byte `metaEncodedSize`); `api/submission.go:460` idempotency probe via `wal.MetaState` | `api/submission_test.go::TestV1Handler_SemanticIdempotency` (full claim-equivalency assertion chain) |
| Hot-path isolation | `api/submission.go` handler does WAL fsync only; sequencer goroutine owns Tessera + Postgres + Badger projections (`sequencer/loop.go:187 insertEntryIndex`) | `sequencer/sequencer_test.go::TestSequencer_processOne_HappyPath` |
| Static CT API (edge offload) | `cmd/ledger/main.go:77` imports `transparency-dev/tessera/storage/posix`; `tessera/embedded_appender.go` | `tessera/embedded_appender_test.go::TestEmbeddedAppender_*` |
| Pure CQRS | `gossipstore/commitment_fetcher.go::BadgerCommitmentFetcher`; `api/commitments.go` consumes `types.CommitmentFetcher`; `gossipstore/projections.go::ListEntryLookupEntriesAt` (line 354) | `api/commitments_test.go::TestCommitmentLookup_EndToEnd_BadgerCQRS`; `TestCommitmentLookup_EndToEnd_EquivocationCase`. Compliance check: `go list -deps ./api/ \| grep pgx \| wc -l == 0` |
| Pull-based gossip | Five gossip GET routes at `api/server.go:361–365` | `api/server_test.go::TestServer_GossipFeedRoutes_Mounted`; `TestServer_GossipFeedByBinding_NotMountedWhenFeedNil` |
| SRE-grade observability | `api/errors.go::writeTypedError`; `apitypes/apitypes.go::ErrorClass` taxonomy (33 typed values; see [observability.md](observability.md)) | `api/errors_test.go::TestWriteTypedError_IncrementsCounter`; `TestWriteTypedError_DistinctClassesIncrementSeparately`; `apitypes/error_class_test.go::TestErrorClass_DistinctStrings` |
| Graceful teardowns | `lifecycle.ShutdownChain` (sync.OnceFunc-protected close fns; full step ordering in [operations.md](operations.md)); `sequencer/sequencer.go:340–356 wg.Wait` for replayer | `sequencer/replay_test.go::TestSequencer_Run_DrainsReplayerOnCtxCancel`; `lifecycle/archive_reader_test.go` |
| Test integrity | Race detector + 703 tests across 21 packages, all green | `go test -race -short ./...` (meta-property; the test suite IS the test) |
| Two clocks (commit vs transparency) | `POST /v1/cosign` (synchronous, server.go:351) vs `POST /v1/gossip` (async, server.go:357). Distinct types: `cosign.Purpose` ≠ `gossip.Kind` | `gossipnet/cross_ledger_test.go::TestCrossLedger_STHRoundTrip` |
| Unified SDK verify | `admission.VerifyEntrySignature` in `api/submission.go`; `BadgerCommitmentFetcher` returns SDK `types.EntryWithMetadata`; `cmd/submit-stamp/main_test.go` uses `sdksct.Verify` | `cmd/submit-stamp/main_test.go::TestVerifyClientSCT_MatchesAPIPath`; `admission/sdk_resolver_pin_test.go` |
| Per-originator parallelism | `gossipstore/badger_store.go:116 originatorLocks []sync.Mutex` (sharded FNV-1a) | `gossipstore/badger_store_test.go::TestAppend_Idempotent`; `TestAppendChain_HeadAdvances` |

### Trust & equivocation properties

| Property | Production code | Test |
|---|---|---|
| STH as universal anchor | `types.TreeHead` consumed via `tessera.NewEmbeddedAppender`; `integrity/integrity_test.go::TestVerifier_HashAt_RoundTrip` | `integrity/integrity_test.go::TestVerifier_HashAt_RoundTrip`; `TestVerifier_HashAt_DistinctSeqs` |
| Decentralized threshold witnessing | `witness/serve.go` uses `cosign.NewWitnessHandler`; `witness/head_sync.go` uses `cosign.WitnessCollector` | `gossipnet/escrow_override_test.go::TestEscrowOverrideService_HappyPath` (K-of-N); `gossipnet/witness_keys_test.go` |
| Deterministic equivocation detection | `gossipnet/equivocation_scanner.go` builds `findings.NewEntryCommitmentEquivocationFinding` | `gossipnet/equivocation_scanner_test.go::TestEquivocationScanner_DetectsAndPublishes`; `gossipnet/equivocation_monitor_test.go` |
| O(1) SplitID sentry | Scanner subscribes to Badger 0x0A (`gossipnet/equivocation_scanner.go`); read serves from 0x0C (`gossipstore/commitment_fetcher.go::BadgerCommitmentFetcher`) | `api/commitments_test.go::TestCommitmentLookup_EndToEnd_EquivocationCase`; `gossipnet/equivocation_scanner_test.go::TestEquivocationScanner_DetectsAndPublishes`; `gossipstore/entry_lookup_test.go::TestWriteAndListEntryLookupEntriesAt_EquivocationOrder` |
| Pure pull-based gossip | Five gossip GET routes at `api/server.go:361–365` | `api/server_test.go::TestServer_GossipFeedRoutes_Mounted` |
| Non-blocking gossip sinks | `gossipnet/wiring.go:398 NewBufferedSink` + `Policy: DropPolicyDropOldest` + `wgSenders` | `gossipnet/wiring_test.go::TestBuild_*`; `gossipnet/cross_ledger_test.go` |
| Universal domain separation | SDK side; consumed via `cosign.Sign` / `cosign.Verify` in `gossipnet/equivocation_scanner.go` | `gossipnet/cross_ledger_test.go::TestCrossLedger_STHRoundTrip` |
| Zero-trust dual verification | Handler returns canonical_bytes_hex; `gossipstore/commitment_fetcher.go:103` returns independent byte copies via `append([]byte(nil), ...)` | `api/commitments_test.go::TestCommitmentLookup_EndToEnd_BadgerCQRS`; `gossipstore/commitment_fetcher_test.go::TestBadgerCommitmentFetcher_CanonicalBytesAreCopies` |
| Cryptographic topologies | SDK `gossip/findings/originator_rotation.go` consumed via gossipnet | `gossipnet/cross_ledger_test.go` (originator/key-set rotation paths) |
| Strict error dimensionality | `apitypes/apitypes.go::ErrorClass` (33 typed values); `api/errors.go::writeTypedError` | `apitypes/error_class_test.go` (5 tests); `api/errors_test.go` (6 tests) |
| Purpose vs Kind isolation | Distinct routes: `POST /v1/cosign` (cosign.Purpose) vs `POST /v1/gossip` (gossip.Kind). Distinct types in SDK `cosign` and `gossip` packages | `api/server_test.go::TestServer_*` (each route mount tested independently) |
| Two-tier quorum (Validate vs ValidateAgainstQuorum) | SDK side; consumed via `findings.Validate` + `findings.ValidateAgainstQuorum` in `gossipnet/equivocation_publisher.go` | `gossipnet/equivocation_publisher_test.go::TestEquivocationPublisher_RejectsZeroNetworkID` |
| Idempotent eventual consistency | `gossipstore/projections.go::SetSplitIDReplayHWM` monotonic; `WriteEntryLookupEntry` idempotent on identical inputs | `gossipstore/replay_hwm_test.go::TestSplitIDReplayHWM_RepeatSetSameSeqIsIdempotent`; `TestSplitIDReplayHWM_BackwardsSetIsNoOp`; `gossipstore/entry_lookup_test.go::TestWriteEntryLookupEntry_Idempotent` |

## Clean-extension rules

When adding a new feature, the test surface expands by following
the existing patterns. The rules below preserve the compliance
properties above — every entry in the table stays anchored.

### Rule 1: Define the consumer-side interface in `api/ports.go`

If your feature adds a read-side handler that needs new data:

```go
// api/ports.go
type MyFeatureFetcher interface {
    FetchSomething(ctx context.Context, key [32]byte) (*apitypes.SomeRow, error)
}
```

The implementation can live in `store/` (Postgres) or
`gossipstore/` (Badger). Both must add a compile-time check (see
[sdk-validation.md](sdk-validation.md)):

```go
// store/my_feature.go
var _ api.MyFeatureFetcher = (*PostgresMyFeatureFetcher)(nil)
```

This pins the contract at build time. The test for the fetcher
lives in the impl package; the test for the handler lives in
`api/`.

**Why:** keeps `go list -deps ./api/ | grep pgx | wc -l == 0`
(the Pure CQRS guarantee for the commitment lookup hot path).

### Rule 2: Move shared value types to `apitypes/`

Anything passed across the api ↔ store boundary is a value type
(no pgx fields):

```go
// apitypes/apitypes.go
type SomeRow struct {
    ID    int64
    Bytes []byte
    // ... pure stdlib types only
}
```

If the type would have pulled in `pgx`, that's a sign the field
shape is wrong — pgx-tagged types belong in `store/`, not the
boundary.

### Rule 3: Every error-emission site goes through `writeTypedError`

```go
// In your handler:
writeTypedError(ctx, w, apitypes.ErrorClassMyNewClass, http.StatusBadRequest, "bad input")
```

If your feature has a NEW failure mode that doesn't fit the
existing 33 ErrorClass values, ADD a new constant in
`apitypes/apitypes.go`:

1. New `const ErrorClassMyNewClass`.
2. Add a case to `String()` returning a kebab-case literal.
3. Add the new constant to `allErrorClasses` in
   `apitypes/error_class_test.go` so the cardinality test catches
   collisions.

**Why:** `TestErrorClass_DistinctStrings` enforces the invariant
that every constant produces a distinct attribute value.

### Rule 4: Test routes both ways — wired AND nil-tolerant

For every new route:

```go
// api/server_test.go
func TestServer_MyFeatureRoute_MountedWhenSet(t *testing.T) {
    called := false
    h := func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }
    srv := newTestServer(t, Handlers{MyFeature: h})
    // ... GET /v1/my-feature → asserts called == true
}

func TestServer_MyFeatureRoute_NotMountedWhenNil(t *testing.T) {
    srv := newTestServer(t, Handlers{}) // MyFeature unset
    // ... GET /v1/my-feature → asserts 404 (not 500 or panic)
}
```

**Why:** prevents a future refactor from accidentally dropping the
mount OR introducing a nil-handler panic.

### Rule 5: Idempotent writes need an explicit re-write test

If you add a new Badger projection or table:

```go
func TestWriteMyProjection_Idempotent(t *testing.T) {
    st := testStore(t)
    for i := 0; i < 3; i++ {
        if err := st.WriteMyProjection(ctx, key, value); err != nil {
            t.Fatalf("iter=%d: %v", i, err)
        }
    }
    rows, _ := st.ListMyProjection(ctx, key)
    if len(rows) != 1 {
        t.Errorf("got %d rows, want 1 (idempotent)", len(rows))
    }
}
```

**Why:** preserves idempotent eventual consistency — re-receive
is a no-op, not a corruption.

### Rule 6: New gossip event Kind needs a binding-stability test

If you add a new `gossip.Kind`, the per-Kind binding key must
remain stable. Anchor with:

```go
func TestMyKind_BindingStable(t *testing.T) {
    binding := findings.MyKindBinding(...)
    for i := 0; i < 10; i++ {
        if got := findings.MyKindBinding(...); got != binding {
            t.Fatalf("iter=%d: drift", i)
        }
    }
}
```

Use the SDK helper — never re-implement. See
`gossipnet/equivocation_binding_pin_test.go` for the canonical
pattern.

### Rule 7: Concurrency-touching code needs `-race` discipline

New goroutine-spawning code must add an explicit drain test:

```go
func TestMyFeature_GracefulShutdown(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan struct{})
    go func() {
        defer close(done)
        myFeature.Run(ctx)
    }()
    time.Sleep(20 * time.Millisecond)
    cancel()
    select {
    case <-done:
        // good
    case <-time.After(2 * time.Second):
        t.Error("goroutine leaked on ctx cancel")
    }
}
```

**Why:** preserves graceful teardown. The release-engineering
discipline is that `go test -race` must catch leaks before they
ship.

### Rule 8: Don't extend `tests/` or `integration/` for unit-level pinning

`tests/` and `integration/` require Postgres + Docker. They run on
CI's "long" lane. Unit-level pinning belongs alongside the package
under test (e.g., `api/foo_test.go` for `api/foo.go`).

```sh
# Unit only — no Postgres needed
go test -count=1 -short ./...

# Integration — needs ATTESTA_TEST_DSN set
go test -count=1 ./integration/... ./tests/...
```

The `t.Skip` pattern is how integration tests advertise their
gate (e.g., `requireDB(t)` returns `*pgxpool.Pool` or skips).
Follow the existing pattern.

## What to delete vs keep

When refactoring, the following files should follow the project's
"no temporary fixes" rule:

| Pattern | Action |
|---|---|
| Stale migration scripts (e.g., `script/run.sh` for old SDK migration) | Delete — they are commit-history artifacts, not runtime tools |
| Unused configuration files (e.g., `config/ledger.yaml` not read by any Go code) | Delete — ledger reads env only |
| Duplicate compose files | Consolidate — one canonical compose per scenario |
| `.bak` files or rotated backups | Delete — git is the backup |
| Test files that contain `TODO` or `FIXME` for behavior never wired | Delete the test, OR wire the behavior. No half-finished tests |

## Filesystem guarantees

```
docs/                  documentation (this folder)
scripts/               runnable utilities
scripts/local/         docker-compose stacks for local + integration + test harness
integration/           Go test sources (Postgres-gated; uses scripts/local/docker-compose.testharness.yml)
tests/                 Go end-to-end test sources (Postgres-gated)
tests/chaos/           chaos suite (lifecycle, WAL durability, shutdown ordering)
```

No `script/` (singular). No `config/`. No `deployment/`. Single
source of truth per concern.
