# SDK v0.1.1 contract validation

Code-level audit of every ledger package against the SDK contract.
Evidence is gathered from `go list`, `go vet`, `go build`, and
compile-time interface assertions — never grep alone.

```
$ go list -m all | grep attesta
github.com/clearcompass-ai/attesta v0.1.1

$ go vet ./...
(clean)

$ go test -count=1 -short ./...
ok 20 packages
```

## Per-package SDK surface

For each ledger package: which SDK packages it imports, which SDK
contracts it depends on, and the compile-time interface checks that
catch drift.

| Package | SDK imports (via `go list -f '{{.Imports}}'`) | Compile-time anchors |
|---|---|---|
| `admission/` | `core/envelope`, `crypto/cosign`, `crypto/signatures`, `did`, `types` | `admission/bls_quorum_verifier.go` (holds `*cosign.WitnessKeySet` directly; v0.1.1 collapsed the prior single-impl `WitnessKeySet` interface + `StaticWitnessKeySet` wrapper into the SDK's encapsulated topology object). Compile-time alignment pinned by `admission/v011_contract_test.go`: `findings.WitnessAttested = (*findings.EquivocationFinding)(nil)` |
| `anchor/` | `core/envelope`, `crypto`, `crypto/signatures`, `log` | (uses SDK directly; no ledger-side interfaces to pin) |
| `api/` | `core/envelope`, `core/smt`, `crypto`, `crypto/admission`, `crypto/sct`, `crypto/signatures`, `crypto/artifact`, `crypto/escrow`, `exchange/policy`, `types` | `api/entries_read.go:381 var _ SeqHashLookup = EntryStore(nil)` |
| `apitypes/` | (none — leaf package, zero pgx, zero SDK) | (boundary types only) |
| `builder/` | `builder`, `core/envelope`, `core/smt`, `types` | `builder/cursor_reader.go:173 var _ BatchReader = (*CursorReader)(nil)` |
| `bytestore/` | (none — leaf package) | `bytestore/memory.go:109 var _ Store = (*Memory)(nil)`; `bytestore/gcs.go:299 var _ Backend = (*GCS)(nil)`; `bytestore/s3.go:340 var _ Backend = (*S3)(nil)` |
| `cmd/ledger/` | `builder`, `core/envelope`, `core/smt`, `crypto/cosign`, `did`, `gossip`, `log`, `types` | (composition root; no interface pins) |
| `gossipnet/` | `crypto/cosign`, `crypto/middleware`, `did`, `gossip`, `gossip/findings` | `gossipnet/sequencer_adapter.go:145-147` (3 sequencer-side interfaces) |
| `gossipstore/` | `gossip`, `types` | `gossipstore/badger_store.go:474-475` (`gossip.Store`, `gossip.Closeable`); `gossipstore/commitment_fetcher.go:121 var _ types.CommitmentFetcher = (*BadgerCommitmentFetcher)(nil)` |
| `integrity/` | (none — ledger-internal verifier) | `integrity/tessera_adapter.go:42 var _ Verifier = (*TesseraAdapter)(nil)` |
| `lifecycle/` | `core/envelope`, `log`, `types` | (no interface pins) |
| `sequencer/` | `core/envelope`, `crypto/artifact`, `crypto/escrow`, `schema` | (consumed via interfaces defined in this package) |
| `shipper/` | (none — ledger-internal migrator) | (no interface pins) |
| `store/` | `crypto/artifact`, `crypto/escrow`, `types` | `store/session_lookup.go:75 var _ middleware.SessionLookup = (*PostgresSessionLookup)(nil)`; `store/commitment_fetcher.go:208 var _ types.CommitmentFetcher = (*PostgresCommitmentFetcher)(nil)`; `store/fetcher.go:169 var _ bytestore.Reader = (*CompositeByteReader)(nil)` |
| `tessera/` | `types` | `tessera/embedded_appender.go:343,395` (`AppenderBackend`); `tessera/posix_tile_backend.go:167 var _ TileBackend = (*POSIXTileBackend)(nil)` |
| `wal/` | (none — ledger-internal storage primitive) | (no SDK contracts; isolated state machine) |
| `witness/` | `crypto/cosign`, `log`, `types` | (uses SDK directly) |

Total: 18 compile-time interface anchors.

## Compliance test (every Principle + Alignment)

[testing.md](testing.md) holds the canonical compliance map — every
Principle (P1-P15) and Alignment (A1-A13) anchored to a production
file:line + a test file:line that pins the contract.

## What "code-level checks" means here

Three layers of evidence beyond grep:

1. **`go list` for the import graph.** The transitive import set is
   the unambiguous answer to "what SDK packages does this consume?"
   Grep can lie — `go list` cannot.

2. **`go vet` for static analysis.** Catches misuse the compiler
   accepts (printf format mismatches, mutex-by-value, unreachable
   code, etc.).

3. **`var _ Interface = (*Impl)(nil)` declarations.** A signature
   change in either side fails the build at the source line. The
   18 anchors in the table are the canonical list — every one is
   currently green.

## What integration tests guarantee against real GCS

Integration tests in `integration/` and `tests/` use
`requireRealGCS(t)` (defined in
`integration/grant_lifecycle_test.go:149` and
`tests/helpers_test.go:678`) which:

1. Skips when `ATTESTA_TEST_GCS_BUCKET` is unset.
2. **Refuses** fake-gcs (fails the test if `ATTESTA_TEST_GCS_ENDPOINT`
   is set). Integration tests must run against real GCS to keep
   production behavior pinned (V4 presigned URLs, ADC chain,
   Workload Identity).
3. Constructs the bytestore via `bytestore.NewFromConfig` with
   `Backend: "gcs"` and no endpoint override — uses the same
   production code path the ledger uses at runtime.

Credential resolution (matches `bytestore.NewGCS`):

```
1. GOOGLE_APPLICATION_CREDENTIALS → service-account key file
2. gcloud application-default login → workstation default
3. Workload Identity → GKE / Cloud Run / GCE metadata
```

Required IAM on the test bucket:

```
storage.objects.create
storage.objects.get
storage.objects.list
storage.objects.delete
iam.serviceAccounts.signBlob # for V4 PresignGet
```

The unit-level GCS tests in `bytestore/gcs_test.go` retain their
fake-gcs option (`ATTESTA_TEST_GCS_ENDPOINT`) so developers can
iterate on bytestore code locally without burning GCS quota.
Integration tests do NOT — production-shaped credential paths are
the only acceptable validation surface there.

## SDK upgrade cadence

When the SDK ships a new version:

1. Bump the pin in `go.mod` — `go get github.com/clearcompass-ai/attesta@vX.Y.Z`
2. Run `go vet ./...` — catches signature drift at the 18 interface
   anchors.
3. Run `go test -count=1 -race -short ./...` — every package's
   pinning tests run.
4. Run the integration suite (`ATTESTA_TEST_DSN` + ADC creds set) —
   exercises end-to-end against a real Postgres + real GCS bucket.

Drift-detection test (`gossipnet/equivocation_binding_pin_test.go::
TestEquivocationBinding_LedgerMatchesSDK`) catches the most
common SDK-side change: a new domain separator on a content hash.
If the SDK adds one, this test fails before any production traffic
sees a key drift.
