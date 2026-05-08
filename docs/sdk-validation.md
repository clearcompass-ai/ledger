# SDK contract validation

Code-level audit of every ledger package against the SDK contract.
Evidence is gathered from `go list`, `go vet`, `go build`, `go doc`,
and compile-time interface assertions — never grep alone.

```
$ go list -m github.com/clearcompass-ai/attesta
github.com/clearcompass-ai/attesta v0.1.3

$ go vet ./...
(clean)

$ go build ./...
(clean)

$ go test -count=1 -short ./...
ok  21 packages with _test.go (admission, anchor, api, api/middleware,
   apitypes, builder, bytestore, cmd/ledger, cmd/submit-stamp,
   gossipnet, gossipstore, integration (skips without ATTESTA_TEST_DSN),
   integrity, lifecycle, sequencer, shipper, store, tessera, tests,
   tests/chaos, wal)
```

Per-package test counts are listed in [testing.md](testing.md).

## Per-package SDK surface

For each ledger package: which SDK packages it imports directly
(via `go list -f '{{.Imports}}' ./<pkg>/`) and the compile-time
interface anchors that catch drift.

| Package | SDK imports (direct) | Compile-time anchors |
|---|---|---|
| `admission/` | `core/envelope`, `crypto/cosign`, `crypto/signatures`, `types` | `admission/bls_quorum_verifier.go` (holds `*cosign.WitnessKeySet` directly — the SDK's encapsulated topology object). Cross-package alignment pinned by `admission/v011_contract_test.go`: `findings.WitnessAttested = (*findings.EquivocationFinding)(nil)` |
| `anchor/` | `core/envelope`, `crypto`, `crypto/signatures`, `log`, `types` | (uses SDK directly; no ledger-side interfaces to pin) |
| `api/` | `core/envelope`, `core/smt`, `crypto`, `crypto/admission`, `crypto/artifact`, `crypto/escrow`, `crypto/sct`, `crypto/signatures`, `exchange/policy`, `types` | `api/entries_read.go:380  var _ SeqHashLookup = EntryStore(nil)` |
| `apitypes/` | (none — leaf package, zero pgx, zero SDK) | (boundary types only) |
| `builder/` | `builder`, `core/envelope`, `core/smt`, `types` | `builder/cursor_reader.go:173  var _ BatchReader = (*CursorReader)(nil)` |
| `bytestore/` | (none — leaf package) | `bytestore/memory.go:111  var _ Store = (*Memory)(nil)`<br>`bytestore/gcs.go:335  var _ Backend = (*GCS)(nil)`<br>`bytestore/gcs.go:459  var _ TileBackend = (*GCSTiles)(nil)`<br>`bytestore/s3.go:392  var _ Backend = (*S3)(nil)` |
| `cmd/ledger/` | `builder`, `core/envelope`, `core/smt`, `crypto/cosign`, `crypto/signatures`, `did`, `exchange/policy`, `log`, `network` | (composition root; no interface pins) |
| `gossipnet/` | `crypto/cosign`, `crypto/middleware`, `did`, `gossip`, `gossip/findings`, `log`, `types`, `witness` | `gossipnet/sequencer_adapter.go:145  var _ sequencer.SplitIDIndexWriter = (*SequencerSplitIDAdapter)(nil)`<br>`gossipnet/sequencer_adapter.go:146  var _ sequencer.EntryLookupWriter = (*SequencerEntryLookupAdapter)(nil)`<br>`gossipnet/sequencer_adapter.go:147  var _ sequencer.SplitIDReplayCursor = (*SequencerReplayCursorAdapter)(nil)` |
| `gossipstore/` | `gossip`, `types` | `gossipstore/badger_store.go:486  var _ gossip.Store = (*BadgerStore)(nil)`<br>`gossipstore/badger_store.go:487  var _ gossip.Closeable = (*BadgerStore)(nil)`<br>`gossipstore/commitment_fetcher.go:119  var _ types.CommitmentFetcher = (*BadgerCommitmentFetcher)(nil)` |
| `integrity/` | (none — ledger-internal verifier) | `integrity/tessera_adapter.go:44  var _ Verifier = (*TesseraAdapter)(nil)` |
| `lifecycle/` | `core/envelope`, `log`, `types` | (no interface pins) |
| `sequencer/` | `core/envelope`, `crypto/artifact`, `crypto/escrow`, `schema` | (consumed via interfaces defined in this package) |
| `shipper/` | (none — ledger-internal migrator) | (no interface pins) |
| `store/` | `crypto/artifact`, `crypto/escrow`, `types` | `store/session_lookup.go:75  var _ middleware.SessionLookup = (*PostgresSessionLookup)(nil)`<br>`store/commitment_fetcher.go:207  var _ types.CommitmentFetcher = (*PostgresCommitmentFetcher)(nil)`<br>`store/fetcher.go:169  var _ bytestore.Reader = (*CompositeByteReader)(nil)` |
| `tessera/` | `types` | `tessera/embedded_appender.go:346  var _ AppenderBackend = (*EmbeddedAppender)(nil)`<br>`tessera/embedded_appender.go:398  var _ AppenderBackend = (*ReadOnlyAppender)(nil)`<br>`tessera/posix_tile_backend.go:166  var _ TileBackend = (*POSIXTileBackend)(nil)` |
| `wal/` | (none — ledger-internal storage primitive) | (no SDK contracts; isolated state machine) |
| `witness/` | `crypto/cosign`, `log`, `types` | (uses SDK directly) |

**Total: 19 compile-time interface anchors.** Reproduce with:

```sh
grep -rnE '^var _ ' admission/ anchor/ api/ builder/ bytestore/ \
                    gossipnet/ gossipstore/ integrity/ lifecycle/ \
                    sequencer/ shipper/ store/ tessera/ wal/ witness/ \
    | grep -v _test.go
```

A signature change in either side fails the build at the source
line carrying the assertion.

## What "code-level checks" means here

Three layers of evidence beyond grep:

1. **`go list` for the import graph.** The transitive import set
   is the unambiguous answer to "what SDK packages does this
   consume?" Grep can lie — `go list` cannot.
2. **`go vet` for static analysis.** Catches misuse the compiler
   accepts (printf format mismatches, mutex-by-value, unreachable
   code).
3. **`var _ Interface = (*Impl)(nil)` declarations.** A signature
   change in either side fails the build at the assertion's
   source line. The 19 anchors above are the canonical list;
   every one is currently green.

## Ownership boundary: SCT signing

`crypto/sct` (SDK) ships only the verifier-side surface:

- `crypto/sct.SigningPayload(...)` — canonical byte packer.
- `crypto/sct.Verify(...)` — verification.
- `crypto/sct.SignedCertificateTimestamp` — wire type.

`SignSCT` lives in the **ledger** at `api/sct.go:65` because the
ledger's private key never leaves the process. Confirmed by
`go doc github.com/clearcompass-ai/attesta/crypto/sct SignSCT`:
> doc: no symbol SignSCT in package …/crypto/sct

The SDK package header explicitly notes: *"The ledger (which
holds the private key) retains SignSCT in attesta-ledger/api/
sct.go."* This boundary is the right one — it lets the verifier
side stay portable while the signer side stays scoped to the
ledger.

## Integration tests against real GCS

Integration suites in `integration/` and `tests/` use
`requireRealGCS(t)`:

- `integration/grant_lifecycle_test.go:141` (function definition)
- `tests/helpers_test.go:733` (function definition)

The helper:

1. Skips when `ATTESTA_TEST_GCS_BUCKET` is unset.
2. **Refuses** fake-gcs (fails the test if
   `ATTESTA_TEST_GCS_ENDPOINT` is set). Integration tests must
   run against real GCS so production-shaped V4 presigned URLs,
   ADC chain, and Workload Identity stay pinned.
3. Constructs the bytestore via `bytestore.NewFromConfig` with
   `Backend: "gcs"` and no endpoint override — the same
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

Unit-level GCS tests in `bytestore/gcs_test.go` retain their
fake-gcs option (`ATTESTA_TEST_GCS_ENDPOINT`) so developers can
iterate on bytestore code locally without burning GCS quota.
Integration tests do NOT — production-shaped credential paths
are the only acceptable validation surface there.

## SDK upgrade cadence

When the SDK ships a new version:

1. Bump the pin in `go.mod` —
   `go get github.com/clearcompass-ai/attesta@vX.Y.Z`.
2. Run `go vet ./...` — catches signature drift at the 19
   interface anchors.
3. Run `go test -count=1 -race -short ./...` — every package's
   pinning tests run.
4. Run the integration suite (`ATTESTA_TEST_DSN` + ADC creds
   set) — exercises end-to-end against real Postgres + real
   GCS bucket.

The drift-detection test
`gossipnet/equivocation_binding_pin_test.go::TestEquivocationBinding_LedgerMatchesSDK`
catches the most common SDK-side change: a new domain separator
on a content hash. If the SDK adds one, this test fails before
any production traffic sees a key drift.
