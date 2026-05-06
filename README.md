# Attesta Ledger

Single-binary log ledger speaking the **Attesta** protocol. Receives
signed entries, sequences them via embedded Tessera, publishes
cryptographically-verified findings to a gossip network, serves
Merkle + SMT proofs and commitment lookups. Postgres-backed write
side; Badger-backed read projections for zero-pgx read paths.

The ledger is **domain-agnostic by construction** — every log DID,
database name, and bucket name is supplied via env vars at deployment
time. Domain-specific demos (judicial-network, supply-chain, identity,
etc.) live in their own repos and consume this generic 2-node topology
with their own values.

```
       Clients
          │
          ▼  POST /v1/entries
     ┌──────────────────────────────────┐
     │  api/  (HTTP handlers)           │   Auth → SizeLimit → handler
     │  go list -deps ./api/ | grep pgx │
     │     == 0 ✓                     │
     └────────────┬─────────────────────┘
                  │
                  ▼  wal.Submit (durable on local NVMe)
     ┌──────────────────────────────────┐
     │  wal/   (Badger WAL)             │   pending → sequenced → shipped
     └────────────┬─────────────────────┘
                  │
                  ▼  background sequencer drain
     ┌──────────────────────────────────┐
     │  sequencer/                      │   tessera.AppendLeaf →
     │                                  │   Postgres entry_index INSERT →
     │                                  │   Badger 0x0A + 0x0C projections
     └─┬────────────┬───────────────────┘
       │            │
       ▼            ▼
   ┌─────────┐  ┌─────────────────────────┐
   │ tessera │  │ gossipstore/            │
   │ tiles │  │  0x0A splitid index │  (detection trigger)
   │ +       │  │  0x0B equiv projection │  (verified findings)
   │ Postgres│  │  0x0C entry lookup │  (Pure CQRS read path)
   └─────────┘  │  0x0D replay HWM │  (boot back-population)
                └─────────────────────────┘
                          │
                          ▼  EquivocationScanner subscribes 0x0A
                ┌─────────────────────────┐
                │ gossipnet/              │   pull-based gossip
                │  /v1/gossip/since │   /v1/gossip/by-binding
                │  /v1/gossip/by-kind │   /v1/gossip/event/{id}
                └─────────────────────────┘
```

Single binary (`cmd/ledger`). Read-only sibling (`cmd/ledger-reader`)
serves the read endpoints without admission. Kubernetes target — one
replica per log DID, advisory-locked builder.

## Documentation

Every page links to the file:line that backs it.

| Page | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Runtime layout, package boundaries, the WAL → Sequencer → Tessera + projections data flow, gossip pipeline |
| [docs/api.md](docs/api.md) | Every HTTP route from `api/server.go`, request/response shapes, error semantics |
| [docs/configuration.md](docs/configuration.md) | Every `LEDGER_*` env var actually read in `cmd/ledger/main.go` |
| [docs/storage.md](docs/storage.md) | WAL state machine, gossipstore keyspace (`0x07 0x01..0x0D`), Postgres role |
| [docs/operations.md](docs/operations.md) | Boot order, Kubernetes deployment, test suite |
| [docs/observability.md](docs/observability.md) | OpenTelemetry wiring, the typed `error_class` taxonomy |
| [docs/testing.md](docs/testing.md) | Test plan, compliance map (named property → test), clean-extension rules |
| [docs/sdk-validation.md](docs/sdk-validation.md) | Per-package SDK contract validation (compile-time anchors, code-level checks) |
| [scripts/local/README.dev.md](scripts/local/README.dev.md) | Local 2-node dev + integration topology (real GCS / fake-gcs-server) |

## Compliance evidence

The architecture is enforced at compile time and verified at every
build:

```
$ go list -deps ./api/ | grep -E 'pgx|database/sql' | wc -l
0

$ go list -deps ./apitypes/ | grep -E 'pgx|database/sql' | wc -l
0

$ go vet ./...
(clean)

$ go test -count=1 -short ./...
ok ...admission ok ...api ok ...api/middleware
ok ...apitypes ok ...anchor ok ...builder
ok ...bytestore ok ...cmd/ledger ok ...cmd/submit-stamp
ok ...gossipnet ok ...gossipstore ok ...integration
ok ...integrity ok ...lifecycle ok ...sequencer
ok ...shipper ok ...store ok ...tessera
ok ...tests ok ...wal
```

Read-side handlers consume the SDK's `types.CommitmentFetcher`
interface. Production wiring uses the Badger-backed implementation;
both implementations satisfy the same SDK type at compile time:

```
gossipstore/commitment_fetcher.go:121
    var _ types.CommitmentFetcher = (*BadgerCommitmentFetcher)(nil)
store/commitment_fetcher.go:208
    var _ types.CommitmentFetcher = (*PostgresCommitmentFetcher)(nil)
```

## Quick start

```sh
# Build
go build ./cmd/ledger

# Required env vars (cmd/ledger/main.go: loadConfig)
export LEDGER_DATABASE_URL="postgres://..."
export LEDGER_LOG_DID="did:web:ledger.example"
export LEDGER_BYTE_STORE_BACKEND=s3 # or gcs
export LEDGER_BYTE_STORE_S3_BUCKET=...

# Run
./ledger
```

Full env-var reference: [docs/configuration.md](docs/configuration.md).

For local development against a 2-node topology with real GCS or
`fake-gcs-server`, see [scripts/local/README.dev.md](scripts/local/README.dev.md)
or run `make help`.

## License

Proprietary. ClearCompass AI.
