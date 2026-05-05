# Ortholog Operator

Single-binary log operator. Receives signed entries, sequences them via
embedded Tessera, publishes cryptographically-verified findings to a
gossip network, serves Merkle + SMT proofs and commitment lookups.
Postgres-backed write side; Badger-backed read projections for
zero-pgx read paths.

```
       Clients
          │
          ▼  POST /v1/entries
     ┌──────────────────────────────────┐
     │  api/  (HTTP handlers)           │   Auth → SizeLimit → handler
     │  go list -deps ./api/ | grep pgx │
     │     == 0   ✓                     │
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
   │ tiles   │  │  0x0A splitid index     │  (detection trigger)
   │ +       │  │  0x0B equiv projection  │  (verified findings)
   │ Postgres│  │  0x0C entry lookup      │  (Pure CQRS read path)
   └─────────┘  │  0x0D replay HWM        │  (boot back-population)
                └─────────────────────────┘
                          │
                          ▼  EquivocationScanner subscribes 0x0A
                ┌─────────────────────────┐
                │ gossipnet/              │   pull-based gossip
                │  /v1/gossip/since       │   /v1/gossip/by-binding
                │  /v1/gossip/by-kind     │   /v1/gossip/event/{id}
                └─────────────────────────┘
```

Single binary (`cmd/operator`). Read-only sibling (`cmd/operator-reader`)
serves the read endpoints without admission. Kubernetes target — one
replica per log DID, advisory-locked builder.

## Documentation

Every page links to the file:line that backs it.

| Page | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Runtime layout, package boundaries, the WAL → Sequencer → Tessera + projections data flow, gossip pipeline |
| [docs/api.md](docs/api.md) | Every HTTP route from `api/server.go`, request/response shapes, error semantics |
| [docs/configuration.md](docs/configuration.md) | Every `OPERATOR_*` env var actually read in `cmd/operator/main.go` |
| [docs/storage.md](docs/storage.md) | WAL state machine, gossipstore keyspace (`0x07 0x01..0x0D`), Postgres role |
| [docs/operations.md](docs/operations.md) | Boot order, Kubernetes deployment, test suite |
| [docs/observability.md](docs/observability.md) | OpenTelemetry wiring, the typed `error_class` taxonomy |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

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
ok  ...admission       ok  ...api            ok  ...api/middleware
ok  ...apitypes        ok  ...anchor         ok  ...builder
ok  ...bytestore       ok  ...cmd/operator   ok  ...cmd/submit-stamp
ok  ...gossipnet       ok  ...gossipstore    ok  ...integration
ok  ...integrity       ok  ...lifecycle      ok  ...sequencer
ok  ...shipper         ok  ...store          ok  ...tessera
ok  ...tests           ok  ...wal
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
go build ./cmd/operator

# Required env vars (cmd/operator/main.go: loadConfig)
export OPERATOR_DATABASE_URL="postgres://..."
export OPERATOR_LOG_DID="did:web:operator.example"
export OPERATOR_BYTE_STORE_BACKEND=s3       # or gcs
export OPERATOR_BYTE_STORE_S3_BUCKET=...

# Run
./operator
```

Full env-var reference: [docs/configuration.md](docs/configuration.md).

## License

Proprietary. ClearCompass AI.
