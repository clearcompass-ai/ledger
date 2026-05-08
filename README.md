# Attesta Ledger

Single-binary log ledger speaking the **Attesta** protocol. Receives
signed entries, sequences them via embedded Tessera, publishes
cryptographically-verified findings to a gossip network, serves
Merkle + SMT proofs and commitment lookups. Postgres-backed write
side; Badger-backed read projections power the zero-pgx
`/v1/commitments/by-split-id` read path.

The ledger is **domain-agnostic by construction** — every log DID,
database name, and bucket name is supplied via env vars at
deployment time. Domain-specific demos (judicial-network,
supply-chain, identity) live in their own repos and consume this
generic 2-node topology with their own values.

```
        Clients
           │
           ▼  POST /v1/entries
      ┌────────────────────────────────────┐
      │  api/   (HTTP handlers)            │   Auth → SizeLimit → handler
      │  go list -deps ./api/ | grep pgx   │   pgx-free read path
      │     == 0 ✓                         │
      └────────────┬───────────────────────┘
                   │
                   ▼  wal.Submit (durable on local NVMe)
      ┌────────────────────────────────────┐
      │  wal/   (Badger WAL)               │   pending → sequenced → shipped
      └────────────┬───────────────────────┘
                   │
                   ▼  background sequencer drain
      ┌────────────────────────────────────┐
      │  sequencer/                        │   tessera.AppendLeaf →
      │                                    │   Postgres entry_index INSERT →
      │                                    │   Badger 0x0A + 0x0C projections
      └─┬───────────┬──────────────────────┘
        │           │
        ▼           ▼
    ┌─────────┐ ┌──────────────────────────┐
    │ tessera │ │ gossipstore/             │
    │ tiles   │ │  0x0A splitid index      │  (detection trigger)
    │ +       │ │  0x0B equiv projection   │  (verified findings)
    │ Postgres│ │  0x0C entry lookup       │  (Pure CQRS read path)
    │         │ │  0x0D replay HWM         │  (boot back-population)
    └─────────┘ └──────────────────────────┘
                           │
                           ▼  EquivocationScanner subscribes 0x0A
                 ┌──────────────────────────┐
                 │ gossipnet/               │  pull-based gossip
                 │  /v1/gossip/since        │  /v1/gossip/by-binding
                 │  /v1/gossip/by-kind      │  /v1/gossip/event/{id}
                 │  /v1/gossip/sth/latest   │
                 └──────────────────────────┘
```

Single binary (`cmd/ledger`). Read-only sibling
(`cmd/ledger-reader`) serves the read endpoints without admission.
Local-dev bootstrap helper (`cmd/init-network`) generates a self-
witness K=1 topology for `scripts/run-local.sh`. Kubernetes target
— one writer replica per log DID, advisory-locked.

## Documentation

Each doc owns one concern. Cross-link rather than duplicate.

| Page | Owns |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Package layout, runtime data flow, sequencer + gossip pipelines, trust split |
| [docs/api.md](docs/api.md) | Every HTTP route from `api/server.go`, request/response shapes, status mapping |
| [docs/configuration.md](docs/configuration.md) | Every `LEDGER_*` env var read by `cmd/ledger/main.go::loadConfig` |
| [docs/storage.md](docs/storage.md) | WAL state machine, gossipstore keyspace (`0x07 0x01..0x0D`), Postgres schema, bytestore object layout |
| [docs/operations.md](docs/operations.md) | Boot order, shutdown chain, k8s/systemd, tile lanes, ops tasks, supply chain |
| [docs/observability.md](docs/observability.md) | OTel meter wiring, every metric the binary emits, ErrorClass taxonomy |
| [docs/testing.md](docs/testing.md) | Test layout, run modes, compliance map (named property → production code → test) |
| [docs/sdk-validation.md](docs/sdk-validation.md) | Per-package SDK contract anchors (every `var _ Interface = (*Impl)(nil)`) |
| [scripts/local/README.dev.md](scripts/local/README.dev.md) | Local 2-node dev + integration topology (real GCS / fake-gcs-server) |

## Quick start

```sh
# Build
go build ./cmd/ledger

# Required env vars (see docs/configuration.md for the full list)
export LEDGER_DATABASE_URL="postgres://..."
export LEDGER_LOG_DID="did:web:ledger.example"
export LEDGER_BYTE_STORE_BACKEND=s3 # or gcs
export LEDGER_BYTE_STORE_S3_BUCKET=...

# Run
./ledger
```

For local dev against a 2-node topology, see
[scripts/local/README.dev.md](scripts/local/README.dev.md) or run
`make help`.

## SDK pin

```
go.mod:  github.com/clearcompass-ai/attesta v0.1.3
```

Verify with `go list -m github.com/clearcompass-ai/attesta`. The
ledger never re-implements SDK validation logic — every signed
artifact goes through SDK primitives. See
[docs/sdk-validation.md](docs/sdk-validation.md) for the per-package
contract anchors.

## Compliance evidence

The build-time invariants and the canonical compile-time interface
checks live in [docs/testing.md](docs/testing.md) (compliance map)
and [docs/sdk-validation.md](docs/sdk-validation.md) (interface
anchors). Run them yourself:

```sh
go build ./...
go vet ./...
go test -count=1 -short ./...
```

## License

Proprietary. ClearCompass AI.
