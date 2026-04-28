# Ortholog Operator

Log operator infrastructure for the Ortholog decentralized credentialing
protocol. Receives signed entries, runs the deterministic builder algorithm
via the SDK, persists state atomically to Postgres, embeds an upstream
Tessera log for sequencing and tile storage, ships entry bytes to a
hexagonal bytestore (GCS or S3), and serves query/proof endpoints to
clients.

Single binary. Single goroutine builder. Kubernetes target.

## Table of contents

| Section | What it covers |
|---|---|
| [readme/architecture.md](readme/architecture.md) | End-to-end flow, three-service split, embedded Tessera, hexagonal bytestore |
| [readme/configuration.md](readme/configuration.md) | Environment variables, quick start, signer key handling |
| [readme/api.md](readme/api.md) | HTTP endpoints, the 14-step admission pipeline, error codes |
| [readme/storage.md](readme/storage.md) | WAL states, bytestore object layout, Postgres schema, builder loop |
| [readme/operations.md](readme/operations.md) | Startup sequence, project structure, testing, Kubernetes deployment |

For day-2 operations (alerts, recovery, volume failure semantics) see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md). The full env-var reference lives in
[`docs/CONFIG.md`](docs/CONFIG.md). Architectural deep-dive in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License

Proprietary. ClearCompass AI.
