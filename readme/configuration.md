# Configuration

All settings come from environment variables. The operator refuses to
start if any required variable is missing — there is no implicit
"fall back to a sensible local-dev value" path on the load-bearing
inputs.

This page mirrors what `cmd/operator/main.go::loadConfig()` actually
reads. The full table — including test-only `ORTHOLOG_TEST_*` and
soak knobs — lives in [`docs/CONFIG.md`](../docs/CONFIG.md).

## Required at startup

| Variable | Semantics |
|---|---|
| `OPERATOR_DATABASE_URL` | Postgres DSN. Migrations are applied at startup. |
| `OPERATOR_LOG_DID` | This operator's log identity. All entries the operator admits MUST have `Header.Destination == OPERATOR_LOG_DID` (destination binding). Validated via `envelope.ValidateDestination`. |
| `OPERATOR_BYTE_STORE_BACKEND` | `gcs` or `s3`. The factory rejects anything else with a fail-closed error. |
| `OPERATOR_BYTE_STORE_GCS_BUCKET` | Required when `OPERATOR_BYTE_STORE_BACKEND=gcs`. |
| `OPERATOR_BYTE_STORE_S3_BUCKET` | Required when `OPERATOR_BYTE_STORE_BACKEND=s3`. |

## Optional with defaults

| Variable | Default | Semantics |
|---|---|---|
| `OPERATOR_ADDR` | `:8080` | HTTP listen address. |
| `OPERATOR_DID` | `OPERATOR_LOG_DID` | Operator's signer identity for self-published commentary. Defaults to the log DID for single-log deployments. |
| `OPERATOR_WAL_PATH` | `/var/lib/ortholog/wal` | BadgerDB directory for the durable WAL. **Required volume in production** — admission writes to disk before returning 202. |
| `OPERATOR_TESSERA_STORAGE_DIR` | `/var/lib/ortholog/tessera` | Tessera tile + checkpoint storage. **Required volume in production**. |
| `OPERATOR_TESSERA_ANTISPAM_PATH` | `/var/lib/ortholog/tessera-antispam` | BadgerDB directory backing Tessera's antispam (dedup) layer. **Required volume in production** — consulted on every Add. |
| `OPERATOR_TESSERA_SIGNER_KEY_FILE` | (unset) | Path to a `note.Signer` private-key file. When unset, an ephemeral Ed25519 signer is generated at boot with a logged warning — the verifier key is printed once and lost on next restart. **Production must set this.** |
| `OPERATOR_TESSERA_ORIGIN` | `OPERATOR_LOG_DID` | The c2sp.org/tlog-tiles origin string embedded in every signed checkpoint. |
| `OPERATOR_BYTE_STORE_PREFIX` | `entries` | Bucket prefix for object keys. Useful for sharing a bucket across multiple operator instances. |
| `OPERATOR_BYTE_STORE_GCS_ENDPOINT` | (unset → real GCS) | Override for the GCS endpoint. Set to a fake-gcs-server URL for local dev. Production must leave empty. |
| `OPERATOR_BYTE_STORE_GCS_ANONYMOUS` | `false` | When `true`, bypass ADC. Local-dev / fake-gcs-server only. |
| `OPERATOR_BYTE_STORE_S3_ENDPOINT` | (unset → real AWS S3) | Override for the S3 endpoint. Set to a RustFS / MinIO URL for local dev. Production on AWS must leave empty. |
| `OPERATOR_BYTE_STORE_S3_REGION` | `us-east-1` (factory default) | AWS region. RustFS accepts any string; AWS S3 requires the bucket's actual region. |
| `OPERATOR_BYTE_STORE_S3_ACCESS_KEY` | (unset → default credential chain) | Static access key. Set for non-AWS endpoints. AWS production should leave empty and rely on IAM role / IRSA / `~/.aws`. |
| `OPERATOR_BYTE_STORE_S3_SECRET_KEY` | (unset → default credential chain) | Pairs with `_S3_ACCESS_KEY`. |
| `OPERATOR_BYTE_STORE_S3_PATH_STYLE` | `false` | `true` for path-style URLs (`host/bucket/key`). Required for RustFS. AWS S3 leaves `false` for virtual-host URLs. |

## Quick start

```bash
# 1. Database
createdb ortholog
export OPERATOR_DATABASE_URL="postgres://user:pass@localhost:5432/ortholog?sslmode=disable"

# 2. Required identity + storage paths
export OPERATOR_LOG_DID="did:ortholog:operator:001"
export OPERATOR_WAL_PATH="/var/lib/ortholog/wal"
export OPERATOR_TESSERA_STORAGE_DIR="/var/lib/ortholog/tessera"
export OPERATOR_TESSERA_ANTISPAM_PATH="/var/lib/ortholog/tessera-antispam"

# 3a. GCS — pick this OR the S3 block.
export OPERATOR_BYTE_STORE_BACKEND="gcs"
export OPERATOR_BYTE_STORE_GCS_BUCKET="my-ortholog-bucket"
# GOOGLE_APPLICATION_CREDENTIALS or workload identity for GCS auth.

# 3b. S3 / RustFS / R2 / AWS S3 (alternative to GCS).
# export OPERATOR_BYTE_STORE_BACKEND="s3"
# export OPERATOR_BYTE_STORE_S3_BUCKET="my-ortholog-bucket"
# AWS production: leave creds empty for the default credential chain.
# RustFS / on-prem:
# export OPERATOR_BYTE_STORE_S3_ENDPOINT="http://rustfs:9000"
# export OPERATOR_BYTE_STORE_S3_ACCESS_KEY="..."
# export OPERATOR_BYTE_STORE_S3_SECRET_KEY="..."
# export OPERATOR_BYTE_STORE_S3_PATH_STYLE="true"

# 4. Build
go mod tidy
go build -o operator ./cmd/operator

# 5. Run (migrations execute automatically on first start)
./operator

# 6. Verify
curl http://localhost:8080/healthz   # → "ok"
curl http://localhost:8080/readyz    # → "ready"
```

## Tessera signer key handling

`cmd/operator/main.go::loadOrGenerateTesseraSigner` resolves the
checkpoint signer in priority order:

1. `OPERATOR_TESSERA_SIGNER_KEY_FILE` non-empty → load `note.Signer`
   from disk; fail if unreadable. **Production must use this.**
2. Empty → generate an ephemeral Ed25519 signer with a loud warning.
   The verifier key is logged once and lost on next restart. Local
   dev only.

The signer is the upstream Tessera/`golang.org/x/mod/sumdb/note`
format — the file content is fed directly to `note.NewSigner`. ECDSA
PEM keys (e.g., what OpenSSL produces) are not accepted; use
`note.GenerateKey` if you need a persistent signer.

## Required Go and Postgres versions

- Go 1.25.7 (declared in `go.mod`).
- PostgreSQL 14 or newer. The operator uses `BIGINT[]` for
  equivocation evidence and standard SQL/`pgx/v5`; nothing more
  exotic.
