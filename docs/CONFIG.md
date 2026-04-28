# Operator configuration reference

All operator settings are read from environment variables. The
process refuses to start if any required variable is missing — there
is no implicit "fall back to a sensible local-dev value" path on the
load-bearing inputs.

## Required at startup

| Variable                            | Semantics                                                                                                                                                                              |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPERATOR_DATABASE_URL`             | Postgres DSN. Migrations are applied at startup.                                                                                                                                       |
| `OPERATOR_LOG_DID`                  | This operator's log identity. All entries the operator admits MUST have `Header.Destination == OPERATOR_LOG_DID` (destination binding). Validated via `envelope.ValidateDestination`.  |
| `OPERATOR_BYTE_STORE_BACKEND`       | Production-grade bytestore selector. `gcs` (Google Cloud Storage) or `s3` (any S3-compatible: AWS S3, RustFS, R2, …). The factory rejects anything else with a fail-closed error.      |
| `OPERATOR_BYTE_STORE_GCS_BUCKET`    | GCS bucket name. Required when `OPERATOR_BYTE_STORE_BACKEND=gcs`.                                                                                                                      |
| `OPERATOR_BYTE_STORE_S3_BUCKET`     | S3 bucket name. Required when `OPERATOR_BYTE_STORE_BACKEND=s3`.                                                                                                                        |

## Optional with defaults

| Variable                            | Default                                | Semantics                                                                                                                                                                              |
|-------------------------------------|----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPERATOR_ADDR`                     | `:8080`                                | HTTP listen address.                                                                                                                                                                   |
| `OPERATOR_DID`                      | `OPERATOR_LOG_DID`                     | Operator identity (signs anchor commitments). Defaults to the log DID for single-log deployments.                                                                                      |
| `OPERATOR_WAL_PATH`                 | `/var/lib/ortholog/wal`                | BadgerDB directory for the durable WAL. **Required volume in production** — admission writes to disk before returning 202.                                                            |
| `OPERATOR_TESSERA_ANTISPAM_PATH`    | `/var/lib/ortholog/tessera-antispam`   | Antispam dedup directory. **Required volume in production** — Tessera consults this on every Add to enforce idempotency under concurrent admission.                                   |
| `OPERATOR_TESSERA_STORAGE_DIR`      | `/var/lib/ortholog/tessera`            | Tessera tile + checkpoint storage. **Required volume in production**.                                                                                                                  |
| `OPERATOR_TESSERA_SIGNER_KEY_FILE`  | (unset)                                | Path to the Tessera-personality signer key. Required for production tree-head signing.                                                                                                 |
| `OPERATOR_TESSERA_ORIGIN`           | `OPERATOR_LOG_DID`                     | Tessera-personality origin string.                                                                                                                                                     |
| `OPERATOR_BYTE_STORE_PREFIX`        | `entries`                              | Bucket prefix for object keys. Useful for sharing a bucket across multiple operator instances. Applies to both backends.                                                               |
| `OPERATOR_BYTE_STORE_GCS_ENDPOINT`  | (unset → real GCS)                     | Override for the GCS endpoint. Set to a fake-gcs-server URL for local dev. Production must leave this empty.                                                                           |
| `OPERATOR_BYTE_STORE_GCS_ANONYMOUS` | `false`                                | When `true`, bypass ADC. Local-dev / fake-gcs-server only.                                                                                                                             |
| `OPERATOR_BYTE_STORE_S3_ENDPOINT`   | (unset → real AWS S3)                  | Override for the S3 endpoint. Set to a RustFS URL for local dev. Production on AWS must leave this empty.                                                                              |
| `OPERATOR_BYTE_STORE_S3_REGION`     | `us-east-1` (factory default)          | AWS region. RustFS accepts any string; AWS S3 requires the bucket's actual region.                                                                                                     |
| `OPERATOR_BYTE_STORE_S3_ACCESS_KEY` | (unset → default credential chain)     | Static access key. Set for RustFS / non-AWS endpoints. AWS production should leave empty and rely on IAM role / IRSA / `~/.aws`.                                                       |
| `OPERATOR_BYTE_STORE_S3_SECRET_KEY` | (unset → default credential chain)     | Static secret key — pairs with `_S3_ACCESS_KEY`.                                                                                                                                       |
| `OPERATOR_BYTE_STORE_S3_PATH_STYLE` | `false`                                | When `true`, use path-style URLs (`host/bucket/key`). Required for RustFS. AWS S3 leaves it `false` for virtual-host URLs.                                                             |

## Test-only environment

These variables are read by tests, never by the operator itself.

| Variable                       | Purpose                                                                                                                                  |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `ORTHOLOG_TEST_DSN`            | Gates HTTP integration + e2e + soak tests. Skip cleanly if unset.                                                                        |
| `ORTHOLOG_TEST_GCS_BUCKET`     | Gates real-GCS conformance + soak tests. Bucket must grant `storage.objects.{create,get,list,delete}` to the test identity.              |
| `ORTHOLOG_TEST_GCS_ENDPOINT`   | Routes real-GCS-shaped tests at fake-gcs-server. Set with `_BUCKET` and the test runs in container mode.                                 |
| `ORTHOLOG_TEST_S3_*`           | S3 conformance equivalents (RustFS / real S3). See `bytestore/conformance_test.go`.                                                      |
| `ORTHOLOG_SOAK_*`              | Soak-test knobs (entry count, concurrency, sample size, p99 bound). See `tests/soak_test.go`.                                            |

## Volume layout in production

```
/var/lib/ortholog/
├── wal/                # OPERATOR_WAL_PATH — Badger
├── tessera-antispam/   # OPERATOR_TESSERA_ANTISPAM_PATH — Tessera dedup
└── tessera/            # OPERATOR_TESSERA_STORAGE_DIR — Tessera tiles + checkpoints
```

Each directory is a separate concern with separate failure semantics
(see RUNBOOK.md). Use distinct PersistentVolumeClaims under
Kubernetes so a corruption in one does not force the operator to
discard the others.
