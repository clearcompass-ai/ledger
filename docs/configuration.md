# Configuration

Every `OPERATOR_*` variable read by `cmd/operator/main.go::loadConfig`.
The operator refuses to start if any required variable is missing —
no implicit fallback on load-bearing inputs.

## Required at startup

| Variable | Read at | Purpose |
|---|---|---|
| `OPERATOR_DATABASE_URL` | `main.go:444` | Postgres DSN. Migrations are applied at startup |
| `OPERATOR_LOG_DID` | `main.go:445` | This operator's log identity. Every entry must have `Header.Destination == OPERATOR_LOG_DID` |
| `OPERATOR_BYTE_STORE_BACKEND` | `main.go:457` | `gcs` or `s3`. Anything else fails closed |

When `OPERATOR_BYTE_STORE_BACKEND=gcs`:

| Variable | Read at |
|---|---|
| `OPERATOR_BYTE_STORE_GCS_BUCKET` | `main.go:461` |

When `OPERATOR_BYTE_STORE_BACKEND=s3`:

| Variable | Read at |
|---|---|
| `OPERATOR_BYTE_STORE_S3_BUCKET` | `main.go:464` |

When `cfg.WitnessQuorumK > 0` (witness mode active):

| Variable | Read at | Purpose |
|---|---|---|
| `OPERATOR_NETWORK_BOOTSTRAP_FILE` | `main.go:477` | Network bootstrap definition |

## Optional with defaults

### Server / identity

| Variable | Default | Read at |
|---|---|---|
| `OPERATOR_ADDR` | `:8080` | `main.go:443` |
| `OPERATOR_DID` | `OPERATOR_LOG_DID` | `main.go:446` (note: ignored if it doesn't match the loaded signer key — see `main.go:296`) |
| `OPERATOR_SERVICE_VERSION` | `dev` | `main.go:483` |

### Storage paths (require persistent volumes in production)

| Variable | Default | Read at |
|---|---|---|
| `OPERATOR_WAL_PATH` | `/var/lib/ortholog/wal` | `main.go:484` |
| `OPERATOR_TESSERA_STORAGE_DIR` | `/var/lib/ortholog/tessera` | `main.go:453` |
| `OPERATOR_TESSERA_ANTISPAM_PATH` | `/var/lib/ortholog/tessera-antispam` | `main.go:485` |

### Signer keys

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `OPERATOR_TESSERA_SIGNER_KEY_FILE` | (unset) | `main.go:454` | Tessera personality signer; ephemeral if unset (logs a warning) |
| `OPERATOR_SIGNER_KEY_FILE` | (unset) | `main.go:455` | Operator signer (signs SCTs + tree heads); ephemeral if unset |
| `OPERATOR_WITNESS_KEY_FILE` | (unset) | `main.go:476` | Witness cosign key. Mounting `POST /v1/cosign` requires this |
| `OPERATOR_TESSERA_ORIGIN` | `OPERATOR_LOG_DID` | `main.go:456` | Tessera personality origin string |

### Bytestore details

| Variable | Default | Read at |
|---|---|---|
| `OPERATOR_BYTE_STORE_PREFIX` | `entries` | `main.go:458` |
| `OPERATOR_BYTE_STORE_GCS_ENDPOINT` | (unset → real GCS) | `main.go:462` |
| `OPERATOR_BYTE_STORE_GCS_ANONYMOUS` | `false` | `main.go:463` |
| `OPERATOR_BYTE_STORE_S3_ENDPOINT` | (unset → AWS S3) | `main.go:465` |
| `OPERATOR_BYTE_STORE_S3_REGION` | (unset) | `main.go:466` |
| `OPERATOR_BYTE_STORE_S3_ACCESS_KEY` | (unset) | `main.go:467` |
| `OPERATOR_BYTE_STORE_S3_SECRET_KEY` | (unset) | `main.go:468` |
| `OPERATOR_BYTE_STORE_S3_PATH_STYLE` | `false` | `main.go:469` |

### Sequencer

| Variable | Default | Read at |
|---|---|---|
| `OPERATOR_SEQUENCER_INTERVAL` | `1s` | `main.go:487` |
| `OPERATOR_SEQUENCER_MAX_INFLIGHT` | `4` | `main.go:488` |
| `OPERATOR_MMD` | `24h` | `main.go:489` |
| `OPERATOR_PG_MAX_CONNS` | `defaultPgMaxConns(MaxInFlight)` | `main.go:493` |

### Gossip

| Variable | Default | Read at |
|---|---|---|
| `OPERATOR_GOSSIP_DISABLE` | `false` | `main.go:480` |
| `OPERATOR_GOSSIP_PEER_ENDPOINTS` | (CSV; default empty) | `main.go:478` |
| `OPERATOR_GOSSIP_PEER_DIDS` | (CSV; default empty) | `main.go:479` |

### Witness mode

| Variable | Default | Read at |
|---|---|---|
| `OPERATOR_WITNESS_ENDPOINTS` | (CSV; default empty) | `main.go:474` |
| `OPERATOR_WITNESS_QUORUM_K` | `1` | `main.go:475` |

### Observability

| Variable | Default | Read at | Effect |
|---|---|---|---|
| `OPERATOR_METRICS_ENABLE` | `false` | `main.go:481` | Mounts `GET /metrics` + installs api error counter |
| `OPERATOR_METRICS_ENVIRONMENT` | `dev` | `main.go:482` | OTel resource attribute |

### Anchor (optional)

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `OPERATOR_ETH_RPC_ENABLED` | `false` | `main.go:732` | EIP-1271 verification path |

## Compile-time defaults (not env-configurable)

`cmd/operator/main.go::loadConfig` hard-codes these:

| Field | Value | Why |
|---|---|---|
| `MaxEntrySize` | 1 MiB | SDK envelope size cap |
| `BatchSize` | 1000 | Builder batch size |
| `PollInterval` | 100 ms | Builder loop tick |
| `EpochWindowSeconds` | 3600 (1h) | Mode B PoW epoch |
| `EpochAcceptanceWindow` | 1 | Accept current ± 1 epoch |
| `AnchorInterval` | 1h | External anchor publish cadence |
| `ByteStoreCacheSize` | 4096 | LRU entries |
| `TileCacheSize` | 10,000 | LRU tile entries |
| `SMTNodeCacheSize` | 100,000 | SMT node LRU |
| `DeltaWindow` | 10 | OCC commit window |

## Quick start

```sh
export OPERATOR_DATABASE_URL="postgres://operator:secret@db:5432/ortholog"
export OPERATOR_LOG_DID="did:web:operator.example/log/main"
export OPERATOR_BYTE_STORE_BACKEND=s3
export OPERATOR_BYTE_STORE_S3_BUCKET=ortholog-entries
export OPERATOR_BYTE_STORE_S3_REGION=us-east-1
export OPERATOR_SIGNER_KEY_FILE=/etc/ortholog/operator.key
export OPERATOR_TESSERA_SIGNER_KEY_FILE=/etc/ortholog/tessera.key

# Optional: enable Prometheus metrics + typed error_class dimensions
export OPERATOR_METRICS_ENABLE=true
export OPERATOR_METRICS_ENVIRONMENT=production
export OPERATOR_SERVICE_VERSION=$(git describe --tags)

./operator
```

## Signer key format

`OPERATOR_SIGNER_KEY_FILE` and `OPERATOR_TESSERA_SIGNER_KEY_FILE` point at
PEM-encoded keys (`crypto/signatures` family). When unset, the operator
generates an ephemeral key at boot and logs a warning — acceptable for
dev, **never for production** because every restart issues a new
identity.
