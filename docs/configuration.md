# Configuration

Every `LEDGER_*` variable read by `cmd/ledger/main.go::loadConfig`.
The ledger refuses to start if any required variable is missing —
no implicit fallback on load-bearing inputs.

## Required at startup

| Variable | Read at | Purpose |
|---|---|---|
| `LEDGER_DATABASE_URL` | `main.go:444` | Postgres DSN. Migrations are applied at startup |
| `LEDGER_LOG_DID` | `main.go:445` | This ledger's log identity. Every entry must have `Header.Destination == LEDGER_LOG_DID` |
| `LEDGER_BYTE_STORE_BACKEND` | `main.go:457` | `gcs` or `s3`. Anything else fails closed |

When `LEDGER_BYTE_STORE_BACKEND=gcs`:

| Variable | Read at |
|---|---|
| `LEDGER_BYTE_STORE_GCS_BUCKET` | `main.go:461` |

When `LEDGER_BYTE_STORE_BACKEND=s3`:

| Variable | Read at |
|---|---|
| `LEDGER_BYTE_STORE_S3_BUCKET` | `main.go:464` |

When witness mode is active — i.e., when EITHER
`LEDGER_WITNESS_KEY_FILE` is set OR `LEDGER_WITNESS_ENDPOINTS` is
non-empty (see `cmd/ledger/main.go::loadConfig`):

| Variable | Read at | Purpose |
|---|---|---|
| `LEDGER_NETWORK_BOOTSTRAP_FILE` | `main.go:477` | Network bootstrap definition (defines the genesis witness DIDs + NetworkID) |

## Optional with defaults

### Server / identity

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_ADDR` | `:8080` | `main.go:443` |
| `LEDGER_DID` | `LEDGER_LOG_DID` | `main.go:446` (note: ignored if it doesn't match the loaded signer key — see `main.go:296`) |
| `LEDGER_SERVICE_VERSION` | `dev` | `main.go:483` |

### Storage paths (require persistent volumes in production)

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_WAL_PATH` | `/var/lib/attesta/wal` | `main.go:484` |
| `LEDGER_TESSERA_STORAGE_DIR` | `/var/lib/attesta/tessera` | `main.go:453` |
| `LEDGER_TESSERA_ANTISPAM_PATH` | `/var/lib/attesta/tessera-antispam` | `main.go:485` |

### Signer keys

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `LEDGER_TESSERA_SIGNER_KEY_FILE` | (unset) | `main.go:454` | Tessera personality signer; ephemeral if unset (logs a warning) |
| `LEDGER_SIGNER_KEY_FILE` | (unset) | `main.go:455` | Ledger signer (signs SCTs + tree heads); ephemeral if unset |
| `LEDGER_WITNESS_KEY_FILE` | (unset) | `main.go:476` | Witness cosign key. Mounting `POST /v1/cosign` requires this |
| `LEDGER_TESSERA_ORIGIN` | `LEDGER_LOG_DID` | `main.go:456` | Tessera personality origin string |

### Bytestore details

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_BYTE_STORE_PREFIX` | `entries` | `main.go:458` |
| `LEDGER_BYTE_STORE_GCS_ENDPOINT` | (unset → real GCS) | `main.go:462` |
| `LEDGER_BYTE_STORE_GCS_ANONYMOUS` | `false` | `main.go:463` |
| `LEDGER_BYTE_STORE_S3_ENDPOINT` | (unset → AWS S3) | `main.go:465` |
| `LEDGER_BYTE_STORE_S3_REGION` | (unset) | `main.go:466` |
| `LEDGER_BYTE_STORE_S3_ACCESS_KEY` | (unset) | `main.go:467` |
| `LEDGER_BYTE_STORE_S3_SECRET_KEY` | (unset) | `main.go:468` |
| `LEDGER_BYTE_STORE_S3_PATH_STYLE` | `false` | `main.go:469` |

### Sequencer

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_SEQUENCER_INTERVAL` | `1s` | `main.go:487` |
| `LEDGER_SEQUENCER_MAX_INFLIGHT` | `4` | `main.go:488` |
| `LEDGER_MMD` | `24h` | `main.go:489` |
| `LEDGER_PG_MAX_CONNS` | `defaultPgMaxConns(MaxInFlight)` | `main.go:493` |

### Gossip

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_GOSSIP_DISABLE` | `false` | `main.go:480` |
| `LEDGER_GOSSIP_PEER_ENDPOINTS` | (CSV; default empty) | `main.go:478` |
| `LEDGER_GOSSIP_PEER_DIDS` | (CSV; default empty) | `main.go:479` |

### Witness mode

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_WITNESS_ENDPOINTS` | (CSV; default empty) | `main.go:474` |
| `LEDGER_WITNESS_QUORUM_K` | `1` | `main.go:475` |

### Observability

| Variable | Default | Read at | Effect |
|---|---|---|---|
| `LEDGER_METRICS_ENABLE` | `false` | `main.go:481` | Mounts `GET /metrics` + installs api error counter |
| `LEDGER_METRICS_ENVIRONMENT` | `dev` | `main.go:482` | OTel resource attribute |

### Anchor (optional)

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `LEDGER_ETH_RPC_ENABLED` | `false` | `main.go:732` | EIP-1271 verification path |

## Compile-time defaults (not env-configurable)

`cmd/ledger/main.go::loadConfig` hard-codes these:

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
export LEDGER_DATABASE_URL="postgres://ledger:secret@db:5432/attesta"
export LEDGER_LOG_DID="did:web:ledger.example/log/main"
export LEDGER_BYTE_STORE_BACKEND=s3
export LEDGER_BYTE_STORE_S3_BUCKET=attesta-entries
export LEDGER_BYTE_STORE_S3_REGION=us-east-1
export LEDGER_SIGNER_KEY_FILE=/etc/attesta/ledger.key
export LEDGER_TESSERA_SIGNER_KEY_FILE=/etc/attesta/tessera.key

# Optional: enable Prometheus metrics + typed error_class dimensions
export LEDGER_METRICS_ENABLE=true
export LEDGER_METRICS_ENVIRONMENT=production
export LEDGER_SERVICE_VERSION=$(git describe --tags)

./ledger
```

## Signer key format

`LEDGER_SIGNER_KEY_FILE` and `LEDGER_TESSERA_SIGNER_KEY_FILE` point at
PEM-encoded keys (`crypto/signatures` family). When unset, the ledger
generates an ephemeral key at boot and logs a warning — acceptable for
dev, **never for production** because every restart issues a new
identity.
