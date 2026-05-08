# Configuration

Every `LEDGER_*` variable read by `cmd/ledger/main.go::loadConfig`
(line 547–632). The ledger refuses to start if any required
variable is missing — no implicit fallback on load-bearing inputs.
Cross-field invariants are enforced by `Config.Validate()` (line
705–768) and surface as a fatal error before any subsystem is
wired.

## Required at startup

| Variable | Read at | Purpose |
|---|---|---|
| `LEDGER_DATABASE_URL` | `main.go:550` | Postgres DSN. Migrations are applied at startup |
| `LEDGER_LOG_DID` | `main.go:551` | This ledger's log identity. Every entry must have `Header.Destination == LEDGER_LOG_DID` |
| `LEDGER_BYTE_STORE_BACKEND` | `main.go:563` | `gcs` or `s3`. Anything else fails closed at `main.go:654` |

When `LEDGER_BYTE_STORE_BACKEND=gcs`:

| Variable | Read at |
|---|---|
| `LEDGER_BYTE_STORE_GCS_BUCKET` | `main.go:567` |

When `LEDGER_BYTE_STORE_BACKEND=s3`:

| Variable | Read at |
|---|---|
| `LEDGER_BYTE_STORE_S3_BUCKET` | `main.go:571` |

When witness mode is active — i.e., when EITHER
`LEDGER_WITNESS_KEY_FILE` is set OR `LEDGER_WITNESS_ENDPOINTS` is
non-empty:

| Variable | Read at | Purpose |
|---|---|---|
| `LEDGER_NETWORK_BOOTSTRAP_FILE` | `main.go:586` | Network bootstrap definition (defines genesis witness DIDs + NetworkID) |

## Optional with defaults

### Server / identity

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_ADDR` | `:8080` | `main.go:549` |
| `LEDGER_DID` | `LEDGER_LOG_DID` | `main.go:552` (ignored if it doesn't match the loaded signer key) |
| `LEDGER_SERVICE_VERSION` | `dev` | `main.go:595` |
| `LEDGER_TLS_CERT_FILE` | (unset) | `main.go:601` |
| `LEDGER_TLS_KEY_FILE` | (unset) | `main.go:602` |
| `LEDGER_MAX_CONCURRENT_CONNS` | `0` (`0` → `8 × NumCPU`) | `main.go:603` |
| `LEDGER_PPROF_ADDR` | (unset) | `main.go:604` |
| `LEDGER_PREDRAIN_GRACE` | `5s` | `main.go:2609` (read late, during shutdown) |

### Storage paths (require persistent volumes in production)

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_WAL_PATH` | `/var/lib/attesta/wal` | `main.go:597` |
| `LEDGER_TESSERA_STORAGE_DIR` | `/var/lib/attesta/tessera` | `main.go:559` |
| `LEDGER_TESSERA_ANTISPAM_PATH` | `/var/lib/attesta/tessera-antispam` | `main.go:598` |

### Signer keys

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `LEDGER_TESSERA_SIGNER_KEY_FILE` | (unset) | `main.go:560` | Tessera personality signer; ephemeral if unset (logs a warning) |
| `LEDGER_SIGNER_KEY_FILE` | (unset) | `main.go:561` | Ledger signer (signs SCTs + tree heads); ephemeral if unset |
| `LEDGER_WITNESS_KEY_FILE` | (unset) | `main.go:585` | Witness cosign key. Mounting `POST /v1/cosign` requires this |
| `LEDGER_TESSERA_ORIGIN` | `LEDGER_LOG_DID` | `main.go:562` | Tessera personality origin string |

### Bytestore details

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_BYTE_STORE_PREFIX` | `entries` | `main.go:564` |
| `LEDGER_BYTE_STORE_PUBLIC_BASE_URL` | (unset) | `main.go:579` |
| `LEDGER_BYTE_STORE_GCS_ENDPOINT` | (unset → real GCS) | `main.go:568` |
| `LEDGER_BYTE_STORE_GCS_ANONYMOUS` | `false` | `main.go:569` |
| `LEDGER_BYTE_STORE_S3_ENDPOINT` | (unset → AWS S3) | `main.go:572` |
| `LEDGER_BYTE_STORE_S3_REGION` | (unset) | `main.go:573` |
| `LEDGER_BYTE_STORE_S3_ACCESS_KEY` | (unset) | `main.go:574` |
| `LEDGER_BYTE_STORE_S3_SECRET_KEY` | (unset) | `main.go:575` |
| `LEDGER_BYTE_STORE_S3_PATH_STYLE` | `false` | `main.go:576` |

### Tile serving

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_TILE_BACKEND` | `posix` | `main.go:606` |
| `LEDGER_TILE_BUCKET_PREFIX` | `tessera/` | `main.go:607` |
| `LEDGER_TILE_SERVE_DISABLE` | `false` | `main.go:605` |

### Sequencer / shipper

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_SEQUENCER_INTERVAL` | `1s` | `main.go:609` |
| `LEDGER_SEQUENCER_MAX_INFLIGHT` | `4` | `main.go:610` |
| `LEDGER_MMD` | `24h` | `main.go:611` |
| `LEDGER_SHIPPER_MAX_IN_FLIGHT` | `64` | `main.go:621` |
| `LEDGER_SHIPPER_POLL_INTERVAL` | env-default (see code) | `main.go:622` |

### Postgres pool

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_PG_MAX_CONNS` | `0` (auto: `defaultPgMaxConns(SequencerMaxInFlight)`) | `main.go:627` |
| `LEDGER_PG_STATEMENT_TIMEOUT` | `5s` (per-statement timeout via `pgxpool.AfterConnect`) | `main.go:628` |

### Gossip

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_GOSSIP_DISABLE` | `false` | `main.go:589` |
| `LEDGER_GOSSIP_PEER_ENDPOINTS` | (CSV; default empty) | `main.go:587` |
| `LEDGER_GOSSIP_PEER_DIDS` | (CSV; default empty) | `main.go:588` |

### Witness mode

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_WITNESS_ENDPOINTS` | (CSV; default empty) | `main.go:583` |
| `LEDGER_WITNESS_QUORUM_K` | `1` | `main.go:584` |

### Observability

| Variable | Default | Read at | Effect |
|---|---|---|---|
| `LEDGER_METRICS_ENABLE` | **`true`** (defaults to enabled; opt-out by setting to the literal string `"false"`) | `main.go:593` | Constructs the OTel MeterProvider, mounts `GET /metrics`, installs counters/histograms |
| `LEDGER_METRICS_ENVIRONMENT` | `dev` | `main.go:594` | OTel resource attribute |
| `LEDGER_OTLP_TRACES_ENDPOINT` | (unset → NoOp tracer) | `main.go:596` | OTLP exporter; accepts `""`, `stdout`, `host:port`, `https://...` |

### Anchor (optional)

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `LEDGER_ETH_RPC_ENABLED` | `false` | `main.go:1099` (probe site; declared earlier in the same file) | EIP-1271 verification path |

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

## Cross-field validation (G1)

`Config.Validate()` runs at the end of `loadConfig()` and rejects
the boot if any of these invariants is violated:

| Check | Failure mode |
|---|---|
| `LEDGER_TLS_CERT_FILE` and `LEDGER_TLS_KEY_FILE` both-set or both-unset | Half-configured TLS would silently fall back to plain HTTP |
| Both TLS files exist on disk | Misnamed path surfaces immediately |
| `LEDGER_GOSSIP_PEER_DIDS` and `LEDGER_GOSSIP_PEER_ENDPOINTS` same length | Length mismatch points at a stale env var |
| `LEDGER_TILE_BACKEND=gcs` requires `LEDGER_BYTE_STORE_BACKEND=gcs` | Tile-GCS reuses the GCS bucket handle |
| `LEDGER_TILE_BACKEND ∈ {posix, gcs}` | Typo protection |
| `LEDGER_SEQUENCER_INTERVAL`, `LEDGER_MMD`, `LEDGER_PG_STATEMENT_TIMEOUT` ≥ 0 | Negative values would invert select branches |
| `LEDGER_WITNESS_QUORUM_K > 0` when witnesses configured | 0-of-N would never finalize |
| `LEDGER_WITNESS_QUORUM_K ≤ len(LEDGER_WITNESS_ENDPOINTS)` | Unreachable quorum |

## Quick start

```sh
export LEDGER_DATABASE_URL="postgres://ledger:secret@db:5432/attesta"
export LEDGER_LOG_DID="did:web:ledger.example/log/main"
export LEDGER_BYTE_STORE_BACKEND=s3
export LEDGER_BYTE_STORE_S3_BUCKET=attesta-entries
export LEDGER_BYTE_STORE_S3_REGION=us-east-1
export LEDGER_SIGNER_KEY_FILE=/etc/attesta/ledger.key
export LEDGER_TESSERA_SIGNER_KEY_FILE=/etc/attesta/tessera.key

# Metrics are ON by default; the only opt-out is the literal "false":
# export LEDGER_METRICS_ENABLE=false
export LEDGER_METRICS_ENVIRONMENT=production
export LEDGER_SERVICE_VERSION=$(git describe --tags)

./ledger
```

## Signer key format

`LEDGER_SIGNER_KEY_FILE` and `LEDGER_TESSERA_SIGNER_KEY_FILE` point
at PEM-encoded keys (`crypto/signatures` family). When unset, the
ledger generates an ephemeral key at boot and logs a warning —
acceptable for dev, **never for production** because every restart
issues a new identity.
