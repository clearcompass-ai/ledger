# Observability

## OpenTelemetry meter provider

Constructed at boot when `OPERATOR_METRICS_ENABLE=true`
(`cmd/operator/main.go::1029`). Exporter: Prometheus, scraped via
`GET /metrics`.

```
mpResult, _ := sdklog.NewMeterProvider(sdklog.MeterProviderConfig{
    ServiceName:    "ledger",
    ServiceVersion: cfg.ServiceVersion,
    Environment:    cfg.MetricsEnvironment,
    Exporters:      []sdklog.ExporterKind{sdklog.PrometheusExporter},
})
otel.SetMeterProvider(mpResult.Provider)

apiMeter := mpResult.Provider.Meter(".../api")
api.InstallErrorCounter(apiMeter)
```

Disabled-by-default. With metrics off, every counter is a no-op (no
panic; no overhead).

## API error counter

Single metric, two attributes, bounded cardinality:

```
attesta_api_errors_total{error_class, http_status}
```

Defined in `api/errors.go`. Every error-emission site in `api/` flows
through `writeTypedError(ctx, w, class, status, msg)` or
`writeTypedJSONError(...)`, both of which:

1. Increment the counter with the typed `error_class` attribute
2. Write the JSON body

There are NO bare `writeError` calls in `api/` outside the wrapper
helpers themselves:

```
$ grep -rn '\twriteError(' api/ | grep -v _test.go
api/errors.go:141:	writeError(w, status, msg)

$ grep -rn '\twriteJSONError(' api/ | grep -v _test.go
api/errors.go:155:	writeJSONError(w, status, msg)
```

## Error class taxonomy

`apitypes/apitypes.go` defines 30 typed `ErrorClass` constants. Each
has a stable kebab-case `String()` that becomes the OTel attribute
value. New classes require an explicit code addition; the cardinality
budget never grows from caller-controlled strings.

### Caller-supplied bytes (network noise — usually a client bug)

| Class | When | HTTP |
|---|---|---|
| `malformed_body` | Body read failed | 400 |
| `malformed_json` | JSON parse failed | 400 |
| `body_too_large` | Exceeds `MaxEntrySize` | 413 |
| `bad_hex_encoding` | Hex decode failed | 400 |
| `bad_hex_length` | Wrong-length hex string | 400 |
| `missing_path_param` | Required path segment empty | 400 |
| `missing_query_param` | Required query string missing | 400 |
| `invalid_query_param` | Query string parse failed | 400 |
| `unsupported_schema` | Schema ID outside the closed-set | 400 |
| `batch_too_large` | Exceeds `MaxBatchSize` | 400 |
| `empty_batch` | Empty `entries` array | 400 |

### Tenant state

| Class | When | HTTP |
|---|---|---|
| `insufficient_credits` | Mode A balance ≤ 0 | 402 |
| `duplicate_entry` | Entry already on the log (idempotent dup) | 409 |
| `invalid_session` | Bearer token doesn't match `sessions` row | 401 |
| `expired_session` | Session row exists but `expires_at` past | 401 |

### Cryptographic / hostile-flavor (alert on sustained rates)

| Class | When | HTTP |
|---|---|---|
| `signature_invalid` | Entry signature didn't verify under SignerDID | 401 |
| `envelope_rejected` | `entry.Validate()` failed (preamble, NFC, fields) | 422 |
| `freshness_expired` | `policy.CheckFreshness` failed | 422 |
| `destination_mismatch` | `entry.Header.Destination != cfg.LogDID` | 403 |
| `admission_proof_invalid` | Mode B PoW stamp didn't verify | 403 |
| `difficulty_too_low` | Stamp's difficulty below current | 403 |

### Not found

| Class | When | HTTP |
|---|---|---|
| `not_found` | No row matches the requested key | 404 |

### Operator infrastructure (page the operator)

| Class | When | HTTP |
|---|---|---|
| `wal_backpressure` | `wal.ErrQueueFull` | 503 |
| `wal_persist_failed` | WAL fsync failed | 500 |
| `sct_signing_failed` | `crypto.Sign` returned an error | 500 |
| `db_query_failed` | Postgres query / scan error | 500 |
| `read_projection_failed` | Badger read on a projection failed | 500 |
| `fetcher_failed` | `types.CommitmentFetcher` impl errored | 500 |
| `proof_gen_failed` | SMT or Merkle proof generator errored | 500 |
| `credit_deduct_failed` | Credit txn failed (other than insufficient) | 500 |
| `escrow_override_failed` | Witness collector failed K-of-N | 502 |

## Cardinality budget

```
ErrorClass values:                30
HTTP statuses (in practice):      ~10
Total attesta_api_errors_total
  time-series:                    ~300
```

Well under Prometheus's recommended 10k/metric ceiling. New classes
are explicit code additions — the cardinality never grows from
caller-controlled strings (which would melt the index).

## Recommended alerts

```promql
# Hostile-flavor — alert on sustained rates
sum by (error_class) (
  rate(attesta_api_errors_total{error_class=~"signature_invalid|admission_proof_invalid|destination_mismatch"}[5m])
)

# Operator infrastructure — page on any uptick
rate(attesta_api_errors_total{error_class=~"wal_backpressure|wal_persist_failed|sct_signing_failed|db_query_failed"}[1m])

# Tenant state — informational dashboard, not paging
rate(attesta_api_errors_total{error_class=~"insufficient_credits|expired_session"}[5m])
```

## Tests

`apitypes/error_class_test.go` and `api/errors_test.go` pin the
contract:

| Test | What it catches |
|---|---|
| `TestErrorClass_StringNonEmpty` | A new class added without a `String()` case |
| `TestErrorClass_DistinctStrings` | Two classes that stringify the same — silent metric merge |
| `TestErrorClass_UnknownZeroValue` | Zero value emits `"unknown"` — flags unclassified call sites |
| `TestErrorClass_HostileNamesAreDistinct` | Hostile-flavor classes don't collide with noise classes (alerting invariant) |
| `TestInstallErrorCounter_Idempotent` | Re-installing on the same meter is a no-op |
| `TestInstallErrorCounter_NilMeterIsNoOp` | nil meter — counter stays a no-op (test/dev path) |
| `TestWriteTypedError_IncrementsCounter` | Counter increments with correct `(class, status)` AND body is written |
| `TestWriteTypedError_DistinctClassesIncrementSeparately` | 3× signature_invalid + 5× malformed_json → independent dims |
| `TestWriteTypedError_NoCounterInstalledIsNoOp` | No InstallErrorCounter call — no panic |
| `TestWriteTypedJSONError_IncrementsCounter` | Same contract for the alternate body shape |

The counter assertion uses
`go.opentelemetry.io/otel/sdk/metric.NewManualReader` — hermetic, no
Prometheus scrape required for the unit tests.

## Logging

Structured logging via `log/slog` throughout. Every error-emission
site logs at `Error` or `Warn` level with structured fields:

```
deps.Logger.Error("range query failed", "error", err)
deps.Logger.Warn("commitment equivocation surfaced via lookup",
    "schema_id", schemaID,
    "split_id_prefix", hexStr[:16],
    "entry_count", len(entries))
```

Log records pair with metric counts: count is the dashboard view, log
is the per-event detail.

## Gossip metrics

`gossipnet/wiring.go` injects an OTel `metric.Meter` into the
gossip pipeline (separate from the api meter, named under the
`.../gossip` instrumentation scope). Provides counters for sink
drops, anti-entropy pulls, signature verification outcomes, etc.
