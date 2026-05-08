# Observability

OTel meter wiring, the metric inventory, the typed `error_class`
taxonomy, logging conventions, and tracing semantics. Owns the
metric/error-class surface; route mappings live in
[api.md](api.md), env vars in [configuration.md](configuration.md),
shutdown chain in [operations.md](operations.md).

## OpenTelemetry meter provider

Constructed at boot when `LEDGER_METRICS_ENABLE=true` (default
**`true`**, opt-out only via the literal string `"false"` — see
[configuration.md](configuration.md)). Construction site:
`cmd/ledger/main.go:1485 sdklog.NewMeterProvider`. Exporter:
Prometheus, scraped via `GET /metrics`.

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

When metrics are off, every counter is a no-op (no panic; no
overhead).

## Metric inventory

The binary emits the metrics below. Every metric name is grep-able
against the source listed in the right-hand column.

### API surface (`api/`)

| Metric | Type | Labels | Source |
|---|---|---|---|
| `attesta_api_errors_total` | counter | `error_class`, `http_status` | `api/errors.go:81` |
| `attesta_api_request_duration_seconds` | histogram | `route` (currently `"*"`) | `api/instruments.go:71` |

### Sequencer / shipper (`sequencer/`, `shipper/`)

| Metric | Type | Labels | Source |
|---|---|---|---|
| `attesta_sequencer_drain_lag_seconds` | gauge | — | `sequencer/instruments.go:58` |
| `attesta_shipper_pending_total` | gauge | — | `shipper/instruments.go:47` |
| `attesta_shipper_shipped_total` | counter | — | `shipper/instruments_counters.go:107` |
| `attesta_shipper_shipped_unique_total` | counter | — | `shipper/instruments_counters.go:115` |
| `attesta_shipper_skipped_inflight_total` | counter | — | `shipper/instruments_counters.go:123` |
| `attesta_shipper_retries_total` | counter | — | `shipper/instruments_counters.go:131` |
| `attesta_shipper_mark_failures_total` | counter | — | `shipper/instruments_counters.go:139` |

### Storage primitives (`wal/`, `tessera/`, `bytestore/`, `store/`)

| Metric | Type | Source |
|---|---|---|
| `attesta_wal_submit_duration_seconds` | histogram | `wal/instruments.go:73` |
| `attesta_tessera_append_duration_seconds` | histogram | `tessera/instruments.go:50` |
| `attesta_bytestore_put_duration_seconds` | histogram | `bytestore/instruments.go:51` |
| `attesta_postgres_pool_acquire_seconds` | histogram | `store/instruments.go:52` |

### Gossip (`gossipnet/`)

`gossipnet/wiring.go` injects an OTel `metric.Meter` into the
gossip pipeline (separate from the api meter, named under the
`.../gossip` instrumentation scope). The SDK's `gossip.Instruments`
registers the metrics below; the ledger does not implement them
directly, but mounting the gossip handler with `Instruments != nil`
exposes them on `/metrics`.

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `attesta_gossip_received_total` | counter | `kind`, `outcome` | Inbound publish accepts vs. rejects, dimensioned by gossip Kind |
| `attesta_gossip_published_total` | counter | `kind`, `peer`, `outcome` | Outbound publish per-peer fan-out |
| `attesta_gossip_verify_duration_seconds` | histogram | `kind` | Verifier time per Kind |
| `attesta_gossip_chain_head_lamport` | gauge | `originator` | Per-originator current chain head Lamport time |
| `attesta_gossip_store_size_total` | gauge | `kind` | Total events in the local gossip store |
| `attesta_gossip_panic_total` | counter | `panic_kind` | Panics recovered by the SDK handler's self-encapsulating defer |
| `attesta_witness_quorum_failures_total` | counter | `network_id` | `gossipnet/instruments.go:53` |

### `attesta_gossip_panic_total` panic_kind values

The SDK's gossip + cosign handlers each embed `defer recoverPanic`
as the first statement of `ServeHTTP`, so it is structurally
impossible to mount these handlers without panic recovery — even
if the ledger forgets to wrap them in middleware. Recovered panics
emit a 500 with the typed `ErrInternalPanic` sentinel and
increment this counter labelled by classifier output:

| `panic_kind` | When |
|---|---|
| `nil_pointer_deref` | nil pointer dereference (the most common code-bug signal) |
| `index_out_of_range` | slice / array indexing past bounds |
| `slice_out_of_range` | slice expression `s[a:b]` with `a` or `b` out of range |
| `integer_division_by_zero` | division by zero |
| `runtime_error_other` | other `runtime.Error` panics not in the above buckets |
| `error_panic` | `panic(err)` with a non-runtime error |
| `string_panic` | `panic("msg")` with a string literal |
| `other` | any other recovered value |

The classifier is best-effort but the label set is stable — SRE
dashboards can pin alerting on specific kinds without worrying
about labels appearing or disappearing.

`http.ErrAbortHandler` is re-panicked rather than recovered so
stdlib's `TimeoutHandler` integration still works as designed.

## Error class taxonomy

`apitypes/apitypes.go` defines the `ErrorClass` enum (`const (...
ErrorClass = iota ...)` block at line 246). Each constant has a
stable kebab-case `String()` that becomes the OTel attribute
value. New classes require an explicit code addition; the
cardinality budget never grows from caller-controlled strings.

`api/errors.go::writeTypedError` and `writeTypedJSONError` are
the single emission paths; both:

1. Increment `attesta_api_errors_total{error_class, http_status}`
2. Write the JSON body

There are NO bare `writeError` calls in `api/` outside the
wrapper helpers themselves — verify with:

```sh
grep -rn '\twriteError(' api/ | grep -v _test.go
# api/errors.go:141:    writeError(w, status, msg)   (helper itself)

grep -rn '\twriteJSONError(' api/ | grep -v _test.go
# api/errors.go:155:    writeJSONError(w, status, msg)  (helper itself)
```

### Caller-supplied bytes (network noise — usually a client bug)

| Class | When | HTTP |
|---|---|---|
| `malformed_body` | Body read failed | 400 |
| `malformed_json` | JSON parse failed | 400 |
| `body_too_large` | Exceeds `MaxEntrySize` (or the relevant body cap) | 413 |
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

### Ledger infrastructure (page the ledger owner)

| Class | When | HTTP |
|---|---|---|
| `wal_backpressure` | `wal.ErrQueueFull` | 503 (sets `Retry-After`) |
| `wal_persist_failed` | WAL fsync failed | 500 |
| `sct_signing_failed` | `crypto.Sign` returned an error | 500 |
| `db_query_failed` | Postgres query / scan error | 500 |
| `read_projection_failed` | Badger read on a projection failed | 500 |
| `fetcher_failed` | `types.CommitmentFetcher` impl errored | 500 |
| `proof_gen_failed` | SMT or Merkle proof generator errored | 500 |
| `credit_deduct_failed` | Credit txn failed (other than insufficient) | 500 |
| `escrow_override_failed` | Witness collector failed K-of-N | 502 |
| `db_unavailable` | Postgres pool circuit breaker tripped (distinct from per-query `db_query_failed`); fail-fast for the cooldown window | 503 |

### Cardinality budget

```
ErrorClass values:                33   (1 zero-value + 32 explicit;
                                       defined at apitypes/apitypes.go:246)
HTTP statuses (in practice):      ~10
Total attesta_api_errors_total
  time-series:                    ~330
```

Well under Prometheus's recommended 10k/metric ceiling. New
classes are explicit code additions — the cardinality never grows
from caller-controlled strings (which would melt the index).

## Recommended alerts

```promql
# Hostile-flavor — alert on sustained rates
sum by (error_class) (
  rate(attesta_api_errors_total{error_class=~"signature_invalid|admission_proof_invalid|destination_mismatch"}[5m])
)

# Ledger infrastructure — page on any uptick
rate(attesta_api_errors_total{error_class=~"wal_backpressure|wal_persist_failed|sct_signing_failed|db_query_failed|db_unavailable"}[1m])

# Tenant state — informational dashboard, not paging
rate(attesta_api_errors_total{error_class=~"insufficient_credits|expired_session"}[5m])

# Any panic at all is page-worthy — code bug or hostile-input attack the SDK contained
sum by (panic_kind) (rate(attesta_gossip_panic_total[5m])) > 0

# Per-peer gossip fan-out failure rate
sum by (peer) (rate(attesta_gossip_published_total{outcome="failed"}[5m]))
```

## Tests pinning the contract

`apitypes/error_class_test.go` and `api/errors_test.go`:

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
| `TestWriteTypedError_NoCounterInstalledIsNoOp` | No `InstallErrorCounter` call — no panic |
| `TestWriteTypedJSONError_IncrementsCounter` | Same contract for the alternate body shape |

The counter assertion uses
`go.opentelemetry.io/otel/sdk/metric.NewManualReader` — hermetic,
no Prometheus scrape required for the unit tests.

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

Log records pair with metric counts: count is the dashboard view,
log is the per-event detail.

Redaction helpers in `lifecycle/logsafe.go` are the canonical way
to emit identifiers without leaking payloads or signatures:
`HashHex`, `PresenceFlag`, `NetworkIDHex`, `HexShort`. Use them
on every log site that touches request-bound bytes.

## Tracing

`LEDGER_OTLP_TRACES_ENDPOINT` selects the tracer behavior
(`lifecycle/tracing.go::NewTracerProvider`):

| Value | Behavior | Use case |
|---|---|---|
| unset / `""` | NoOp tracer (zero overhead, default) | unit tests, one-shot tools |
| `stdout` | Pretty-print spans to stderr | laptop dev, single operator |
| `localhost:4318` | OTLP HTTP (insecure) | Jaeger / OTel collector on the same host |
| `http://otel:4318` | OTLP HTTP (insecure, explicit) | sidecar collector |
| `https://otel.example.com` | OTLP HTTP over TLS | hosted Honeycomb / Datadog / Tempo |

`pprof.Do` labels are applied around every wrapped goroutine
(`lifecycle/safe_run.go`) so pprof samples carry the supervisor-
assigned name.
