# API

Every HTTP route the ledger serves. Single source of truth:
`api/server.go`. Lines below resolve to the exact `mux.Handle` /
`mux.HandleFunc` call site.

Routes are nil-guarded — every handler in `api.Handlers` is
optional, so `cmd/ledger-reader` and trimmed test harnesses can
omit any of them. A nil handler means the route is not mounted
(stdlib mux returns 404), never a 500.

## Health

| Route | File:Line | Behavior |
|---|---|---|
| `GET /healthz` | `server.go:257` | Always 200 while the process runs |
| `GET /readyz` | `server.go:261` | 200 ready / 503 shutting-down (atomic bool) or 503 with subsystem error message when a `SetReadinessProbe` is installed and returns non-nil |

## Admission

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/entries` | `server.go:288` | Mounted iff `Submission` handler set. Middleware: `SizeLimit(MaxEntrySize+1024)` → `Auth(SessionLookup)` → handler |
| `POST /v1/entries/batch` | `server.go:297` | Mounted iff `BatchSubmission` set. Same middleware chain; cap is `AbsoluteMaxBatchPayloadBytes+1024` (64 MiB hard ceiling, `api/batch.go:35`) |
| `GET /v1/admission/mmd` | `server.go:301` | Maximum Merge Delay (the SCT SLA) |
| `GET /v1/admission/difficulty` | `server.go:346` | Live Mode B PoW difficulty + hash function |

### `POST /v1/entries`

Request body: canonical entry wire bytes (length-prefixed envelope
with signatures section).

Response on success: `202 Accepted` + JSON
`SignedCertificateTimestamp` (`api/sct.go::SignSCT`, line 65 — note:
`SignSCT` is **owned by the ledger** because the private key never
leaves the process; the SDK only ships the verifier-side
`crypto/sct.Verify` + `crypto/sct.SigningPayload`).

```json
{
  "version": 1,
  "signer_did": "did:web:ledger.example",
  "sig_algo_id": "ECDSA-secp256k1-SHA256",
  "log_did": "did:web:log.example",
  "canonical_hash": "abcd...",
  "log_time_micros": 1714659120000000,
  "log_time": "2024-05-02T13:32:00Z",
  "signature": "..."
}
```

Idempotency contract: byte-identical resubmission re-issues the
SAME SCT. The `LogTimeMicros` set on first admission is persisted
in `wal.Meta` and re-read on replay
(`api/submission.go::prepareSubmission`, line 283; idempotency
probe at `api/submission.go:460`). Pinned by
`api/submission_test.go::TestV1Handler_SemanticIdempotency`.

Status mapping (every site emits a typed `error_class`; see
[observability.md](observability.md) for the full taxonomy):

| Status | Meaning | `error_class` examples |
|---|---|---|
| 400 | Caller-supplied bytes malformed | `malformed_body`, `malformed_json`, `bad_hex_*`, `unsupported_schema` |
| 401 | Signature / session | `signature_invalid`, `invalid_session`, `expired_session` |
| 402 | Mode A credits exhausted | `insufficient_credits` |
| 403 | Authoritative rejection | `destination_mismatch`, `admission_proof_invalid`, `difficulty_too_low` |
| 413 | Body too large | `body_too_large` |
| 422 | Envelope rejected | `envelope_rejected`, `freshness_expired` |
| 500 | Ledger infrastructure | `wal_persist_failed`, `sct_signing_failed`, `db_query_failed`, `read_projection_failed`, `proof_gen_failed`, `credit_deduct_failed`, `fetcher_failed` |
| 502 | Witness collector failed K-of-N | `escrow_override_failed` |
| 503 | WAL backpressure / DB breaker tripped | `wal_backpressure` (sets `Retry-After`), `db_unavailable` |

## Tree head + Merkle proofs

| Route | File:Line | Notes |
|---|---|---|
| `GET /v1/tree/head[?size=N]` | `server.go:306` | Latest cosigned tree head; `?size=N` returns the head at exactly that size |
| `GET /v1/tree/inclusion/{seq}` | `server.go:309` | Inclusion proof for sequence number; 503 if no head available |
| `GET /v1/tree/consistency/{old}/{new}` | `server.go:312` | Consistency proof between two tree sizes; old must be < new |

## SMT proofs

| Route | File:Line | Notes |
|---|---|---|
| `GET /v1/smt/proof/{key}` | `server.go:317` | Membership OR non-membership proof for a 32-byte key |
| `POST /v1/smt/batch_proof` | `server.go:321` | Up to 1000 keys; canonically ordered batch proof. Cap: `MaxSMTBatchPayloadBytes+1024` (256 KiB + framing, `api/body_caps.go:80`) |
| `GET /v1/smt/root` | `server.go:325` | Current SMT root + leaf count |
| `GET /v1/smt/leaf/{key}` | `server.go:391` | OriginTip + AuthorityTip for a subject |
| `POST /v1/smt/leaves` | `server.go:394` | Up to 100 keys per batch. Cap: `MaxSMTLeavesPayloadBytes+1024` (64 KiB + framing, `api/body_caps.go:84`) |

## Index queries

`{pos}` encodes a `LogPosition` as `did:sequence`.

| Route | File:Line |
|---|---|
| `GET /v1/query/cosignature_of/{pos}` | `server.go:330` |
| `GET /v1/query/target_root/{pos}` | `server.go:333` |
| `GET /v1/query/signer_did/{did}` | `server.go:336` |
| `GET /v1/query/schema_ref/{pos}` | `server.go:339` |
| `GET /v1/query/scan?start=N&count=M` | `server.go:342` |

## Entry reads

| Route | File:Line | Notes |
|---|---|---|
| `GET /v1/entries/{sequence}` | `server.go:378` | JSON metadata only |
| `GET /v1/entries/batch?start&count` | `server.go:381` | JSON list (count capped at server-side max) |
| `GET /v1/entries-hash/{hashHex}` | `server.go:384` | WAL-aware hash lookup; surfaces `pending` / `manual` states |
| `GET /v1/entries/{sequence}/raw` | `server.go:387` | Wire bytes — 200 inline (WAL) OR 302 to bytestore (shipped) |

The `/raw` route applies a routing decision matrix
(`api/entries_read.go`):

| WAL state | entry_index | Outcome |
|---|---|---|
| `StatePending` | — | 200 `{"state":"pending"}` (truthful — bytes durable, not yet sequenced) |
| `StateManual` | — | 200 `{"state":"manual"}` (sequencer gave up; needs operator intervention) |
| `StateSequenced` / `StateShipped` | row exists | 200 + full metadata |
| `wal.ErrNotFound` | row exists | 200 + full metadata (post-GC; sequenced long ago) |
| `wal.ErrNotFound` | no row | 404 |

## Cryptographic commitment lookup (Pure CQRS — Badger 0x0C)

| Route | File:Line |
|---|---|
| `GET /v1/commitments/by-split-id/{schema_id}/{hex}` | `server.go:402` |

Backed by `gossipstore.BadgerCommitmentFetcher` (Badger 0x0C
prefix). The Postgres-free read path is pinned at compile time —
the SDK interface satisfied by both implementations is
`types.CommitmentFetcher` (see
[sdk-validation.md](sdk-validation.md) for the anchors). Allowed
schema IDs are gated against an internal closed set
(`api/commitments.go::allowedCommitmentSchemas`, dispatch at line
167); unknown IDs return 400 `unsupported_schema`.

`{schema_id}` ∈ {`pre-grant-commitment-v1`,
`escrow-split-commitment-v1`}.
`{hex}` is the 64-character hex-encoded SplitID (32 bytes).

| Outcome | Meaning |
|---|---|
| 404 | No commitment for this (schema_id, split_id) |
| 200 with `len(entries) == 1` | Normal admission |
| 200 with `len(entries) ≥ 2` | Cryptographic equivocation; SDK consumer surfaces `*CommitmentEquivocationError` |

## Derivation commitment lookup

| Route | File:Line |
|---|---|
| `GET /v1/commitments?seq=N` | `server.go:399` |

Returns the SMT batch derivation commitment whose range covers
sequence N. Distinct from `/by-split-id` (cryptographic Pedersen
commitments).

## Witness cosign

Mounted only when the `WitnessCosign` handler is set (i.e. the
ledger runs in witness mode):

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/cosign` | `server.go:351` | Synchronous K-of-N cosign collector. Signs only `cosign.PurposeTreeHead` payloads. Cap: `MaxCosignRequestBytes+1024` (128 KiB + framing, `api/body_caps.go:50`) |

## Gossip

Mounted iff gossip is enabled (`gossipBStore != nil`):

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/gossip` | `server.go:357` | Peers publish signed events. Cap: `MaxGossipPostBytes+1024` (128 KiB + framing, `api/body_caps.go:61`) |
| `GET /v1/gossip/sth/latest` | `server.go:361` | Latest cosigned STH per originator |
| `GET /v1/gossip/since` | `server.go:362` | Anti-entropy cursor pull (with ETag + Cache-Control) |
| `GET /v1/gossip/by-kind` | `server.go:363` | Filter by gossip Kind |
| `GET /v1/gossip/event/{eventID}` | `server.go:364` | Direct fetch by content-derived EventID |
| `GET /v1/gossip/by-binding/{hash}` | `server.go:365` | Zero-trust audit: content-keyed lookup of equivocation findings |

## Escrow override

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/escrow-override` | `server.go:368` | K-of-N witness cosignature collection + broadcast as `KindEscrowOverrideAuth`. Mounted iff witness mode + gossip both wired. Cap: `MaxEscrowOverrideBytes+1024` (64 KiB + framing, `api/body_caps.go:71`) |

## Metrics

| Route | File:Line |
|---|---|
| `GET /metrics` | `server.go:373` |

Prometheus scrape endpoint. Mounted iff `Metrics` handler is set
(toggled per-deployment via `LEDGER_METRICS_ENABLE`, default
`true`). Surfaces every counter, histogram, and gauge cataloged in
[observability.md](observability.md).

## Static-CT tile serving

External auditors fetch the c2sp.org/tlog-tiles surface offline to
reconstruct inclusion + consistency proofs.

| Route | File:Line | Notes |
|---|---|---|
| `GET /checkpoint` | `server.go:414` | Signed root, mutates per integration cycle. `Cache-Control: max-age=2` |
| `GET /tile/{level}/{rest...}` | `server.go:420` | Hash tiles + entry-bundle tiles (handler dispatches `level == "entries"` internally to avoid stdlib-mux specificity collisions) |

Disabled per-deployment via `LEDGER_TILE_SERVE_DISABLE=true`.
Backend selected via `LEDGER_TILE_BACKEND` ∈ {`posix`, `gcs`}; see
[operations.md](operations.md) for the deployment lanes.

## Public introspection

| Route | File:Line | Notes |
|---|---|---|
| `GET /version` | `server.go:432` | Build provenance: `version`, `commit`, `build_time`, `sdk_version`. `Cache-Control: public, max-age=3600`. Populated at build time via `-ldflags -X main.{Version,Commit,BuildTime}=...` |
| `GET /v1/log-info` | `server.go:435` | Public deployment posture: log DID, network ID, witness set count + K, byte-store backend, tile backend, gossip enabled, TLS enabled. `Cache-Control: public, max-age=60` |

Both are PUBLIC + cacheable by design (zero-trust posture; same
shape every CT log monitor expects). Operational tunables (pool
sizes, internal paths) are NOT exposed here — they live in the
boot-banner log line and on pprof's private listener.

## Cross-cutting middleware

Every request — including `/healthz`, `/readyz`, every read path —
flows through:

1. `RequestDurationMiddleware("*", root)` (`api/server.go:453`):
   Histogram `attesta_api_request_duration_seconds` labelled
   `route="*"`. Outermost wrap so authn time is included.
2. `WithRequestID(mux)` (`api/server.go:445`): Per-request
   correlation ID (`X-Request-ID`); every structured log line
   carries it.

The HTTP server is constructed with non-zero
`ReadTimeout=30s`, `ReadHeaderTimeout=10s` (Slowloris cap),
`WriteTimeout=60s`, `IdleTimeout=60s`. `MaxEntrySize=1 MiB` is the
default, overridable per deployment.

## Route-mount tests

Every route's mount + nil-tolerance contract is pinned in
`api/server_test.go`:

```
TestServer_V1EntriesRouteReachesSubmissionHandler
TestServer_V2EntriesRouteNotMounted
TestServer_BatchEntriesRouteReachesBatchHandler
TestServer_BatchEntriesRouteNotMountedWhenNil
TestServer_MMDRouteWired
TestServer_GossipFeedRoutes_Mounted
TestServer_GossipFeedByBinding_NotMountedWhenFeedNil
TestServer_CommitmentLookupRoute_MountedWhenSet
TestServer_CommitmentLookupRoute_NotMountedWhenNil
TestServer_HealthAndReadyWired
```

A future refactor that drops a route or mounts a nil handler
trips these.
