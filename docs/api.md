# API

Every HTTP route the operator serves. Single source of truth:
`api/server.go`. Lines below are exact references.

## Health

| Route | File:Line | Behavior |
|---|---|---|
| `GET /healthz` | `server.go:202` | Always 200 while process runs |
| `GET /readyz` | `server.go:206` | 200 ready / 503 shutting-down (atomic bool) |

## Admission

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/entries` | `server.go:222` | Mounted iff `Submission` handler set. Middleware: `SizeLimit(MaxEntrySize+1024)` → `Auth(SessionLookup)` → handler |
| `POST /v1/entries/batch` | `server.go:234` | Mounted iff `BatchSubmission` set. Same middleware chain; cap is `AbsoluteMaxBatchPayloadBytes+1024` (64 MiB hard ceiling) |
| `GET /v1/admission/mmd` | `server.go:241` | Maximum Merge Delay (the SCT SLA) |
| `GET /v1/admission/difficulty` | `server.go:285` | Live Mode B PoW difficulty + hash function |

### `POST /v1/entries`

Request body: canonical entry wire bytes (length-prefixed envelope
with signatures section).

Response on success: `202 Accepted` + JSON
`SignedCertificateTimestamp` (`api/sct.go::SignSCT`):

```json
{
  "version": 1,
  "signer_did": "did:web:operator.example",
  "sig_algo_id": "ECDSA-secp256k1-SHA256",
  "log_did": "did:web:log.example",
  "canonical_hash": "abcd...",
  "log_time_micros": 1714659120000000,
  "log_time": "2024-05-02T13:32:00Z",
  "signature": "..."
}
```

Idempotency contract: byte-identical resubmission re-issues the SAME
SCT (semantic equivalence — the operator-side
`LogTimeMicros` is persisted in WAL `Meta`, so the SCT's signed
fields are identical). Pinned by
`api/submission_test.go::TestV1Handler_SemanticIdempotency`.

Error mapping (every site emits a typed `error_class` —
see [observability.md](observability.md)):

| Status | Meaning | `error_class` examples |
|---|---|---|
| 400 | Caller-supplied bytes malformed | `malformed_body`, `malformed_json`, `bad_hex_*` |
| 401 | Signature / session | `signature_invalid`, `invalid_session` |
| 402 | Mode A credits exhausted | `insufficient_credits` |
| 403 | Authoritative rejection | `destination_mismatch`, `admission_proof_invalid` |
| 413 | Body too large | `body_too_large` |
| 422 | Envelope rejected | `envelope_rejected`, `freshness_expired` |
| 503 | WAL backpressure | `wal_backpressure` (sets `Retry-After`) |
| 500 | Operator infrastructure | `wal_persist_failed`, `sct_signing_failed` |

## Tree head + Merkle proofs

| Route | File:Line | Notes |
|---|---|---|
| `GET /v1/tree/head[?size=N]` | `server.go:246` | Latest cosigned tree head; `?size=N` returns the head at exactly that size |
| `GET /v1/tree/inclusion/{seq}` | `server.go:249` | Inclusion proof for sequence number; 503 if no head available |
| `GET /v1/tree/consistency/{old}/{new}` | `server.go:252` | Consistency proof between two tree sizes; old must be < new |

## SMT proofs

| Route | File:Line | Notes |
|---|---|---|
| `GET /v1/smt/proof/{key}` | `server.go:257` | Membership OR non-membership proof for a 32-byte key |
| `POST /v1/smt/batch_proof` | `server.go:260` | Up to 1000 keys; canonically ordered batch proof |
| `GET /v1/smt/root` | `server.go:263` | Current SMT root + leaf count |
| `GET /v1/smt/leaf/{key}` | `server.go:359` | OriginTip + AuthorityTip for a subject |
| `POST /v1/smt/leaves` | `server.go:362` | Up to 100 keys per batch |

## Index queries

`{pos}` encodes a `LogPosition` as `did:sequence`.

| Route | File:Line |
|---|---|
| `GET /v1/query/cosignature_of/{pos}` | `server.go:268` |
| `GET /v1/query/target_root/{pos}` | `server.go:271` |
| `GET /v1/query/signer_did/{did}` | `server.go:274` |
| `GET /v1/query/schema_ref/{pos}` | `server.go:277` |
| `GET /v1/query/scan?start=N&count=M` | `server.go:280` |

## Entry reads

| Route | File:Line | Notes |
|---|---|---|
| `GET /v1/entries/{sequence}` | `server.go:332` | JSON metadata only |
| `GET /v1/entries/batch?start&count` | `server.go:335` | JSON list (count capped at server-side max) |
| `GET /v1/entries-hash/{hashHex}` | `server.go:348` | WAL-aware hash lookup; surfaces `pending` / `manual` states |
| `GET /v1/entries/{sequence}/raw` | `server.go:354` | Wire bytes — 200 inline (WAL) OR 302 to bytestore (shipped) |

The `/raw` route applies a routing decision matrix (`api/entries_read.go`):

| WAL state | entry_index | Outcome |
|---|---|---|
| `StatePending` | — | 200 `{"state":"pending"}` (truthful — bytes durable, not yet sequenced) |
| `StateManual` | — | 200 `{"state":"manual"}` (sequencer gave up; needs operator) |
| `StateSequenced` / `StateShipped` | row exists | 200 + full metadata |
| `wal.ErrNotFound` | row exists | 200 + full metadata (post-GC; sequenced long ago) |
| `wal.ErrNotFound` | no row | 404 |

## Cryptographic commitment lookup (Pure CQRS — Badger 0x0C)

| Route | File:Line |
|---|---|
| `GET /v1/commitments/by-split-id/{schema_id}/{hex}` | `server.go:377` |

Backed by `gossipstore.BadgerCommitmentFetcher`. Zero Postgres on
this path (`go list -deps ./api/ \| grep pgx \| wc -l == 0`).

`{schema_id}` ∈ {`pre-grant-commitment-v1`, `escrow-split-commitment-v1`}.
`{hex}` is the 64-character hex-encoded SplitID (32 bytes).

| Outcome | Meaning |
|---|---|
| 404 | No commitment for this (schema_id, split_id) |
| 200 with `len(entries) == 1` | Normal admission |
| 200 with `len(entries) ≥ 2` | Cryptographic equivocation; SDK consumer surfaces `*CommitmentEquivocationError` |

## Derivation commitment lookup

| Route | File:Line |
|---|---|
| `GET /v1/commitments?seq=N` | `server.go:367` |

SMT batch derivation commitment whose range covers sequence N.
Distinct from `/by-split-id` (cryptographic Pedersen commitments).

## Witness cosign

Mounted only when `WitnessCosign` handler is set (i.e. operator runs
in witness mode):

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/cosign` | `server.go:290` | Synchronous K-of-N cosign collector. Signs only `cosign.PurposeTreeHead` payloads |

## Gossip

Mounted iff gossip is enabled (`gossipBStore != nil`):

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/gossip` | `server.go:300` | Peers publish signed events |
| `GET /v1/gossip/sth/latest` | `server.go:303` | Latest cosigned STH per originator |
| `GET /v1/gossip/since` | `server.go:304` | Anti-entropy cursor pull (with ETag + Cache-Control) |
| `GET /v1/gossip/by-kind` | `server.go:305` | Filter by gossip Kind |
| `GET /v1/gossip/event/{eventID}` | `server.go:306` | Direct fetch by content-derived EventID |
| `GET /v1/gossip/by-binding/{hash}` | `server.go:312` | Zero-trust audit: content-keyed lookup of equivocation findings |

## Escrow override

| Route | File:Line | Notes |
|---|---|---|
| `POST /v1/escrow-override` | `server.go:315` | K-of-N witness cosignature collection + broadcast as `KindEscrowOverrideAuth`. Mounted iff witness mode + gossip both wired |

## Metrics

| Route | File:Line |
|---|---|
| `GET /metrics` | `server.go:322` |

Prometheus scrape endpoint. Mounted iff `OPERATOR_METRICS_ENABLE=true`.
Metric: `ortholog_api_errors_total{error_class, http_status}` —
see [observability.md](observability.md).

## Route-mount tests

Every route's mount + nil-tolerance contract is pinned by
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
