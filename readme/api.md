# API

HTTP routes the operator serves under `/v1/`, the 14-step admission
pipeline that runs behind `POST /v1/entries`, and the read endpoints
covering tree heads, Merkle proofs, SMT proofs, and entry queries.
Routes are wired in `api/server.go`.

## Routes

### Submission

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/entries` | Submit a signed entry for admission |

Middleware chain (`api/server.go:131`): `SizeLimit(MaxEntrySize+1024)`
→ `Auth(sessions table)` → handler. `Auth` validates Bearer tokens
against the `sessions` table; an invalid token returns 401 (not a
silent drop into Mode B).

### Tree head and Merkle proofs

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tree/head` | Latest tree head |
| `GET` | `/v1/tree/inclusion/{seq}` | Merkle inclusion proof for sequence number |
| `GET` | `/v1/tree/consistency/{old}/{new}` | Consistency proof between two tree sizes |

### SMT proofs

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/smt/proof/{key}` | Membership or non-membership proof (auto-detected) |
| `POST` | `/v1/smt/batch_proof` | Batch multiproof for multiple keys |
| `GET` | `/v1/smt/root` | Current SMT root hash + leaf count |
| `GET` | `/v1/smt/leaf/{key}` | Single leaf state |
| `POST` | `/v1/smt/leaves` | Batch leaf states |

### Entry reads

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/entries/{sequence}` | JSON metadata (no bytes) |
| `GET` | `/v1/entries/batch` | Batch metadata |
| `GET` | `/v1/entries/{sequence}/raw` | Wire bytes — 200 inline if WAL has them, 302 + presigned URL if shipped |

The raw-bytes endpoint sets `X-Source: wal` on inline responses and
`X-Source: bytestore` on redirects. See
[readme/storage.md](storage.md) for state-by-state behavior.

### Query endpoints

All return a JSON array (empty if no results, never null).

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/query/cosignature_of/{pos}` | Entries whose `Cosignature_Of` matches position |
| `GET` | `/v1/query/target_root/{pos}` | Entries targeting a specific root entity |
| `GET` | `/v1/query/signer_did/{did}` | Entries signed by a specific DID |
| `GET` | `/v1/query/schema_ref/{pos}` | Entries governed by a specific schema |
| `GET` | `/v1/query/scan?start=N&count=M` | Sequential scan |

### Admission and commitments

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/admission/difficulty` | Current Mode B difficulty + hash function (live, not cached) |
| `GET` | `/v1/commitments?seq=N` | Commitment metadata for a given sequence |

### Witness cosign (conditional)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/cosign` | Witness cosignature endpoint — registered only when `Handlers.WitnessCosign != nil` |

The `WitnessCosign` handler is currently `nil` in
`cmd/operator/main.go`; the route is not registered in the default
build. Wiring `witness.NewCosignServer` enables it.

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness probe (always 200 while the process runs) |
| `GET` | `/readyz` | Readiness probe (atomic bool, 503 during shutdown) |

## Admission pipeline

`api/submission.go` runs 14 numbered steps for each `POST /v1/entries`
request. Failures are fail-fast: the first failure terminates the
request with the corresponding HTTP status.

| Step | Action | File reference |
|---|---|---|
| 1 | Read raw bytes; validate the 6-byte preamble. Protocol version must equal `envelope.CurrentProtocolVersion()` | `submission.go:277` |
| 2 | `envelope.Deserialize` wire bytes; validate the signature algorithm ID | `submission.go:297` |
| 3a | `entry.Validate()` re-applies `NewEntry`'s write-time invariants | `submission.go:317` |
| 3a-NFC | `admission.CheckNFC` asserts NFC normalization on DID-shaped header fields | `submission.go:324` |
| 3b | Destination binding: `entry.Header.Destination == OPERATOR_LOG_DID` | `submission.go:331` |
| 3c | Late-replay freshness: `policy.CheckFreshness` (default 5 minutes) | `submission.go:339` |
| 4 | Signature verification (`admission.VerifyEntrySignature`, SDK-D5) | `submission.go:346` |
| 4-Schema | Recognized commitment-schema dispatch — extracts `SplitID` for index population | `submission.go:364` |
| 5 | Entry size cap (`OPERATOR_MAX_ENTRY_SIZE`, default 1 MB; SDK-D11) | `submission.go:377` |
| 6 | `Evidence_Pointers` cap (Decision 51) | `submission.go:387` |
| 7 | Admission mode dispatch — Mode A (Bearer + credit deduction) or Mode B (compute stamp via live difficulty) | `submission.go:396` |
| 8 | Canonical hash via `envelope.EntryIdentity` | `submission.go:440` |
| 8a | Early duplicate check — `EntryStore.FetchByHash` short-circuits before WAL write | `submission.go:443` |
| 9 | `Log_Time` assignment (UTC, outside canonical bytes; SDK-D1, Decision 50) | `submission.go:457` |
| 10 | `wal.Submit` — durable on local NVMe, fsynced via group commit | `submission.go:460` |
| 11 | `tessera.AppendLeaf` — Tessera assigns the sequence; antispam dedup makes re-Add idempotent | `submission.go:477` |
| 12 | Postgres sidecar — `entry_index` INSERT (+ `commitment_split_id` row when step 4-Schema extracted a SplitID) inside one ReadCommitted tx; Mode A credit deduction lives here too | `submission.go:490` |
| 13 | `wal.Sequence` — record Tessera-assigned seq in WAL meta (pending → sequenced) | `submission.go:568` |
| 14 | 202 with `{ sequence_number, canonical_hash, log_time }` | `submission.go:584` |

Tessera append happens twice for every admitted entry: once at
admission step 11 (to allocate the sequence number for the 202
response) and again post-commit in `builder/loop.go:429` (to make
crash recovery between admission and builder run safe). Antispam
dedup at the embedded Tessera layer guarantees both paths converge on
the same sequence.

## Error responses

| Status | Condition |
|---|---|
| 401 | Signature verification failed / invalid Bearer token / signer DID resolution failed |
| 402 | Insufficient write credits (Mode A) |
| 403 | Wrong destination DID, or unauthenticated submission failed compute-stamp verification (Mode B) |
| 409 | Duplicate entry (canonical hash already stored — race winner returns 202) |
| 413 | Entry exceeds `MaxEntrySize` |
| 422 | Malformed preamble / unsupported protocol version / failed entry validation / NFC violation / freshness violation / unrecognized commitment schema payload / Evidence_Pointers cap exceeded |
| 500 | WAL submit failed / Tessera AppendLeaf failed / WAL Sequence failed (recoverable on next boot via integrity reconcile) |
| 503 | WAL queue full (`Retry-After: 5`) — backpressure, not failure |

## Entry response shape

Query endpoints and `/v1/entries/{seq}` return entries enriched with
extracted header fields:

```json
{
  "sequence_number": 42,
  "canonical_hash": "a1b2c3...",
  "log_time": "2024-01-15T10:30:00Z",
  "signer_did": "did:example:alice",
  "target_root": "...",
  "cosignature_of": null,
  "schema_ref": null,
  "canonical_bytes": "00060000..."
}
```

The 6-byte preamble at the start of `canonical_bytes` is the protocol
version (currently per `envelope.CurrentProtocolVersion()`).
