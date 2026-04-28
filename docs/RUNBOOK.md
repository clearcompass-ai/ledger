# Operator runbook

Day-2 operational guidance. For architectural background see
`ARCHITECTURE.md`. For configuration see `CONFIG.md`.

## Boot order

1. Postgres pool + migrations.
2. WAL open at `OPERATOR_WAL_PATH`.
3. Tessera embedded appender at `OPERATOR_TESSERA_STORAGE_DIR` +
   antispam at `OPERATOR_TESSERA_ANTISPAM_PATH`.
4. Bytestore from `OPERATOR_BYTE_STORE_*`.
5. CompositeByteReader (WAL → bytestore fallback).
6. Integrity Detector — boot `Reconcile` re-Adds inflight WAL
   entries to Tessera (idempotent via antispam dedup).
7. Shipper goroutine.
8. HTTP server.
9. Fatal-channel supervisor goroutines (Loop, Shipper, etc.).

The boot reconciliation is **permissive** — per-entry failures log
and continue. Hard transport errors (e.g., antispam directory
unreadable) terminate the boot.

## Storage volumes

| Volume                         | What lives there                          | What happens if you lose it                                                                                                                       |
|--------------------------------|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPERATOR_WAL_PATH`            | Bytes-of-record + meta + inflight + HWM   | Pre-admission: nothing lost. Post-admission, pre-shipping: bytes are lost; entry_index rows orphan; reads 404 or post-GC redirect to a 404.       |
| `OPERATOR_TESSERA_ANTISPAM_PATH`| Hash → seq dedup map                     | Tessera's idempotent re-Add becomes non-idempotent. A boot reconciliation could integrate the same entry under a fresh seq.                       |
| `OPERATOR_TESSERA_STORAGE_DIR` | Tile data + checkpoint                    | Tessera-personality cannot reconstruct the tree. Tree-head signing offline. Verifiers cannot fetch tiles.                                          |
| `OPERATOR_BYTE_STORE_*` (GCS)  | Shipped entry wire bytes                  | Post-shipping reads 404 via the 302 redirect. The WAL still has a copy until GC retention; until then reads come from the WAL.                    |

Use distinct PersistentVolumeClaims so a corruption in one does not
cascade.

## Common alerts

### Operator panicked with `operator FATAL: integrity detector:`

**Severity:** PAGE.

The integrity Detector saw a hash mismatch between the WAL and
Tessera. CT logs cannot tolerate this. The operator stopped
serving so consumers don't see corrupt proofs.

**Do NOT auto-restart loop blindly** — a divergence indicates one
of these has corrupt state:
- WAL (Badger) — `OPERATOR_WAL_PATH`
- Tessera tiles — `OPERATOR_TESSERA_STORAGE_DIR`
- Antispam — `OPERATOR_TESSERA_ANTISPAM_PATH`

Steps:
1. Snapshot all three volumes before doing anything else.
2. Capture the panic message — it includes `seq=N wal=<32-byte>
   tessera=<32-byte>`. Persist these for forensics.
3. Decide which side is authoritative. Tessera is usually the
   committed source of truth — verifiers' inclusion proofs are
   rooted in Tessera's tree. If WAL diverges, the WAL is the
   problem.
4. Restart only after a human has reviewed the snapshots and
   chosen a recovery path.

### Antispam directory corruption

**Severity:** HIGH.

Symptom: boot fails at the Tessera antispam open call, or
admission errors with antispam-related messages.

A follower can be rebuilt from the log by replaying every
sequenced hash. While the rebuild runs, the operator can stay up
in degraded mode (every Add becomes a fresh integration; dedup is
lost, double-admission via concurrent submission is possible). Do
not stay in this mode longer than necessary.

### Shipper backlog growing

**Severity:** WARN, escalates if sustained.

Symptom: `wal HWM` lags far behind the highest sequenced entry;
`shipper.Metrics().Shipped` rate drops below admission rate.

Differential diagnosis:
- Bytestore latency spike — check the GCS dashboard for tail
  latency or quota exhaustion.
- Shipper retry storm — check `shipper.Metrics().Retries`. A high
  retry count + low Shipped rate means uploads are failing.
- WAL volume saturation — when WAL fills, admission backpressure
  kicks in (HTTP 503 Retry-After). Check disk usage.

If shipper backlog reaches the WAL volume's free-space watermark,
the WAL committer will start returning `ErrQueueFull` and
admission will return 503. Pre-grow WAL volumes for known-busy
log periods.

### Bytestore 404 on `/raw` redirect

**Severity:** depends on cause.

The redirect path issued a presigned URL, the consumer followed
it, and the bytestore returned 404.

Causes:
- **Pre-shipping race** (transient). The Shipper has not yet
  uploaded this seq. The handler should not have redirected
  unless the WAL meta state was Shipped — investigate why.
- **Post-GC + bucket misconfig.** WAL has GC'd its copy; the
  bytestore is the only source. If the bucket is misconfigured
  (wrong prefix, wrong bucket, IAM lockout), reads fail.
- **Object lifecycle deletion.** Some bucket lifecycles delete
  objects after N days. Verify the bucket's lifecycle rules
  exclude the operator's prefix.

### Submission returning 503 Retry-After

**Severity:** WARN.

The WAL committer's in-memory queue is full. Submitters are
seeing backpressure. Check:
- WAL group-commit batch latency (`BatchMaxLatency` setting).
- Shipper backlog (above) — if the WAL fills with unshipped
  entries, the queue fills too.
- Disk fsync latency on the WAL volume.

## Test surfaces

| Suite                                     | Build tag | Cost            | When to run                                                |
|-------------------------------------------|-----------|-----------------|------------------------------------------------------------|
| `go test ./...`                           | default   | seconds         | every commit                                               |
| `go test ./... -count=1` with DSN         | default   | tens of seconds | local validation; CI integration job                       |
| `go test -tags=soak ./tests/`             | `soak`    | minutes + cloud | release gates; performance regression checks               |
| `scripts/run-soak.sh`                     | `soak`    | minutes + cloud | scripted soak with summary report                          |
| `scripts/run-gcs-tests-real.sh`           | default   | seconds         | bytestore conformance against real GCS                     |
| `scripts/run-bytestore-tests-real-s3.sh`  | default   | seconds         | bytestore conformance against real S3                      |
| `scripts/run-bytestore-tests-rustfs.sh`   | default   | seconds         | bytestore conformance against the local RustFS container   |

## Graceful shutdown

`SIGTERM` → ctx cancel → server.Shutdown drains in-flight HTTP
requests → builder loop exits → shipper drains in-flight uploads
→ WAL committer drains group-commit batch → process exits 0.

The shipper does NOT half-ship: bytestore.WriteEntry runs BEFORE
wal.MarkShipped, so if shutdown lands mid-upload the WAL state
stays `Sequenced` and the next boot's Shipper retries. Bytestore
writes are content-addressed and idempotent.
