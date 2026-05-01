# Local dev topology

Two compose files live here, for two different audiences:

| File | When to use | GCS backend |
|---|---|---|
| `docker-compose.dev.yml` | **Daily development.** What `make dev-up` runs. | **Real GCS** — your own buckets in your own GCP project. Same path as production. |
| `docker-compose.integration.yml` | CI integration tests, offline / air-gapped runs. What `make integration-up` runs. | `fake-gcs-server` — in-process, anonymous, deterministic. |

This document covers the dev topology (real GCS). For the
integration-tests topology, jump to [§ Integration topology](#integration-topology) below.

---

## Dev topology — real GCS

| Service | Port (host) | Purpose |
|---|---|---|
| `operator-davidson` | `:8080` | Trial-court operator, `LogDID = did:web:state:tn:davidson` |
| `operator-coa` | `:8081` | Appellate-court operator, `LogDID = did:web:state:tn:coa` |
| `postgres` | `:5432` | Shared Postgres 18 with two databases (`ortholog_davidson`, `ortholog_coa`) |
| (no GCS service) | — | Each operator hits `storage.googleapis.com` directly using your gcloud Application Default Credentials. |

This is the runtime the **judicial-network walkthrough** runs
against. It mirrors production: same GCS adapter code path, same
IAM behaviour, same multipart upload thresholds, same
ListObjects pagination.

### One-time developer setup

You need three things on your laptop **before** `make dev-up`:

1. A Google Cloud project where you can create buckets.
2. `gcloud auth application-default login` completed (writes
   `~/.config/gcloud/application_default_credentials.json`,
   which the compose mounts read-only into both operator
   containers).
3. Two GCS buckets created:

   ```bash
   export GOOGLE_PROJECT=your-gcp-project-id
   gcloud storage buckets create gs://yourname-davidson-entries \
     --location=US --project=$GOOGLE_PROJECT
   gcloud storage buckets create gs://yourname-coa-entries \
     --location=US --project=$GOOGLE_PROJECT
   ```

   Bucket names are global; pick something unlikely to collide.
   `gcloud storage buckets list --project=$GOOGLE_PROJECT`
   confirms they exist.

4. Two env vars exported in the shell from which you run
   `make dev-up`:

   ```bash
   export OPERATOR_DEV_BUCKET_DAVIDSON=yourname-davidson-entries
   export OPERATOR_DEV_BUCKET_COA=yourname-coa-entries
   ```

Persist them in your shell rc if you'll be doing this often.

### Quick start

```bash
make dev-up
```

Behind the scenes, `dev-up` first runs `dev-preflight`, which
verifies that ADC exists and that both bucket env vars are set.
On any preflight failure the target exits non-zero with a clear
message — no half-built containers.

After ~15 seconds:

```bash
$ curl -fsS http://localhost:8080/healthz   # → ok
$ curl -fsS http://localhost:8081/healthz   # → ok
```

Inspect your real GCS buckets with `gcloud` or `gsutil`:

```bash
gcloud storage ls gs://$OPERATOR_DEV_BUCKET_DAVIDSON
gcloud storage cat gs://$OPERATOR_DEV_BUCKET_DAVIDSON/<object>
```

(Empty until walkthrough or your own client submits entries.)

### Tear down

```bash
make dev-down
```

`dev-down` removes containers and the **local** volumes (Postgres
data, Tessera state, WAL, antispam DBs). It does **NOT** delete
your GCS buckets or the objects in them. To clear bucket state:

```bash
gcloud storage rm 'gs://yourname-davidson-entries/**'
gcloud storage rm 'gs://yourname-coa-entries/**'
```

Re-running `make dev-up` after `dev-down` gives you a fresh log
starting at sequence 1 on both exchanges (Postgres-side state was
wiped); orphaned objects in GCS get rewritten by sequence number.

### Logs and status

```bash
make dev-status     # `docker compose ps`
make dev-logs       # tail both operators (Ctrl-C to stop)
```

### Why real GCS for dev (not fake-gcs-server)

At-scale tests, latency profiles, IAM behaviour, multipart upload
thresholds, and ListObjects pagination all behave differently
against real GCS than against `fake-gcs-server`. The dev path is
where GCS-related bugs need to surface; faking the backend masks
them. `fake-gcs-server` lives in the integration-tests topology
where deterministic offline runs matter more than GCS realism.

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `dev-preflight` fails: missing ADC | Never ran `gcloud auth application-default login` | Run it; ADC lands at `~/.config/gcloud/application_default_credentials.json`. |
| `dev-preflight` fails: bucket env unset | Forgot to `export OPERATOR_DEV_BUCKET_*` | Export both, then re-run `make dev-up`. |
| Operator startup: `bytestore init: ... permission denied` | ADC user lacks `roles/storage.objectAdmin` on the bucket | `gcloud storage buckets add-iam-policy-binding gs://<bucket> --member=user:you@example.com --role=roles/storage.objectAdmin` |
| Operator startup: `bytestore init: ... bucket doesn't exist` | Bucket name typo or bucket in different project | `gcloud storage buckets list --project=$GOOGLE_PROJECT` to confirm. |
| `dev-up` hangs at "waiting for both operators" | Postgres init still running on first boot | `make dev-logs` to inspect; usually resolves in 20–30 sec. |
| `/healthz` returns 503 from `operator-coa` | `ortholog_coa` database doesn't exist | `make dev-down && make dev-up` (full reset; init script only runs on fresh volumes). |
| `docker compose: command not found` | Old docker-compose v1 only | Install Docker Compose v2. |

---

## Integration topology

For tests that must run offline, deterministically, or in CI
without GCS credentials. Uses `fake-gcs-server`
(`fsouza/fake-gcs-server`) on port `:4443` instead of real GCS.

### Quick start

```bash
make integration-up

# Once both operators are healthy:
curl -fsS http://localhost:8080/healthz   # → ok
curl -fsS http://localhost:8081/healthz   # → ok
curl -fsS http://localhost:4443/storage/v1/b   # GCS-shape JSON
```

No `gcloud` setup required. No real cloud cost. No flaky network.

### Tear down

```bash
make integration-down       # also wipes fake-gcs-server bucket data
```

### Limits

`fake-gcs-server` is great for correctness and shape testing; it's
NOT a replacement for the real-GCS path during development. It
diverges from real GCS in:
- Latency profile (synchronous local vs. ~50 ms global)
- IAM model (anonymous; no policy enforcement)
- Multipart upload thresholds
- ListObjects pagination behaviour
- Conditional headers (matches the spec but not always verbatim
  with Google's implementation)

If a feature works against `fake-gcs-server` and breaks against
real GCS, that's not a bug in your code — it's a bug in the
emulator's coverage of the spec. Always validate against
`make dev-up` before merging.

---

## What's next

The walkthrough at
`/home/user/judicial-network/docs/walkthrough/` (in the
judicial-network repo) uses **`make dev-up` (real GCS)** to
demonstrate two real-world Tennessee judicial cases plus web3
(`did:pkh`) DIDs. Run `make dev-up` here, then follow the
walkthrough there.
