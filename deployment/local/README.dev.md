# Local dev topology

`docker-compose.dev.yml` boots a two-exchange laptop topology:

| Service | Port (host) | Purpose |
|---|---|---|
| `operator-davidson` | `:8080` | Trial-court operator, `LogDID = did:web:state:tn:davidson` |
| `operator-coa` | `:8081` | Appellate-court operator, `LogDID = did:web:state:tn:coa` |
| `postgres` | `:5432` | Shared Postgres 18 with two databases (`ortholog_davidson`, `ortholog_coa`) |
| `gcs` | `:4443` | `fake-gcs-server` — anonymous-mode GCS API emulator. Production code path runs unchanged. |
| `gcs-init` | (one-shot) | Creates the two buckets (`davidson-entries`, `coa-entries`) via REST |

This is the runtime the **judicial-network walkthrough** relies on for
its cross-exchange demonstration (Davidson trial → TN COA appeal).

## Quick start

```bash
# from the operator repo root
make dev-up

# wait ~15 sec; the target polls /healthz on both operators and
# exits 0 when both report "ok".
```

Then verify:

```bash
curl -fsS http://localhost:8080/healthz   # → ok
curl -fsS http://localhost:8081/healthz   # → ok
curl -fsS http://localhost:8080/v1/admission/mmd    # → JSON
curl -fsS http://localhost:8080/v1/tree/head        # → JSON
```

Inspect the GCS buckets:

```bash
# List buckets
curl -fsS http://localhost:4443/storage/v1/b | jq '.items[].name'
"davidson-entries"
"coa-entries"

# List objects in a bucket (will be empty until walkthrough runs)
curl -fsS 'http://localhost:4443/storage/v1/b/davidson-entries/o' | jq '.items // []'
```

`fake-gcs-server` has no web console, but its REST surface is the
same GCS HTTP API the production operator hits — so any tool that
speaks GCS (e.g., `gsutil` configured for the local endpoint, or
the Google Cloud SDK with `STORAGE_EMULATOR_HOST=localhost:4443`)
works against this dev topology.

## Tear down

```bash
make dev-down       # removes containers AND volumes (full reset)
```

`dev-down` is destructive on purpose — it wipes Postgres data, GCS
bucket data, Tessera state, WAL, and antispam DBs. Re-running
`dev-up` gives you a fresh log starting at sequence 1 on both
exchanges.

## Logs and status

```bash
make dev-status     # `docker compose ps` shape
make dev-logs       # tail both operators (Ctrl-C to stop)
```

## Design notes

- **GCS, not S3.** The production deployment runs on Google Cloud
  Storage; `fake-gcs-server` (`fsouza/fake-gcs-server`) speaks the
  GCS HTTP API verbatim, so the operator's GCS adapter exercises
  the same code path locally and in production. The operator
  reaches it via `OPERATOR_BYTE_STORE_GCS_ENDPOINT=http://gcs:4443`
  and `OPERATOR_BYTE_STORE_GCS_ANONYMOUS=true` — anonymous mode is
  a config-time switch in the operator (`cmd/operator/main.go`,
  the `ByteStoreGCSAnon` field).
- **Two databases, not one.** Each operator owns its own
  `entry_index`, `commitments`, `antispam` tables. A shared schema
  would conflate sequence-number namespaces across exchanges.
  Postgres' multi-database support is a clean isolation boundary
  with no resource overhead. The init script (`postgres-init.sh`)
  is mounted at `/docker-entrypoint-initdb.d/00-init.sh` and runs
  once per fresh volume to `CREATE DATABASE ortholog_coa`.
- **One image, two services.** `operator-coa` reuses the image
  `ortholog-operator:dev` built once via `operator-davidson`. Saves
  ~30 seconds per cold boot.
- **No witness cosignatures.** The dev topology omits
  `OPERATOR_WITNESS_KEY_FILE`, so each operator self-signs
  checkpoints unwitnessed. Adding a witness is a follow-up.
- **No anchor publisher.** The walkthrough doesn't exercise the
  anchor-commentary path. `OPERATOR_ANCHOR_INTERVAL` is left at its
  default (1h); on a 30-second walkthrough run, no anchor entries
  fire.
- **Sequencer interval is 500ms.** Faster than the production
  default (1s) so SCT → entry-sequenced delay is barely noticeable
  in the walkthrough's `judicial-cli wait` step.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `dev-up` hangs after "waiting for both operators to report healthy" | Postgres init still running | `make dev-logs` to inspect; usually resolves in 20–30 sec on first boot |
| `/healthz` returns 503 from `operator-coa` | `ortholog_coa` database doesn't exist | `make dev-down && make dev-up` (full reset; the init script only runs on fresh volumes) |
| Operator startup logs show `bytestore init: ...` | `gcs` not yet ready | The compose has a `service_completed_successfully` dep on `gcs-init`; if you skipped it, restart with `dev-up` |
| `gcs-init` exits with HTTP 4xx | Bucket already exists from a prior boot but volume kept | The init script's curl falls back to a GET to confirm existence; idempotent. If it really fails, `make dev-down && make dev-up` |
| `docker compose: command not found` | Old docker-compose v1 only | Install Docker Compose v2 (the `docker compose` plugin) |
| `failed to connect to the docker API` | Docker daemon not running | `sudo systemctl start docker` (Linux) or open Docker Desktop |

## What's next

The walkthrough at
`/home/user/judicial-network/docs/walkthrough/` (in the
judicial-network repo) uses this topology to demonstrate two
real-world Tennessee judicial cases plus web3 (did:pkh) DIDs.
Run `make dev-up` here, then follow the walkthrough there.
