# Local dev topology

`docker-compose.dev.yml` boots a two-exchange laptop topology:

| Service | Port (host) | Purpose |
|---|---|---|
| `operator-davidson` | `:8080` | Trial-court operator, `LogDID = did:web:state:tn:davidson` |
| `operator-coa` | `:8081` | Appellate-court operator, `LogDID = did:web:state:tn:coa` |
| `postgres` | `:5432` | Shared Postgres 18 with two databases (`ortholog_davidson`, `ortholog_coa`) |
| `minio` | `:9000` (S3 API), `:9001` (web console) | S3-compatible bytestore (replaces real GCS/S3) |
| `minio-init` | (one-shot) | Creates the two buckets (`davidson-entries`, `coa-entries`) |

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

MinIO console is at <http://localhost:9001> (login `minioadmin` /
`minioadmin`) — useful to watch entry bytes appear in
`davidson-entries` and `coa-entries` as the walkthrough runs.

## Tear down

```bash
make dev-down       # removes containers AND volumes (full reset)
```

`dev-down` is destructive on purpose — it wipes Postgres data, MinIO
buckets, Tessera state, WAL, and antispam DBs. Re-running `dev-up`
gives you a fresh log starting at sequence 1 on both exchanges.

## Logs and status

```bash
make dev-status     # `docker compose ps` shape
make dev-logs       # tail both operators (Ctrl-C to stop)
```

## Design notes

- **Two databases, not one.** Each operator owns its own
  `entry_index`, `commitments`, `antispam` tables. A shared schema
  would conflate sequence-number namespaces across exchanges.
  Postgres' multi-database support is a clean isolation boundary
  with no resource overhead. The init script
  (`postgres-init.sh`) is mounted at
  `/docker-entrypoint-initdb.d/00-init.sh` and runs once per fresh
  volume to `CREATE DATABASE ortholog_coa`.
- **MinIO instead of GCS/S3.** The operator's `loadConfig` rejects
  `OPERATOR_BYTE_STORE_BACKEND=memory` for production; MinIO speaks
  S3 over HTTP and is the recommended local stand-in. The compose
  pins `OPERATOR_BYTE_STORE_S3_PATH_STYLE=true` because MinIO uses
  path-style URLs (not vhost-style like AWS S3).
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
| Operator startup logs show `bytestore init: ...` | MinIO not yet ready | The compose has a `service_completed_successfully` dep on `minio-init`; if you skipped it, restart with `dev-up` |
| `docker compose: command not found` | Old docker-compose v1 only | Install Docker Compose v2 (the `docker compose` plugin) |
| `failed to connect to the docker API` | Docker daemon not running | `sudo systemctl start docker` (Linux) or open Docker Desktop |

## What's next

The walkthrough at
`/home/user/judicial-network/docs/walkthrough/` (in the
judicial-network repo) uses this topology to demonstrate three
real-world Tennessee judicial cases. Run `make dev-up` here, then
follow the walkthrough there.
