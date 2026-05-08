# Attesta ledger — Helm chart

Modular Helm chart for the Attesta ledger. The only supported
Kubernetes deployment path; the previous single-file manifest
under `deploy/k8s/` has been removed.

Optional in-cluster Postgres comes from
[`bitnami/postgresql`](https://github.com/bitnami/charts/tree/main/bitnami/postgresql)
pulled from the OCI registry. Production deployments typically
disable that and point at a managed instance (Cloud SQL, RDS).

## Install

### Quick start (laptop / smoke deploy)

In-cluster Postgres via the bitnami sub-chart, ephemeral signer
keys, no Prometheus Operator. Note: `byteStore.backend` MUST be
`gcs` or `s3` — those are the only values the ledger accepts at
boot (`cmd/ledger/main.go:642–654`). The smoke-deploy path below
assumes a developer-owned GCS bucket; for an air-gapped lab use a
local S3-compatible service such as `rustfs` and set
`byteStore.backend=s3` with the corresponding `byteStore.s3.*`
fields.

```sh
helm dependency build deploy/helm/ledger

helm install ledger deploy/helm/ledger \
    -n ledger --create-namespace \
    --set image.tag=1.0.0 \
    --set config.logDID=did:web:smoke.example.com \
    --set config.byteStore.backend=gcs \
    --set config.byteStore.gcs.bucket=my-smoke-bucket \
    --set config.tile.backend=posix \
    --set postgresql.enabled=true \
    --set postgresql.auth.password='choose-a-password'
```

The ledger boots with ephemeral signing keys (`NOT for production`
warning in logs).

### Production

External managed Postgres, GCS bucket, signer keys from Secret,
ServiceMonitor on. Use the worked overlay:

```sh
cp deploy/helm/ledger/values-production.example.yaml my-values.yaml
$EDITOR my-values.yaml  # fill placeholders

helm upgrade --install ledger deploy/helm/ledger \
    -n ledger --create-namespace -f my-values.yaml
```

## Database modes

The deployment composes `LEDGER_DATABASE_URL` along one of three
paths, selected by your values:

| Mode | Trigger | What happens |
|---|---|---|
| Bitnami sub-chart | `postgresql.enabled: true` | Pod composes the URL at startup from `postgresql.auth.username`, `auth.database`, the `<release>-postgresql` Service, and the password from `auth.existingSecret` (or the bitnami-generated Secret if `auth.password` is set inline). |
| External Secret  | `externalDatabase.existingSecret: <name>` | Pod reads `LEDGER_DATABASE_URL` directly from the Secret. Recommended for production (rotated by external-secrets / Vault). |
| External inline  | `externalDatabase.url: postgres://…` | Chart writes a Secret containing the URL. Dev / CI only. |

If none of the three is configured the chart fails at template
time (`helm.sh/template`) — no silent CrashLoopBackOff.

## Architecture

| Resource              | Conditional knob                                |
|-----------------------|-------------------------------------------------|
| `Namespace`           | `namespace.create`                              |
| `ServiceAccount`      | `serviceAccount.create`                         |
| `ConfigMap`           | always                                          |
| `Secret` (DB URL)     | inline-URL external mode only                   |
| `PVC` × {wal,tessera,antispam} | each `persistence.<v>.enabled`         |
| `Deployment`          | always                                          |
| `Service`             | always                                          |
| `PodDisruptionBudget` | `pdb.enabled`                                   |
| `ServiceMonitor`      | `serviceMonitor.enabled`                        |
| Bitnami Postgres      | `postgresql.enabled`                            |

## Signer keys (production stable identity)

By default the ledger generates ephemeral signing keys at boot and
emits a `NOT for production` warning. Witnesses + auditors will see
a fresh DID on every restart. Suitable for smoke deploys, CI, and
laptop-K8s.

For production:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out signer.pem
openssl ecparam -genkey -name prime256v1 -noout -out tessera-signer.pem
kubectl -n ledger create secret generic ledger-signer-keys \
    --from-file=signer.pem=signer.pem \
    --from-file=tessera-signer.pem=tessera-signer.pem
```

```yaml
signerKeys:
  enabled: true
  existingSecret: ledger-signer-keys
```

The Deployment mounts the Secret read-only at `/etc/ledger/keys`
and sets `LEDGER_SIGNER_KEY_FILE` + `LEDGER_TESSERA_SIGNER_KEY_FILE`.
Missing Secret → admission rejection, never a runtime crash.

## Singleton-writer discipline

`replicas: 1` is non-negotiable. The Postgres advisory lock
(`store/postgres.go:400 BuilderLockID = 0x4F5254484F4C4F47`)
enforces singleton-writer at the DB level; a second pod fails
fast with a rolling-update conflict message.
`strategy.type: Recreate` for the same reason.

Read-scaling lives in `cmd/ledger-reader` (separate chart, not in
this directory).

## Values reference

See `values.yaml` for the full schema. Notable knobs:

| Key                            | Purpose                                               |
|--------------------------------|-------------------------------------------------------|
| `image.tag`                    | Pinned ledger image tag (defaults to AppVersion).     |
| `config.logDID`                | Required in production; `LEDGER_LOG_DID`.             |
| `config.byteStore.backend`     | `gcs` or `s3` — these are the only values the binary accepts. |
| `config.tile.backend`          | `gcs` or `posix`.                                     |
| `extraEnv`                     | Free-form `LEDGER_*` env (witness, gossip, MMD).      |
| `extraEnvFrom`                 | `envFrom` Secret/ConfigMap refs (S3 creds, etc.).     |
| `persistence.storageClassName` | Storage class for all three PVCs.                     |
| `serviceAccount.annotations`   | Workload-identity bindings (GKE / EKS).               |

For the bitnami postgres knobs (`postgresql.*`) refer to the
[upstream chart README](https://github.com/bitnami/charts/tree/main/bitnami/postgresql#parameters).

The full `LEDGER_*` env contract — including which vars are
required vs. optional and their defaults — is in
[../../docs/configuration.md](../../docs/configuration.md).

## Local validation

```sh
helm dependency build deploy/helm/ledger
helm lint     deploy/helm/ledger
helm template deploy/helm/ledger \
    --set postgresql.enabled=true \
    --set postgresql.auth.password=test \
    --set config.logDID=did:web:lint.test \
    --set config.byteStore.backend=gcs \
    --set config.byteStore.gcs.bucket=lint-test \
    | kubectl apply --dry-run=client -f -
```
