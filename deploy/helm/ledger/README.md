# Attesta ledger — Helm chart

Modular Helm chart for the Attesta ledger. Replaces the single-file
`deploy/k8s/ledger.yaml` manifest.

## Install

### Quick start (laptop / smoke deploy)

In-cluster Postgres via Bitnami sub-chart, ephemeral signer keys, no
Prometheus Operator:

```bash
helm dependency update deploy/helm/ledger

helm install ledger deploy/helm/ledger \
    -n ledger --create-namespace \
    --set postgresql.enabled=true \
    --set postgresql.auth.password='choose-a-password' \
    --set image.tag=1.0.0 \
    --set config.logDID=did:web:smoke.example.com \
    --set config.byteStore.backend=posix \
    --set config.tile.backend=posix
```

The ledger boots with ephemeral signing keys (`NOT for production`
warning in logs) and writes everything to PVCs.

### Production

External managed Postgres, GCS bucket, signer keys from Secret,
ServiceMonitor on. Use the worked example overlay:

```bash
cp deploy/helm/ledger/values-production.example.yaml my-values.yaml
$EDITOR my-values.yaml  # fill placeholders

helm upgrade --install ledger deploy/helm/ledger \
    -n ledger --create-namespace \
    -f my-values.yaml
```

## Architecture

| Resource              | Conditional knob                     |
|-----------------------|--------------------------------------|
| `Namespace`           | `namespace.create`                   |
| `ServiceAccount`      | `serviceAccount.create`              |
| `ConfigMap`           | always                               |
| `Secret` (DB DSN)     | when `database.urlSecret.name` empty |
| `PVC` × {wal,tessera,antispam} | each `persistence.<v>.enabled` |
| `Deployment`          | always                               |
| `Service`             | always                               |
| `PodDisruptionBudget` | `pdb.enabled`                        |
| `ServiceMonitor`      | `serviceMonitor.enabled`             |
| Bitnami Postgres      | `postgresql.enabled`                 |

### Database modes

The chart resolves `LEDGER_DATABASE_URL` through one of three paths,
selected by `postgresql.enabled` and `database.*`:

1. `postgresql.enabled: true` — pulls in `bitnami/postgresql`
   (chart dependency). The chart writes a Secret `<release>-db`
   containing the composed URL. Requires `postgresql.auth.password`
   to be set so both bitnami's auth Secret and ours agree.
2. `postgresql.enabled: false` + `database.externalUrl` set —
   chart writes the URL into a chart-managed Secret. Fits
   managed Postgres (Cloud SQL, RDS) when the URL is known
   at deploy time.
3. `postgresql.enabled: false` + `database.urlSecret.name` set —
   chart references a pre-existing Secret. Fits external secret
   stores (Vault, external-secrets) where the URL never reaches
   the chart.

### Signer keys (production stable identity)

By default the ledger generates ephemeral signing keys at boot and
emits a `NOT for production` warning. Witnesses + auditors will see
a fresh DID on every restart. Suitable for smoke deploys, CI, and
laptop-K8s.

For production, generate the keys off-cluster:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out signer.pem
openssl ecparam -genkey -name prime256v1 -noout -out tessera-signer.pem
kubectl -n ledger create secret generic ledger-signer-keys \
    --from-file=signer.pem=signer.pem \
    --from-file=tessera-signer.pem=tessera-signer.pem
```

Then enable:

```yaml
signerKeys:
  enabled: true
  existingSecret: ledger-signer-keys
```

The Deployment mounts the Secret read-only at `/etc/ledger/keys`
and sets `LEDGER_SIGNER_KEY_FILE` + `LEDGER_TESSERA_SIGNER_KEY_FILE`.
If the Secret is missing the pod is rejected at admission control —
no `CrashLoopBackOff` surprise at runtime.

## Values reference

See `values.yaml` for the full schema. Notable knobs:

| Key                        | Purpose                                         |
|----------------------------|-------------------------------------------------|
| `image.tag`                | Pinned ledger image tag (defaults to AppVersion).|
| `config.logDID`            | Required in production; sets `LEDGER_LOG_DID`.  |
| `config.byteStore.backend` | `gcs` / `s3` / `posix`.                         |
| `config.tile.backend`      | `gcs` / `posix`.                                |
| `extraEnv`                 | Free-form `LEDGER_*` env (witness, gossip, MMD).|
| `extraEnvFrom`             | `envFrom` Secret/ConfigMap refs (S3 creds, etc.).|
| `persistence.storageClassName` | Storage class for all three PVCs.           |
| `serviceAccount.annotations` | Workload-identity bindings (GKE / EKS).      |

## Singleton-writer discipline

`replicas: 1` is non-negotiable. The Postgres advisory lock
(`BuilderLockID = 0x4F5254484F4C4F47`) enforces singleton-writer at
the DB level; a second pod fails fast with a rolling-update
conflict message. `strategy.type: Recreate` for the same reason — a
rolling update would race the lock.

Read-scaling lives in `cmd/ledger-reader` (separate chart, not in
this directory).

## Local validation

```bash
helm dependency update deploy/helm/ledger
helm lint        deploy/helm/ledger
helm template    deploy/helm/ledger \
    --set postgresql.enabled=true \
    --set postgresql.auth.password=test \
    --set config.logDID=did:web:lint.test \
    | kubectl apply --dry-run=client -f -
```
