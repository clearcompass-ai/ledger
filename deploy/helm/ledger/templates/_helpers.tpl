{{/*
=============================================================================
templates/_helpers.tpl — shared template snippets

Defines:
  - ledger.name           Chart's short name (override via .Values.nameOverride).
  - ledger.fullname       Resource-name prefix every chart-managed object uses.
  - ledger.chart          chart-version label string.
  - ledger.labels         Standard k8s labels block.
  - ledger.selectorLabels Subset used in label selectors (must be stable).
  - ledger.serviceAccountName  Resolves to .Values.serviceAccount.name OR
                          ledger.fullname when create=true, else "default".
  - ledger.dbSecretName   Resolves to .Values.database.urlSecret.name OR
                          a chart-managed "<fullname>-db" Secret.
  - ledger.dbSecretKey    The key inside the DB secret carrying
                          LEDGER_DATABASE_URL.
  - ledger.databaseUrl    Compose the URL string when chart-managed
                          (postgresql.enabled OR externalUrl set).
  - ledger.postgresqlHost Service name of the bitnami sub-chart.
=============================================================================
*/}}

{{- define "ledger.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ledger.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ledger.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ledger.labels" -}}
helm.sh/chart: {{ include "ledger.chart" . }}
{{ include "ledger.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: ledger
app.kubernetes.io/part-of: attesta
{{- end -}}

{{- define "ledger.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ledger.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ledger.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ledger.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
DB-secret resolution.

Three modes (see values.yaml comments):
  1. urlSecret.name set        → use the named existing Secret.
  2. otherwise                 → use the chart-managed Secret named
                                 "<fullname>-db" populated by
                                 templates/secret-db.yaml.
*/}}
{{- define "ledger.dbSecretName" -}}
{{- if .Values.database.urlSecret.name -}}
{{- .Values.database.urlSecret.name -}}
{{- else -}}
{{- printf "%s-db" (include "ledger.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "ledger.dbSecretKey" -}}
{{- if .Values.database.urlSecret.name -}}
{{- default "LEDGER_DATABASE_URL" .Values.database.urlSecret.key -}}
{{- else -}}
LEDGER_DATABASE_URL
{{- end -}}
{{- end -}}

{{/*
Bitnami postgresql sub-chart deploys a Service named
"<release>-postgresql". Centralised here so callers don't
hand-roll the convention.
*/}}
{{- define "ledger.postgresqlHost" -}}
{{- printf "%s-postgresql" .Release.Name -}}
{{- end -}}

{{/*
Compose the Postgres DSN.

Mode A (postgresql.enabled): build from sub-chart auth + service.
  REQUIRES postgresql.auth.password (or rely on existingSecret +
  database.urlSecret bypass instead).
Mode B (postgresql.enabled=false, externalUrl set): pass-through.
Mode C (postgresql.enabled=false, urlSecret.name set): NEVER
  emitted — secret-db.yaml is skipped and the deployment references
  the existing Secret directly. The required check below would
  trip otherwise.
*/}}
{{- define "ledger.databaseUrl" -}}
{{- if .Values.postgresql.enabled -}}
{{- $pwd := required "postgresql.auth.password is required when postgresql.enabled is true and existingSecret is unset" .Values.postgresql.auth.password -}}
{{- printf "postgres://%s:%s@%s:5432/%s?sslmode=disable" .Values.postgresql.auth.username $pwd (include "ledger.postgresqlHost" .) .Values.postgresql.auth.database -}}
{{- else -}}
{{- required "database.externalUrl OR database.urlSecret.name must be set when postgresql.enabled is false" .Values.database.externalUrl -}}
{{- end -}}
{{- end -}}

{{/*
ledger.podEnv emits the env: list common to the deployment.
LEDGER_DATABASE_URL is the only env var sourced from a Secret;
everything else lives in the ConfigMap (envFrom).
*/}}
{{- define "ledger.podEnv" -}}
- name: LEDGER_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ledger.dbSecretName" . }}
      key: {{ include "ledger.dbSecretKey" . }}
{{- if .Values.signerKeys.enabled }}
- name: LEDGER_SIGNER_KEY_FILE
  value: {{ printf "%s/%s" .Values.signerKeys.mountPath .Values.signerKeys.signerFile | quote }}
- name: LEDGER_TESSERA_SIGNER_KEY_FILE
  value: {{ printf "%s/%s" .Values.signerKeys.mountPath .Values.signerKeys.tesseraSignerFile | quote }}
{{- end }}
{{- range $k, $v := .Values.extraEnv }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}
