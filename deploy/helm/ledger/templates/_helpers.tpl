{{/*
=============================================================================
templates/_helpers.tpl — shared snippets.

Names + labels follow Helm's stock convention. Database-secret
helpers resolve the bitnami-vs-external choice once and feed the
deployment.
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
Bitnami-postgresql Secret resolution.

When postgresql.auth.existingSecret is set, the operator's Secret
is the source of truth (bitnami uses it; we read the password from
the same place). Otherwise the bitnami chart creates a Secret named
"<release>-postgresql".
*/}}
{{- define "ledger.bitnamiSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgresql" .Release.Name -}}
{{- end -}}
{{- end -}}

{{- define "ledger.bitnamiPasswordKey" -}}
{{- default "password" .Values.postgresql.auth.secretKeys.userPasswordKey -}}
{{- end -}}

{{/*
External-database Secret resolution.

externalDatabase.existingSecret takes precedence; otherwise the
chart writes its own Secret "<fullname>-db" populated from
externalDatabase.url. The required check below trips when neither
is supplied (and postgresql.enabled is false).
*/}}
{{- define "ledger.externalDbSecretName" -}}
{{- if .Values.externalDatabase.existingSecret -}}
{{- .Values.externalDatabase.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "ledger.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate database mode at template time. Exactly one path must be
configured. Catches "forgot to set anything" before the pod boots
and crash-loops on a missing env var.
*/}}
{{- define "ledger.validateDatabase" -}}
{{- if not .Values.postgresql.enabled -}}
{{- if and (not .Values.externalDatabase.existingSecret) (not .Values.externalDatabase.url) -}}
{{- fail "Configure exactly one of: postgresql.enabled=true, externalDatabase.existingSecret, or externalDatabase.url" -}}
{{- end -}}
{{- end -}}
{{- end -}}
