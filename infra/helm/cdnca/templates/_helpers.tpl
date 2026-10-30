{{- define "cdnca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cdnca.fullname" -}}
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

{{- define "cdnca.componentFullname" -}}
{{- printf "%s-%s" (include "cdnca.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cdnca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cdnca.labels" -}}
helm.sh/chart: {{ include "cdnca.chart" .root }}
app.kubernetes.io/name: {{ include "cdnca.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- end -}}

{{- define "cdnca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cdnca.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "cdnca.topologySpreadConstraints" -}}
{{- range .root.Values.topologySpreadConstraints }}
- maxSkew: {{ .maxSkew }}
  topologyKey: {{ .topologyKey | quote }}
  whenUnsatisfiable: {{ .whenUnsatisfiable }}
  labelSelector:
    matchLabels:
      {{- include "cdnca.selectorLabels" (dict "root" $.root "component" $.component) | nindent 6 }}
{{- end }}
{{- end -}}

{{- define "cdnca.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "cdnca.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
capabilities:
  drop:
    - ALL
{{- end -}}

{{- define "cdnca.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "cdnca.image" -}}
{{- if .digest -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}
