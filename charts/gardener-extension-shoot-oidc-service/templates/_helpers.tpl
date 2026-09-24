{{-  define "image" -}}
  {{- if .Values.image.ref -}}
  {{ .Values.image.ref }}
  {{- else -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
  {{- end }}
{{- end }}

{{- define "leaderelectionid" -}}
extension-shoot-oidc-service-leader-election
{{- end -}}

{{- define "name" -}}
{{- /* TODO(vpnachev): Remove gardener.runtimeCluster.enabled, replaced by gardener.runtimeCluster, it will be no longer supported by Gardener after v1.159.0 is released. */}}
{{- if (or .Values.gardener.runtimeCluster (.Values | merge (dict) | dig "gardener" "runtimeCluster" "enabled" false)) -}}
shoot-oidc-service-runtime
{{- else -}}
shoot-oidc-service
{{- end -}}
{{- end -}}
