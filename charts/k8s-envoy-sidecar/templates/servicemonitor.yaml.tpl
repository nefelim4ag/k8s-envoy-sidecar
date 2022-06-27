{{- if .Values.envoy.monitoring.enabled }}
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ $.Release.Name }}-envoy
spec:
  endpoints:
    - path: /stats/prometheus
      port: admin
      interval: 30s
      params:
        usedonly: []
  namespaceSelector:
    matchNames:
      - {{ $.Release.Namespace }}
  selector:
    matchLabels:
      app: {{ $.Release.Name }}
{{- end }}
