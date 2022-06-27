---
kind: Service
apiVersion: v1
metadata:
  name: {{ .Release.Name }}
  annotations:
    {{- with .Values.service.annotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  labels:
    app: {{ .Release.Name }}
spec:
  ports:
  {{- .Values.service.ports | toYaml | nindent 4 }}
{{- if .Values.envoy.enabled }}
    - name: admin
      protocol: TCP
      port: 9901
      targetPort: admin
{{- end }}
  selector:
    app: {{ .Release.Name }}
  {{- with .Values.service.clusterIP }}
  clusterIP: {{ . }}
  {{- end }}
  type: {{ .Values.service.type }}
{{- if eq .Values.service.type "ClusterIP" }}
---
kind: Service
apiVersion: v1
metadata:
  name: {{ .Release.Name }}-headless
  annotations:
    {{- with .Values.service.annotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  labels:
    app: {{ .Release.Name }}
spec:
  ports:
  {{- .Values.service.ports | toYaml | nindent 4 }}
{{- if .Values.envoy.enabled }}
    - name: envoy-admin
      protocol: TCP
      port: 9901
      targetPort: admin
{{- end }}
  selector:
    app: {{ .Release.Name }}
  clusterIP: None
  type: ClusterIP
{{- end }}
