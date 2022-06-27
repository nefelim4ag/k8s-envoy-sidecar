{{- if .Values.envoy.deployment.enabled }}
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: {{ .Release.Name }}
spec:
  minReadySeconds: {{ .Values.minReadySeconds }}
  selector:
    matchLabels:
      app: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app: {{ .Release.Name }}
    spec:
      serviceAccountName: {{ .Release.Name }}
      serviceAccount: {{ .Release.Name }}
      containers:
{{- with .Values.envoy }}
        - name: envoy
          image: {{ .image }}
          imagePullPolicy: IfNotPresent
          ports:
          - name: admin
            containerPort: 9901
{{- range $key, $value := .proxy }}
          - name: {{ printf "%s-%s" $key ($value.type | default "tcp") | trunc 15 }}
            containerPort: {{ $value.lport }}
{{- end }}
{{- with .proxy }}
          # startupProbe:
          #   tcpSocket:
          #     port: {{ . }}
          #   initialDelaySeconds: 1
          #   periodSeconds: 2
          #   failureThreshold: 30
{{- end }}
          resources: {{ .resources | toJson }}
          command:
          - bash
          - /etc/envoy_origin/run-envoy.sh
          volumeMounts:
          - name: envoy-src-config
            mountPath: /etc/envoy_origin/
{{- end }}
      volumes:
      - name: envoy-src-config
        configMap:
          name: {{ $.Release.Name }}-envoy
          defaultMode: 0755
      hostNetwork: {{ .Values.hostNetwork }}
      {{- with .Values.dnsConfig }}
      dnsConfig: {{ . | toJson }}
      {{- end }}
{{- end }}
