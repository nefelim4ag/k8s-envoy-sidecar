---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ $.Release.Name }}-envoy
data:
  envoy.yaml: |
    ---
    admin:
      address:
        socket_address:
          protocol: TCP
          address: 0.0.0.0
          port_value: 9901
    node:
      id: envoy
      cluster: {{ $.Release.Name }}-envoy
      locality:
        region: ${REGION}
        zone: ${ZONE}
        sub_zone: ${NODE}
    dynamic_resources:
      lds_config:
        resource_api_version: V3
        path_config_source:
          path: "/etc/envoy/lds.yaml"
      cds_config:
        resource_api_version: V3
        path_config_source:
          path: "/etc/envoy/cds.yaml"

  lds.yaml: |
    ---
    version_info: '0'
    resources:
{{- range $key, $value := .Values.envoy.proxy }}
    - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
      name: listener_{{ $key }}
      address:
        socket_address:
          address: 0.0.0.0
          port_value: {{ $value.lport }}
      filter_chains:
      - filters:
{{- if eq ($value.type | default "tcp") "tcp" }}
        - name: envoy.filters.network.tcp_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
            stat_prefix: tcp_{{ $key }}
            cluster: cluster_{{ $key }}
            idle_timeout: 60s
            max_downstream_connection_duration: 3600s
            on_demand:
              odcds_config:
                initial_fetch_timeout: 15s
                resource_api_version: V3
                path_config_source:
                  path: "/etc/envoy/cds.yaml"
{{- end }}
{{- if eq ($value.type | default "tcp") "redis" }}
        - name: envoy.redis_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.redis_proxy.v3.RedisProxy
            stat_prefix: redis_{{ $key }}
            settings:
              op_timeout: 5s
              read_policy: ANY
            prefix_routes:
              catch_all_route:
                cluster: cluster_{{ $key }}
{{- end }}
{{- if eq ($value.type | default "tcp") "http" }}
        - name: envoy.filters.network.http_connection_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            stat_prefix: http_{{ $key }}
            codec_type: AUTO
            http_protocol_options: {}
            http2_protocol_options:
              initial_connection_window_size: 1048576
              initial_stream_window_size: 65536
              max_concurrent_streams: 128
              allow_connect: true
            common_http_protocol_options:
              idle_timeout: 60s
              max_connection_duration: 3600s
              max_stream_duration: 3600s
              max_requests_per_connection: 1000
            request_timeout: 300s
            route_config:
              name: route_{{ $key }}
              virtual_hosts:
              - name: service_{{ $key }}
                domains: ["*"]
                routes:
                - match:
                    prefix: "/"
                  route:
                    cluster: cluster_{{ $key }}
            http_filters:
            - name: envoy.filters.http.compressor
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor
                compressor_library:
                  name: text_optimized
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip
                    memory_level: 9
                    window_bits: 15
                    compression_level: BEST_SPEED
                    compression_strategy: DEFAULT_STRATEGY
            # Wait for envoy 1.23 to be released
            # - name: envoy.filters.http.on_demand
            #   typed_config:
            #     "@type": type.googleapis.com/envoy.extensions.filters.http.on_demand.v3.OnDemand
            #     odcds:
            #       timeout: 15s
            #       source:
            #         resource_api_version: V3
            #         path_config_source:
            #           path: "/etc/envoy/cds.yaml"
            - name: envoy.filters.http.router
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
{{- end }}
{{- end }}

  cds.yaml.sh: |
    #!/bin/bash
    cat <<EOF > /etc/envoy/cds.yaml
    ---
    version_info: '0'
    resources:
{{- range $key, $value := .Values.envoy.proxy }}
    - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
      name: cluster_{{ $key }}
      connect_timeout: 5s
      lb_policy: LEAST_REQUEST
      type: STRICT_DNS
      dns_lookup_family: AUTO
      {{- with $value.sni }}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: {{ $value.sni }}
          {{- if $value.secretName }}
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: /etc/certs/{{ $key }}/tls.crt
              private_key:
                filename: /etc/certs/{{ $key }}/tls.key
          {{- end }}
      {{- end }}
      load_assignment:
        cluster_name: cluster_{{ $key }}
        endpoints:
        {{- if $value.hosts }}
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: {{ $value.hosts }}
                  port_value: {{ $value.dport }}
        {{- end }}
        {{- if $value.search }}
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: {{ $value.search.service }}.{{ $value.search.namespace }}
                  port_value: {{ $value.dport }}
        {{- end }}
{{- end }}
    EOF

  cds-eds-gen.sh: |
    #!/bin/bash
    UNIXTIME=$(date +%s)

    CALLER=new-by-${1:-"empty"}
    CDS_FILE=/etc/envoy/cds-${CALLER}.yaml

    cmp_wrp(){
      [ ! -f "$1" ] && return 1
      return $(cmp $1 $2 &> /dev/null)
    }

    TMP_FILES=("$CDS_FILE")

    cleanup(){
      rm -f ${TMP_FILES[@]}
    }
    trap cleanup EXIT

{{- range $key, $value := .Values.envoy.proxy }}
{{ if $value.hosts }}
    TMP_FILES+=(/etc/envoy/eds-{{ $key }}.yaml.${CALLER})
    [ ! -f /tmp/mtr-locality-gen.{{ $key }}.list ] && { echo "Cluster: {{ $key }} not ready"; exit 0; }

    cat <<EOF > /etc/envoy/eds-{{ $key }}.yaml.${CALLER}
    version_info: "0"
    resources:
    - "@type": type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
      cluster_name: cluster_{{ $key }}
      endpoints:
    EOF

    PRIO=0
    for HOST in $(cat /tmp/mtr-locality-gen.{{ $key }}.list); do
    cat <<EOF >> /etc/envoy/eds-{{ $key }}.yaml.${CALLER}
        - priority: $PRIO
          lb_endpoints:
          - endpoint:
              health_check_config: { "port_value": {{ $value.dport }} }
              address:
                socket_address:
                  address: $HOST
                  port_value: {{ $value.dport }}
    EOF
    PRIO=$((PRIO+1))
    done

    if ! cmp_wrp /etc/envoy/eds-{{ $key }}.yaml /etc/envoy/eds-{{ $key }}.yaml.${CALLER}; then
      mv -vf /etc/envoy/eds-{{ $key }}.yaml.${CALLER} /etc/envoy/eds-{{ $key }}.yaml;
    fi
{{- end }}
{{- end }}

{{- range $key, $value := .Values.envoy.proxy }}
{{ if $value.search }}
    TMP_FILES+=(/etc/envoy/eds-{{ $key }}.yaml.${CALLER})
    [ ! -f /tmp/k8s-event-parser/{{ $key }}.json ] && { echo "Cluster: {{ $key }} not ready"; exit 0; }

    cat <<EOF > /etc/envoy/eds-{{ $key }}.yaml.${CALLER}
    version_info: "0"
    resources:
    - "@type": type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
      cluster_name: cluster_{{ $key }}
      endpoints:
    EOF

    cluster_section(){
      PRIO=$1
      FILE=$2
      [ ! -f "$FILE" ] && return
    cat $FILE | while read HOST NODE ZONE REGION; do
    cat <<EOF >> /etc/envoy/eds-{{ $key }}.yaml.${CALLER}
      - priority: $PRIO
        locality:
          region: $REGION
          zone: $ZONE
          sub_zone: $NODE
        lb_endpoints:
          - endpoint:
              health_check_config: { "port_value": {{ $value.dport }} }
              address:
                socket_address:
                  address: $HOST
                  port_value: {{ $value.dport }}
    EOF
      done
    }

    cluster_section 0 /tmp/k8s-locality-gen.{{ $key }}.local.list
    cluster_section 1 /tmp/k8s-locality-gen.{{ $key }}.remote.list
    cluster_section 2 /tmp/k8s-locality-gen.{{ $key }}.notReady.list

    if ! cmp_wrp /etc/envoy/eds-{{ $key }}.yaml /etc/envoy/eds-{{ $key }}.yaml.${CALLER}; then
      mv -vf /etc/envoy/eds-{{ $key }}.yaml.${CALLER} /etc/envoy/eds-{{ $key }}.yaml;
    fi
{{- end }}
{{- end }}

    cat <<EOF > ${CDS_FILE}
    ---
    version_info: "${UNIXTIME}"
    resources:
    EOF

{{- range $key, $value := .Values.envoy.proxy }}
    cat <<EOF >> ${CDS_FILE}
    - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
      name: cluster_{{ $key }}
      connect_timeout: 5s
      lb_policy: LEAST_REQUEST
      type: EDS
      circuit_breakers:
        thresholds:
          - max_connections: 1024
            max_pending_requests: 1024
            max_requests: 1024
            max_retries: 3
      upstream_connection_options:
        tcp_keepalive:
          keepalive_probes: 9
          keepalive_time: 30
          keepalive_interval: 60
      ignore_health_on_host_removal: true
      {{- if ne (int $value.dport) 3306 }}
      health_checks:
        - timeout: 3s
          interval: 10s # Assume Kubernetes will update state faster than health check
          interval_jitter_percent: 50
          unhealthy_threshold: 1
          healthy_threshold: 1
          {{- if eq (int $value.dport) 6379 }}
          custom_health_check:
            name: envoy.health_checkers.redis
            typed_config:
              "@type": "type.googleapis.com/envoy.extensions.health_checkers.redis.v3.Redis"
              # https://www.envoyproxy.io/docs/envoy/v1.22.0/configuration/upstream/health_checkers/redis
              key: key_that_not_exists
          {{- else }}
          {{- if eq ($value.type | default "tcp") "tcp" }}
          tcp_health_check: {}
          {{- else }}
          http_health_check:
            path: /
            expected_statuses:
              start: 100
              end: 405
          {{- end }}
          {{- end }}
          no_traffic_interval: 60s
          no_traffic_healthy_interval: 60s
          event_log_path: /dev/stderr
      {{- end }}
      {{- with $value.sni }}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: {{ $value.sni }}
          {{- if $value.secretName }}
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: /etc/certs/{{ $key }}/tls.crt
              private_key:
                filename: /etc/certs/{{ $key }}/tls.key
          {{- end }}
      {{- end }}
      eds_cluster_config:
        eds_config:
          resource_api_version: V3
          path_config_source:
            path: "/etc/envoy/eds-{{ $key }}.yaml"
    EOF
{{- end }}

    if ! cmp_wrp /etc/envoy/cds.yaml ${CDS_FILE}; then
      mv -vf ${CDS_FILE} /etc/envoy/cds.yaml
    fi

  k8s-event-bus.sh: |
    #!/bin/bash
    kubectl_wrp(){
      timeout $(($RANDOM*10%86400)) kubectl -n $KUBE_NAMESPACE "${@}"
    }
    kubectl_watch_endpoint(){
      kubectl_wrp get endpoints "${@}" -o jsonpath="{}{'\n'}" -w --watch-only=false
    }

    mkdir -p /tmp/k8s-event-bus/
{{- range $key, $value := .Values.envoy.proxy }}
{{- if $value.search }}
    # Watch for pods endpoint {{ tpl $value.search.namespace $ }}/{{ $value.search.service }}
    export KUBE_NAMESPACE={{ tpl $value.search.namespace $ }}
    while sleep $((1 + $RANDOM%5)); do
      kubectl_watch_endpoint {{ $value.search.service }} | ./k8s-event-parser.sh {{ $key }}
    done &
{{- end }}
{{- end }}
    wait

  k8s-event-parser.sh: |
    #!/bin/bash
    kubectl_get_pod_node(){
      [ -z "$1" ] && exit 1
      kubectl get pods $1 -o jsonpath='{range .items[*]}{@.spec.nodeName}{"\n"}'
    }

    kubectl_get_node_lbl(){
      [ -z "$1" ] && return 1
      [ -z "$2" ] && return 1
      node="$1"
      label="$2"
      cat /var/cache/node-${label}/$node 2> /dev/null || {
        string=$(kubectl get node $1 -o jsonpath={@.metadata.labels.topology\\.kubernetes\\.io/${label}})
        mkdir -p /var/cache/node-${label}
        echo ${string} > /var/cache/node-${label}/$node
        echo ${string}
      }
    }

    # Update config with locality aware values
    [ -f /run/local-node ] || kubectl_get_pod_node $(cat /etc/hostname) > /run/local-node
    [ -f /run/local-zone ] || kubectl_get_node_lbl $(cat /run/local-node) zone > /run/local-zone
    LOCAL_ZONE=$(cat /run/local-zone)

    print_status(){
      if [ -f "$2" ]; then
        echo "$1"
        cat "$2"
      fi
    }

    ERR(){ echo "$@" >&2; exit 1; }

    CLUSTER="$1"
    [ -z "$CLUSTER" ] && ERR "Empty CLUSTER arg!"

    FILE=/tmp/k8s-event-parser/${CLUSTER}.json

    last_line_type(){
      case "$1" in
        ready)
          cat $FILE | jq '.subsets[].addresses[] | select(.targetRef.kind == "Pod")' ;;
        notReady)
          # Can be null
          cat $FILE | jq '.subsets[].notReadyAddresses[] | select(.targetRef.kind == "Pod")' 2> /dev/null ;;
      esac
    }

    get_pods_type(){
      type=$1
      last_line_type ${type} | jq .targetRef.name -r
    }

    print_endpoint_line(){
      ip=$1
      node=$2
      zone=$3
      region=$4
      echo $ip $node $zone $region
    }

    mkdir -p /tmp/k8s-event-parser/

    while read -r messageline; do
      echo "$messageline" > $FILE

      rm -f /tmp/k8s-locality-gen.${CLUSTER}.local.list
      rm -f /tmp/k8s-locality-gen.${CLUSTER}.remote.list
      rm -f /tmp/k8s-locality-gen.${CLUSTER}.notReady.list

      for pod in $(get_pods_type ready); do
        [ -z "$pod" ] && continue
        ip=$(last_line_type ready | jq -rc ". | select(.targetRef.name == \"$pod\") | .ip" | tail -n1)
        node=$(last_line_type ready | jq -rc ". | select(.targetRef.name == \"$pod\") | .nodeName" | tail -n1)
        zone=$(kubectl_get_node_lbl "${node}" zone)
        region=$(kubectl_get_node_lbl "${node}" region)
        if [ "$LOCAL_ZONE" == "$zone" ]; then
          print_endpoint_line ${ip} ${node} ${zone} ${region} >> /tmp/k8s-locality-gen.${CLUSTER}.local.list
        else
          print_endpoint_line ${ip} ${node} ${zone} ${region} >> /tmp/k8s-locality-gen.${CLUSTER}.remote.list
        fi
      done

      # Add not ready endpoints
      for pod in $(get_pods_type notReady); do
        [ -z "$pod" ] && continue
        ip=$(last_line_type notReady | jq -rc ". | select(.targetRef.name == \"$pod\") | .ip" | tail -n1)
        print_endpoint_line ${ip} >> /tmp/k8s-locality-gen.${CLUSTER}.notReady.list
      done

      echo         "## ${CLUSTER}"
      print_status "## Local zone - $LOCAL_ZONE" /tmp/k8s-locality-gen.${CLUSTER}.local.list
      print_status "## Remote zone" /tmp/k8s-locality-gen.${CLUSTER}.remote.list
      print_status "## Not Ready" /tmp/k8s-locality-gen.${CLUSTER}.notReady.list

      ./cds-eds-gen.sh $CLUSTER
    done

  mtr-event-bus.sh: |
    #!/bin/bash
    mkdir -p /tmp/mtr-event-bus

    resolve(){
      getent hosts $1 | awk '{print $1}'
    }

    cmp_wrp(){
      [ ! -f "$1" ] && return 1
      return $(cmp $1 $2 &> /dev/null)
    }

    while sleep $((5 + $RANDOM%11)); do
{{- range $key, $value := .Values.envoy.proxy }}
{{- if $value.hosts }}
      resolve {{ $value.hosts }} | sort -u > /tmp/mtr-event-bus/{{ $key }}.list.new
      if ! cmp_wrp /tmp/mtr-event-bus/{{ $key }}.list /tmp/mtr-event-bus/{{ $key }}.list.new; then
        RECORDS_COUNT=$(cat /tmp/mtr-event-bus/{{ $key }}.list.new | wc -l)
        # Skip update on empty response
        [ "$RECORDS_COUNT" -gt 0 ] && \
          mv -vf /tmp/mtr-event-bus/{{ $key }}.list.new /tmp/mtr-event-bus/{{ $key }}.list
        ./mtr-locality-gen.sh /tmp/mtr-event-bus/{{ $key }}.list {{ $value.dport }} > /tmp/mtr-locality-gen.{{ $key }}.list
        ./cds-eds-gen.sh {{ $key }}
      fi
{{- end }}
{{- end }}
      true # In case hosts are empty - no op
    done

  mtr-locality-gen.sh: |
    #!/bin/bash
    # Update config with locality aware valueses
    collect_latency_info(){
      xargs -n1 -P 16 mtr -i 0.1 -rwc 5 --tcp --port $1 --json;
    }

    filter_host_latency(){
      jq -rc '. | [.report.mtr.dst, .report.hubs[-1].Best] | @csv';
    }

    filter_nearest_host(){
      sort -n -k2 -t ','
    }

    FILE=$1
    PORT=$2
    RECORDS_COUNT=$(cat $1 | wc -l)

    cat $FILE | \
      collect_latency_info $PORT | \
      filter_host_latency | \
      filter_nearest_host > ${FILE}.raw
    RECORDS_COUNT_RAW=$(cat ${FILE}.raw | wc -l)

    if [ "$RECORDS_COUNT" -eq "$RECORDS_COUNT_RAW" ]; then
      cut -d'"' -f2 ${FILE}.raw
    else
      # Return dns records on mtr error
      cat $FILE
    fi


  run-envoy.sh: |
    #!/bin/bash
    cd "$(dirname $0)"

    # Generate startup config
    install -vDm644 ./envoy.yaml /etc/envoy/envoy.yaml
    install -vDm644 ./lds.yaml /etc/envoy/lds.yaml
    ./cds.yaml.sh # Support endpoint as ENV var

    ./k8s-event-bus.sh &
    ./mtr-event-bus.sh &

    envoy -c /etc/envoy/envoy.yaml
