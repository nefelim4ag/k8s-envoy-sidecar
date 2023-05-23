#!/bin/bash

set -eo pipefail

LDS_FILE=/etc/envoy/lds.yaml
CDS_FILE=/etc/envoy/cds.yaml

PARAMS=$(env | grep ENVOY_)

for FILE in $LDS_FILE $CDS_FILE; do
cat << YAML > $FILE
---
version_info: '0'
resources:
YAML
done

for PARAM in ${PARAMS[@]}; do
    ENV_KEY=$(echo $PARAM | cut -d'=' -f1)
    NAME=$(echo $ENV_KEY | cut -d'_' -f2)
    NAME=${NAME,,} # lowercase
    PROTOCOL=$(echo $ENV_KEY | cut -d'_' -f3)
    LISTENER_PORT=$(echo $ENV_KEY | cut -d'_' -f4)

    ENV_VALUE=$(echo $PARAM | cut -d'=' -f2)
    HOST=$(echo $ENV_VALUE | cut -d':' -f1)
    PORT=$(echo $ENV_VALUE | cut -d':' -f2)
    echo Listen on :$LISTENER_PORT proxy by $PROTOCOL to backend $HOST:$PORT

cat << YAML >> $LDS_FILE
- "@type": type.googleapis.com/envoy.config.listener.v3.Listener
  name: listener_$NAME
  address:
    socket_address:
      address: 0.0.0.0
      port_value: $LISTENER_PORT
  filter_chains:
  - filters:
YAML

    case $PROTOCOL in
        HTTP)
cat << YAML >> $LDS_FILE
    - name: envoy.filters.network.http_connection_manager
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
        stat_prefix: http_${NAME}
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
          name: route_${NAME}
          virtual_hosts:
          - name: service_${NAME}
            domains: ["*"]
            routes:
            - match:
                prefix: "/"
              route:
                cluster: cluster_${NAME}
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
        - name: envoy.filters.http.on_demand
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.on_demand.v3.OnDemand
            odcds:
              timeout: 15s
              source:
                resource_api_version: V3
                path_config_source:
                  path: "/etc/envoy/cds.yaml"
        - name: envoy.filters.http.router
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
YAML
        ;;

        TCP)
cat << YAML >> $LDS_FILE
    - name: envoy.filters.network.tcp_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
        stat_prefix: tcp_${NAME}
        cluster: cluster_${NAME}
        idle_timeout: 60s
        max_downstream_connection_duration: 3600s
        on_demand:
          odcds_config:
            initial_fetch_timeout: 15s
            resource_api_version: V3
            path_config_source:
              path: "/etc/envoy/cds.yaml"
YAML
        ;;

        REDIS)
cat << YAML >> $LDS_FILE
        - name: envoy.redis_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.redis_proxy.v3.RedisProxy
            stat_prefix: redis_${NAME}
            settings:
              op_timeout: 5s
              read_policy: ANY
            prefix_routes:
              catch_all_route:
                cluster: cluster_${NAME}
YAML
        ;;

        *) echo Not supported $PROTOCOL; exit 1;;
    esac

cat << YAML >> $CDS_FILE
- "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
  name: cluster_${NAME}
  connect_timeout: 5s
  lb_policy: LEAST_REQUEST
  type: STRICT_DNS
  dns_lookup_family: AUTO
  load_assignment:
    cluster_name: cluster_${NAME}
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: ${HOST}
              port_value: ${PORT}
YAML

done
