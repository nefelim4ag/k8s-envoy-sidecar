ARG SRC_TAG=v1.22-latest
FROM envoyproxy/envoy:${SRC_TAG}

RUN apt update && apt install -y mtr-tiny jq curl && apt clean

ENV KUBECTL_VER=v1.23.6

RUN ARCH=$(dpkg --print-architecture); \
    curl -SL "https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VER}/bin/linux/$ARCH/kubectl" -o /usr/bin/kubectl; \
    chmod +x /usr/bin/kubectl
