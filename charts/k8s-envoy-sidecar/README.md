# k8s-envoy-sidecar

# TL;DR
```
helm repo add k8s-envoy-sidecar https://nefelim4ag.github.io/k8s-envoy-sidecar/
helm install k8s-envoy-sidecar k8s-envoy-sidecar/k8s-envoy-sidecar
```

# Description
Helm to deploy Envoy proxy for solving some problems without a real service mesh or service mesh in hard way

It can be easy deployed as is, or you can look at deployment YAML, just copy the envoy container block and add it as sidecar to your pod and deploy that chart as a dependency

Initially designed for EKS, but can be changed and re-proposed for other environments
