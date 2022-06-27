# k8s-envoy-sidecar
Helm to deploy Envoy proxy for solving some problems without a real service mesh or service mesh in hard way

It can be easy deployed as is, or you can look at deployment YAML, just copy the envoy container block and add it as sidecar to your pod and deploy that chart as a dependency
