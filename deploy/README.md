# JetAuth Deployment Manifests

This directory contains declarative Kubernetes and wasmCloud manifests for deploying JetAuth alongside [jetcache](https://github.com/Taika-3D-Oy/jetcache).

## Manifest Overview

| File | Description |
|------|-------------|
| `workloaddeployment-ghcr.yaml` | Production/staging deployment using published GHCR OCI components |
| `workloaddeployment-local.yaml` | Local development deployment targeting a local registry |
| `workloaddeployment-local-prod.yaml` | Local configuration simulating production email & registration settings |
| `workloaddeployment-eu.yaml` | Multi-region EU authority manifest |
| `workloaddeployment-us.yaml` | Multi-region US authority manifest |
| `nats-data.conf` | Standalone JetStream configuration for state persistence |
| `kind-config.yaml` | Sample Kind cluster definition with NodePort exposure |

---

## Deploying with wasmCloud Operator

JetAuth runs as a single wasmCloud `WorkloadDeployment` custom resource. The `jetcache` storage service runs co-located as a sidecar service, communicating with the WebAssembly components over localhost TCP (`127.0.0.1:4080`) and persisting state directly to NATS JetStream KV.

### Prerequisites

1. **Kubernetes Cluster** with the [wasmCloud runtime-operator](https://github.com/wasmCloud/wasmcloud-operator) installed.
2. **NATS JetStream** running and accessible within the cluster (e.g., `nats:4222`).

### Quickstart

1. Configure your environment variables and apply `workloaddeployment-ghcr.yaml`:

```bash
sed -e 's|__ISSUER_URL__|https://auth.example.com|' \
    -e 's|__HOST__|auth.example.com|' \
    -e 's|__NATS_DATA_URL__|nats.default.svc.cluster.local:4222|' \
    -e 's|__EMAIL_PROVIDER__|log|' \
    deploy/workloaddeployment-ghcr.yaml | kubectl apply -f -
```

2. Verify that the workload comes up:

```bash
kubectl get workloaddeployment jetauth
kubectl get pods -l app.kubernetes.io/name=jetauth
```

3. Check health and OIDC discovery:

```bash
curl https://auth.example.com/healthz
curl https://auth.example.com/.well-known/openid-configuration
```
