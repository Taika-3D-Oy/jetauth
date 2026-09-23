#!/usr/bin/env bash
# deploy-two-region.sh — Deploy a two-region Lattice-ID environment on Kind.
#
# Sets up EU (localhost:8000) and US (localhost:8001) regions with separate
# NATS clusters.
#
# The local Docker registry runs on HTTP. After Helm install the script
# patches the wasmCloud host pods with --allow-insecure-registries so they
# can pull components over HTTP.  (The Helm chart value
# hostConfig.allowInsecureRegistries does not propagate to the host CLI args;
# the patch is the reliable workaround.)
#
# Usage:
#   bash deploy/deploy-two-region.sh          # full setup from scratch
#   bash deploy/deploy-two-region.sh rebuild  # rebuild + redeploy only (keep cluster)
#   bash deploy/deploy-two-region.sh teardown # destroy everything

set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER_NAME="wasmcloud-two-region"
REGISTRY_NAME="kind-registry"
REGISTRY_PORT=5001
HELM_VERSION="2.0.1"
EU_PORT=8000
US_PORT=8001

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Teardown ─────────────────────────────────────────────────

teardown() {
  log "Tearing down two-region environment"
  kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
  docker rm -f "$REGISTRY_NAME" 2>/dev/null || true
  log "Done"
}

if [[ "${1:-}" == "teardown" ]]; then
  teardown
  exit 0
fi

# ── Build ────────────────────────────────────────────────────

build_and_push() {
  log "Building workspace (release)"
  cargo build --workspace --target wasm32-wasip2 --release

  log "Pushing components to local registry"
  wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/oidc-gateway:dev" \
    target/wasm32-wasip2/release/oidc_gateway.wasm
  wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/password-hasher:dev" \
    target/wasm32-wasip2/release/password_hasher.wasm
  wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/email-worker:dev" \
    target/wasm32-wasip2/release/email_worker.wasm
}

if [[ "${1:-}" == "rebuild" ]]; then
  build_and_push

  log "Clearing OCI cache and redeploying"
  for ns in eu us; do
    for pod in $(kubectl get pods -n "$ns" -l wasmcloud.com/hostgroup=default -o name 2>/dev/null); do
      kubectl exec -n "$ns" "$pod" -- sh -c 'rm -rf /oci-cache/kind-registry_5000_*' 2>/dev/null || true
    done
    kubectl delete workloaddeployment -n "$ns" --all 2>/dev/null || true
  done
  sleep 2
  kubectl apply -f deploy/workloaddeployment-eu.yaml
  kubectl apply -f deploy/workloaddeployment-us.yaml
  log "Rebuild done. Wait for workloads to come up."
  exit 0
fi

# ── Full Setup ───────────────────────────────────────────────

# 1. Ensure local Docker registry (HTTP)
if docker inspect "$REGISTRY_NAME" &>/dev/null; then
  log "Registry '$REGISTRY_NAME' already running"
else
  log "Starting local Docker registry"
  docker run -d --restart=always -p "${REGISTRY_PORT}:5000" \
    --network bridge --name "$REGISTRY_NAME" registry:2
fi

# 2. Create Kind cluster
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  log "Kind cluster '$CLUSTER_NAME' already exists"
else
  log "Creating Kind cluster '$CLUSTER_NAME'"
  kind create cluster --name "$CLUSTER_NAME" --config deploy/kind-two-region.yaml
  docker network connect kind "$REGISTRY_NAME" 2>/dev/null || true
fi

# 3. Create namespaces
log "Creating namespaces"
kubectl create namespace eu --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace us --dry-run=client -o yaml | kubectl apply -f -

# 4. Registry in-cluster DNS
log "Setting up in-cluster registry DNS"
REGISTRY_IP=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$REGISTRY_NAME")
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: kind-registry
  namespace: eu
spec:
  type: ClusterIP
  ports:
    - port: 5000
      targetPort: 5000
---
apiVersion: v1
kind: Endpoints
metadata:
  name: kind-registry
  namespace: eu
subsets:
  - addresses:
      - ip: ${REGISTRY_IP}
    ports:
      - port: 5000
---
apiVersion: v1
kind: Service
metadata:
  name: kind-registry
  namespace: us
spec:
  type: ClusterIP
  ports:
    - port: 5000
      targetPort: 5000
---
apiVersion: v1
kind: Endpoints
metadata:
  name: kind-registry
  namespace: us
subsets:
  - addresses:
      - ip: ${REGISTRY_IP}
    ports:
      - port: 5000
EOF

# 5. Install wasmCloud operator in each namespace
log "Installing wasmCloud operator in EU namespace"
helm install wasmcloud-eu oci://ghcr.io/wasmcloud/charts/runtime-operator \
  --namespace eu \
  --version "$HELM_VERSION" \
  --set 'gateway.service.type=NodePort' \
  --set 'gateway.service.nodePort=30950' 2>/dev/null || \
  log "wasmcloud-eu already installed"

log "Installing wasmCloud operator in US namespace"
helm install wasmcloud-us oci://ghcr.io/wasmcloud/charts/runtime-operator \
  --namespace us \
  --version "$HELM_VERSION" \
  --set 'gateway.service.type=NodePort' \
  --set 'gateway.service.nodePort=30951' 2>/dev/null || \
  log "wasmcloud-us already installed"

# 6. Wait for pods to be ready
log "Waiting for wasmCloud pods in both namespaces"
for ns in eu us; do
  kubectl wait --for=condition=available --timeout=120s \
    deployment -l app.kubernetes.io/instance="wasmcloud-${ns}" -n "$ns" 2>/dev/null || true
done

# 6b. Patch hosts to allow insecure (HTTP) registry pulls and use
#     per-namespace hostgroups so workloads are scheduled in their own region.
log "Patching host pods: insecure registry + namespace-specific hostgroups"
for ns in eu us; do
  kubectl patch deploy hostgroup-default -n "$ns" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/2\",\"value\":\"--host-group=${ns}\"},{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--allow-insecure-registries\"}]"
done

log "Waiting for host pods to restart"
for ns in eu us; do
  kubectl rollout status deploy/hostgroup-default -n "$ns" --timeout=60s 2>/dev/null || true
done
sleep 5  # settle time for NATS JetStream init

# 7. Create KV buckets in each region
create_buckets() {
  local ns="$1"

  log "Creating KV buckets in $ns"
  local overrides='{"spec":{"volumes":[{"name":"tls","secret":{"secretName":"wasmcloud-data-tls"}}],"containers":[{"name":"nats-setup","image":"natsio/nats-box:latest","stdin":true,"tty":false,"volumeMounts":[{"name":"tls","mountPath":"/tls","readOnly":true}],"command":["sh","-c","NATS=\"nats --server nats://nats:4222 --tlscert /tls/tls.crt --tlskey /tls/tls.key --tlsca /tls/ca.crt\"; for b in lid-users lid-user-idx lid-sessions lid-clients lid-tenants lid-memberships lid-keys; do $NATS kv add $b 2>&1 || true; done; $NATS kv add lid-audit --ttl 30d --history 1 2>&1 || true; $NATS kv add lid-abuse-rate-limits --ttl 1h --history 1 2>&1 || true;"]}]}}'
  kubectl run "nats-setup-${ns}" --rm -i --restart=Never -n "$ns" \
    --image=natsio/nats-box:latest \
    --overrides="$overrides" 2>&1 || true
}
create_buckets eu
create_buckets us

# 8. Build and push components
build_and_push

# 9. Deploy workloads
log "Deploying workloads"
kubectl apply -f deploy/workloaddeployment-eu.yaml
kubectl apply -f deploy/workloaddeployment-us.yaml

# 10. Wait for workloads to be ready
log "Waiting for workloads to become ready"
for attempt in $(seq 1 60); do
  eu_ok=0; us_ok=0
  curl -sf "http://localhost:${EU_PORT}/healthz" 2>/dev/null | grep -q ok && eu_ok=1
  curl -sf "http://localhost:${US_PORT}/healthz" 2>/dev/null | grep -q ok && us_ok=1
  if [[ $eu_ok -eq 1 && $us_ok -eq 1 ]]; then
    break
  fi
  sleep 5
done

if curl -sf "http://localhost:${EU_PORT}/healthz" &>/dev/null; then
  log "EU region ready at http://localhost:${EU_PORT}"
else
  log "WARNING: EU region not responding yet"
fi

if curl -sf "http://localhost:${US_PORT}/healthz" &>/dev/null; then
  log "US region ready at http://localhost:${US_PORT}"
else
  log "WARNING: US region not responding yet"
fi

log ""
log "Two-region environment deployed!"
log "  EU: http://localhost:${EU_PORT}"
log "  US: http://localhost:${US_PORT}"
log ""
log "Run the cross-region test:"
log "  EU_URL=http://localhost:${EU_PORT} US_URL=http://localhost:${US_PORT} bash tests/integration_two_region.sh"
log ""
log "Tear down:"
log "  bash deploy/deploy-two-region.sh teardown"
