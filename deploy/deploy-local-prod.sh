#!/usr/bin/env bash
# deploy-local-prod.sh — Deploy lattice-id in "local-prod" mode:
#   - Email verification enforced (via AWS SES)
#   - Self-service registration disabled
#   - Bootstrap hook restricted to a single superadmin email
#
# Reads credentials from .env (see .env.example).
#
# Prerequisites:
#   - A running local Kind cluster with wasmCloud + nats-data
#     (use deploy/deploy-local.sh first, then this script to switch modes)
#   - AWS SES credentials in .env
#
# Usage:
#   bash deploy/deploy-local-prod.sh            # deploy/redeploy
#   bash deploy/deploy-local-prod.sh teardown   # remove workloads

set -euo pipefail
cd "$(dirname "$0")/.."

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Load .env ────────────────────────────────────────────────

ENV_FILE="${ENV_FILE:-.env}"
if [[ ! -f "$ENV_FILE" ]]; then
  die "No .env file found. Copy .env.example to .env and fill in your values."
fi

# Source the .env (only exports KEY=VALUE lines, ignoring comments)
set -a
source "$ENV_FILE"
set +a

# Validate required vars
for var in SES_ACCESS_KEY_ID SES_SECRET_ACCESS_KEY SES_FROM_ADDRESS SUPERADMIN_EMAIL; do
  if [[ -z "${!var:-}" ]]; then
    die "Missing required variable: $var (check your .env)"
  fi
done

SES_REGION="${SES_REGION:-eu-west-1}"
INTERNAL_AUTH_SECRET="${INTERNAL_AUTH_SECRET:-local-prod-$(openssl rand -hex 16)}"

# ── Teardown ─────────────────────────────────────────────────

if [[ "${1:-}" == "teardown" ]]; then
  log "Removing local-prod workloads"
  kubectl delete workloaddeployment lattice-id --ignore-not-found 2>/dev/null || true
  kubectl delete workloaddeployment lattice-db --ignore-not-found 2>/dev/null || true
  log "Done"
  exit 0
fi

# ── Generate YAML from template ──────────────────────────────

TEMPLATE="deploy/workloaddeployment-local-prod.yaml"
GENERATED="/tmp/lattice-id-local-prod.yaml"

log "Generating workload YAML from $TEMPLATE"

sed \
  -e "s|__SES_REGION__|${SES_REGION}|g" \
  -e "s|__SES_ACCESS_KEY_ID__|${SES_ACCESS_KEY_ID}|g" \
  -e "s|__SES_SECRET_ACCESS_KEY__|${SES_SECRET_ACCESS_KEY}|g" \
  -e "s|__SES_FROM_ADDRESS__|${SES_FROM_ADDRESS}|g" \
  -e "s|__SUPERADMIN_EMAIL__|${SUPERADMIN_EMAIL}|g" \
  -e "s|__INTERNAL_AUTH_SECRET__|${INTERNAL_AUTH_SECRET}|g" \
  "$TEMPLATE" > "$GENERATED"

# ── Build ────────────────────────────────────────────────────

if [[ "${1:-}" != "--no-build" ]]; then
  log "Building lattice-id (release, wasm32-wasip2)"
  cargo build --workspace --target wasm32-wasip2 --release

  log "Pushing components to local OCI registry"
  REGISTRY_PORT="${REGISTRY_PORT:-5001}"
  components=(oidc-gateway password-hasher email-worker)
  for comp in "${components[@]}"; do
    wasm="${comp//-/_}"
    wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/${comp}:dev" \
      "target/wasm32-wasip2/release/${wasm}.wasm"
  done
fi

# ── Deploy ───────────────────────────────────────────────────

log "Removing existing lattice-id workload (if any)"
kubectl delete workloaddeployment lattice-id --ignore-not-found --wait=true 2>/dev/null || true
sleep 2

# Clear host OCI cache so fresh components are pulled
for pod in $(kubectl get pods -l wasmcloud.com/hostgroup -o name 2>/dev/null); do
  kubectl exec "$pod" -- \
    sh -c 'rm -rf /oci-cache/kind-registry_5000_*' 2>/dev/null || true
done

log "Applying local-prod workload"
kubectl apply -f "$GENERATED"

# ── Wait for readiness ───────────────────────────────────────

log "Waiting for lattice-id to become ready"
for attempt in $(seq 1 90); do
  if curl -sf http://localhost:8000/.well-known/openid-configuration >/dev/null 2>&1; then
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

if curl -sf http://localhost:8000/.well-known/openid-configuration >/dev/null 2>&1; then
  log "lattice-id is ready!"
else
  log "WARNING: lattice-id not responding yet — check pod logs"
fi

# ── Summary ──────────────────────────────────────────────────

echo ""
log "Local-prod environment deployed!"
echo ""
echo "  Configuration:"
echo "    Email verification:  ENABLED (via SES)"
echo "    Self-registration:   DISABLED"
echo "    Superadmin email:    ${SUPERADMIN_EMAIL}"
echo "    SES region:          ${SES_REGION}"
echo "    SES from:            ${SES_FROM_ADDRESS}"
echo ""
echo "  Next steps:"
echo "    1. Open Admin Panel: http://localhost:8000/admin"
echo "    2. Bootstrap or login as superadmin (${SUPERADMIN_EMAIL})"
echo "    5. Log in → you'll have full management access"
echo ""
echo "  Rebuild after code changes:"
echo "    bash deploy/deploy-local-prod.sh"
echo ""
echo "  Switch back to dev mode:"
echo "    kubectl delete workloaddeployment lattice-id"
echo "    kubectl apply -f deploy/workloaddeployment-local.yaml"
