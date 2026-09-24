#!/usr/bin/env bash
# Run integration tests against a Kind cluster.
#
# Usage:
#   BASE_URL=http://eu.lid.internal:8000 ./tests/run_cluster_tests.sh
#   ./tests/run_cluster_tests.sh --no-reset   # skip reset, use existing state
#   ./tests/run_cluster_tests.sh authority     # run only matching test(s)
#
# Environment:
#   BASE_URL          — cluster URL (default: http://localhost:8000)
#   KUBE_NS_FLAG      — kubectl namespace flag, e.g. "-n eu" (default: "")
#   KUBE_CTX_FLAG     — kubectl context flag, e.g. "--context kind-lattice-id-eu" (default: "")
#   LATTICE_ID_YAML   — path to lattice-id workload YAML (auto-detected)
#
# Requires: kubectl configured for the target cluster, curl, python3.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

RESET=true
FILTER=""
for arg in "$@"; do
  case "$arg" in
    --no-reset) RESET=false ;;
    *)          FILTER="$arg" ;;
  esac
done

BASE_URL="${BASE_URL:-http://localhost:8000}"
export KUBE_NS_FLAG="${KUBE_NS_FLAG:-}"
export KUBE_CTX_FLAG="${KUBE_CTX_FLAG:-}"

# Auto-detect workload YAML file from deploy/ directory.
auto_detect_yaml() {
  if [[ -z "${LATTICE_ID_YAML:-}" ]]; then
    for f in "$ROOT"/deploy/workloaddeployment*.yaml; do
      if [[ -f "$f" ]] && (grep -q "jetauth" "$f" 2>/dev/null || grep -q "lattice-id" "$f" 2>/dev/null); then
        LATTICE_ID_YAML="$f"
        break
      fi
    done
  fi
  log "Using workload YAML: ${LATTICE_ID_YAML:-<not found>}"
}

# ── Cluster reset ────────────────────────────────────────────
reset_cluster() {
  log "Resetting cluster state (wiping NATS data + lattice-db cache)..."

  # Delete workloads so no components are running during reset.
  for wd in $(kubectl ${KUBE_CTX_FLAG} get workloaddeployment ${KUBE_NS_FLAG} -o name 2>/dev/null || true); do
    kubectl ${KUBE_CTX_FLAG} delete "$wd" ${KUBE_NS_FLAG} --wait=true >/dev/null 2>&1 || true
  done
  sleep 2

  # Bounce the nats-data pod — its data volume is emptyDir, so a restart
  # wipes all JetStream KV buckets and gives us a clean slate.
  kubectl ${KUBE_CTX_FLAG} rollout restart deploy/nats-data ${KUBE_NS_FLAG} >/dev/null
  kubectl ${KUBE_CTX_FLAG} rollout status deploy/nats-data ${KUBE_NS_FLAG} --timeout=60s >/dev/null

  # The host's NATS client may lose connection when nats-data restarts,
  # so bounce the host too so it reconnects cleanly.
  kubectl ${KUBE_CTX_FLAG} rollout restart deploy/hostgroup-default ${KUBE_NS_FLAG} >/dev/null
  kubectl ${KUBE_CTX_FLAG} rollout status deploy/hostgroup-default ${KUBE_NS_FLAG} --timeout=60s >/dev/null
  sleep 10

  # Re-apply the lattice-id workload deployment (lattice-db is co-located as a service).
  if [[ -n "${LATTICE_ID_YAML:-}" && -f "${LATTICE_ID_YAML}" ]]; then
    kubectl ${KUBE_CTX_FLAG} apply -f "$LATTICE_ID_YAML" >/dev/null
  else
    fail "No lattice-id YAML found — set LATTICE_ID_YAML"
  fi
  log "Workloads re-applied, waiting for OIDC readiness..."

  # Wait for the system to become ready.
  local attempts=0
  while true; do
    if curl -sf "$BASE_URL/.well-known/openid-configuration" >/dev/null 2>&1 \
      && curl -sf "$BASE_URL/.well-known/jwks.json" >/dev/null 2>&1; then
      # Probe registration — an empty-body POST should get a validation error
      # (not "no responders" which means components aren't up yet).
      local probe
      probe=$(curl -s -X POST "$BASE_URL/register" \
        -H 'content-type: application/json' \
        -d '{"email":"","password":"","name":""}' 2>/dev/null || true)
      if [[ "$probe" != *"no responders"* ]]; then
        break
      fi
    fi
    attempts=$((attempts + 1))
    if [[ $attempts -ge 180 ]]; then
      fail "Timed out waiting for cluster readiness after reset"
    fi
    sleep 1
  done
  log "Cluster ready at $BASE_URL"
}

# ── Test list ─────────────────────────────────────────────────
CLUSTER_TESTS=(
  integration_authority
  integration_protocol
  integration_rate_limit
  integration_mfa
  integration_hardening
  integration_hooks
  integration_isolation
  integration_restart
  integration_new_features
  integration_account
  integration_logout
  integration_backchannel
  integration_sso
  integration_concurrent
)

# ── Run tests ─────────────────────────────────────────────────
main() {
  auto_detect_yaml

  local passed=0 failed=0
  local failures=()

  for test in "${CLUSTER_TESTS[@]}"; do
    if [[ -n "$FILTER" ]]; then
      local matched=false
      for f in $(echo "$FILTER" | tr ',' ' '); do
        if [[ "$test" == *"$f"* ]]; then matched=true; break; fi
      done
      if ! $matched; then
        continue
      fi
    fi

    local script="$SCRIPT_DIR/${test}.sh"
    if [[ ! -f "$script" ]]; then
      error "Test script not found: $script"
      continue
    fi

    # Each test expects a clean slate (fresh bootstrap hook, no prior users).
    # Reset wipes NATS + lattice-db. The test's own register_and_login_superadmin
    # call will be the first registration and trigger the bootstrap hook.
    if $RESET; then
      reset_cluster
    fi

    log "────────────────────────────────────────────"
    log "Running: $test"
    log "────────────────────────────────────────────"

    if BASE_URL="$BASE_URL" KUBE_NS_FLAG="$KUBE_NS_FLAG" KUBE_CTX_FLAG="$KUBE_CTX_FLAG" bash "$script"; then
      log "PASS: $test"
      passed=$((passed + 1))
    else
      error "FAIL: $test"
      failed=$((failed + 1))
      failures+=("$test")
    fi
  done

  log "════════════════════════════════════════════"
  log "Results: $passed passed, $failed failed"
  if [[ ${#failures[@]} -gt 0 ]]; then
    error "Failed tests: ${failures[*]}"
  fi
  log "════════════════════════════════════════════"

  [[ $failed -eq 0 ]]
}

main
