#!/usr/bin/env bash
#
# Lattice-ID Benchmark Suite
#
# Deploys a single-region local Kind cluster (or uses an existing one),
# then runs the Python benchmark suite against it.
#
# Usage:
#   ./tests/benchmark.sh                    # use existing cluster at localhost:8000
#   ./tests/benchmark.sh --deploy           # deploy fresh single-region cluster first
#   ./tests/benchmark.sh -c 20 -n 200      # 20 concurrency, 200 requests/scenario
#   ./tests/benchmark.sh --scenarios discovery jwks oidc
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_URL="${BASE_URL:-http://localhost:8000}"
HOST="${HOST:-}"

DEPLOY=false
CONCURRENCY=10
REQUESTS=50
SCENARIOS="all"
EXTRA_ARGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deploy)
      DEPLOY=true
      shift
      ;;
    -c|--concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    -n|--requests)
      REQUESTS="$2"
      shift 2
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --scenarios)
      shift
      SCENARIOS=""
      while [[ $# -gt 0 ]] && [[ ! "$1" =~ ^- ]]; do
        SCENARIOS="$SCENARIOS $1"
        shift
      done
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

echo "============================================"
echo "  Lattice-ID Benchmark Suite"
echo "============================================"
echo "  Base URL:     $BASE_URL"
if [[ -n "$HOST" ]]; then
  echo "  Host header:  $HOST"
fi
echo "  Concurrency:  $CONCURRENCY"
echo "  Requests:     $REQUESTS per scenario"
echo ""

# Deploy if requested
if [[ "$DEPLOY" == "true" ]]; then
  echo "  Deploying workload..."
  kubectl apply -f "$PROJECT_DIR/deploy/workloaddeployment-local.yaml" || {
    echo "  ERROR: failed to apply deploy/workloaddeployment-local.yaml"
    exit 1
  }
  echo ""
fi

# Wait for cluster readiness
echo "  Waiting for cluster readiness..."
for i in $(seq 1 60); do
  if curl -sf "$BASE_URL/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "  Cluster ready."
    break
  fi
  if [[ $i -eq 60 ]]; then
    echo "  ERROR: Cluster not ready after 60s"
    exit 1
  fi
  sleep 1
done
echo ""

# Build host/scenario args
HOST_ARGS=()
if [[ -n "$HOST" ]]; then
  HOST_ARGS+=(--host "$HOST")
fi

SCENARIO_ARGS=()
if [[ -n "$SCENARIOS" ]] && [[ "$SCENARIOS" != "all" ]]; then
  SCENARIO_ARGS+=(--scenarios $SCENARIOS)
fi

# Run benchmark
exec python3 "$SCRIPT_DIR/benchmark.py" \
  --base-url "$BASE_URL" \
  --concurrency "$CONCURRENCY" \
  --requests "$REQUESTS" \
  "${HOST_ARGS[@]}" \
  "${SCENARIO_ARGS[@]}" \
  "${EXTRA_ARGS[@]}"
