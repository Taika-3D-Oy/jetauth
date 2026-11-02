#!/usr/bin/env bash
# Shared testing utilities for lattice-id integration tests

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://localhost:8000}"
TMP_DIR="$(mktemp -d)"

# wasmCloud vhost is configured with just the hostname (ports aren't allowed
# in RFC 1123 hostnames).  Wrap curl so the Host header always omits the port.
# Extracts host from URL if present; respects explicit -H "Host:..." from caller.
_LIB_HOST=$(echo "$BASE_URL" | awk -F/ '{print $3}' | cut -d: -f1)
curl() {
  # If caller already provides a Host header, pass through unchanged
  local prev=""
  for arg in "$@"; do
    if [[ "$prev" == "-H" && ("$arg" == Host:* || "$arg" == host:*) ]]; then
      command curl "$@"
      return
    fi
    prev="$arg"
  done
  # Extract hostname from URL arg (strips port for RFC 1123)
  local host=""
  for arg in "$@"; do
    if [[ "$arg" == http://* || "$arg" == https://* ]]; then
      host=$(echo "$arg" | awk -F/ '{print $3}' | cut -d: -f1)
      break
    fi
  done
  command curl -H "Host: ${host:-$_LIB_HOST}" "$@"
}

# Logging utilities
log() { echo "INFO: $*" >&2; }
error() { echo "ERROR: $*" >&2; }

# Environment management
cleanup() {
  rm -rf "$TMP_DIR"
}

fail() {
  error "$*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

# Wait for the cluster to be ready (OIDC discovery + JWKS responding).
wait_for_cluster() {
  require_cmd curl
  require_cmd python3

  log "Waiting for cluster readiness at $BASE_URL ..."
  local attempts=0
  local max_attempts=120
  while true; do
    if curl -sf "$BASE_URL/.well-known/openid-configuration" >/dev/null 2>&1 \
      && curl -sf "$BASE_URL/.well-known/jwks.json" >/dev/null 2>&1; then
      break
    fi
    attempts=$((attempts + 1))
    if [[ $attempts -ge $max_attempts ]]; then
      fail "Timed out waiting for cluster OIDC readiness at $BASE_URL"
    fi
    sleep 1
  done
  log "Cluster ready at $BASE_URL"
}



# JSON/HTTP helpers
json_get() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
try:
    path = sys.argv[2].split('.')
    with open(sys.argv[1], 'r', encoding='utf-8') as handle:
        value = json.load(handle)
    for part in path:
        if part:
            if isinstance(value, list):
                value = value[int(part)]
            else:
                value = value[part]
    if isinstance(value, bool):
        print('true' if value else 'false')
    elif value is None:
        print('')
    else:
        print(value)
except Exception as e:
    sys.stderr.write(f"Error extracting {sys.argv[2]}: {e}\n")
    sys.exit(1)
PY
}

header_value() {
  python3 - "$1" "$2" <<'PY'
import sys
target = sys.argv[2].lower()
try:
    for line in open(sys.argv[1], 'r', encoding='utf-8', errors='ignore'):
        if ':' not in line: continue
        name, value = line.split(':', 1)
        if name.lower().strip() == target:
            print(value.strip())
            sys.exit(0)
    sys.exit(1)
except Exception as e:
    sys.stderr.write(f"Error extracting header {sys.argv[2]}: {e}\n")
    sys.exit(1)
PY
}

url_query_get() {
  python3 - "$1" "$2" <<'PY'
import sys
from urllib.parse import urlparse, parse_qs
try:
    url = sys.argv[1]
    key = sys.argv[2]
    values = parse_qs(urlparse(url).query).get(key)
    if not values: sys.exit(1)
    print(values[0])
except Exception as e:
    sys.stderr.write(f"Error extracting query {sys.argv[2]}: {e}\n")
    sys.exit(1)
PY
}

random_string() {
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
}

extract_session_id() {
  python3 - "$1" <<'PY'
import re
import sys

html = open(sys.argv[1], 'r', encoding='utf-8').read()
match = re.search(r'name="session_id"\s+value="([^"]+)"', html)
if not match:
    sys.stderr.write('Could not find session_id in HTML form\n')
    sys.exit(1)
print(match.group(1))
PY
}

pkce_challenge() {
  python3 - "$1" <<'PY'
import base64
import hashlib
import sys

digest = hashlib.sha256(sys.argv[1].encode('utf-8')).digest()
print(base64.urlsafe_b64encode(digest).decode('ascii').rstrip('='))
PY
}

jwt_claim() {
  python3 - "$1" "$2" <<'PY'
import base64
import json
import sys

token = sys.argv[1]
path = sys.argv[2].split('.')
parts = token.split('.')
if len(parts) != 3:
    sys.stderr.write('invalid JWT format\n')
    sys.exit(1)

payload = parts[1]
payload += '=' * (-len(payload) % 4)
value = json.loads(base64.urlsafe_b64decode(payload.encode('ascii')))
try:
    for part in path:
        if not part:
            continue
        if isinstance(value, list):
            value = value[int(part)]
        else:
            value = value[part]
except (KeyError, IndexError, TypeError):
    print('')
    sys.exit(0)

if isinstance(value, bool):
    print('true' if value else 'false')
elif value is None:
    print('')
else:
    print(value)
PY
}

jwt_header_claim() {
  python3 - "$1" "$2" <<'PY'
import base64
import json
import sys

token = sys.argv[1]
key = sys.argv[2]
parts = token.split('.')
if len(parts) != 3:
  sys.stderr.write('invalid JWT format\n')
  sys.exit(1)

header = parts[0]
header += '=' * (-len(header) % 4)
value = json.loads(base64.urlsafe_b64decode(header.encode('ascii')))
result = value.get(key, '')
if isinstance(result, bool):
  print('true' if result else 'false')
elif result is None:
  print('')
else:
  print(result)
PY
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local context="$3"
  if [[ "$expected" != "$actual" ]]; then
    fail "$context: expected '$expected', got '$actual'"
  fi
}

assert_ne() {
  local left="$1"
  local right="$2"
  local context="$3"
  if [[ "$left" == "$right" ]]; then
    fail "$context: values should differ but both were '$left'"
  fi
}

assert_contains_file() {
  local needle="$1"
  local file="$2"
  local context="$3"
  if ! grep -Fq "$needle" "$file"; then
    fail "$context: expected '$needle' in $(basename "$file")"
  fi
}

curl_capture() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local headers_file="$4"
  shift 4
  curl -sS -o "$body_file" -D "$headers_file" -w '%{http_code}' -X "$method" "$url" "$@"
}

prometheus_metric_value() {
  python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

path, target_name, selector_raw = sys.argv[1:4]
selector = {}
if selector_raw:
  for item in selector_raw.split(','):
    if not item:
      continue
    key, value = item.split('=', 1)
    selector[key] = value

pattern = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+([0-9.eE+-]+)$')

with open(path, 'r', encoding='utf-8') as handle:
  for raw_line in handle:
    line = raw_line.strip()
    if not line or line.startswith('#'):
      continue
    match = pattern.match(line)
    if not match:
      continue
    name = match.group(1)
    if name != target_name:
      continue
    labels = {}
    labels_str = match.group(3) or ''
    if labels_str:
      for part in labels_str.split(','):
        key, value = part.split('=', 1)
        labels[key] = value.strip().strip('"')
    if labels == selector:
      print(match.group(4))
      sys.exit(0)

sys.stderr.write(f"Metric {target_name} with labels {selector} not found\n")
sys.exit(1)
PY
}

# Register a user via POST /register and login via the OIDC code flow.
# The bootstrap_hook in the WorkloadDeployment promotes the first registrant
# to superadmin when none exists.
# Usage: TOKEN=$(register_and_login_superadmin "email" "password" "name")
register_and_login_superadmin() {
  local email="$1"
  local password="$2"
  local name="$3"
  local tag
  tag="$(echo "$email" | tr '@.' '__')"
  local reg_body="$TMP_DIR/boot-reg-$tag.json"
  local reg_headers="$TMP_DIR/boot-reg-$tag.headers"

  # 1. Register
  local status
  status=$(curl_capture POST "$BASE_URL/register" "$reg_body" "$reg_headers" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$password\",\"name\":\"$name\"}")
  if [[ "$status" != "201" ]]; then
    fail "register_and_login_superadmin: register returned $status (expected 201)"
  fi

  # 2. PKCE
  local verifier
  verifier="$(random_string)"
  local challenge
  challenge="$(pkce_challenge "$verifier")"

  # 3. Authorize (get session)
  local auth_body="$TMP_DIR/boot-auth-$tag.html"
  local auth_headers="$TMP_DIR/boot-auth-$tag.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&state=test&nonce=test-nonce&code_challenge=$challenge&code_challenge_method=S256" \
    "$auth_body" "$auth_headers" -c "$TMP_DIR/boot-cookies-$tag.txt" >/dev/null
  local session_id
  session_id=$(extract_session_id "$auth_body")

  # 4. Login (get code)
  local login_body="$TMP_DIR/boot-login-$tag.html"
  local login_headers="$TMP_DIR/boot-login-$tag.headers"
  status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -b "$TMP_DIR/boot-cookies-$tag.txt" -c "$TMP_DIR/boot-cookies-$tag.txt" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "session_id=$session_id&email=$email&password=$password")
  if [[ "$status" != "302" ]]; then
    fail "register_and_login_superadmin: login returned $status (expected 302)"
  fi
  local location
  location=$(header_value "$login_headers" "location")
  local code
  code=$(url_query_get "$location" "code")

  # 5. Exchange code for tokens
  local token_body="$TMP_DIR/boot-token-$tag.json"
  local token_headers="$TMP_DIR/boot-token-$tag.headers"
  status=$(curl_capture POST "$BASE_URL/token" "$token_body" "$token_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=$code&code_verifier=$verifier&client_id=lid-admin&redirect_uri=http://localhost:8090/callback")
  if [[ "$status" != "200" ]]; then
    fail "register_and_login_superadmin: token exchange returned $status (expected 200)"
  fi
  json_get "$token_body" access_token
}

# Generate a unique email address for tests (avoids collisions across runs).
unique_email() {
  local prefix="${1:-test}"
  echo "${prefix}.$(date +%s).${RANDOM}@example.com"
}

# Email verification is handled transparently by the cluster — the bootstrap
# hook auto-verifies the first user, and the integration tests don't exercise
# the verification flow.  Individual test scripts can override this no-op.
verify_user_email() {
  local email="$1"
  log "Skipping email verification for $email (cluster mode)"
  return 0
}

# Get a user's ID (sub) by logging them in and reading /userinfo.
# Works in both local and cluster mode.
user_id_via_login() {
  local email="$1"
  local password="$2"
  local tag
  tag="uid-$(echo "$email" | tr '@.' '__')"

  local verifier challenge
  verifier="$(random_string)"
  challenge="$(pkce_challenge "$verifier")"

  local auth_body="$TMP_DIR/$tag-auth.html"
  local auth_headers="$TMP_DIR/$tag-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&state=uid&nonce=uid-nonce&code_challenge=$challenge&code_challenge_method=S256" \
    "$auth_body" "$auth_headers" -c "$TMP_DIR/$tag-cookies.txt" >/dev/null
  local session_id
  session_id=$(extract_session_id "$auth_body")

  local login_body="$TMP_DIR/$tag-login.html"
  local login_headers="$TMP_DIR/$tag-login.headers"
  local status
  status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -b "$TMP_DIR/$tag-cookies.txt" -c "$TMP_DIR/$tag-cookies.txt" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "session_id=$session_id&email=$email&password=$password")
  if [[ "$status" != "302" ]]; then
    fail "user_id_via_login: login returned $status (expected 302)"
  fi
  local location code
  location=$(header_value "$login_headers" "location")
  code=$(url_query_get "$location" "code")

  local token_body="$TMP_DIR/$tag-token.json"
  local token_headers="$TMP_DIR/$tag-token.headers"
  status=$(curl_capture POST "$BASE_URL/token" "$token_body" "$token_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=$code&code_verifier=$verifier&client_id=lid-admin&redirect_uri=http://localhost:8090/callback")
  if [[ "$status" != "200" ]]; then
    fail "user_id_via_login: token exchange returned $status (expected 200)"
  fi
  local access_token
  access_token=$(json_get "$token_body" access_token)

  local userinfo_body="$TMP_DIR/$tag-userinfo.json"
  local userinfo_headers="$TMP_DIR/$tag-userinfo.headers"
  status=$(curl_capture GET "$BASE_URL/userinfo" "$userinfo_body" "$userinfo_headers" \
    -H "Authorization: Bearer $access_token")
  if [[ "$status" != "200" ]]; then
    fail "user_id_via_login: userinfo returned $status (expected 200)"
  fi
  json_get "$userinfo_body" sub
}
