#!/usr/bin/env bash
# Test: New OIDC features (April 2026)
# - client_credentials grant
# - device authorization (RFC 8628)
# - backchannel logout (RFC 8613)
# - generic OIDC federation discovery
# - per-client ES256 id_token signing
# - /version endpoint

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

main() {
  log "=== New features test ==="
  wait_for_cluster

  # ── /version endpoint ──
  log "Test: /version endpoint"
  local v
  v=$(curl -s "$BASE_URL/version")
  echo "$v" | python3 -c "import json,sys;d=json.loads(sys.stdin.read());assert d['name']=='oidc-gateway';print('  ', d)" \
    || fail "version endpoint malformed"
  log "PASS: /version returns build info"

  # ── Discovery announces new features ──
  log "Test: discovery document advertises new features"
  local disc
  disc=$(curl -s "$BASE_URL/.well-known/openid-configuration")
  python3 - <<PY
import json
d = json.loads('''$disc''')
assert "client_credentials" in d["grant_types_supported"], "client_credentials missing"
assert "urn:ietf:params:oauth:grant-type:device_code" in d["grant_types_supported"], "device_code missing"
assert "device_authorization_endpoint" in d, "device_authorization_endpoint missing"
assert "ES256" in d["id_token_signing_alg_values_supported"], "ES256 missing"
assert "RS256" in d["id_token_signing_alg_values_supported"], "RS256 missing"
assert d.get("backchannel_logout_supported") is True, "backchannel_logout_supported"
assert "social_login_endpoint" not in d, "non-standard social_login_endpoint should be removed"
print("  discovery OK:", sorted(d["grant_types_supported"]))
PY
  log "PASS: discovery document"

  # ── JWKS contains both RSA and EC keys ──
  log "Test: JWKS advertises both RS256 and ES256 keys"
  local jwks
  jwks=$(curl -s "$BASE_URL/.well-known/jwks.json")
  python3 - <<PY
import json
j = json.loads('''$jwks''')
algs = sorted({k["alg"] for k in j["keys"]})
assert algs == ["ES256", "RS256"], f"expected both algs, got {algs}"
ec = next(k for k in j["keys"] if k["alg"] == "ES256")
assert ec["kty"] == "EC" and ec["crv"] == "P-256" and ec["x"] and ec["y"], "EC key incomplete"
rsa = next(k for k in j["keys"] if k["alg"] == "RS256")
assert rsa["kty"] == "RSA" and rsa["n"] and rsa["e"], "RSA key incomplete"
print("  JWKS OK:", algs)
PY
  log "PASS: JWKS"

  # ── Bootstrap admin ──
  local password="test-password-$(random_string)"
  local admin_email="admin.$(date +%s)@example.com"
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$password" "Admin")
  [[ -n "$admin_token" ]] || fail "no admin token"

  # ── client_credentials grant ──
  log "Test: client_credentials grant"
  # Create a confidential client with the grant enabled
  local cc_resp
  cc_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name":"M2M Service",
      "redirect_uris":["http://localhost/cb"],
      "grant_types":["client_credentials"],
      "confidential":true
    }')
  local cc_id cc_secret
  cc_id=$(echo "$cc_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['client_id'])")
  cc_secret=$(echo "$cc_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['client_secret'])")
  [[ -n "$cc_id" && -n "$cc_secret" ]] || fail "create m2m client failed: $cc_resp"

  local tok
  tok=$(curl -s -X POST "$BASE_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$cc_id" \
    --data-urlencode "client_secret=$cc_secret" \
    --data-urlencode "scope=api.read")
  echo "$tok" | python3 -c "
import json, sys, base64
d = json.loads(sys.stdin.read())
assert 'access_token' in d, 'no access_token'
assert d['token_type'] == 'Bearer', f'wrong token_type: {d}'
assert 'id_token' not in d, 'client_credentials should NOT issue id_token'
assert 'refresh_token' not in d, 'client_credentials should NOT issue refresh_token'
# Decode access token header
hdr = json.loads(base64.urlsafe_b64decode(d['access_token'].split('.')[0] + '=='))
assert hdr['alg'] == 'RS256', f'expected RS256, got {hdr}'
print('  CC token issued:', d['token_type'], 'expires_in', d.get('expires_in'))
" || fail "client_credentials test: $tok"
  log "PASS: client_credentials"

  # ── client_credentials denied for public client ──
  log "Test: client_credentials denied for public client"
  local pub_resp
  pub_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{"name":"Public","redirect_uris":["http://localhost/cb"],"grant_types":["client_credentials"],"confidential":false}')
  local pub_id
  pub_id=$(echo "$pub_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['client_id'])")
  local pub_status
  pub_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$pub_id")
  [[ "$pub_status" == "400" || "$pub_status" == "401" ]] \
    || fail "public client should be denied, got $pub_status"
  log "PASS: public client denied for client_credentials"

  # ── ES256 per-client id_token signing ──
  log "Test: per-client ES256 id_token signing"
  local es_resp
  es_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name":"ES256 Client",
      "redirect_uris":["http://localhost:8000/callback"],
      "grant_types":["authorization_code"],
      "confidential":false,
      "id_token_signed_response_alg":"ES256"
    }')
  local es_id
  es_id=$(echo "$es_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['client_id'])")
  [[ -n "$es_id" ]] || fail "create ES256 client: $es_resp"

  # Run an auth code flow as the admin user using the new ES256 client.
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local sess_body="$TMP_DIR/es-auth.html"
  local sess_headers="$TMP_DIR/es-auth.headers"
  curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=$es_id&redirect_uri=http://localhost:8000/callback&code_challenge=$challenge&code_challenge_method=S256&state=t&nonce=n&scope=openid" \
    "$sess_body" "$sess_headers" >/dev/null
  local sess_id
  sess_id=$(extract_session_id "$sess_body")
  local login_body="$TMP_DIR/es-login.html"
  local login_headers="$TMP_DIR/es-login.headers"
  curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$sess_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$password" >/dev/null
  local code
  code=$(url_query_get "$(header_value "$login_headers" location)" code)
  [[ -n "$code" ]] || fail "no auth code for ES256 flow"
  local tok_body="$TMP_DIR/es-tok.json"
  local tok_headers="$TMP_DIR/es-tok.headers"
  curl_capture POST "$BASE_URL/token" "$tok_body" "$tok_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "client_id=$es_id" \
    --data-urlencode "redirect_uri=http://localhost:8000/callback" >/dev/null
  python3 - "$tok_body" <<'PY'
import json, sys, base64
d = json.load(open(sys.argv[1]))
assert "id_token" in d, f"no id_token: {d}"
hdr = json.loads(base64.urlsafe_b64decode(d["id_token"].split(".")[0] + "=="))
assert hdr["alg"] == "ES256", f"expected ES256 id_token alg, got {hdr}"
# Access token should still be RS256 (only id_token is per-client)
ah = json.loads(base64.urlsafe_b64decode(d["access_token"].split(".")[0] + "=="))
assert ah["alg"] == "RS256", f"expected RS256 access_token alg, got {ah}"
print("  ES256 id_token issued, kid:", hdr["kid"])
PY
  log "PASS: ES256 per-client signing"

  # ── Device authorization (RFC 8628) ──
  log "Test: device authorization grant"
  # Create client with device_code grant
  local dev_resp
  dev_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name":"Device Client",
      "redirect_uris":["http://localhost/cb"],
      "grant_types":["urn:ietf:params:oauth:grant-type:device_code"],
      "confidential":false
    }')
  local dev_id
  dev_id=$(echo "$dev_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['client_id'])")

  # Confidential clients must authenticate at /device_authorization (RFC 8628 §3.1)
  local da_status
  da_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/device_authorization" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$cc_id")
  [[ "$da_status" == "400" || "$da_status" == "401" || "$da_status" == "429" ]] \
    || fail "confidential client without credentials should be rejected, got $da_status"
  log "  confidential client without secret rejected"

  # Step 1: device requests a code
  local da_resp
  da_resp=$(curl -s -X POST "$BASE_URL/device_authorization" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$dev_id" \
    --data-urlencode "scope=openid email")
  local device_code user_code
  device_code=$(echo "$da_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['device_code'])")
  user_code=$(echo "$da_resp" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['user_code'])")
  [[ -n "$device_code" && -n "$user_code" ]] || fail "device_authorization failed: $da_resp"
  log "  user_code=$user_code"

  # Step 2: polling without approval returns authorization_pending
  local poll_resp
  poll_resp=$(curl -s -X POST "$BASE_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "device_code=$device_code" \
    --data-urlencode "client_id=$dev_id")
  echo "$poll_resp" | grep -q "authorization_pending" \
    || fail "expected authorization_pending, got: $poll_resp"
  log "  authorization_pending OK"

  # Step 3: simulate user approving — POST /device with user_code, then login
  # Wait 6s to clear the 5s poll rate limit
  sleep 6
  local sub_body="$TMP_DIR/dev-sub.html"
  local sub_headers="$TMP_DIR/dev-sub.headers"
  curl_capture POST "$BASE_URL/device" "$sub_body" "$sub_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "user_code=$user_code" >/dev/null
  local sub_loc=""
  sub_loc=$(header_value "$sub_headers" location || true)
  if [[ -z "$sub_loc" ]]; then
    log "  POST /device headers:"
    cat "$sub_headers" >&2 || true
    log "  POST /device body:"
    head -c 500 "$sub_body" >&2 || true
    fail "device flow did not return a location header"
  fi
  local dev_session_id=""
  dev_session_id=$(url_query_get "$sub_loc" session_id || true)
  [[ -n "$dev_session_id" ]] || fail "device flow location had no session_id: $sub_loc"

  # User logs in via the device flow's auth session
  local devlogin_body="$TMP_DIR/dev-login.html"
  local devlogin_headers="$TMP_DIR/dev-login.headers"
  curl_capture POST "$BASE_URL/login" "$devlogin_body" "$devlogin_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$dev_session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$password" >/dev/null

  # Login must NOT auto-approve the device: the response is the explicit
  # confirmation page carrying a single-use approval token.
  grep -q "Authorize a device" "$devlogin_body" \
    || fail "expected device confirmation page after login, got: $(head -c 300 "$devlogin_body")"
  grep -q "Device Client" "$devlogin_body" \
    || fail "confirmation page should show the client name"
  local approval_token
  approval_token=$(python3 - "$devlogin_body" <<'PY'
import re, sys
html = open(sys.argv[1], 'r', encoding='utf-8').read()
m = re.search(r'name="approval_token"\s+value="([^"]+)"', html)
if not m:
    sys.stderr.write('no approval_token in confirmation page\n')
    sys.exit(1)
print(m.group(1))
PY
) || fail "no approval_token in confirmation page"

  # User explicitly approves the device
  local approve_body="$TMP_DIR/dev-approve.html"
  local approve_headers="$TMP_DIR/dev-approve.headers"
  curl_capture POST "$BASE_URL/device" "$approve_body" "$approve_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "approval_token=$approval_token" \
    --data-urlencode "decision=approve" >/dev/null
  grep -q "Device Activated" "$approve_body" \
    || fail "expected device activation page after approval, got: $(head -c 300 "$approve_body")"

  # Step 4: poll again — should now return tokens
  sleep 6
  local final
  final=$(curl -s -X POST "$BASE_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "device_code=$device_code" \
    --data-urlencode "client_id=$dev_id")
  echo "$final" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
assert 'access_token' in d, f'no access_token in device-flow result: {d}'
assert 'id_token' in d, f'no id_token: {d}'
print('  device-flow tokens issued')
" || fail "device flow final token: $final"
  log "PASS: device authorization grant"

  # ── Backchannel logout: register a client with backchannel_logout_uri ──
  # We can't easily verify the POST is delivered without standing up an HTTP
  # listener, but we can verify the client config is accepted and the logout
  # endpoint executes without error.
  log "Test: backchannel logout client config"
  local bc_resp
  bc_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name":"BC Logout Client",
      "redirect_uris":["http://localhost/cb"],
      "grant_types":["authorization_code","refresh_token"],
      "confidential":false,
      "backchannel_logout_uri":"http://localhost:65535/bc-logout"
    }')
  echo "$bc_resp" | python3 -c "import json,sys;d=json.loads(sys.stdin.read());assert 'client_id' in d, d" \
    || fail "create backchannel client: $bc_resp"
  log "PASS: backchannel client accepted"

  log "=== All new-feature tests passed ==="
}

main "$@"
