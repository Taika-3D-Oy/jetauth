#!/usr/bin/env bash
# Test: Account self-service, CSRF protection, consent screen, GDPR endpoints
#
# Covers:
#  - CSRF token is required for destructive account actions
#  - Consent screen shown for non-first-party clients (prompt=consent)
#  - Consent allow → receives auth code with correct state
#  - Consent deny  → receives access_denied with correct state
#  - first_party flag skips consent screen
#  - GET /api/users/:id/export (GDPR Art. 15/20)
#  - DELETE /api/users/:id (GDPR Art. 17) including superadmin self-delete refusal

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

# ── helper: do a full OIDC auth-code flow, return id_token + account cookie ──
# Usage: do_oidc_flow <client_id> <redirect_uri> <email> <password> <verifier>
#   Outputs: "code=<code> location=<loc>" lines — caller parses with grep/sed
do_oidc_flow() {
  local client_id="$1" redirect_uri="$2" email="$3" password="$4" verifier="$5"
  local challenge
  challenge=$(pkce_challenge "$verifier")
  local auth_body="$TMP_DIR/flow-auth.html"
  local auth_headers="$TMP_DIR/flow-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&code_challenge=${challenge}&code_challenge_method=S256&state=xyzstate&nonce=n&scope=openid+offline_access" \
    "$auth_body" "$auth_headers" >/dev/null
  local session_id
  session_id=$(extract_session_id "$auth_body")
  local login_body="$TMP_DIR/flow-login.txt"
  local login_headers="$TMP_DIR/flow-login.headers"
  local status
  status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password")
  echo "$status"
}

# ── helper: get account session cookie by visiting /account ──
get_account_cookie() {
  local email="$1" password="$2"
  local verifier
  verifier=$(random_string)
  local challenge
  challenge=$(pkce_challenge "$verifier")
  local auth_body="$TMP_DIR/acct-auth.html"
  local auth_headers="$TMP_DIR/acct-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid" \
    "$auth_body" "$auth_headers" >/dev/null
  local session_id
  session_id=$(extract_session_id "$auth_body")
  local login_body="$TMP_DIR/acct-login.txt"
  local login_headers="$TMP_DIR/acct-login.headers"
  curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password" >/dev/null
  # The login response sets the account session cookie in the Location redirect;
  # follow it to get the cookie jar.
  local code
  code=$(url_query_get "$(header_value "$login_headers" location)" code)
  # Exchange the code to get a real account cookie via /account
  local account_body="$TMP_DIR/acct-page.html"
  local account_headers="$TMP_DIR/acct-page.headers"
  curl -sS -L -c "$TMP_DIR/acct-cookies.txt" -o "$account_body" -D "$account_headers" \
    "$BASE_URL/account"
  # Return the cookie jar path
  echo "$TMP_DIR/acct-cookies.txt"
}

main() {
  log "=== Account / CSRF / Consent / GDPR integration test ==="
  wait_for_cluster

  # ── Bootstrap admin ──────────────────────────────────────────────────────
  local ts
  ts=$(date +%s)
  local admin_email="acct.admin.${ts}@example.com"
  local admin_pass="AdminPass123!"
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$admin_pass" "AccountAdmin")
  [[ -n "$admin_token" ]] || fail "no admin token"
  log "Admin registered OK"

  # ── Get admin user ID ─────────────────────────────────────────────────────
  local admin_id
  admin_id=$(user_id_via_login "$admin_email" "$admin_pass")
  [[ -n "$admin_id" ]] || fail "could not get admin user id"
  log "Admin user id: $admin_id"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 1: CSRF — /account/mfa/disable requires csrf form field
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 1: CSRF protection on /account/mfa/disable"

  # Get an account session cookie by going through login → /account
  # We need the actual cookie from the Set-Cookie header, not a code exchange.
  # Simulate by doing the authorize flow, reading the login redirect, and
  # following /account which sets the cookie.
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local auth_body="$TMP_DIR/csrf-auth.html"
  local auth_headers="$TMP_DIR/csrf-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid" \
    "$auth_body" "$auth_headers" >/dev/null
  local session_id
  session_id=$(extract_session_id "$auth_body")

  local login_body="$TMP_DIR/csrf-login.txt"
  local login_headers="$TMP_DIR/csrf-login.headers"
  local login_status
  login_status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_pass")
  assert_eq "302" "$login_status" "login for CSRF test"

  # The login redirects to /callback?code=... ; the Set-Cookie on /account
  # is issued when the browser hits /account (direct cookie flow).
  # Follow to /account with cookie jar to capture the session cookie.
  local cookie_jar="$TMP_DIR/csrf-cookies.txt"
  local acct_page="$TMP_DIR/csrf-acct.html"
  curl -sS -c "$cookie_jar" -b "$cookie_jar" -L -o "$acct_page" "$BASE_URL/account" 2>/dev/null || true
  # Attempt mfa/disable WITHOUT csrf — must be rejected (403 or 4xx)
  local disable_status
  disable_status=$(curl -sS -o /dev/null -w "%{http_code}" -b "$cookie_jar" \
    -X POST "$BASE_URL/account/mfa/disable" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d '')
  [[ "$disable_status" == "4"* || "$disable_status" == "302" ]] \
    || fail "mfa/disable without csrf should be rejected, got $disable_status"
  log "PASS: CSRF missing → request rejected (HTTP $disable_status)"

  # Attempt mfa/disable with wrong csrf — must be rejected
  disable_status=$(curl -sS -o /dev/null -w "%{http_code}" -b "$cookie_jar" \
    -X POST "$BASE_URL/account/mfa/disable" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "csrf=definitely-wrong-token")
  [[ "$disable_status" == "4"* || "$disable_status" == "302" ]] \
    || fail "mfa/disable with wrong csrf should be rejected, got $disable_status"
  log "PASS: Wrong CSRF → request rejected (HTTP $disable_status)"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 2: Consent screen — non-first-party client triggers consent page
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 2: Consent screen for non-first-party client"

  # Create a third-party client (first_party defaults to false)
  local tp_resp
  tp_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Third Party App",
      "redirect_uris": ["http://localhost:8090/callback"],
      "grant_types": ["authorization_code"],
      "confidential": false
    }')
  local tp_id
  tp_id=$(echo "$tp_resp" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['client_id'])")
  [[ -n "$tp_id" ]] || fail "failed to create third-party client: $tp_resp"
  log "Created third-party client: $tp_id"

  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  auth_body="$TMP_DIR/consent-auth.html"
  auth_headers="$TMP_DIR/consent-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${tp_id}&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=mystate123&nonce=n&scope=openid" \
    "$auth_body" "$auth_headers" >/dev/null
  session_id=$(extract_session_id "$auth_body")

  login_body="$TMP_DIR/consent-login.txt"
  login_headers="$TMP_DIR/consent-login.headers"
  login_status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_pass")
  # Should show consent page (200), NOT redirect straight to callback
  assert_eq "200" "$login_status" "non-first-party login should show consent"
  assert_contains_file "consent" "$login_body" "consent page rendered"
  assert_contains_file "Third Party App" "$login_body" "app name in consent"
  log "PASS: Consent page shown for third-party client"

  # Extract the pending code from the hidden form field
  local pending_code
  pending_code=$(python3 - "$login_body" <<'PY'
import re, sys
html = open(sys.argv[1]).read()
m = re.search(r'name="code"\s+value="([^"]+)"', html)
if not m:
    raise SystemExit("could not find code in consent form")
print(m.group(1))
PY
)
  [[ -n "$pending_code" ]] || fail "no pending code in consent page"

  # ── Case 2a: Deny consent — should redirect with access_denied + state ──
  log "Case 2a: Deny consent"
  local deny_body="$TMP_DIR/deny.txt"
  local deny_headers="$TMP_DIR/deny.headers"
  local deny_status
  deny_status=$(curl_capture POST "$BASE_URL/consent" "$deny_body" "$deny_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "code=$pending_code" \
    --data-urlencode "decision=deny")
  assert_eq "302" "$deny_status" "deny consent redirect"
  local deny_loc
  deny_loc=$(header_value "$deny_headers" location)
  assert_contains_file "access_denied" "$deny_headers" "access_denied in redirect"
  local deny_state
  deny_state=$(url_query_get "$deny_loc" state) || true
  assert_eq "mystate123" "$deny_state" "state preserved on deny"
  log "PASS: Consent deny → access_denied with correct state"

  # ── Case 2b: Allow consent — should redirect with code + state ──
  log "Case 2b: Allow consent (fresh flow)"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  auth_body="$TMP_DIR/consent2-auth.html"
  auth_headers="$TMP_DIR/consent2-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${tp_id}&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=allowstate&nonce=n2&scope=openid" \
    "$auth_body" "$auth_headers" >/dev/null
  session_id=$(extract_session_id "$auth_body")
  login_body="$TMP_DIR/consent2-login.txt"
  login_headers="$TMP_DIR/consent2-login.headers"
  curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_pass" >/dev/null
  pending_code=$(python3 - "$login_body" <<'PY'
import re, sys
html = open(sys.argv[1]).read()
m = re.search(r'name="code"\s+value="([^"]+)"', html)
if not m:
    raise SystemExit("no code in consent form")
print(m.group(1))
PY
)
  local allow_csrf
  allow_csrf=$(python3 - "$login_body" <<'PY'
import re, sys
html = open(sys.argv[1]).read()
m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
if m:
    print(m.group(1))
else:
    print("")
PY
)
  local allow_body="$TMP_DIR/allow.txt"
  local allow_headers="$TMP_DIR/allow.headers"
  local allow_status
  allow_status=$(curl_capture POST "$BASE_URL/consent" "$allow_body" "$allow_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "code=$pending_code" \
    --data-urlencode "decision=approve" \
    --data-urlencode "csrf_token=$allow_csrf")
  assert_eq "302" "$allow_status" "approve consent redirect"
  local allow_loc
  allow_loc=$(header_value "$allow_headers" location)
  local got_code
  got_code=$(url_query_get "$allow_loc" code)
  [[ -n "$got_code" ]] || fail "no auth code in consent approve redirect"
  local got_state
  got_state=$(url_query_get "$allow_loc" state) || true
  assert_eq "allowstate" "$got_state" "state preserved on allow"
  log "PASS: Consent allow → auth code + correct state"

  # Exchange the code to confirm it works end-to-end
  local tok_body="$TMP_DIR/consent-tok.json"
  local tok_status
  tok_status=$(curl_capture POST "$BASE_URL/token" "$tok_body" "$TMP_DIR/consent-tok.headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$got_code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "client_id=$tp_id" \
    --data-urlencode "redirect_uri=http://localhost:8090/callback")
  assert_eq "200" "$tok_status" "token exchange after consent"
  local id_token
  id_token=$(python3 -c "import json; print(json.load(open('$tok_body'))['id_token'])")
  [[ -n "$id_token" ]] || fail "no id_token after consent approval"
  log "PASS: Consent allow → token exchange succeeds"

  # ── Case 2c: first_party client skips consent ──
  log "Case 2c: first_party client skips consent screen"
  local fp_resp
  fp_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Internal App",
      "redirect_uris": ["http://localhost:8090/callback"],
      "grant_types": ["authorization_code"],
      "confidential": false,
      "first_party": true
    }')
  local fp_id
  fp_id=$(echo "$fp_resp" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['client_id'])")
  [[ -n "$fp_id" ]] || fail "failed to create first-party client: $fp_resp"

  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local fp_auth="$TMP_DIR/fp-auth.html"
  local fp_auth_h="$TMP_DIR/fp-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${fp_id}&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=fpstate&nonce=n&scope=openid" \
    "$fp_auth" "$fp_auth_h" >/dev/null
  session_id=$(extract_session_id "$fp_auth")
  local fp_login="$TMP_DIR/fp-login.txt"
  local fp_login_h="$TMP_DIR/fp-login.headers"
  local fp_status
  fp_status=$(curl_capture POST "$BASE_URL/login" "$fp_login" "$fp_login_h" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_pass")
  # first_party → should redirect directly to callback, no consent page
  assert_eq "302" "$fp_status" "first-party login should redirect, not show consent"
  local fp_loc
  fp_loc=$(header_value "$fp_login_h" location)
  got_code=$(url_query_get "$fp_loc" code)
  [[ -n "$got_code" ]] || fail "no auth code from first-party client"
  log "PASS: first_party client skips consent screen"

  # ── Case 2d: prompt=consent forces consent even for first-party ──
  log "Case 2d: prompt=consent forces consent for first-party client"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local pc_auth="$TMP_DIR/pc-auth.html"
  local pc_auth_h="$TMP_DIR/pc-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${fp_id}&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid&prompt=consent" \
    "$pc_auth" "$pc_auth_h" >/dev/null
  session_id=$(extract_session_id "$pc_auth")
  local pc_login="$TMP_DIR/pc-login.txt"
  local pc_login_h="$TMP_DIR/pc-login.headers"
  local pc_status
  pc_status=$(curl_capture POST "$BASE_URL/login" "$pc_login" "$pc_login_h" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_pass")
  assert_eq "200" "$pc_status" "prompt=consent should show consent even for first-party"
  assert_contains_file "consent" "$pc_login" "consent page rendered on prompt=consent"
  log "PASS: prompt=consent forces consent screen"

  # ── Case 2e: Persistent consent — previously consented 3rd-party app skips consent on subsequent login ──
  log "Case 2e: Persistent consent remembered for third-party client (tp_id)"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local p_auth="$TMP_DIR/persist-auth.html"
  local p_auth_h="$TMP_DIR/persist-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${tp_id}&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=persisted123&nonce=pn&scope=openid" \
    "$p_auth" "$p_auth_h" >/dev/null
  session_id=$(extract_session_id "$p_auth")

  local p_login="$TMP_DIR/persist-login.txt"
  local p_login_h="$TMP_DIR/persist-login.headers"
  local p_status
  p_status=$(curl_capture POST "$BASE_URL/login" "$p_login" "$p_login_h" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_pass")
  # Because Case 2b granted consent for tp_id with scope openid, subsequent login must NOT show consent page (302 redirect)
  assert_eq "302" "$p_status" "previously granted 3rd-party client should skip consent on subsequent login"
  local p_loc
  p_loc=$(header_value "$p_login_h" location)
  got_code=$(url_query_get "$p_loc" code)
  [[ -n "$got_code" ]] || fail "no auth code returned when consent was remembered"
  got_state=$(url_query_get "$p_loc" state) || true
  assert_eq "persisted123" "$got_state" "state preserved when skipping consent"
  log "PASS: Persistent consent remembered and consent screen skipped"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 3: GDPR — GET /api/users/:id/export
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 3: GDPR data export GET /api/users/$admin_id/export"

  local export_body="$TMP_DIR/export.json"
  local export_status
  export_status=$(curl_capture GET "$BASE_URL/api/users/${admin_id}/export" \
    "$export_body" "$TMP_DIR/export.headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$export_status" "GDPR export"
  python3 - "$export_body" "$admin_email" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
email = sys.argv[2]
# Must have user object
u = d.get("user") or d
assert "id" in u or "user" in d, f"no user data: {d}"
# Must have consents list
assert "consents" in d, "export must include consents field"
assert len(d["consents"]) >= 1, "consents list should contain previously granted client"
# Must NOT expose sensitive fields
raw = open(sys.argv[1]).read()
assert "password_hash" not in raw, "export must not include password_hash"
assert "totp_secret" not in raw, "export must not include totp_secret"
print(f"  Export keys: {sorted(d.keys())}")
PY
  log "PASS: GDPR export returns user data, no sensitive fields"

  # Export of a nonexistent user should 404
  local missing_status
  missing_status=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $admin_token" \
    "$BASE_URL/api/users/nonexistent-user-xxx/export")
  assert_eq "404" "$missing_status" "export of missing user"
  log "PASS: Export of nonexistent user → 404"

  # Unauthenticated export must 401
  missing_status=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE_URL/api/users/${admin_id}/export")
  assert_eq "401" "$missing_status" "unauthenticated export"
  log "PASS: Unauthenticated export rejected → 401"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 4: GDPR — DELETE /api/users/:id
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 4: GDPR user deletion"

  # 4a: Create a regular user to delete
  local del_email="del.${ts}@example.com"
  local del_pass="DelPass123!"
  local reg_status
  reg_status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$del_email\",\"password\":\"$del_pass\",\"name\":\"ToDelete\"}")
  assert_eq "201" "$reg_status" "register user to delete"
  local del_id
  del_id=$(user_id_via_login "$del_email" "$del_pass")
  [[ -n "$del_id" ]] || fail "could not get id of user to delete"
  log "Created user to delete: $del_id"

  # 4b: Delete the user
  local del_status
  del_status=$(curl -sS -o /dev/null -w "%{http_code}" \
    -X DELETE "$BASE_URL/api/users/${del_id}" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$del_status" "delete user"
  log "PASS: DELETE /api/users/:id returned 200"

  # 4c: Export of deleted user should now 404
  local after_del_status
  after_del_status=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $admin_token" \
    "$BASE_URL/api/users/${del_id}/export")
  assert_eq "404" "$after_del_status" "export after deletion"
  log "PASS: Deleted user's export → 404"

  # 4d: Superadmin must not be able to delete themselves
  local self_del_status
  self_del_status=$(curl -sS -o /dev/null -w "%{http_code}" \
    -X DELETE "$BASE_URL/api/users/${admin_id}" \
    -H "Authorization: Bearer $admin_token")
  [[ "$self_del_status" == "400" || "$self_del_status" == "403" ]] \
    || fail "superadmin self-deletion should be rejected, got $self_del_status"
  log "PASS: Superadmin cannot delete themselves (HTTP $self_del_status)"

  # 4e: Unauthenticated delete must 401
  local unauth_del
  unauth_del=$(curl -sS -o /dev/null -w "%{http_code}" \
    -X DELETE "$BASE_URL/api/users/${del_id}")
  assert_eq "401" "$unauth_del" "unauthenticated delete"
  log "PASS: Unauthenticated delete → 401"

  log "=== Account / CSRF / Consent / GDPR: ALL TESTS PASSED ==="
}

main "$@"
