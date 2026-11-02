#!/usr/bin/env bash
# Test: SCIM discovery, Users lifecycle, filtering, ETags, tenant isolation, and token rotation

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
trap cleanup EXIT

main() {
  log "=== SCIM 2.0 integration test ==="
  wait_for_cluster
  local password="ScimPass123!"
  local admin_email="scim.admin.$(date +%s)@example.com"
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$password" "SCIM Admin")

  local tenant_body="$TMP_DIR/scim-tenant.json"
  local status
  status=$(curl_capture POST "$BASE_URL/api/tenants" "$tenant_body" "$TMP_DIR/scim-tenant.headers" \
    -H "Authorization: Bearer $admin_token" -H 'content-type: application/json' \
    -d '{"name":"scim-test","display_name":"SCIM Test"}')
  assert_eq "201" "$status" "create SCIM tenant"
  local tenant_id
  tenant_id=$(json_get "$tenant_body" id)

  local conn_body="$TMP_DIR/scim-connection.json"
  status=$(curl_capture POST "$BASE_URL/api/scim/connections" "$conn_body" "$TMP_DIR/scim-connection.headers" \
    -H "Authorization: Bearer $admin_token" -H 'content-type: application/json' \
    -d "{\"name\":\"Directory\",\"tenant_id\":\"$tenant_id\",\"default_role\":\"member\"}")
  assert_eq "201" "$status" "create SCIM connection"
  local connection_id token
  connection_id=$(json_get "$conn_body" id)
  token=$(json_get "$conn_body" token)
  [[ "$token" =~ ^[a-f0-9]{64}$ ]] || fail "SCIM raw token missing"

  status=$(curl_capture GET "$BASE_URL/scim/v2/ServiceProviderConfig" "$TMP_DIR/scim-unauthorized.json" "$TMP_DIR/scim-unauthorized.headers")
  assert_eq "401" "$status" "SCIM requires bearer token"
  status=$(curl_capture GET "$BASE_URL/scim/v2/ServiceProviderConfig" "$TMP_DIR/scim-config.json" "$TMP_DIR/scim-config.headers" \
    -H "Authorization: Bearer $token")
  assert_eq "200" "$status" "SCIM ServiceProviderConfig"
  assert_eq "false" "$(json_get "$TMP_DIR/scim-config.json" bulk.supported)" "SCIM bulk disabled"
  assert_eq "true" "$(json_get "$TMP_DIR/scim-config.json" patch.supported)" "SCIM PATCH enabled"

  local email="scim.user.$(date +%s)@example.com"
  local user_body="$TMP_DIR/scim-user.json"
  status=$(curl_capture POST "$BASE_URL/scim/v2/Users" "$user_body" "$TMP_DIR/scim-user.headers" \
    -H "Authorization: Bearer $token" -H 'content-type: application/scim+json' \
    -d "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$email\",\"externalId\":\"directory-123\",\"name\":{\"formatted\":\"SCIM User\"},\"active\":true}")
  assert_eq "201" "$status" "create SCIM user"
  local user_id
  user_id=$(json_get "$user_body" id)
  assert_eq "directory-123" "$(json_get "$user_body" externalId)" "externalId preserved"
  assert_eq "W/\"1\"" "$(header_value "$TMP_DIR/scim-user.headers" etag)" "initial ETag"

  status=$(curl_capture GET "$BASE_URL/api/tenants/$tenant_id/users" "$TMP_DIR/scim-members.json" "$TMP_DIR/scim-members.headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$status" "list tenant members"
  python3 - "$TMP_DIR/scim-members.json" "$user_id" <<'PY'
import json, sys
users = json.load(open(sys.argv[1]))
member = next(user for user in users if user['id'] == sys.argv[2])
assert member['role'] == 'member'
PY
  log "PASS: user provisioning and tenant membership"

  status=$(curl_capture GET "$BASE_URL/scim/v2/Users?filter=externalId%20eq%20%22directory-123%22" "$TMP_DIR/scim-filter.json" "$TMP_DIR/scim-filter.headers" \
    -H "Authorization: Bearer $token")
  assert_eq "200" "$status" "filter SCIM users"
  assert_eq "1" "$(json_get "$TMP_DIR/scim-filter.json" totalResults)" "externalId filter result"

  local patch_body="$TMP_DIR/scim-patch.json"
  status=$(curl_capture PATCH "$BASE_URL/scim/v2/Users/$user_id" "$patch_body" "$TMP_DIR/scim-patch.headers" \
    -H "Authorization: Bearer $token" -H 'content-type: application/scim+json' \
    -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}')
  assert_eq "200" "$status" "deactivate SCIM user"
  assert_eq "false" "$(json_get "$patch_body" active)" "user deactivated"
  assert_eq "W/\"2\"" "$(header_value "$TMP_DIR/scim-patch.headers" etag)" "updated ETag"

  status=$(curl_capture PUT "$BASE_URL/scim/v2/Users/$user_id" "$TMP_DIR/scim-stale.json" "$TMP_DIR/scim-stale.headers" \
    -H "Authorization: Bearer $token" -H 'content-type: application/scim+json' -H 'If-Match: W/"99"' \
    -d "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$email\",\"externalId\":\"directory-123\",\"active\":true}")
  assert_eq "412" "$status" "stale ETag rejected"
  log "PASS: deactivation and optimistic concurrency"

  local other_body="$TMP_DIR/scim-other.json"
  status=$(curl_capture POST "$BASE_URL/api/scim/connections" "$other_body" "$TMP_DIR/scim-other.headers" \
    -H "Authorization: Bearer $admin_token" -H 'content-type: application/json' \
    -d "{\"name\":\"Other directory\",\"tenant_id\":\"$tenant_id\"}")
  assert_eq "201" "$status" "create second SCIM connection"
  local other_token
  other_token=$(json_get "$other_body" token)
  status=$(curl_capture GET "$BASE_URL/scim/v2/Users/$user_id" "$TMP_DIR/scim-cross.json" "$TMP_DIR/scim-cross.headers" \
    -H "Authorization: Bearer $other_token")
  assert_eq "404" "$status" "cross-connection user access denied"
  log "PASS: connection isolation"

  local rotated_body="$TMP_DIR/scim-rotated.json"
  status=$(curl_capture POST "$BASE_URL/api/scim/connections/$connection_id/rotate-token" "$rotated_body" "$TMP_DIR/scim-rotated.headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$status" "rotate SCIM token"
  local rotated_token
  rotated_token=$(json_get "$rotated_body" token)
  status=$(curl_capture GET "$BASE_URL/scim/v2/Users/$user_id" "$TMP_DIR/scim-old-token.json" "$TMP_DIR/scim-old-token.headers" \
    -H "Authorization: Bearer $token")
  assert_eq "401" "$status" "old SCIM token rejected"
  status=$(curl_capture GET "$BASE_URL/scim/v2/Users/$user_id" "$TMP_DIR/scim-new-token.json" "$TMP_DIR/scim-new-token.headers" \
    -H "Authorization: Bearer $rotated_token")
  assert_eq "200" "$status" "new SCIM token accepted"
  log "PASS: token rotation"

  status=$(curl_capture DELETE "$BASE_URL/scim/v2/Users/$user_id" "$TMP_DIR/scim-delete.out" "$TMP_DIR/scim-delete.headers" \
    -H "Authorization: Bearer $rotated_token")
  assert_eq "204" "$status" "delete SCIM user"
  [[ ! -s "$TMP_DIR/scim-delete.out" ]] || fail "SCIM DELETE response must be empty"
  status=$(curl_capture GET "$BASE_URL/scim/v2/Users/$user_id" "$TMP_DIR/scim-after-delete.json" "$TMP_DIR/scim-after-delete.headers" \
    -H "Authorization: Bearer $rotated_token")
  assert_eq "404" "$status" "deleted SCIM user absent"
  log "PASS: permanent deprovisioning"
}

main "$@"
