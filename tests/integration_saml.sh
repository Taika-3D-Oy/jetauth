#!/usr/bin/env bash
# Test: SAML 2.0 IdP metadata, SP-initiated SSO, browser SSO reuse, replay rejection, and key rotation

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
trap cleanup EXIT

make_authn_request() {
  local request_id="$1" acs="${2:-http://localhost:8090/saml/acs}"
  python3 - "$request_id" "$acs" "$BASE_URL" <<'PY'
import base64, datetime, sys
request_id, acs, base_url = sys.argv[1:]
now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
xml = f'''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{request_id}" Version="2.0" IssueInstant="{now}" Destination="{base_url}/saml/sso" AssertionConsumerServiceURL="{acs}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>'''
print(base64.b64encode(xml.encode()).decode())
PY
}

extract_saml_response() {
  python3 - "$1" "$2" <<'PY'
import base64, html, os, re, sys
import xml.etree.ElementTree as ET
body = open(sys.argv[1], encoding='utf-8').read()
request_id = sys.argv[2]
admin_email = os.environ['admin_email']
match = re.search(r'name="SAMLResponse" value="([^"]+)"', body)
if not match:
    raise SystemExit('SAMLResponse form field missing; login may not have completed')
encoded = html.unescape(match.group(1))
xml = base64.b64decode(encoded)
root = ET.fromstring(xml)
ns = {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol', 'saml': 'urn:oasis:names:tc:SAML:2.0:assertion', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
assert root.attrib['InResponseTo'] == f'_{request_id}', root.attrib
assert root.attrib['Destination'] == 'http://localhost:8090/saml/acs', root.attrib
assert root.find('.//saml:NameID', ns).text == admin_email
assert root.find('.//saml:SubjectConfirmationData', ns).attrib['InResponseTo'] == f'_{request_id}'
assert root.find('.//saml:SubjectConfirmationData', ns).attrib['Recipient'] == 'http://localhost:8090/saml/acs'
assert root.find('.//saml:Assertion/ds:Signature', ns) is not None, 'assertion is not signed'
attributes = {node.attrib['Name']: ''.join(node.itertext()) for node in root.findall('.//saml:Attribute', ns)}
assert attributes['email'] == admin_email
assert attributes['displayName'] == 'SAML Admin'
assert 'name="RelayState" value="relay-123"' in body, 'RelayState not preserved'
print('SAML response signature, subject, ACS, attributes, and RelayState OK')
PY
}

main() {
  log "=== SAML 2.0 IdP integration test ==="
  wait_for_cluster
  local password="SamlPass123!"
  admin_email="saml.admin.$(date +%s)@example.com"
  export admin_email
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$password" "SAML Admin")

  local metadata="$TMP_DIR/saml-metadata.xml"
  curl -sf "$BASE_URL/saml/metadata" -o "$metadata" || fail "SAML metadata unavailable"
  python3 - "$metadata" "$BASE_URL" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
assert root.attrib['entityID'] == sys.argv[2] + '/saml/metadata'
ns = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
assert root.find('.//md:SingleSignOnService', ns) is not None
assert root.find('.//ds:X509Certificate', ns).text.strip()
PY
  log "PASS: metadata and signing certificate"

  local sp_body="$TMP_DIR/saml-sp.json"
  local status
  status=$(curl_capture POST "$BASE_URL/api/saml-service-providers" "$sp_body" "$TMP_DIR/saml-sp.headers" \
    -H "Authorization: Bearer $admin_token" -H 'content-type: application/json' \
    -d '{"name":"Integration SP","entity_id":"https://sp.example.com/metadata","acs_urls":["http://localhost:8090/saml/acs"],"name_id_format":"email","attribute_mappings":[["email","email"],["displayName","name"]]}')
  assert_eq "201" "$status" "create SAML SP"
  local sp_id
  sp_id=$(json_get "$sp_body" id)

  local jar="$TMP_DIR/saml-cookies.txt"
  local request_id="first-$(date +%s)"
  local request
  request=$(make_authn_request "$request_id")
  local login_page="$TMP_DIR/saml-login.html"
  curl_capture POST "$BASE_URL/saml/sso" "$login_page" "$TMP_DIR/saml-start.headers" \
    -c "$jar" -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLRequest=$request" --data-urlencode 'RelayState=relay-123' >/dev/null
  local session_id
  session_id=$(extract_session_id "$login_page")
  local response_page="$TMP_DIR/saml-response.html"
  curl_capture POST "$BASE_URL/login" "$response_page" "$TMP_DIR/saml-login.headers" \
    -b "$jar" -c "$jar" -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$password" >/dev/null
  extract_saml_response "$response_page" "$request_id"
  log "PASS: interactive SP-initiated SSO"

  local second_id="second-$(date +%s)"
  local second_request
  second_request=$(make_authn_request "$second_id")
  local second_page="$TMP_DIR/saml-second.html"
  curl_capture POST "$BASE_URL/saml/sso" "$second_page" "$TMP_DIR/saml-second.headers" \
    -b "$jar" -c "$jar" -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLRequest=$second_request" --data-urlencode 'RelayState=relay-123' >/dev/null
  extract_saml_response "$second_page" "$second_id"
  log "PASS: existing JetAuth browser session reused"

  local replay_status
  replay_status=$(curl_capture POST "$BASE_URL/saml/sso" "$TMP_DIR/saml-replay.html" "$TMP_DIR/saml-replay.headers" \
    -b "$jar" -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLRequest=$request" --data-urlencode 'RelayState=relay-123')
  assert_eq "400" "$replay_status" "SAML request replay rejected"
  log "PASS: request replay rejected"

  local bad_request
  bad_request=$(make_authn_request "bad-acs-$(date +%s)" "http://attacker.example/acs")
  local bad_status
  bad_status=$(curl_capture POST "$BASE_URL/saml/sso" "$TMP_DIR/saml-bad.html" "$TMP_DIR/saml-bad.headers" \
    -H 'content-type: application/x-www-form-urlencoded' --data-urlencode "SAMLRequest=$bad_request")
  assert_eq "400" "$bad_status" "unregistered ACS rejected"
  log "PASS: unregistered ACS rejected"

  local rotate_body="$TMP_DIR/saml-rotate.json"
  status=$(curl_capture POST "$BASE_URL/api/saml-signing-key/rotate" "$rotate_body" "$TMP_DIR/saml-rotate.headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$status" "rotate SAML signing key"
  curl -sf "$BASE_URL/saml/metadata" -o "$metadata"
  python3 - "$metadata" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
ns = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata'}
keys = root.findall('.//md:KeyDescriptor[@use="signing"]', ns)
assert len(keys) == 2, f'expected current and previous signing certificates, got {len(keys)}'
PY
  log "PASS: key rotation publishes current and previous certificates"

  status=$(curl_capture DELETE "$BASE_URL/api/saml-service-providers/$sp_id" "$TMP_DIR/saml-delete.json" "$TMP_DIR/saml-delete.headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$status" "delete SAML SP"
}

main "$@"
