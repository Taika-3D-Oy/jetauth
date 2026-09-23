use crate::store::{self, AuthSession};
use crate::util;
use http::{Response, StatusCode};

#[derive(Default, Debug)]
struct ClaimsRequest {
    id_token_claims: Vec<String>,
    userinfo_claims: Vec<String>,
    acr_values: Vec<String>,
}

struct ValidatedHint {
    user_id: String,
    email: String,
}

fn parse_acr_values(raw: Option<&str>) -> Vec<String> {
    let mut values = Vec::new();
    for item in raw.unwrap_or("").split(' ') {
        let item = item.trim();
        if item.is_empty() || values.iter().any(|existing| existing == item) {
            continue;
        }
        values.push(item.to_string());
    }
    values
}

fn push_unique(values: &mut Vec<String>, candidate: &str) {
    if !candidate.is_empty() && !values.iter().any(|existing| existing == candidate) {
        values.push(candidate.to_string());
    }
}

fn parse_claims_param(raw: Option<&str>) -> Result<ClaimsRequest, String> {
    let Some(raw) = raw.filter(|value| !value.is_empty()) else {
        return Ok(ClaimsRequest::default());
    };

    let claims_json: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "invalid claims parameter (must be JSON object)")?;
    let claims_obj = claims_json
        .as_object()
        .ok_or("invalid claims parameter (must be JSON object)")?;

    let mut parsed = ClaimsRequest::default();
    for (target, output) in [
        ("id_token", &mut parsed.id_token_claims),
        ("userinfo", &mut parsed.userinfo_claims),
    ] {
        let Some(requested) = claims_obj.get(target) else {
            continue;
        };
        let requested = requested
            .as_object()
            .ok_or("invalid claims parameter target (must be object)")?;
        for (claim_name, descriptor) in requested {
            if !(descriptor.is_null() || descriptor.is_object()) {
                return Err("invalid claims parameter claim descriptor".into());
            }
            push_unique(output, claim_name);

            if target == "id_token"
                && claim_name == "acr"
                && let Some(descriptor) = descriptor.as_object()
            {
                if let Some(value) = descriptor.get("value").and_then(|value| value.as_str()) {
                    push_unique(&mut parsed.acr_values, value);
                }
                if let Some(values) = descriptor.get("values").and_then(|value| value.as_array()) {
                    for value in values {
                        let value = value
                            .as_str()
                            .ok_or("invalid claims parameter acr values")?;
                        push_unique(&mut parsed.acr_values, value);
                    }
                }
            }
        }
    }

    Ok(parsed)
}

fn authorize_error_redirect(
    redirect_uri: &str,
    state: &str,
    error: &str,
    description: &str,
) -> Response<String> {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut location = format!(
        "{redirect_uri}{separator}error={}&error_description={}",
        util::percent_encode(error),
        util::percent_encode(description),
    );
    if !state.is_empty() {
        location.push_str("&state=");
        location.push_str(&util::percent_encode(state));
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location)
        .body(String::new())
        .unwrap()
}

async fn validate_id_token_hint(
    raw_hint: Option<&str>,
    issuer: &str,
    client_id: &str,
) -> Result<Option<ValidatedHint>, String> {
    let Some(raw_hint) = raw_hint.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let claims =
        crate::service_client::verify_token_scoped(raw_hint, Some(issuer), Some(client_id), None)
            .await
            .map_err(|_| "invalid id_token_hint")?;

    if claims
        .get("token_type")
        .and_then(|value| value.as_str())
        .is_some()
    {
        return Err("invalid id_token_hint".into());
    }

    let user_id = claims
        .get("sub")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or("invalid id_token_hint")?;
    let user = store::get_user(user_id)
        .await?
        .filter(|user| user.status == "active")
        .ok_or("invalid id_token_hint")?;

    Ok(Some(ValidatedHint {
        user_id: user.id,
        email: user.email,
    }))
}

/// Handle GET /authorize — validate PKCE params, store session, serve login page.
pub async fn handle(
    query: &str,
    issuer: &str,
    headers: &http::HeaderMap,
) -> Result<Response<String>, String> {
    let query_params = util::parse_query(query);
    let mut params = query_params.clone();
    let query_get = |key: &str| -> Option<&str> {
        query_params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    let mut used_par = false;
    if let Some(req_uri) = query_get("request_uri") {
        if !req_uri.starts_with("urn:ietf:params:oauth:request_uri:") {
            return Err("invalid request_uri parameter format".into());
        }
        let par_entry = store::get_pushed_auth_request(req_uri)
            .await?
            .ok_or_else(|| "invalid or expired request_uri".to_string())?;
        let _ = store::delete_pushed_auth_request(req_uri).await;

        if par_entry.expires_at < store::unix_now() {
            return Err("request_uri has expired".into());
        }

        if let Some(qid) = query_get("client_id") {
            if qid != par_entry.client_id {
                return Err("client_id in authorization request does not match request_uri".into());
            }
        }

        for (k, v) in par_entry.parameters {
            if !params.iter().any(|(pk, _)| pk == &k) {
                params.push((k, v));
            }
        }
        used_par = true;
    }

    let get = |key: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    // Required OIDC params
    let response_type = get("response_type").ok_or("missing response_type")?;
    if response_type != "code" {
        return Err(format!("unsupported response_type: {response_type}"));
    }

    let client_id = get("client_id").ok_or("missing client_id")?;
    let redirect_uri = get("redirect_uri").ok_or("missing redirect_uri")?;
    let code_challenge = get("code_challenge");
    let code_challenge_method = get("code_challenge_method").unwrap_or("S256");
    if code_challenge.is_some() && code_challenge_method != "S256" {
        return Err("only S256 code_challenge_method is supported".into());
    }

    let prompt = get("prompt").unwrap_or("");
    let state = get("state").unwrap_or("");
    let id_token_hint = get("id_token_hint");
    let login_hint = get("login_hint");
    let max_age = match get("max_age") {
        Some(value) => Some(
            value
                .parse::<u64>()
                .map_err(|_| "invalid max_age (must be a non-negative integer)")?,
        ),
        None => None,
    };

    // ── IdP browser session: enables SSO and prompt=none ────────────
    // Look up the lid_session cookie. Skip when prompt=login (force re-auth).
    let idp_session = if prompt != "login" {
        crate::account::get_idp_session_from_headers(headers).await
    } else {
        None
    };
    // Honour max_age: discard the session if the original auth is too old.
    let idp_session = idp_session.filter(|s| {
        max_age.map_or(true, |age| {
            store::unix_now().saturating_sub(s.auth_time) <= age
        })
    });

    // Task 2.16: Support OIDC prompt parameter (OIDC Core §3.1.2.1).
    if prompt == "none" && idp_session.is_none() {
        // No valid browser session — cannot satisfy prompt=none.
        let err_redirect = format!(
            "{}{}error=login_required&error_description=prompt%3Dnone%20requires%20existing%20session&state={}",
            redirect_uri,
            if redirect_uri.contains('?') { "&" } else { "?" },
            state
        );
        return Ok(Response::builder()
            .status(http::StatusCode::FOUND)
            .header("location", &err_redirect)
            .body(String::new())
            .unwrap());
    }
    // prompt=login: Force re-authentication (idp_session already cleared above).
    // prompt=consent: Always implied (no stored consent).

    let scope = get("scope").unwrap_or("openid");
    let nonce = get("nonce").unwrap_or("");
    let mut acr_values = parse_acr_values(get("acr_values"));
    let claims_request = parse_claims_param(get("claims"))?;
    if !acr_values.is_empty() && !claims_request.acr_values.is_empty() {
        return Err("claims parameter acr request cannot be combined with acr_values".into());
    }
    if acr_values.is_empty() {
        acr_values = claims_request.acr_values.clone();
    }

    // Validate client (auto-ensure lid-admin if requested)
    let client = match store::get_client(client_id).await? {
        Some(c) => c,
        None if client_id == "lid-admin" => {
            store::ensure_admin_client(issuer, false).await?;
            store::get_client(client_id)
                .await?
                .ok_or_else(|| format!("unknown client_id: {client_id}"))?
        }
        None => return Err(format!("unknown client_id: {client_id}")),
    };

    if client.require_pushed_authorization_requests && !used_par {
        return Err("client is required to use pushed authorization requests (PAR)".into());
    }

    // PKCE is required for public third-party clients; optional for confidential clients and first-party clients
    if !client.first_party && client.client_secret.is_none() && code_challenge.is_none() {
        return Err("missing code_challenge (PKCE required for public clients)".into());
    }

    // Validate redirect_uri
    let is_valid_redirect = client.redirect_uris.iter().any(|u| {
        u == redirect_uri
            || (client.first_party
                && (u == &format!("{issuer}{redirect_uri}")
                    || (redirect_uri.starts_with('/')
                        && !redirect_uri.starts_with("//")
                        && !redirect_uri.starts_with("/\\"))))
    });
    if !is_valid_redirect {
        return Err("redirect_uri not registered for this client".into());
    }

    let validated_hint = match validate_id_token_hint(id_token_hint, issuer, client_id).await {
        Ok(value) => value,
        Err(_) => {
            return Ok(authorize_error_redirect(
                redirect_uri,
                state,
                "invalid_request",
                "invalid id_token_hint",
            ));
        }
    };

    // ── IdP session fast-path: skip login page ──────────────────────
    // If a valid browser session exists and the client does not require
    // re-authentication, issue the auth code directly. This enables
    // prompt=none for SPAs doing silent token renewal, and SSO across
    // clients for interactive flows.
    if let Some(ref sso) = idp_session {
        // If id_token_hint identifies a *different* user, fall through to
        // the login page so the correct account can authenticate.
        let hint_matches = validated_hint
            .as_ref()
            .map_or(true, |hint| hint.user_id == sso.user_id);

        // Check that requested ACR values are satisfiable by the existing
        // session.  If the client demands TOTP MFA but the user only used a
        // password, we must not silently satisfy it.
        let acr_satisfied = acr_values.is_empty()
            || acr_values.iter().all(|v| {
                if v == "urn:lattice-id:mfa:totp" {
                    sso.amr.iter().any(|a| a == "mfa") && sso.amr.iter().any(|a| a == "otp")
                } else {
                    true
                }
            });

        if hint_matches && acr_satisfied {
            if let Ok(Some(user)) = store::get_user(&sso.user_id).await {
                if user.status == "active" {
                    let builtin_clients = ["lid-admin", "lid-default"];
                    let is_first_party = client.first_party || builtin_clients.contains(&client_id);
                    let already_consented = if prompt == "consent" {
                        false
                    } else {
                        store::has_user_consented(&user.id, client_id, scope)
                            .await
                            .unwrap_or(false)
                    };
                    let needs_consent =
                        prompt == "consent" || (!is_first_party && !already_consented);

                    let code = store::random_hex(32);
                    let acr = crate::login::acr_from_amr(&sso.amr);
                    let auth_code = store::AuthCode {
                        user_id: user.id.clone(),
                        client_id: client_id.to_string(),
                        redirect_uri: redirect_uri.to_string(),
                        code_challenge: code_challenge.unwrap_or("").to_string(),
                        code_challenge_method: code_challenge_method.to_string(),
                        nonce: nonce.to_string(),
                        scope: scope.to_string(),
                        auth_time: sso.auth_time,
                        amr: sso.amr.clone(),
                        acr,
                        requested_id_token_claims: claims_request.id_token_claims.clone(),
                        requested_userinfo_claims: claims_request.userinfo_claims.clone(),
                        extra_claims: vec![],
                        csrf_token: String::new(),
                        expires_at: store::unix_now() + 300,
                        state: state.to_string(),
                    };
                    store::save_auth_code(&code, &auth_code).await?;
                    let _ = store::log_audit("sso_reuse", &user.id, &user.id, client_id).await;

                    // Slide the IdP session TTL (rolling window).
                    let refreshed_idp =
                        crate::account::refresh_idp_session_cookie_header(headers).await;
                    let account_cookie = crate::account::create_session_cookie(&user.id).await.ok();

                    if needs_consent {
                        let resp =
                            crate::login::consent_page(&code, &auth_code, &client, &user).await;
                        let (mut parts, body) = resp.into_parts();
                        if let Some(c) = refreshed_idp {
                            if let Ok(val) = c.parse() {
                                parts.headers.append("set-cookie", val);
                            }
                        }
                        if let Some(c) = account_cookie {
                            if let Ok(val) = c.parse() {
                                parts.headers.append("set-cookie", val);
                            }
                        }
                        return Ok(Response::from_parts(parts, body));
                    }

                    let redirect_url =
                        util::build_auth_code_redirect(redirect_uri, &code, state, issuer);
                    let mut builder = Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", &redirect_url)
                        .header("cache-control", "no-store");
                    if let Some(c) = refreshed_idp {
                        builder = builder.header("set-cookie", c);
                    }
                    if let Some(c) = account_cookie {
                        builder = builder.header("set-cookie", c);
                    }
                    return Ok(builder.body(String::new()).unwrap());
                }
            }
        }
        // Session unusable (deleted user, inactive, mismatched hint, ACR gap)
        // — fall through to the normal login page.
    }

    // No valid IdP session — create an AuthSession and show the login page.
    let session_id = store::random_hex(16);
    // Require consent when:
    //  - explicitly requested with prompt=consent, OR
    //  - the client is not first-party (and not the built-in admin/default clients)
    let builtin_clients = ["lid-admin", "lid-default"];
    let is_first_party = client.first_party || builtin_clients.contains(&client_id);
    let needs_consent = prompt == "consent" || !is_first_party;
    let session = AuthSession {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        code_challenge: code_challenge.unwrap_or("").to_string(),
        code_challenge_method: code_challenge_method.to_string(),
        state: state.to_string(),
        scope: scope.to_string(),
        nonce: nonce.to_string(),
        max_age,
        acr_values,
        requested_id_token_claims: claims_request.id_token_claims,
        requested_userinfo_claims: claims_request.userinfo_claims,
        hinted_user_id: validated_hint.as_ref().map(|hint| hint.user_id.clone()),
        hinted_email: validated_hint
            .as_ref()
            .map(|hint| hint.email.clone())
            .or_else(|| login_hint.filter(|h| !h.is_empty()).map(|h| h.to_string())),
        created_at: store::unix_now(),
        needs_consent,
        prompt: if prompt.is_empty() {
            None
        } else {
            Some(prompt.to_string())
        },
    };
    store::save_auth_session(&session_id, &session).await?;

    // Serve login page
    Ok(crate::login::login_page(&session_id, None).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acr_values_empty() {
        assert!(parse_acr_values(None).is_empty());
    }

    #[test]
    fn test_parse_acr_values_single() {
        let values = parse_acr_values(Some("urn:lattice-id:mfa:totp"));
        assert_eq!(values, vec!["urn:lattice-id:mfa:totp"]);
    }

    #[test]
    fn test_parse_acr_values_dedup() {
        let values = parse_acr_values(Some("a a b"));
        assert_eq!(values, vec!["a", "b"]);
    }

    #[test]
    fn test_parse_acr_values_ignores_whitespace() {
        let values = parse_acr_values(Some("  a   b  "));
        assert_eq!(values, vec!["a", "b"]);
    }

    #[test]
    fn test_push_unique_adds() {
        let mut v = vec!["a".to_string()];
        push_unique(&mut v, "b");
        assert_eq!(v, vec!["a", "b"]);
    }

    #[test]
    fn test_push_unique_skips_duplicate() {
        let mut v = vec!["a".to_string()];
        push_unique(&mut v, "a");
        assert_eq!(v, vec!["a"]);
    }

    #[test]
    fn test_push_unique_skips_empty() {
        let mut v: Vec<String> = vec![];
        push_unique(&mut v, "");
        assert!(v.is_empty());
    }

    #[test]
    fn test_parse_claims_param_none() {
        let result = parse_claims_param(None).unwrap();
        assert!(result.id_token_claims.is_empty());
        assert!(result.userinfo_claims.is_empty());
    }

    #[test]
    fn test_parse_claims_param_empty() {
        let result = parse_claims_param(Some("")).unwrap();
        assert!(result.id_token_claims.is_empty());
    }

    #[test]
    fn test_parse_claims_param_valid() {
        let raw = r#"{"id_token": {"name": null, "email": null}, "userinfo": {"profile": null}}"#;
        let result = parse_claims_param(Some(raw)).unwrap();
        assert_eq!(result.id_token_claims.len(), 2);
        assert!(result.id_token_claims.contains(&"name".to_string()));
        assert!(result.id_token_claims.contains(&"email".to_string()));
        assert_eq!(result.userinfo_claims, vec!["profile"]);
    }

    #[test]
    fn test_parse_claims_param_invalid_json() {
        let result = parse_claims_param(Some("not json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be JSON"));
    }

    #[test]
    fn test_parse_claims_param_invalid_descriptor() {
        let raw = r#"{"id_token": {"name": "not-null-or-object"}}"#;
        let result = parse_claims_param(Some(raw));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("invalid claims parameter claim descriptor")
        );
    }

    #[test]
    fn test_authorize_error_redirect_contains_error() {
        let resp = authorize_error_redirect(
            "https://client.example.com/cb",
            "state123",
            "invalid_request",
            "bad request",
        );
        assert_eq!(resp.status(), 302);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
        assert!(location.contains("state=state123"));
    }

    #[test]
    fn test_authorize_error_redirect_no_state() {
        let resp = authorize_error_redirect(
            "https://client.example.com/cb",
            "",
            "access_denied",
            "denied",
        );
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(!location.contains("&state="));
    }

    #[test]
    fn test_parse_acr_values_with_claims_parameter() {
        let raw = r#"{"id_token": {"acr": {"values": ["a", "b"]}}}"#;
        let result = parse_claims_param(Some(raw)).unwrap();
        assert_eq!(result.acr_values, vec!["a", "b"]);
    }

    #[test]
    fn test_acr_values_and_claims_acr_cannot_combine() {
        // This is enforced at the handle() level, not parse level.
        // parse_claims_param only extracts data; the combination check is in handle().
        let raw = r#"{"id_token": {"acr": {"value": "x"}}}"#;
        let result = parse_claims_param(Some(raw)).unwrap();
        assert_eq!(result.acr_values, vec!["x"]);
    }

    #[test]
    fn test_parse_claims_acr_value_sets_acr_values() {
        let raw = r#"{"id_token": {"acr": {"value": "single"}}}"#;
        let result = parse_claims_param(Some(raw)).unwrap();
        assert_eq!(result.acr_values, vec!["single"]);
    }

    #[test]
    fn test_authorize_par_enforced_rejects_direct_query() {
        futures::executor::block_on(async {
            store::init_config_for_test(false, Some("test_pepper_123456789012345678901234567890"));
            let client = store::OidcClient {
                client_id: "par-enforced-client".to_string(),
                client_secret: None,
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                post_logout_redirect_uris: vec![],
                grant_types: vec!["authorization_code".to_string()],
                name: "PAR Enforced Client".to_string(),
                theme: None,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                id_token_signed_response_alg: None,
                first_party: false,
                token_endpoint_auth_method: Some("none".to_string()),
                jwks: None,
                require_pushed_authorization_requests: true,
            };
            store::save_client(&client).await.unwrap();

            let headers = http::HeaderMap::new();
            let query = "client_id=par-enforced-client&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid";
            let res = handle(query, "https://auth.example.com", &headers).await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("pushed authorization requests"));
        });
    }

    #[test]
    fn test_authorize_par_success_flow() {
        futures::executor::block_on(async {
            store::init_config_for_test(false, Some("test_pepper_123456789012345678901234567890"));
            let client = store::OidcClient {
                client_id: "par-flow-client".to_string(),
                client_secret: None,
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                post_logout_redirect_uris: vec![],
                grant_types: vec!["authorization_code".to_string()],
                name: "PAR Flow Client".to_string(),
                theme: None,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                id_token_signed_response_alg: None,
                first_party: false,
                token_endpoint_auth_method: Some("none".to_string()),
                jwks: None,
                require_pushed_authorization_requests: true,
            };
            store::save_client(&client).await.unwrap();

            let req_uri = "urn:ietf:params:oauth:request_uri:abc1234567890";
            let mut params = std::collections::HashMap::new();
            params.insert("client_id".to_string(), "par-flow-client".to_string());
            params.insert(
                "redirect_uri".to_string(),
                "https://app.example.com/cb".to_string(),
            );
            params.insert("response_type".to_string(), "code".to_string());
            params.insert("scope".to_string(), "openid".to_string());
            params.insert("state".to_string(), "par_state_999".to_string());
            params.insert(
                "code_challenge".to_string(),
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            );
            params.insert("code_challenge_method".to_string(), "S256".to_string());

            let now = store::unix_now();
            let par_entry = store::PushedAuthRequest {
                client_id: "par-flow-client".to_string(),
                parameters: params,
                created_at: now,
                expires_at: now + 90,
            };
            store::save_pushed_auth_request(req_uri, &par_entry, 90)
                .await
                .unwrap();

            let headers = http::HeaderMap::new();
            let query = format!("client_id=par-flow-client&request_uri={req_uri}");
            let res = handle(&query, "https://auth.example.com", &headers).await;
            assert!(res.is_ok());
            let resp = res.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
            assert!(resp.body().contains("<!DOCTYPE html>") || resp.body().contains("<html"));

            // Verify the PAR entry was consumed (single-use)
            let consumed = store::get_pushed_auth_request(req_uri).await.unwrap();
            assert!(consumed.is_none());
        });
    }
}
