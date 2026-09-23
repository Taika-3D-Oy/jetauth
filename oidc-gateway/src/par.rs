use crate::client_auth;
use crate::store::{self, PushedAuthRequest, TTL_PAR_REQUEST};
use crate::util;
use http::{Response, StatusCode};
use std::collections::HashMap;

/// Handle POST /connect/par (RFC 9126 Pushed Authorization Requests)
pub async fn handle_par(
    body_bytes: &[u8],
    issuer: &str,
    auth_header: Option<&str>,
) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);

    let auth_client =
        match client_auth::authenticate_client(&form, auth_header, issuer, "/connect/par").await {
            Ok(c) => c,
            Err(e) => {
                let status = if e.contains("multiple") || e.contains("missing") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::UNAUTHORIZED
                };
                return Ok(par_error(status, "invalid_client", &e));
            }
        };

    let client = auth_client.client;
    let get = |k: &str| -> Option<&str> {
        form.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };

    // If client_id was passed in form, ensure it matches authenticated client
    if let Some(cid) = get("client_id") {
        if cid != client.client_id {
            return Ok(par_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id mismatch between authentication and request body",
            ));
        }
    }

    // Validate response_type
    let response_type = match get("response_type") {
        Some(rt) => rt,
        None => {
            return Ok(par_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing response_type",
            ));
        }
    };
    if response_type != "code" {
        return Ok(par_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }

    // Validate redirect_uri
    let redirect_uri = match get("redirect_uri") {
        Some(ru) => ru,
        None => {
            return Ok(par_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing redirect_uri",
            ));
        }
    };
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return Ok(par_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not registered for this client",
        ));
    }

    // Validate PKCE code_challenge if present
    if let Some(method) = get("code_challenge_method") {
        if method != "S256" {
            return Ok(par_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_challenge_method must be S256",
            ));
        }
    }

    let request_uri = format!(
        "urn:ietf:params:oauth:request_uri:{}",
        store::random_hex(24)
    );
    let expires_at = store::unix_now() + TTL_PAR_REQUEST;

    let mut params = HashMap::new();
    for (k, v) in form {
        // Strip credentials from stored PAR parameters
        if k != "client_secret" && k != "client_assertion" && k != "client_assertion_type" {
            params.insert(k, v);
        }
    }
    params.insert("client_id".to_string(), client.client_id.clone());

    let created_at = store::unix_now();
    let par_entry = PushedAuthRequest {
        client_id: client.client_id,
        parameters: params,
        created_at,
        expires_at,
    };

    if let Err(e) = store::save_pushed_auth_request(&request_uri, &par_entry, TTL_PAR_REQUEST).await
    {
        return Ok(par_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &format!("failed to store PAR request: {e}"),
        ));
    }

    let resp_body = serde_json::json!({
        "request_uri": request_uri,
        "expires_in": TTL_PAR_REQUEST
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&resp_body).unwrap_or_default())
        .unwrap())
}

fn par_error(status: StatusCode, error: &str, description: &str) -> Response<String> {
    let body = serde_json::json!({
        "error": error,
        "error_description": description
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&body).unwrap_or_default())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_par_missing_client_auth() {
        futures::executor::block_on(async {
            store::init_config_for_test(false, Some("test_pepper_123456789012345678901234567890"));
            let body =
                b"response_type=code&client_id=unknown&redirect_uri=https://app.example.com/cb";
            let resp = handle_par(body, "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        });
    }

    #[test]
    fn test_handle_par_unsupported_response_type() {
        futures::executor::block_on(async {
            store::init_config_for_test(false, Some("test_pepper_123456789012345678901234567890"));
            let client = store::OidcClient {
                client_id: "test-par-client".to_string(),
                client_secret: None,
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                post_logout_redirect_uris: vec![],
                grant_types: vec!["authorization_code".to_string()],
                name: "Test PAR Client".to_string(),
                theme: None,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                id_token_signed_response_alg: None,
                first_party: false,
                token_endpoint_auth_method: Some("none".to_string()),
                jwks: None,
                require_pushed_authorization_requests: false,
            };
            store::save_client(&client).await.unwrap();

            let body = b"response_type=token&client_id=test-par-client&redirect_uri=https://app.example.com/cb";
            let resp = handle_par(body, "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert_eq!(val["error"], "unsupported_response_type");
        });
    }

    #[test]
    fn test_handle_par_success() {
        futures::executor::block_on(async {
            store::init_config_for_test(false, Some("test_pepper_123456789012345678901234567890"));
            let secret = "test_par_secret_1234567890";
            let secret_hash = store::hmac_client_secret(secret);
            let client = store::OidcClient {
                client_id: "test-par-confidential".to_string(),
                client_secret: Some(secret_hash),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                post_logout_redirect_uris: vec![],
                grant_types: vec!["authorization_code".to_string()],
                name: "Test PAR Confidential Client".to_string(),
                theme: None,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                id_token_signed_response_alg: None,
                first_party: false,
                token_endpoint_auth_method: Some("client_secret_post".to_string()),
                jwks: None,
                require_pushed_authorization_requests: true,
            };
            store::save_client(&client).await.unwrap();

            let body = format!(
                "client_id=test-par-confidential&client_secret={}&response_type=code&redirect_uri=https://app.example.com/cb&scope=openid+email&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
                secret
            );
            let resp = handle_par(body.as_bytes(), "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            let req_uri = val["request_uri"].as_str().unwrap();
            assert!(req_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
            assert_eq!(val["expires_in"], 90);

            // Verify stored PAR entry
            let stored = store::get_pushed_auth_request(req_uri)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.client_id, "test-par-confidential");
            assert_eq!(stored.parameters.get("scope").unwrap(), "openid email");
            assert_eq!(stored.parameters.get("state").unwrap(), "xyz123");
            assert!(!stored.parameters.contains_key("client_secret")); // sensitive cred stripped
        });
    }
}
