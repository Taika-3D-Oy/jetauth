use http::{Response, StatusCode};

/// GET /.well-known/openid-configuration
pub fn openid_configuration(issuer: &str) -> Response<String> {
    let doc = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "introspection_endpoint": format!("{issuer}/token/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "revocation_endpoint": format!("{issuer}/token/revoke"),
        "device_authorization_endpoint": format!("{issuer}/device_authorization"),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "dpop_signing_alg_values_supported": ["RS256", "ES256"],
        "pushed_authorization_request_endpoint": format!("{issuer}/connect/par"),
        "require_pushed_authorization_requests": false,
        "code_challenge_methods_supported": ["S256"],
        "claims_parameter_supported": true,
        "claim_types_supported": ["normal"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "acr", "amr", "email", "email_verified", "name", "given_name", "family_name", "preferred_username", "nonce", "tenant_id", "role"],
        "acr_values_supported": ["urn:lattice-id:mfa:totp"],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": false,
    });

    let mut doc = doc;
    if crate::store::client_registration_mode() != "disabled"
        && let Some(obj) = doc.as_object_mut()
    {
        obj.insert(
            "registration_endpoint".to_string(),
            serde_json::Value::String(format!("{issuer}/connect/register")),
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "public, max-age=3600")
        .body(serde_json::to_string(&doc).unwrap_or_default())
        .unwrap()
}

/// GET /.well-known/oauth-authorization-server (RFC 8414)
pub fn oauth_authorization_server(issuer: &str) -> Response<String> {
    let mut doc = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "introspection_endpoint": format!("{issuer}/token/introspect"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{issuer}/token/revoke"),
        "device_authorization_endpoint": format!("{issuer}/device_authorization"),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "dpop_signing_alg_values_supported": ["RS256", "ES256"],
        "pushed_authorization_request_endpoint": format!("{issuer}/connect/par"),
        "require_pushed_authorization_requests": false,
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    });

    if crate::store::client_registration_mode() != "disabled"
        && let Some(obj) = doc.as_object_mut()
    {
        obj.insert(
            "registration_endpoint".to_string(),
            serde_json::Value::String(format!("{issuer}/connect/register")),
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "public, max-age=3600")
        .body(serde_json::to_string(&doc).unwrap_or_default())
        .unwrap()
}

/// GET /.well-known/jwks.json — fetches JWKS from key-manager.
pub async fn jwks() -> Response<String> {
    match crate::service_client::get_jwks().await {
        Ok(jwks) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("cache-control", "public, max-age=300")
            .body(serde_json::to_string(&jwks).unwrap_or_default())
            .unwrap(),
        Err(e) => {
            crate::logger::error_message("jwks.fetch_failed", &e);
            crate::error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("signing key service unavailable: {e}"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openid_configuration_does_not_contain_user_register_endpoint() {
        let resp = openid_configuration("https://auth.example.com");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["issuer"], "https://auth.example.com");
        assert!(body.get("registration_endpoint").is_none());
        assert_eq!(body["authorization_response_iss_parameter_supported"], true);
    }

    #[test]
    fn test_oauth_authorization_server_metadata() {
        let resp = oauth_authorization_server("https://auth.example.com");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["issuer"], "https://auth.example.com");
        assert_eq!(
            body["authorization_endpoint"],
            "https://auth.example.com/authorize"
        );
        assert_eq!(body["token_endpoint"], "https://auth.example.com/token");
        assert_eq!(
            body["revocation_endpoint"],
            "https://auth.example.com/token/revoke"
        );
        assert_eq!(
            body["introspection_endpoint"],
            "https://auth.example.com/token/introspect"
        );
        assert_eq!(body["authorization_response_iss_parameter_supported"], true);
        assert!(
            body["code_challenge_methods_supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("S256"))
        );
    }

    #[test]
    fn test_openid_configuration_advertises_registration_when_enabled() {
        crate::store::init_registration_config_for_test("open", None);
        let resp = openid_configuration("https://auth.example.com");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(
            body["registration_endpoint"],
            "https://auth.example.com/connect/register"
        );

        let oauth_resp = oauth_authorization_server("https://auth.example.com");
        assert_eq!(oauth_resp.status(), StatusCode::OK);
        let oauth_body: serde_json::Value = serde_json::from_str(oauth_resp.body()).unwrap();
        assert_eq!(
            oauth_body["registration_endpoint"],
            "https://auth.example.com/connect/register"
        );
    }

    #[test]
    fn test_discovery_stage4_metadata() {
        let resp = openid_configuration("https://auth.example.com");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(
            body["pushed_authorization_request_endpoint"],
            "https://auth.example.com/connect/par"
        );
        assert_eq!(body["require_pushed_authorization_requests"], false);
        assert_eq!(body["request_uri_parameter_supported"], true);
        assert!(
            body["dpop_signing_alg_values_supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("ES256"))
        );
        assert!(
            body["token_endpoint_auth_methods_supported"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("private_key_jwt"))
        );
    }
}
