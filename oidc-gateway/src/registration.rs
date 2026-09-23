use http::{Response, StatusCode};
use subtle::ConstantTimeEq;

use crate::store::{self, OidcClient};

fn reg_error(status: StatusCode, error: &str, description: &str) -> Response<String> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(
            serde_json::to_string(&serde_json::json!({
                "error": error,
                "error_description": description
            }))
            .unwrap_or_default(),
        )
        .unwrap()
}

fn reg_unauthorized(description: &str) -> Response<String> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header(
            "www-authenticate",
            format!(r#"Bearer error="invalid_token", error_description="{description}""#),
        )
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(
            serde_json::to_string(&serde_json::json!({
                "error": "invalid_token",
                "error_description": description
            }))
            .unwrap_or_default(),
        )
        .unwrap()
}

fn extract_bearer_token(auth_header: Option<&str>) -> Option<&str> {
    let val = auth_header?.trim();
    if val.len() > 7 && val[..7].eq_ignore_ascii_case("bearer ") {
        Some(val[7..].trim())
    } else {
        None
    }
}

/// Validates policy for initial registration.
fn check_registration_gating(auth_header: Option<&str>) -> Result<(), Response<String>> {
    let mode = store::client_registration_mode();
    match mode.as_str() {
        "open" => Ok(()),
        "protected" => {
            let required_token = match store::client_registration_token() {
                Some(t) => t,
                None => {
                    return Err(reg_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "Client registration is configured as protected but no registration token is configured",
                    ));
                }
            };
            let presented_token = match extract_bearer_token(auth_header) {
                Some(t) => t,
                None => {
                    return Err(reg_unauthorized("Initial access token is required"));
                }
            };

            let matches: bool = presented_token
                .as_bytes()
                .ct_eq(required_token.as_bytes())
                .into();
            if !matches {
                return Err(reg_unauthorized("Invalid initial access token"));
            }
            Ok(())
        }
        _ => Err(reg_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Dynamic client registration is disabled",
        )),
    }
}

/// Authenticates a client configuration request (RFC 7592) using its registration access token.
async fn authenticate_registration_token(
    client_id: &str,
    auth_header: Option<&str>,
) -> Result<(), Response<String>> {
    let presented_token = match extract_bearer_token(auth_header) {
        Some(t) => t,
        None => return Err(reg_unauthorized("Registration access token is required")),
    };

    let stored_hash = match store::get_registration_token(client_id).await {
        Ok(Some(h)) => h,
        _ => return Err(reg_unauthorized("Invalid registration access token")),
    };

    let presented_hash = store::sha256_hex(presented_token);
    let matches: bool = presented_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into();
    if !matches {
        return Err(reg_unauthorized("Invalid registration access token"));
    }
    Ok(())
}

fn validate_redirect_uri(uri: &str) -> Result<(), &'static str> {
    if uri.contains('#') {
        return Err("Redirect URIs must not contain a fragment identifier");
    }
    if !uri.starts_with("http://") && !uri.starts_with("https://") {
        return Err("Redirect URIs must use http or https scheme");
    }
    // Reject plain HTTP unless localhost/127.0.0.1
    if uri.starts_with("http://") {
        let rest = &uri["http://".len()..];
        let host = rest.split(['/', ':']).next().unwrap_or("");
        if host != "localhost" && host != "127.0.0.1" {
            return Err("Redirect URIs must use https (plain http only allowed for localhost)");
        }
    }
    Ok(())
}

fn validate_post_logout_uri(uri: &str) -> Result<(), &'static str> {
    if uri.contains('#') {
        return Err("Post-logout redirect URIs must not contain a fragment identifier");
    }
    if !uri.starts_with("http://") && !uri.starts_with("https://") {
        return Err("Post-logout redirect URIs must use http or https scheme");
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct ClientRegistrationReq {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    backchannel_logout_uri: Option<String>,
    #[serde(default)]
    backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    id_token_signed_response_alg: Option<String>,
}

/// POST /connect/register (RFC 7591)
pub async fn register_client(
    auth_header: Option<&str>,
    body: &[u8],
    issuer: &str,
) -> Result<Response<String>, String> {
    if let Err(resp) = check_registration_gating(auth_header) {
        return Ok(resp);
    }

    let req: ClientRegistrationReq = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("invalid JSON payload: {e}"),
            ));
        }
    };

    let redirect_uris = req.redirect_uris.unwrap_or_default();
    if redirect_uris.is_empty() {
        return Ok(reg_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "At least one redirect_uri is required",
        ));
    }

    for uri in &redirect_uris {
        if let Err(e) = validate_redirect_uri(uri) {
            return Ok(reg_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", e));
        }
    }

    let post_logout_uris = req.post_logout_redirect_uris.unwrap_or_default();
    for uri in &post_logout_uris {
        if let Err(e) = validate_post_logout_uri(uri) {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                e,
            ));
        }
    }

    let supported_grants = [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
    ];
    let grant_types = req.grant_types.unwrap_or_else(|| {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    });
    for g in &grant_types {
        if !supported_grants.contains(&g.as_str()) {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("Unsupported grant_type: {g}"),
            ));
        }
    }

    let response_types = req
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);
    for r in &response_types {
        if r != "code" {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("Unsupported response_type: {r}"),
            ));
        }
    }

    let auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_string());
    let is_confidential = match auth_method.as_str() {
        "client_secret_basic" | "client_secret_post" => true,
        "none" => false,
        other => {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("Unsupported token_endpoint_auth_method: {other}"),
            ));
        }
    };

    let id_token_alg = match req.id_token_signed_response_alg.as_deref() {
        Some("RS256") | None => None,
        Some("ES256") => Some("ES256".to_string()),
        Some(other) => {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("Unsupported id_token_signed_response_alg: {other}"),
            ));
        }
    };

    let client_name = req.client_name.unwrap_or_else(|| "Dynamic Client".into());
    let client_id = store::random_hex(16);

    let (raw_secret, hashed_secret) = if is_confidential {
        let raw = store::random_hex(32);
        let hashed = store::hmac_client_secret(&raw);
        (Some(raw), Some(hashed))
    } else {
        (None, None)
    };

    let client = OidcClient {
        client_id: client_id.clone(),
        client_secret: hashed_secret,
        name: client_name.clone(),
        redirect_uris: redirect_uris.clone(),
        post_logout_redirect_uris: post_logout_uris.clone(),
        grant_types: grant_types.clone(),
        theme: None,
        first_party: false,
        backchannel_logout_uri: req.backchannel_logout_uri,
        backchannel_logout_session_required: req
            .backchannel_logout_session_required
            .unwrap_or(false),
        id_token_signed_response_alg: id_token_alg,
    };

    if let Err(e) = store::save_client(&client).await {
        return Ok(reg_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &format!("Failed to save client: {e}"),
        ));
    }

    // Generate RFC 7592 Registration Access Token
    let raw_reg_token = store::random_hex(32);
    let reg_token_hash = store::sha256_hex(&raw_reg_token);
    let _ = store::save_registration_token(&client_id, &reg_token_hash).await;

    // Cross-region replication (secret stripped)
    let mut sync_val = serde_json::to_value(&client).unwrap_or_default();
    if let Some(obj) = sync_val.as_object_mut() {
        obj.remove("client_secret");
    }
    crate::service_client::replicate_to_regions("put", "client", &client_id, Some(&sync_val)).await;

    let _ = store::log_audit("client_registered", "dynamic_registration", &client_id, &client_name).await;

    let registration_client_uri = format!("{issuer}/connect/register/{client_id}");
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut resp_json = serde_json::json!({
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": auth_method,
        "registration_client_uri": registration_client_uri,
        "registration_access_token": raw_reg_token,
    });

    if let Some(secret) = raw_secret {
        resp_json["client_secret"] = serde_json::json!(secret);
    }

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&resp_json).unwrap_or_default())
        .unwrap())
}

/// GET /connect/register/:id (RFC 7592 §2 Read)
pub async fn read_client(
    auth_header: Option<&str>,
    client_id: &str,
    issuer: &str,
) -> Result<Response<String>, String> {
    if let Err(resp) = authenticate_registration_token(client_id, auth_header).await {
        return Ok(resp);
    }

    let client = match store::get_client(client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Ok(reg_error(
                StatusCode::NOT_FOUND,
                "invalid_client",
                "Client not found",
            ));
        }
        Err(e) => {
            return Ok(reg_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e,
            ));
        }
    };

    let auth_method = if client.client_secret.is_some() {
        "client_secret_basic"
    } else {
        "none"
    };

    let registration_client_uri = format!("{issuer}/connect/register/{client_id}");
    let resp_json = serde_json::json!({
        "client_id": client.client_id,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": auth_method,
        "registration_client_uri": registration_client_uri,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&resp_json).unwrap_or_default())
        .unwrap())
}

/// PUT /connect/register/:id (RFC 7592 §3 Update)
pub async fn update_client(
    auth_header: Option<&str>,
    client_id: &str,
    body: &[u8],
    issuer: &str,
) -> Result<Response<String>, String> {
    if let Err(resp) = authenticate_registration_token(client_id, auth_header).await {
        return Ok(resp);
    }

    let mut client = match store::get_client(client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Ok(reg_error(
                StatusCode::NOT_FOUND,
                "invalid_client",
                "Client not found",
            ));
        }
        Err(e) => {
            return Ok(reg_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e,
            ));
        }
    };

    let req: ClientRegistrationReq = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("invalid JSON payload: {e}"),
            ));
        }
    };

    if let Some(uris) = req.redirect_uris {
        if uris.is_empty() {
            return Ok(reg_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "At least one redirect_uri is required",
            ));
        }
        for uri in &uris {
            if let Err(e) = validate_redirect_uri(uri) {
                return Ok(reg_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", e));
            }
        }
        client.redirect_uris = uris;
    }

    if let Some(post_logout_uris) = req.post_logout_redirect_uris {
        for uri in &post_logout_uris {
            if let Err(e) = validate_post_logout_uri(uri) {
                return Ok(reg_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    e,
                ));
            }
        }
        client.post_logout_redirect_uris = post_logout_uris;
    }

    if let Some(name) = req.client_name {
        if !name.is_empty() {
            client.name = name;
        }
    }

    if let Some(grants) = req.grant_types {
        let supported_grants = [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ];
        for g in &grants {
            if !supported_grants.contains(&g.as_str()) {
                return Ok(reg_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    &format!("Unsupported grant_type: {g}"),
                ));
            }
        }
        client.grant_types = grants;
    }

    if let Some(uri) = req.backchannel_logout_uri {
        client.backchannel_logout_uri = if uri.is_empty() { None } else { Some(uri) };
    }
    if let Some(req_sess) = req.backchannel_logout_session_required {
        client.backchannel_logout_session_required = req_sess;
    }
    if let Some(alg) = req.id_token_signed_response_alg {
        client.id_token_signed_response_alg = match alg.as_str() {
            "RS256" | "" => None,
            "ES256" => Some("ES256".to_string()),
            other => {
                return Ok(reg_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    &format!("unsupported id_token_signed_response_alg: {other}"),
                ));
            }
        };
    }

    if let Err(e) = store::save_client(&client).await {
        return Ok(reg_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &format!("Failed to update client: {e}"),
        ));
    }

    let mut sync_val = serde_json::to_value(&client).unwrap_or_default();
    if let Some(obj) = sync_val.as_object_mut() {
        obj.remove("client_secret");
    }
    crate::service_client::replicate_to_regions("put", "client", client_id, Some(&sync_val)).await;

    let _ = store::log_audit("client_updated", "dynamic_registration", client_id, &client.name).await;

    let auth_method = if client.client_secret.is_some() {
        "client_secret_basic"
    } else {
        "none"
    };
    let registration_client_uri = format!("{issuer}/connect/register/{client_id}");

    let resp_json = serde_json::json!({
        "client_id": client.client_id,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": auth_method,
        "registration_client_uri": registration_client_uri,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&resp_json).unwrap_or_default())
        .unwrap())
}

/// DELETE /connect/register/:id (RFC 7592 §4 Delete)
pub async fn delete_client(
    auth_header: Option<&str>,
    client_id: &str,
) -> Result<Response<String>, String> {
    if let Err(resp) = authenticate_registration_token(client_id, auth_header).await {
        return Ok(resp);
    }

    if client_id == "lid-admin" {
        return Ok(reg_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Cannot delete system admin client",
        ));
    }

    let existing = match store::get_client(client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Ok(reg_error(
                StatusCode::NOT_FOUND,
                "invalid_client",
                "Client not found",
            ));
        }
        Err(e) => {
            return Ok(reg_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e,
            ));
        }
    };

    let _ = store::delete_client(client_id).await;
    let _ = store::delete_registration_token(client_id).await;
    crate::service_client::replicate_to_regions("delete", "client", client_id, None).await;

    let _ = store::log_audit("client_deleted", "dynamic_registration", client_id, &existing.name).await;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(String::new())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token(Some("Bearer token123")), Some("token123"));
        assert_eq!(extract_bearer_token(Some("bearer token123")), Some("token123"));
        assert_eq!(extract_bearer_token(Some("Basic dXNlcjpwYXNz")), None);
        assert_eq!(extract_bearer_token(None), None);
    }

    #[test]
    fn test_validate_redirect_uri() {
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:8080/cb").is_ok());

        // Fragment rejected (RFC 7591 / RFC 3986)
        assert!(validate_redirect_uri("https://example.com/callback#token").is_err());

        // Insecure scheme rejected for non-localhost
        assert!(validate_redirect_uri("http://example.com/callback").is_err());
        assert!(validate_redirect_uri("ftp://example.com").is_err());
    }

    #[test]
    fn test_registration_gating_disabled_by_default() {
        crate::store::init_config_for_test(false, None);
        let resp = check_registration_gating(None).unwrap_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "access_denied");
    }

    #[test]
    fn test_registration_gating_protected_requires_token() {
        crate::store::init_registration_config_for_test("protected", Some("secret-iat-token"));

        // Missing token
        let err_missing = check_registration_gating(None).unwrap_err();
        assert_eq!(err_missing.status(), StatusCode::UNAUTHORIZED);
        let val: serde_json::Value = serde_json::from_str(err_missing.body()).unwrap();
        assert_eq!(val["error"], "invalid_token");

        // Wrong token
        let err_wrong = check_registration_gating(Some("Bearer wrong-token")).unwrap_err();
        assert_eq!(err_wrong.status(), StatusCode::UNAUTHORIZED);

        // Correct token
        assert!(check_registration_gating(Some("Bearer secret-iat-token")).is_ok());
    }

    #[test]
    fn test_registration_gating_open_allows_all() {
        crate::store::init_registration_config_for_test("open", None);
        assert!(check_registration_gating(None).is_ok());
        assert!(check_registration_gating(Some("Bearer whatever")).is_ok());
    }

    #[test]
    fn test_register_client_gating_disabled_returns_403() {
        crate::store::init_config_for_test(false, None);
        let resp = futures::executor::block_on(register_client(
            None,
            b"{}",
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "access_denied");
    }

    #[test]
    fn test_register_client_invalid_json() {
        crate::store::init_registration_config_for_test("open", None);
        let resp = futures::executor::block_on(register_client(
            None,
            b"not json",
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "invalid_client_metadata");
    }

    #[test]
    fn test_register_client_missing_redirect_uris() {
        crate::store::init_registration_config_for_test("open", None);
        let resp = futures::executor::block_on(register_client(
            None,
            b"{\"client_name\": \"test\"}",
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "invalid_redirect_uri");
    }

    #[test]
    fn test_register_client_redirect_uri_with_fragment() {
        crate::store::init_registration_config_for_test("open", None);
        let payload = serde_json::json!({
            "client_name": "test",
            "redirect_uris": ["https://example.com/cb#frag"]
        });
        let resp = futures::executor::block_on(register_client(
            None,
            serde_json::to_vec(&payload).unwrap().as_slice(),
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "invalid_redirect_uri");
        assert!(body["error_description"]
            .as_str()
            .unwrap()
            .contains("fragment"));
    }

    #[test]
    fn test_register_client_unsupported_grant_type() {
        crate::store::init_registration_config_for_test("open", None);
        let payload = serde_json::json!({
            "client_name": "test",
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["implicit_unsupported"]
        });
        let resp = futures::executor::block_on(register_client(
            None,
            serde_json::to_vec(&payload).unwrap().as_slice(),
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "invalid_client_metadata");
        assert!(body["error_description"]
            .as_str()
            .unwrap()
            .contains("grant_type"));
    }

    #[test]
    fn test_register_client_unsupported_response_type() {
        crate::store::init_registration_config_for_test("open", None);
        let payload = serde_json::json!({
            "client_name": "test",
            "redirect_uris": ["https://example.com/cb"],
            "response_types": ["token"]
        });
        let resp = futures::executor::block_on(register_client(
            None,
            serde_json::to_vec(&payload).unwrap().as_slice(),
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "invalid_client_metadata");
    }

    #[test]
    fn test_register_client_unsupported_auth_method() {
        crate::store::init_registration_config_for_test("open", None);
        let payload = serde_json::json!({
            "client_name": "test",
            "redirect_uris": ["https://example.com/cb"],
            "token_endpoint_auth_method": "private_key_jwt"
        });
        let resp = futures::executor::block_on(register_client(
            None,
            serde_json::to_vec(&payload).unwrap().as_slice(),
            "https://auth.example.com",
        ))
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
        assert_eq!(body["error"], "invalid_client_metadata");
    }

    #[test]
    fn test_validate_post_logout_uri() {
        assert!(validate_post_logout_uri("https://example.com/logged-out").is_ok());
        assert!(validate_post_logout_uri("http://localhost:3000/logged-out").is_ok());
        assert!(validate_post_logout_uri("https://example.com/out#frag").is_err());
        assert!(validate_post_logout_uri("javascript:alert(1)").is_err());
    }
}
