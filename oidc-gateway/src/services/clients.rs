//! OIDC client mutations shared by the management API and the admin panel.

use crate::error::ApiError;
use crate::store::{self, ClientTheme, OidcClient};

use super::authz::Caller;

/// Fields for creating a client. Both surfaces converge on this shape; the
/// management API handler maps its JSON body onto it, the admin panel maps
/// its form fields.
#[derive(Default)]
pub struct CreateClientParams {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub confidential: bool,
    pub theme: Option<ClientTheme>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    /// "RS256" (default) or "ES256".
    pub id_token_signed_response_alg: Option<String>,
    pub first_party: bool,
    pub token_endpoint_auth_method: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub require_pushed_authorization_requests: bool,
}

/// Partial update for a client; `None` leaves the field unchanged.
/// `backchannel_logout_uri: Some("")` clears the URI, and
/// `id_token_signed_response_alg: Some("")` resets to the default ("RS256").
#[derive(Default)]
pub struct UpdateClientParams {
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub name: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub theme: Option<Option<ClientTheme>>,
    pub first_party: Option<bool>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub id_token_signed_response_alg: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub require_pushed_authorization_requests: Option<bool>,
}

fn validate_redirect_uris(uris: &[String], field: &str) -> Result<(), ApiError> {
    for uri in uris {
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            return Err(format!("{field} must use http or https scheme").into());
        }
    }
    Ok(())
}

fn parse_signing_alg(alg: Option<&str>) -> Result<Option<String>, ApiError> {
    match alg {
        Some("RS256") | Some("") | None => Ok(None),
        Some("ES256") => Ok(Some("ES256".to_string())),
        Some(other) => Err(format!("unsupported id_token_signed_response_alg: {other}").into()),
    }
}

/// Replicate a client mutation to remote regions (fire-and-forget).
/// `client_secret` is already stored as an HMAC-SHA256 digest, so preserving it
/// keeps confidential client authentication intact across regions.
async fn replicate_client(op: &str, client_id: &str, client: Option<&OidcClient>) {
    let data = client.map(|c| serde_json::to_value(c).unwrap_or_default());
    crate::service_client::replicate_to_regions(op, "client", client_id, data.as_ref()).await;
}

/// Create a client. Superadmin only. Returns the stored client and, for
/// confidential clients, the raw secret (shown to the caller exactly once).
pub async fn create_client(
    caller: &Caller,
    params: CreateClientParams,
) -> Result<(OidcClient, Option<String>), ApiError> {
    caller.require_superadmin()?;

    if params.name.is_empty() {
        return Err("name is required".into());
    }
    if params.redirect_uris.is_empty() {
        return Err("at least one redirect_uri is required".into());
    }
    validate_redirect_uris(&params.redirect_uris, "redirect_uris")?;
    validate_redirect_uris(
        &params.post_logout_redirect_uris,
        "post_logout_redirect_uris",
    )?;
    if let Some(theme) = &params.theme {
        crate::theme::validate_theme(theme)?;
    }
    if let Some(uri) = &params.backchannel_logout_uri
        && !uri.is_empty()
    {
        crate::util::is_safe_external_url(uri)
            .map_err(|e| ApiError::bad_request(format!("invalid backchannel_logout_uri: {e}")))?;
    }

    let resolved_auth_method = params.token_endpoint_auth_method.or_else(|| {
        if params.confidential {
            Some("client_secret_basic".to_string())
        } else if params.jwks.is_some() {
            Some("private_key_jwt".to_string())
        } else {
            Some("none".to_string())
        }
    });
    if params.jwks.is_some() && resolved_auth_method.as_deref() == Some("none") {
        return Err("jwks cannot be configured when token_endpoint_auth_method is none".into());
    }

    let client_secret = if params.confidential {
        let raw = store::random_hex(32);
        // Store an HMAC of the secret, not the raw value.
        // The raw secret is returned to the caller once at creation time.
        let hashed = store::hmac_client_secret(&raw);
        Some((raw, hashed))
    } else {
        None
    };

    let client = OidcClient {
        client_id: format!("client_{}", store::random_alphanumeric(16)),
        client_secret: client_secret.as_ref().map(|(_, h)| h.clone()),
        name: params.name,
        redirect_uris: params.redirect_uris,
        post_logout_redirect_uris: params.post_logout_redirect_uris,
        grant_types: params.grant_types.unwrap_or_else(|| {
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ]
        }),
        theme: params.theme,
        backchannel_logout_uri: params.backchannel_logout_uri,
        backchannel_logout_session_required: params.backchannel_logout_session_required,
        id_token_signed_response_alg: parse_signing_alg(
            params.id_token_signed_response_alg.as_deref(),
        )?,
        first_party: params.first_party,
        token_endpoint_auth_method: resolved_auth_method,
        jwks: params.jwks,
        require_pushed_authorization_requests: params.require_pushed_authorization_requests,
    };
    store::save_client(&client)
        .await
        .map_err(ApiError::internal)?;

    replicate_client("put", &client.client_id, Some(&client)).await;

    let _ = store::log_audit(
        "client_created",
        &caller.user_id,
        &client.client_id,
        &client.name,
    )
    .await;

    Ok((client, client_secret.map(|(raw, _)| raw)))
}

/// Apply a partial update to a client. Superadmin only.
pub async fn update_client(
    caller: &Caller,
    client_id: &str,
    params: UpdateClientParams,
) -> Result<OidcClient, ApiError> {
    caller.require_superadmin()?;

    let mut client = store::get_client(client_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("client not found"))?;

    if let Some(uris) = params.redirect_uris {
        if uris.is_empty() {
            return Err("at least one redirect_uri is required".into());
        }
        validate_redirect_uris(&uris, "redirect_uris")?;
        client.redirect_uris = uris;
    }
    if let Some(uris) = params.post_logout_redirect_uris {
        validate_redirect_uris(&uris, "post_logout_redirect_uris")?;
        client.post_logout_redirect_uris = uris;
    }
    if let Some(name) = params.name {
        if name.is_empty() {
            return Err("name is required".into());
        }
        client.name = name;
    }
    if let Some(grant_types) = params.grant_types {
        client.grant_types = grant_types;
    }
    if let Some(theme_opt) = params.theme {
        if let Some(theme) = &theme_opt {
            crate::theme::validate_theme(theme)?;
        }
        client.theme = theme_opt;
    }
    if let Some(fp) = params.first_party {
        client.first_party = fp;
    }
    if let Some(uri) = params.backchannel_logout_uri {
        if !uri.is_empty() {
            crate::util::is_safe_external_url(&uri).map_err(|e| {
                ApiError::bad_request(format!("invalid backchannel_logout_uri: {e}"))
            })?;
        }
        client.backchannel_logout_uri = if uri.is_empty() { None } else { Some(uri) };
    }
    if let Some(req_sess) = params.backchannel_logout_session_required {
        client.backchannel_logout_session_required = req_sess;
    }
    if let Some(alg) = params.id_token_signed_response_alg {
        client.id_token_signed_response_alg = parse_signing_alg(Some(&alg))?;
    }
    if let Some(method) = params.token_endpoint_auth_method {
        client.token_endpoint_auth_method = Some(method);
    }
    if let Some(jwks) = params.jwks {
        client.jwks = Some(jwks);
    }
    if client.jwks.is_some() && client.token_endpoint_auth_method.as_deref() == Some("none") {
        return Err("jwks cannot be configured when token_endpoint_auth_method is none".into());
    }
    if let Some(req_par) = params.require_pushed_authorization_requests {
        client.require_pushed_authorization_requests = req_par;
    }

    store::save_client(&client)
        .await
        .map_err(ApiError::internal)?;

    replicate_client("put", &client.client_id, Some(&client)).await;

    let _ = store::log_audit(
        "client_updated",
        &caller.user_id,
        &client.client_id,
        &client.name,
    )
    .await;

    Ok(client)
}

/// Delete a client. Superadmin only. The built-in `lid-admin` client cannot
/// be deleted.
pub async fn delete_client(caller: &Caller, client_id: &str) -> Result<(), ApiError> {
    caller.require_superadmin()?;

    if client_id == "lid-admin" {
        return Err("cannot delete system admin client".into());
    }

    store::get_client(client_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("client not found"))?;
    store::delete_client(client_id)
        .await
        .map_err(ApiError::internal)?;

    replicate_client("delete", client_id, None).await;

    let _ = store::log_audit("client_deleted", &caller.user_id, client_id, "").await;

    Ok(())
}

/// Rotate a confidential client's secret. Superadmin only. Returns the new
/// raw secret (shown to the caller exactly once).
pub async fn rotate_client_secret(caller: &Caller, client_id: &str) -> Result<String, ApiError> {
    caller.require_superadmin()?;

    let mut client = store::get_client(client_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("client not found"))?;

    if client.token_endpoint_auth_method.as_deref() == Some("none") {
        return Err(
            "This is a public client (token_endpoint_auth_method=none) and cannot hold a secret."
                .into(),
        );
    }

    let raw_secret = store::random_hex(32);
    client.client_secret = Some(store::hmac_client_secret(&raw_secret));
    store::save_client(&client)
        .await
        .map_err(ApiError::internal)?;

    replicate_client("put", &client.client_id, Some(&client)).await;

    let _ = store::log_audit(
        "client_secret_rotated",
        &caller.user_id,
        client_id,
        &client.name,
    )
    .await;

    Ok(raw_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::authz::Caller;

    fn superadmin() -> Caller {
        Caller {
            user_id: "admin-1".to_string(),
            is_superadmin: true,
            tenant_roles: Vec::new(),
        }
    }

    fn non_admin() -> Caller {
        Caller {
            user_id: "user-1".to_string(),
            is_superadmin: false,
            tenant_roles: Vec::new(),
        }
    }

    fn confidential_client(id: &str) -> OidcClient {
        OidcClient {
            client_id: id.to_string(),
            client_secret: Some(store::hmac_client_secret("old-secret")),
            name: "Test".to_string(),
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_rotate_secret_requires_superadmin() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let err = rotate_client_secret(&non_admin(), "whatever")
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::FORBIDDEN);
        });
    }

    #[test]
    fn test_rotate_secret_unknown_client_404() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let err = rotate_client_secret(&superadmin(), "client-does-not-exist")
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn test_rotate_secret_public_client_rejected() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let mut client = confidential_client("rotate-public-test");
            client.client_secret = None;
            client.token_endpoint_auth_method = Some("none".to_string());
            store::save_client(&client).await.unwrap();

            let err = rotate_client_secret(&superadmin(), "rotate-public-test")
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::BAD_REQUEST);
            assert!(err.message.contains("public client"));
        });
    }

    #[test]
    fn test_rotate_secret_lid_admin_rejected() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            // lid-admin is the built-in PUBLIC admin client; the
            // token_endpoint_auth_method == "none" guard must refuse rotation.
            store::ensure_admin_client("https://idp-rotate-test.example.com", false)
                .await
                .unwrap();
            let err = rotate_client_secret(&superadmin(), "lid-admin")
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn test_rotate_secret_confidential_client_succeeds() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            store::save_client(&confidential_client("rotate-ok-test"))
                .await
                .unwrap();
            let raw = rotate_client_secret(&superadmin(), "rotate-ok-test")
                .await
                .unwrap();
            assert_eq!(raw.len(), 64); // random_hex(32)
            let stored = store::get_client("rotate-ok-test").await.unwrap().unwrap();
            assert_eq!(
                stored.client_secret.as_deref(),
                Some(store::hmac_client_secret(&raw).as_str())
            );
        });
    }
}
