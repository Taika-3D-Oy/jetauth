//! Identity provider mutations shared by the management API and the admin panel.

use crate::error::ApiError;
use crate::store::{self, IdentityProvider};

use super::authz::Caller;

/// Provider types with a runtime login flow. Google and GitHub have dedicated
/// handlers; Microsoft and any other standards-compliant provider run through
/// the generic OIDC federation path.
const SUPPORTED_PROVIDER_TYPES: &[&str] = &["google", "github", "microsoft"];

/// Create an identity provider. Superadmin only.
pub async fn create_identity_provider(
    caller: &Caller,
    provider_type: &str,
    client_id: &str,
    client_secret: &str,
    enabled: bool,
) -> Result<IdentityProvider, ApiError> {
    caller.require_superadmin()?;

    if !SUPPORTED_PROVIDER_TYPES.contains(&provider_type) {
        return Err(format!(
            "unsupported provider_type (supported: {})",
            SUPPORTED_PROVIDER_TYPES.join(", ")
        )
        .into());
    }
    if client_id.is_empty() || client_secret.is_empty() {
        return Err("client_id and client_secret are required".into());
    }

    let idp = IdentityProvider {
        id: format!("idp_{}", store::random_alphanumeric(12)),
        provider_type: provider_type.to_string(),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        enabled,
        discovery_url: None,
        display_name: None,
    };
    store::save_identity_provider(&idp)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "identity_provider_created",
        &caller.user_id,
        &idp.id,
        &idp.provider_type,
    )
    .await;

    Ok(idp)
}

/// Partial identity provider update; empty strings leave secrets untouched.
/// `display_name`/`discovery_url`: `Some("")` clears the field.
#[derive(Default)]
pub struct UpdateIdpParams {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub enabled: Option<bool>,
    pub display_name: Option<String>,
    pub discovery_url: Option<String>,
}

/// Update an identity provider. Superadmin only.
pub async fn update_identity_provider(
    caller: &Caller,
    idp_id: &str,
    params: UpdateIdpParams,
) -> Result<IdentityProvider, ApiError> {
    caller.require_superadmin()?;

    let mut idp = store::get_identity_provider(idp_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("identity provider not found"))?;

    if let Some(client_id) = params.client_id
        && !client_id.is_empty()
    {
        idp.client_id = client_id;
    }
    if let Some(client_secret) = params.client_secret
        && !client_secret.is_empty()
    {
        idp.client_secret = client_secret;
    }
    if let Some(enabled) = params.enabled {
        idp.enabled = enabled;
    }
    if let Some(display_name) = params.display_name {
        idp.display_name = if display_name.is_empty() {
            None
        } else {
            Some(display_name)
        };
    }
    if let Some(discovery_url) = params.discovery_url {
        if !discovery_url.is_empty() {
            if !discovery_url.starts_with("https://") {
                return Err("discovery_url must use https scheme".into());
            }
            crate::util::is_safe_external_url(&discovery_url)
                .map_err(|e| format!("invalid discovery_url: {e}"))?;
        }
        idp.discovery_url = if discovery_url.is_empty() {
            None
        } else {
            Some(discovery_url)
        };
    }

    store::save_identity_provider(&idp)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "identity_provider_updated",
        &caller.user_id,
        &idp.id,
        &format!("type={} enabled={}", idp.provider_type, idp.enabled),
    )
    .await;

    Ok(idp)
}

/// Delete an identity provider. Superadmin only.
pub async fn delete_identity_provider(caller: &Caller, idp_id: &str) -> Result<(), ApiError> {
    caller.require_superadmin()?;

    store::get_identity_provider(idp_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("identity provider not found"))?;
    store::delete_identity_provider(idp_id)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit("identity_provider_deleted", &caller.user_id, idp_id, "").await;

    Ok(())
}
