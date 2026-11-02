use crate::error::ApiError;
use crate::store::{self, ScimConnection};

use super::authz::Caller;

fn validate_role(role: &str) -> Result<(), ApiError> {
    if !["admin", "manager", "member"].contains(&role) {
        return Err("SCIM default_role must be admin, manager, or member".into());
    }
    Ok(())
}

async fn authorize(caller: &Caller, tenant_id: &str) -> Result<(), ApiError> {
    caller.require_tenant_role(tenant_id, "admin")?;
    store::get_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("tenant not found"))?;
    Ok(())
}

pub async fn create_connection(
    caller: &Caller,
    name: &str,
    tenant_id: &str,
    default_role: &str,
) -> Result<(ScimConnection, String), ApiError> {
    authorize(caller, tenant_id).await?;
    validate_role(default_role)?;
    if name.trim().is_empty() || name.len() > 128 {
        return Err("name is required and must be at most 128 characters".into());
    }
    let raw_token = store::random_hex(32);
    let connection = ScimConnection {
        id: format!("scim_{}", store::random_alphanumeric(12)),
        name: name.to_string(),
        tenant_id: tenant_id.to_string(),
        token_hash: store::sha256_hex(&raw_token),
        enabled: true,
        default_role: default_role.to_string(),
        created_at: store::unix_now(),
    };
    store::save_scim_connection(&connection)
        .await
        .map_err(ApiError::internal)?;
    let json = serde_json::to_value(&connection).unwrap_or_default();
    crate::service_client::replicate_to_regions(
        "put",
        "scim_connection",
        &connection.id,
        Some(&json),
    )
    .await;
    let _ = store::log_audit(
        "scim_connection_created",
        &caller.user_id,
        &connection.id,
        tenant_id,
    )
    .await;
    Ok((connection, raw_token))
}

pub async fn set_enabled(
    caller: &Caller,
    id: &str,
    enabled: bool,
) -> Result<ScimConnection, ApiError> {
    let mut connection = store::get_scim_connection(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("SCIM connection not found"))?;
    authorize(caller, &connection.tenant_id).await?;
    connection.enabled = enabled;
    store::save_scim_connection(&connection)
        .await
        .map_err(ApiError::internal)?;
    let json = serde_json::to_value(&connection).unwrap_or_default();
    crate::service_client::replicate_to_regions(
        "put",
        "scim_connection",
        &connection.id,
        Some(&json),
    )
    .await;
    let _ = store::log_audit("scim_connection_updated", &caller.user_id, id, "").await;
    Ok(connection)
}

pub async fn rotate_token(caller: &Caller, id: &str) -> Result<String, ApiError> {
    let mut connection = store::get_scim_connection(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("SCIM connection not found"))?;
    authorize(caller, &connection.tenant_id).await?;
    let raw_token = store::random_hex(32);
    connection.token_hash = store::sha256_hex(&raw_token);
    store::save_scim_connection(&connection)
        .await
        .map_err(ApiError::internal)?;
    let json = serde_json::to_value(&connection).unwrap_or_default();
    crate::service_client::replicate_to_regions(
        "put",
        "scim_connection",
        &connection.id,
        Some(&json),
    )
    .await;
    let _ = store::log_audit("scim_token_rotated", &caller.user_id, id, "").await;
    Ok(raw_token)
}

pub async fn delete_connection(caller: &Caller, id: &str) -> Result<(), ApiError> {
    let connection = store::get_scim_connection(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("SCIM connection not found"))?;
    authorize(caller, &connection.tenant_id).await?;
    store::delete_scim_connection(id)
        .await
        .map_err(ApiError::internal)?;
    crate::service_client::replicate_to_regions("delete", "scim_connection", id, None).await;
    let _ = store::log_audit("scim_connection_deleted", &caller.user_id, id, "").await;
    Ok(())
}
