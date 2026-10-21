//! Tenant and tenant-membership mutations shared by the management API and
//! the admin panel.

use crate::error::ApiError;
use crate::store::{self, Invitation, Membership, Tenant};

use super::authz::{ASSIGNABLE_ROLES, Caller, INVITABLE_ROLES, role_level};

/// Create a tenant. Superadmin only. Replicates to remote regions.
pub async fn create_tenant(
    caller: &Caller,
    name: &str,
    display_name: &str,
) -> Result<Tenant, ApiError> {
    caller.require_superadmin()?;
    let id = format!("tenant_{}", store::random_alphanumeric(12));
    create_tenant_with_id(caller, &id, name, display_name).await
}

/// Create a tenant with a caller-specified ID (admin-panel convenience for
/// pre-agreed tenant IDs). Superadmin only; same validation, audit logging
/// and replication as [`create_tenant`].
pub async fn create_tenant_with_id(
    caller: &Caller,
    id: &str,
    name: &str,
    display_name: &str,
) -> Result<Tenant, ApiError> {
    caller.require_superadmin()?;

    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.len() > 128 {
        return Err("name too long (max 128 characters)".into());
    }
    if display_name.len() > 256 {
        return Err("display_name too long (max 256 characters)".into());
    }

    let tenant = Tenant {
        id: id.to_string(),
        name: name.to_string(),
        display_name: display_name.to_string(),
        status: "active".to_string(),
        created_at: store::unix_now(),
    };
    store::create_tenant(&tenant)
        .await
        .map_err(ApiError::internal)?;

    // Replicate to remote regions (fire-and-forget)
    let tenant_json = serde_json::to_value(&tenant).unwrap_or_default();
    crate::service_client::replicate_to_regions("put", "tenant", &tenant.id, Some(&tenant_json))
        .await;

    let _ = store::log_audit("tenant_created", &caller.user_id, &tenant.id, &tenant.name).await;

    Ok(tenant)
}

/// Partial tenant update; `None` leaves the field unchanged.
#[derive(Default)]
pub struct UpdateTenantParams {
    pub display_name: Option<String>,
    pub status: Option<String>,
}

/// Valid tenant lifecycle states.
const VALID_TENANT_STATUSES: &[&str] = &["active", "suspended"];

/// Update a tenant's display name and/or status. Superadmin only.
/// Replicates to remote regions.
pub async fn update_tenant(
    caller: &Caller,
    tenant_id: &str,
    params: UpdateTenantParams,
) -> Result<Tenant, ApiError> {
    caller.require_superadmin()?;

    let mut tenant = store::get_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("tenant not found"))?;

    if let Some(display_name) = params.display_name {
        if display_name.is_empty() {
            return Err("display_name is required".into());
        }
        if display_name.len() > 256 {
            return Err("display_name too long (max 256 characters)".into());
        }
        tenant.display_name = display_name;
    }
    if let Some(status) = params.status {
        if !VALID_TENANT_STATUSES.contains(&status.as_str()) {
            return Err(format!(
                "invalid status (valid: {})",
                VALID_TENANT_STATUSES.join(", ")
            )
            .into());
        }
        tenant.status = status;
    }

    store::update_tenant(&tenant)
        .await
        .map_err(ApiError::internal)?;

    // Replicate to remote regions (fire-and-forget)
    let tenant_json = serde_json::to_value(&tenant).unwrap_or_default();
    crate::service_client::replicate_to_regions("put", "tenant", &tenant.id, Some(&tenant_json))
        .await;

    let _ = store::log_audit(
        "tenant_updated",
        &caller.user_id,
        &tenant.id,
        &format!(
            "status={} display_name={}",
            tenant.status, tenant.display_name
        ),
    )
    .await;

    Ok(tenant)
}

/// Delete a tenant. Superadmin only. Replicates the deletion to remote regions.
pub async fn delete_tenant(caller: &Caller, tenant_id: &str) -> Result<(), ApiError> {
    caller.require_superadmin()?;

    store::get_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("tenant not found"))?;
    store::delete_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?;

    // Replicate deletion to remote regions (fire-and-forget)
    crate::service_client::replicate_to_regions("delete", "tenant", tenant_id, None).await;

    let _ = store::log_audit("tenant_deleted", &caller.user_id, tenant_id, "").await;

    Ok(())
}

/// Add an existing user to a tenant with the given role.
/// Requires manager or higher on the tenant; the assigned role may not exceed
/// the caller's own role on that tenant.
pub async fn add_member(
    caller: &Caller,
    tenant_id: &str,
    user_id: &str,
    role: &str,
) -> Result<Membership, ApiError> {
    caller.require_tenant_role(tenant_id, "manager")?;

    if !ASSIGNABLE_ROLES.contains(&role) {
        return Err("invalid role (must be owner, admin, manager, or member)".into());
    }

    // Hierarchy check: cannot assign a role higher than your own
    let caller_role = caller.tenant_role(tenant_id);
    if role_level(role) > role_level(caller_role) {
        return Err(ApiError::forbidden(format!(
            "forbidden: cannot assign role {role} which is higher than your role {caller_role}"
        )));
    }

    store::get_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("tenant not found"))?;
    store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;

    if store::get_membership(tenant_id, user_id)
        .await
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::conflict(
            "user is already a member of this tenant",
        ));
    }

    let membership = Membership {
        tenant_id: tenant_id.to_string(),
        user_id: user_id.to_string(),
        role: role.to_string(),
        joined_at: store::unix_now(),
    };
    store::add_membership(&membership)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "user_added_to_tenant",
        &caller.user_id,
        user_id,
        &format!("tenant:{tenant_id} role:{role}"),
    )
    .await;

    Ok(membership)
}

/// Remove a user from a tenant. Requires manager or higher; a caller may not
/// remove a member with an equal or higher role (superadmins and self-removal
/// excepted).
pub async fn remove_member(
    caller: &Caller,
    tenant_id: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    caller.require_tenant_role(tenant_id, "manager")?;

    let membership = store::get_membership(tenant_id, user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("membership not found"))?;

    // Hierarchy check: cannot remove someone with a role higher or equal to
    // yours, unless you are superadmin. You can always remove yourself.
    let caller_role = caller.tenant_role(tenant_id);
    let target_role = membership.role.as_str();
    if caller.user_id != user_id
        && !caller.is_superadmin
        && role_level(target_role) >= role_level(caller_role)
    {
        return Err(ApiError::forbidden(format!(
            "forbidden: cannot remove user with role {target_role} (you are {caller_role})"
        )));
    }

    store::remove_membership(tenant_id, user_id)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "user_removed_from_tenant",
        &caller.user_id,
        user_id,
        &format!("tenant:{tenant_id}"),
    )
    .await;

    Ok(())
}

/// Invite a new member to a tenant by email: creates an invitation token and
/// sends the invitation email. Requires manager or higher; the invited role
/// may not exceed the caller's own role. Ownership is never invitable.
pub async fn invite_user(
    caller: &Caller,
    tenant_id: &str,
    email: &str,
    role: &str,
) -> Result<Invitation, ApiError> {
    caller.require_tenant_role(tenant_id, "manager")?;

    if !INVITABLE_ROLES.contains(&role) {
        return Err("invalid role for invitation".into());
    }

    // Hierarchy check: cannot invite someone to a role higher than your own
    let caller_role = caller.tenant_role(tenant_id);
    if role_level(role) > role_level(caller_role) {
        return Err(ApiError::forbidden(format!(
            "forbidden: cannot invite to role {role} which is higher than your role {caller_role}"
        )));
    }

    let tenant = store::get_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("tenant not found"))?;

    let invitation = Invitation {
        tenant_id: tenant_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        token: store::random_hex(32),
        invited_by: caller.user_id.clone(),
        expires_at: store::unix_now() + 86400 * 7, // 7 days
    };
    store::save_invitation(&invitation)
        .await
        .map_err(ApiError::internal)?;

    crate::email::send_invitation_email(
        &crate::get_issuer(),
        email,
        &invitation.token,
        &tenant.display_name,
        role,
    )
    .await;

    Ok(invitation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superadmin() -> Caller {
        Caller {
            user_id: "admin-1".to_string(),
            is_superadmin: true,
            tenant_roles: Vec::new(),
        }
    }

    #[test]
    fn test_update_tenant_happy_path_and_validation() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let caller = superadmin();
            let tenant = create_tenant_with_id(&caller, "tenant-ut-1", "acme", "Acme")
                .await
                .unwrap();
            assert_eq!(tenant.status, "active");

            let updated = update_tenant(
                &caller,
                "tenant-ut-1",
                UpdateTenantParams {
                    display_name: Some("Acme Corp".to_string()),
                    status: Some("suspended".to_string()),
                },
            )
            .await
            .unwrap();
            assert_eq!(updated.display_name, "Acme Corp");
            assert_eq!(updated.status, "suspended");

            let stored = store::get_tenant("tenant-ut-1").await.unwrap().unwrap();
            assert_eq!(stored.display_name, "Acme Corp");
            assert_eq!(stored.status, "suspended");

            // Invalid status rejected
            let err = update_tenant(
                &caller,
                "tenant-ut-1",
                UpdateTenantParams {
                    status: Some("deleted".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
            assert_eq!(err.status, http::StatusCode::BAD_REQUEST);

            // Unknown tenant → 404
            let err = update_tenant(&caller, "tenant-missing", UpdateTenantParams::default())
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn test_update_tenant_requires_superadmin() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let caller = Caller {
                user_id: "user-1".to_string(),
                is_superadmin: false,
                tenant_roles: vec![("t".to_string(), "owner".to_string())],
            };
            let err = update_tenant(&caller, "t", UpdateTenantParams::default())
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::FORBIDDEN);
        });
    }

    #[test]
    fn test_invite_rejects_owner_role() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            // Even a superadmin cannot invite someone as owner.
            let err = match invite_user(&superadmin(), "t", "x@example.com", "owner").await {
                Ok(_) => panic!("owner invite must be rejected"),
                Err(e) => e,
            };
            assert_eq!(err.status, http::StatusCode::BAD_REQUEST);
        });
    }
}
