//! Caller context and role-based authorization shared by the management API
//! and the admin panel.

use serde_json::Value;

use crate::error::ApiError;

/// Numeric rank of a tenant role; a higher rank outranks a lower one.
/// Unknown or empty roles rank 0.
pub fn role_level(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "manager" => 2,
        "member" => 1,
        _ => 0,
    }
}

/// Roles that can be assigned when adding an existing user to a tenant.
pub const ASSIGNABLE_ROLES: &[&str] = &["owner", "admin", "manager", "member"];

/// Roles offered when inviting a new member by email. Tenant ownership is
/// never handed out through an invitation.
pub const INVITABLE_ROLES: &[&str] = &["admin", "manager", "member"];

/// An authenticated management-plane caller: the management API builds this
/// from verified JWT claims, the admin panel from the resolved admin session.
#[derive(Clone, Debug)]
pub struct Caller {
    /// The caller's user id (JWT `sub` / session user id).
    pub user_id: String,
    /// Superadmins bypass tenant scoping and count as owner of every tenant.
    pub is_superadmin: bool,
    /// (tenant_id, role) pairs the caller holds. Empty for superadmins.
    pub tenant_roles: Vec<(String, String)>,
}

impl Caller {
    /// Build a caller from verified management-API JWT claims.
    ///
    /// Claim layout: `role` is the global role ("superadmin" or the role on
    /// the `tenant_id` claim tenant); `tenants` is an array of
    /// `{tenant_id, role}` memberships. A direct `tenant_id` claim takes
    /// precedence over the `tenants` array for the same tenant.
    pub fn from_claims(claims: &Value) -> Self {
        let user_id = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let global_role = claims.get("role").and_then(|v| v.as_str()).unwrap_or("");
        let is_superadmin = global_role == "superadmin";

        let mut tenant_roles: Vec<(String, String)> = claims
            .get("tenants")
            .and_then(|v| v.as_array())
            .map(|tenants| {
                tenants
                    .iter()
                    .filter_map(|t| {
                        let id = t.get("tenant_id").and_then(|v| v.as_str())?;
                        let role = t.get("role").and_then(|v| v.as_str())?;
                        Some((id.to_string(), role.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        if !is_superadmin && let Some(tid) = claims.get("tenant_id").and_then(|v| v.as_str()) {
            tenant_roles.retain(|(id, _)| id != tid);
            tenant_roles.push((tid.to_string(), global_role.to_string()));
        }

        Self {
            user_id,
            is_superadmin,
            tenant_roles,
        }
    }

    /// Build a caller from a resolved admin-panel session. Tenant roles are
    /// loaded from the membership store (superadmins need none).
    pub async fn from_admin_session(session: &crate::admin::layout::AdminSession) -> Self {
        let tenant_roles = if session.is_superadmin {
            Vec::new()
        } else {
            crate::store::list_user_tenants(&session.user.id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|m| (m.tenant_id, m.role))
                .collect()
        };
        Self {
            user_id: session.user.id.clone(),
            is_superadmin: session.is_superadmin,
            tenant_roles,
        }
    }

    /// The caller's effective role on a tenant. Superadmins are effectively
    /// owners of every tenant; unknown tenants yield "".
    pub fn tenant_role(&self, tenant_id: &str) -> &str {
        if self.is_superadmin {
            return "owner";
        }
        self.tenant_roles
            .iter()
            .find(|(id, _)| id == tenant_id)
            .map(|(_, role)| role.as_str())
            .unwrap_or("")
    }

    /// Check that the caller is a superadmin.
    pub fn require_superadmin(&self) -> Result<(), ApiError> {
        if self.is_superadmin {
            Ok(())
        } else {
            Err(ApiError::forbidden("forbidden: superadmin role required"))
        }
    }

    /// Check that the caller has at least `min_role` on `tenant_id`.
    pub fn require_tenant_role(&self, tenant_id: &str, min_role: &str) -> Result<(), ApiError> {
        if role_level(self.tenant_role(tenant_id)) >= role_level(min_role) {
            return Ok(());
        }
        Err(ApiError::forbidden(format!(
            "forbidden: requires {min_role} role or higher"
        )))
    }

    /// Check that the caller is the given user, or a superadmin.
    pub fn require_self_or_superadmin(&self, user_id: &str) -> Result<(), ApiError> {
        if self.user_id == user_id || self.is_superadmin {
            return Ok(());
        }
        Err(ApiError::forbidden(
            "forbidden: can only manage your own credentials, or requires superadmin role",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mock_claims(role: &str, tenant_id: Option<&str>) -> Value {
        if let Some(tid) = tenant_id {
            json!({ "sub": "user123", "role": role, "tenant_id": tid })
        } else {
            json!({ "sub": "user123", "role": role })
        }
    }

    fn mock_claims_with_tenants(role: &str, tenants: Vec<(&str, &str)>) -> Value {
        let tenant_objs: Vec<_> = tenants
            .iter()
            .map(|(id, r)| json!({ "tenant_id": id, "role": r }))
            .collect();
        json!({ "sub": "user123", "role": role, "tenants": tenant_objs })
    }

    #[test]
    fn test_role_level_hierarchy() {
        assert!(role_level("owner") > role_level("admin"));
        assert!(role_level("admin") > role_level("manager"));
        assert!(role_level("manager") > role_level("member"));
        assert!(role_level("member") > role_level("guest"));
        assert_eq!(role_level(""), 0);
    }

    #[test]
    fn test_invitable_roles_exclude_owner() {
        assert!(!INVITABLE_ROLES.contains(&"owner"));
        assert!(INVITABLE_ROLES.contains(&"admin"));
        assert!(INVITABLE_ROLES.contains(&"manager"));
        assert!(INVITABLE_ROLES.contains(&"member"));
        // Direct assignment may still grant owner (subject to hierarchy checks).
        assert!(ASSIGNABLE_ROLES.contains(&"owner"));
    }

    #[test]
    fn test_caller_from_claims_superadmin() {
        let caller = Caller::from_claims(&mock_claims("superadmin", None));
        assert!(caller.is_superadmin);
        assert_eq!(caller.tenant_role("any"), "owner");
        assert!(caller.require_superadmin().is_ok());
        assert!(caller.require_tenant_role("any", "owner").is_ok());
    }

    #[test]
    fn test_caller_from_claims_tenant_claim() {
        let caller = Caller::from_claims(&mock_claims("admin", Some("t1")));
        assert!(!caller.is_superadmin);
        assert_eq!(caller.tenant_role("t1"), "admin");
        assert_eq!(caller.tenant_role("t2"), "");
    }

    #[test]
    fn test_caller_from_claims_tenants_array() {
        let caller =
            Caller::from_claims(&mock_claims_with_tenants("member", vec![("t1", "manager")]));
        assert_eq!(caller.tenant_role("t1"), "manager");
        assert_eq!(caller.tenant_role("t2"), "");
        assert!(caller.require_tenant_role("t1", "member").is_ok());
        assert!(caller.require_tenant_role("t1", "admin").is_err());
    }

    #[test]
    fn test_caller_tenant_id_claim_precedence() {
        // A direct tenant_id claim wins over the tenants array for that tenant.
        let claims = json!({
            "sub": "user123",
            "role": "admin",
            "tenant_id": "t1",
            "tenants": [{ "tenant_id": "t1", "role": "member" }],
        });
        let caller = Caller::from_claims(&claims);
        assert_eq!(caller.tenant_role("t1"), "admin");
    }

    #[test]
    fn test_require_self_or_superadmin() {
        use http::StatusCode;
        let member = Caller::from_claims(&mock_claims("member", None));
        assert!(member.require_self_or_superadmin("user123").is_ok());
        let err = member.require_self_or_superadmin("other").unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        let superadmin = Caller::from_claims(&mock_claims("superadmin", None));
        assert!(superadmin.require_self_or_superadmin("other").is_ok());
    }
}
