use base64::Engine;
use http::{Response, StatusCode};
use serde_json::Value;

use crate::store::{self, IdentityProvider, Invitation, Membership, Tenant};

// ── Auth helpers ────────────────────────────────────────────

/// Extract and verify Bearer token, returning JWT claims.
pub(crate) async fn require_auth(auth_header: Option<&str>) -> Result<Value, String> {
    let header = auth_header.ok_or("missing Authorization header")?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or("invalid Authorization header")?;
    crate::service_client::verify_token_scoped(
        token,
        Some(&crate::get_issuer()),
        Some("lid-admin"),
        Some("access"),
    )
    .await
}

/// Check that claims have the "superadmin" role (no tenant scope).
pub(crate) fn require_superadmin(claims: &Value) -> Result<(), String> {
    let role = claims.get("role").and_then(|v| v.as_str()).unwrap_or("");
    if role == "superadmin" {
        Ok(())
    } else {
        Err("forbidden: superadmin role required".into())
    }
}

/// Check that the caller has at least the given role for a specific tenant.
fn require_tenant_role(claims: &Value, tenant_id: &str, min_role: &str) -> Result<(), String> {
    if claim_has_tenant_role(claims, tenant_id, min_role) {
        return Ok(());
    }
    Err(format!("forbidden: requires {min_role} role or higher"))
}

pub(crate) fn claim_has_tenant_role(claims: &Value, tenant_id: &str, min_role: &str) -> bool {
    let caller_role = get_caller_tenant_role(claims, tenant_id);
    role_level(caller_role) >= role_level(min_role)
}

pub(crate) fn role_level(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "manager" => 2,
        "member" => 1,
        _ => 0,
    }
}

pub(crate) fn get_caller_tenant_role<'a>(claims: &'a Value, tenant_id: &str) -> &'a str {
    let global_role = claims.get("role").and_then(|v| v.as_str()).unwrap_or("");
    if global_role == "superadmin" {
        return "owner"; // effectively
    }

    if claims
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .is_some_and(|claim_tenant| claim_tenant == tenant_id)
    {
        return global_role;
    }

    claims
        .get("tenants")
        .and_then(|v| v.as_array())
        .and_then(|tenants| {
            tenants
                .iter()
                .find(|tenant| tenant.get("tenant_id").and_then(|v| v.as_str()) == Some(tenant_id))
        })
        .and_then(|t| t.get("role").and_then(|v| v.as_str()))
        .unwrap_or("")
}

// ── Tenant endpoints ────────────────────────────────────────

/// GET /api/tenants
pub async fn list_tenants(auth: Option<&str>) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let tenants = store::list_tenants().await?;
    let list: Vec<Value> = tenants
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "display_name": t.display_name,
                "status": t.status,
                "created_at": t.created_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// GET /api/audit?actor_id=...&target_id=...&event_type=...&since=...&until=...&limit=...
pub async fn list_audit_events(
    auth: Option<&str>,
    query: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let params = crate::util::parse_query(query);
    let get = |key: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    let actor_id = get("actor_id").filter(|value| !value.is_empty());
    let target_id = get("target_id").filter(|value| !value.is_empty());
    let event_type = get("event_type").filter(|value| !value.is_empty());
    let since = match get("since") {
        Some(value) => Some(value.parse::<u64>().map_err(|_| "invalid since")?),
        None => None,
    };
    let until = match get("until") {
        Some(value) => Some(value.parse::<u64>().map_err(|_| "invalid until")?),
        None => None,
    };
    if let (Some(lower), Some(upper)) = (since, until)
        && lower > upper
    {
        return Err("invalid time range: since must be <= until".into());
    }

    let requested_limit = match get("limit") {
        Some(value) => value.parse::<usize>().map_err(|_| "invalid limit")?,
        None => 100,
    };
    if requested_limit == 0 {
        return Err("limit must be at least 1".into());
    }
    let limit = requested_limit.min(500);

    let events =
        store::list_audit_events(actor_id, target_id, event_type, since, until, limit).await?;
    let body = serde_json::json!({
        "events": events,
        "filters": {
            "actor_id": actor_id,
            "target_id": target_id,
            "event_type": event_type,
            "since": since,
            "until": until,
            "limit": limit,
        }
    });
    json_ok(&body)
}

/// POST /api/tenants
pub async fn create_tenant(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        display_name: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if req.name.is_empty() {
        return Err("name is required".into());
    }
    if req.name.len() > 128 {
        return Err("name too long (max 128 characters)".into());
    }
    if req.display_name.len() > 256 {
        return Err("display_name too long (max 256 characters)".into());
    }

    let tenant = Tenant {
        id: store::random_hex(16),
        name: req.name,
        display_name: req.display_name,
        status: "active".to_string(),
        created_at: store::unix_now(),
    };
    store::create_tenant(&tenant).await?;

    // Replicate to remote regions (fire-and-forget)
    let tenant_json = serde_json::to_value(&tenant).unwrap_or_default();
    crate::service_client::replicate_to_regions("put", "tenant", &tenant.id, Some(&tenant_json))
        .await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("tenant_created", sub, &tenant.id, &tenant.name).await;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": tenant.id,
            "name": tenant.name,
            "display_name": tenant.display_name,
            "status": tenant.status,
        }),
    )
}

/// GET /api/tenants/:id
pub async fn get_tenant(auth: Option<&str>, tenant_id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let tenant = store::get_tenant(tenant_id)
        .await?
        .ok_or("tenant not found")?;
    json_ok(&serde_json::json!({
        "id": tenant.id,
        "name": tenant.name,
        "display_name": tenant.display_name,
        "status": tenant.status,
        "created_at": tenant.created_at,
    }))
}

/// DELETE /api/tenants/:id
pub async fn delete_tenant(
    auth: Option<&str>,
    tenant_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    store::get_tenant(tenant_id)
        .await?
        .ok_or("tenant not found")?;
    store::delete_tenant(tenant_id).await?;

    // Replicate deletion to remote regions (fire-and-forget)
    crate::service_client::replicate_to_regions("delete", "tenant", tenant_id, None).await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("tenant_deleted", sub, tenant_id, "").await;

    json_ok(&serde_json::json!({"deleted": true}))
}

// ── Tenant user/membership endpoints ────────────────────────

/// GET /api/tenants/:id/users
pub async fn list_tenant_users(
    auth: Option<&str>,
    tenant_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    let members = store::list_tenant_members(tenant_id).await?;
    let mut users = Vec::new();
    for m in &members {
        if let Some(user) = store::get_user(&m.user_id).await? {
            users.push(serde_json::json!({
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": m.role,
                "joined_at": m.joined_at,
            }));
        }
    }

    json_ok(&serde_json::json!(users))
}

/// POST /api/tenants/:id/users — add existing user to tenant
pub async fn add_tenant_user(
    auth: Option<&str>,
    tenant_id: &str,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    #[derive(serde::Deserialize)]
    struct Req {
        user_id: String,
        role: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !["owner", "admin", "manager", "member"].contains(&req.role.as_str()) {
        return Err("invalid role (must be owner, admin, manager, or member)".into());
    }

    // Hierarchy check: cannot assign a role higher than your own
    let caller_role = get_caller_tenant_role(&claims, tenant_id);
    if role_level(&req.role) > role_level(caller_role) {
        return Err(format!(
            "forbidden: cannot assign role {} which is higher than your role {}",
            req.role, caller_role
        ));
    }

    store::get_tenant(tenant_id)
        .await?
        .ok_or("tenant not found")?;
    store::get_user(&req.user_id)
        .await?
        .ok_or("user not found")?;

    if store::get_membership(tenant_id, &req.user_id)
        .await?
        .is_some()
    {
        return Err("user is already a member of this tenant".into());
    }

    let membership = Membership {
        tenant_id: tenant_id.to_string(),
        user_id: req.user_id.clone(),
        role: req.role.clone(),
        joined_at: store::unix_now(),
    };
    store::add_membership(&membership).await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "user_added_to_tenant",
        sub,
        &req.user_id,
        &format!("tenant:{tenant_id} role:{}", req.role),
    )
    .await;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "tenant_id": tenant_id,
            "user_id": req.user_id,
            "role": req.role,
        }),
    )
}

/// DELETE /api/tenants/:tid/users/:uid
pub async fn remove_tenant_user(
    auth: Option<&str>,
    tenant_id: &str,
    user_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    let membership = store::get_membership(tenant_id, user_id)
        .await?
        .ok_or("membership not found")?;

    // Hierarchy check: cannot remove someone with a role higher or equal to yours,
    // unless you are superadmin.
    let caller_role = get_caller_tenant_role(&claims, tenant_id);
    let target_role = membership.role.as_str();

    // Special case: can always remove yourself.
    let caller_sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if caller_sub != user_id
        && claims.get("role").and_then(|v| v.as_str()) != Some("superadmin")
        && role_level(target_role) >= role_level(caller_role)
    {
        return Err(format!(
            "forbidden: cannot remove user with role {} (you are {})",
            target_role, caller_role
        ));
    }

    store::remove_membership(tenant_id, user_id).await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "user_removed_from_tenant",
        sub,
        user_id,
        &format!("tenant:{tenant_id}"),
    )
    .await;

    json_ok(&serde_json::json!({"removed": true}))
}

/// POST /api/tenants/:id/users/invite
pub async fn invite_user(
    auth: Option<&str>,
    tenant_id: &str,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    #[derive(serde::Deserialize)]
    struct Req {
        email: String,
        role: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !["admin", "manager", "member"].contains(&req.role.as_str()) {
        return Err("invalid role for invitation".into());
    }

    // Hierarchy check: cannot invite someone to a role higher than your own
    let caller_role = get_caller_tenant_role(&claims, tenant_id);
    if role_level(&req.role) > role_level(caller_role) {
        return Err(format!(
            "forbidden: cannot invite to role {} which is higher than your role {}",
            req.role, caller_role
        ));
    }

    store::get_tenant(tenant_id)
        .await?
        .ok_or("tenant not found")?;

    let inviter_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let invitation = Invitation {
        tenant_id: tenant_id.to_string(),
        email: req.email.clone(),
        role: req.role.clone(),
        token: store::random_hex(32),
        invited_by: inviter_id.to_string(),
        expires_at: store::unix_now() + 86400 * 7, // 7 days
    };
    store::save_invitation(&invitation).await?;

    // Publish invitation email event
    let tenant_display = crate::store::get_tenant(tenant_id)
        .await
        .ok()
        .flatten()
        .map(|t| t.display_name)
        .unwrap_or_else(|| tenant_id.to_string());
    crate::email::send_invitation_email(
        &crate::get_issuer(),
        &req.email,
        &invitation.token,
        &tenant_display,
        &req.role,
    )
    .await;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "email": req.email,
            "role": req.role,
            "invite_token": invitation.token,
            "expires_at": invitation.expires_at,
        }),
    )
}

/// POST /api/invitations/accept — accept an invitation token
pub async fn accept_invitation(body: &[u8]) -> Result<Response<String>, String> {
    #[derive(serde::Deserialize)]
    struct Req {
        token: String,
        user_id: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let inv = store::get_invitation(&req.token)
        .await?
        .ok_or("invalid or expired invitation")?;

    if store::unix_now() > inv.expires_at {
        store::delete_invitation(&req.token).await?;
        return Err("invitation expired".into());
    }

    // Verify user exists and email matches
    let user = store::get_user(&req.user_id)
        .await?
        .ok_or("user not found")?;
    if user.email.to_lowercase() != inv.email.to_lowercase() {
        return Err("email does not match invitation".into());
    }

    // Create membership
    let membership = Membership {
        tenant_id: inv.tenant_id.clone(),
        user_id: req.user_id.clone(),
        role: inv.role.clone(),
        joined_at: store::unix_now(),
    };
    store::add_membership(&membership).await?;
    store::delete_invitation(&req.token).await?;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "tenant_id": inv.tenant_id,
            "user_id": req.user_id,
            "role": inv.role,
        }),
    )
}

// ── Client endpoints ────────────────────────────────────────

/// GET /api/clients
pub async fn list_clients(auth: Option<&str>) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let clients = store::list_clients().await?;
    let list: Vec<Value> = clients
        .iter()
        .map(|c| {
            serde_json::json!({
                "client_id": c.client_id,
                "name": c.name,
                "redirect_uris": c.redirect_uris,
                "grant_types": c.grant_types,
                "theme": c.theme,
                "first_party": c.first_party,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// POST /api/clients
pub async fn create_client(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        redirect_uris: Vec<String>,
        #[serde(default)]
        post_logout_redirect_uris: Option<Vec<String>>,
        grant_types: Option<Vec<String>>,
        #[serde(default)]
        confidential: bool,
        #[serde(default)]
        theme: Option<store::ClientTheme>,
        #[serde(default)]
        backchannel_logout_uri: Option<String>,
        #[serde(default)]
        backchannel_logout_session_required: bool,
        /// "RS256" (default) or "ES256".
        #[serde(default)]
        id_token_signed_response_alg: Option<String>,
        /// Skip consent screen for this client (first-party / trusted app).
        #[serde(default)]
        first_party: bool,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if req.name.is_empty() {
        return Err("name is required".into());
    }
    if req.redirect_uris.is_empty() {
        return Err("at least one redirect_uri is required".into());
    }
    // Validate redirect URI schemes
    for uri in &req.redirect_uris {
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            return Err("redirect_uris must use http or https scheme".into());
        }
    }
    let post_logout_uris = req.post_logout_redirect_uris.unwrap_or_default();
    for uri in &post_logout_uris {
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            return Err("post_logout_redirect_uris must use http or https scheme".into());
        }
    }

    let client_secret = if req.confidential {
        let raw = store::random_hex(32);
        // Store an HMAC of the secret, not the raw value.
        // The raw secret is returned to the caller once at creation time.
        let hashed = store::hmac_client_secret(&raw);
        Some((raw, hashed))
    } else {
        None
    };

    let client = store::OidcClient {
        client_id: store::random_hex(16),
        client_secret: client_secret.as_ref().map(|(_, h)| h.clone()),
        name: req.name,
        redirect_uris: req.redirect_uris,
        post_logout_redirect_uris: post_logout_uris,
        grant_types: req.grant_types.unwrap_or_else(|| {
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ]
        }),
        theme: req.theme,
        backchannel_logout_uri: req.backchannel_logout_uri,
        backchannel_logout_session_required: req.backchannel_logout_session_required,
        id_token_signed_response_alg: match req.id_token_signed_response_alg.as_deref() {
            Some("RS256") | None => None,
            Some("ES256") => Some("ES256".to_string()),
            Some(other) => {
                return Err(format!("unsupported id_token_signed_response_alg: {other}"));
            }
        },
        first_party: req.first_party,
    };
    store::save_client(&client).await?;

    // Replicate to remote regions (fire-and-forget, secret stripped)
    let mut client_for_sync = serde_json::to_value(&client).unwrap_or_default();
    if let Some(obj) = client_for_sync.as_object_mut() {
        obj.remove("client_secret");
    }
    crate::service_client::replicate_to_regions(
        "put",
        "client",
        &client.client_id,
        Some(&client_for_sync),
    )
    .await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("client_created", sub, &client.client_id, &client.name).await;

    let mut resp = serde_json::json!({
        "client_id": client.client_id,
        "name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.grant_types,
        "theme": client.theme,
        "first_party": client.first_party,
    });
    // Only show raw secret once at creation time
    if let Some((raw_secret, _)) = client_secret {
        resp["client_secret"] = serde_json::json!(raw_secret);
    }

    json_response(StatusCode::CREATED, &resp)
}

/// GET /api/clients/:id
pub async fn get_client(auth: Option<&str>, id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let client = store::get_client(id).await?.ok_or("client not found")?;
    let mut v = serde_json::to_value(&client).map_err(|e| e.to_string())?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("client_secret");
    }
    json_ok(&v)
}

/// DELETE /api/clients/:id
pub async fn delete_client(auth: Option<&str>, id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    if id == "lid-admin" {
        return Err("cannot delete system admin client".into());
    }

    let _ = store::get_client(id).await?.ok_or("client not found")?;
    store::delete_client(id).await?;

    crate::service_client::replicate_to_regions("delete", "client", id, None).await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("client_deleted", sub, id, "").await;

    json_ok(&serde_json::json!({ "deleted": true, "client_id": id }))
}

/// PUT /api/clients/:id
pub async fn update_client(
    auth: Option<&str>,
    id: &str,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let mut client = store::get_client(id).await?.ok_or("client not found")?;

    #[derive(serde::Deserialize)]
    struct Req {
        redirect_uris: Option<Vec<String>>,
        post_logout_redirect_uris: Option<Vec<String>>,
        name: Option<String>,
        grant_types: Option<Vec<String>>,
        theme: Option<Option<store::ClientTheme>>,
        first_party: Option<bool>,
        backchannel_logout_uri: Option<String>,
        backchannel_logout_session_required: Option<bool>,
        id_token_signed_response_alg: Option<String>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if let Some(uris) = req.redirect_uris {
        if uris.is_empty() {
            return Err("at least one redirect_uri is required".into());
        }
        for uri in &uris {
            if !uri.starts_with("http://") && !uri.starts_with("https://") {
                return Err("redirect_uris must use http or https scheme".into());
            }
        }
        client.redirect_uris = uris;
    }
    if let Some(uris) = req.post_logout_redirect_uris {
        for uri in &uris {
            if !uri.starts_with("http://") && !uri.starts_with("https://") {
                return Err("post_logout_redirect_uris must use http or https scheme".into());
            }
        }
        client.post_logout_redirect_uris = uris;
    }
    if let Some(name) = req.name {
        if name.is_empty() {
            return Err("name is required".into());
        }
        client.name = name;
    }
    if let Some(grant_types) = req.grant_types {
        client.grant_types = grant_types;
    }
    if let Some(theme_opt) = req.theme {
        client.theme = theme_opt;
    }
    if let Some(fp) = req.first_party {
        client.first_party = fp;
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
            other => return Err(format!("unsupported id_token_signed_response_alg: {other}")),
        };
    }

    store::save_client(&client).await?;

    let mut client_for_sync = serde_json::to_value(&client).unwrap_or_default();
    if let Some(obj) = client_for_sync.as_object_mut() {
        obj.remove("client_secret");
    }
    crate::service_client::replicate_to_regions("put", "client", id, Some(&client_for_sync)).await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("client_updated", sub, &client.client_id, &client.name).await;

    json_ok(&serde_json::json!({
        "client_id": client.client_id,
        "name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.grant_types,
        "theme": client.theme,
        "first_party": client.first_party,
    }))
}

// ── Password reset initiation ───────────────────────────────

/// POST /api/users/:id/password-reset
pub async fn initiate_password_reset(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    // Rate limit password reset initiation: 3 per hour per user_id
    match crate::service_client::check_rate(&format!("reset_init:{}", user_id), 3, 3600).await {
        Ok((false, _)) => return Err("too many reset requests. please try again later.".into()),
        Err(e) => crate::logger::error_message("rate_limit.password_reset_init_check_failed", e),
        _ => {}
    }

    let user = store::get_user(user_id).await?.ok_or("user not found")?;

    let reset_token = store::random_hex(32);
    // Store as a short-lived invitation-like entry
    let inv = Invitation {
        tenant_id: String::new(),
        email: user.email.clone(),
        role: "password_reset".to_string(),
        token: reset_token.clone(),
        invited_by: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("system")
            .to_string(),
        expires_at: store::unix_now() + 3600, // 1 hour
    };
    store::save_invitation(&inv).await?;

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("system")
        .to_string();
    let _ = store::log_audit("password_reset_initiated", &sub, user_id, &user.email).await;

    // Publish password reset email event
    crate::email::send_password_reset_email(
        &crate::get_issuer(),
        &user.email,
        &user.name,
        &reset_token,
    )
    .await;

    json_ok(&serde_json::json!({
        "user_id": user_id,
        "email": user.email,
        "expires_in": 3600,
        "message": "Password reset email sent",
    }))
}

// ── Settings management ─────────────────────────────────────

/// GET /api/settings — read current runtime settings (superadmin only)
pub async fn get_settings(auth: Option<&str>) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let settings = store::get_runtime_settings().await;
    json_ok(&serde_json::json!({
        "allow_registration": settings.allow_registration,
    }))
}

/// PUT /api/settings — update runtime settings (superadmin only)
pub async fn update_settings(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        #[serde(default)]
        allow_registration: Option<bool>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let mut settings = store::get_runtime_settings().await;

    if let Some(v) = req.allow_registration {
        settings.allow_registration = v;
    }

    store::save_runtime_settings(&settings).await?;

    let actor = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let _ = store::log_audit(
        "settings_updated",
        actor,
        "settings:global",
        &serde_json::to_string(&serde_json::json!({
            "allow_registration": settings.allow_registration,
        }))
        .unwrap_or_default(),
    )
    .await;

    json_ok(&serde_json::json!({
        "allow_registration": settings.allow_registration,
    }))
}

// ── Response helpers ────────────────────────────────────────

fn json_ok(value: &Value) -> Result<Response<String>, String> {
    json_response(StatusCode::OK, value)
}

fn json_response(status: StatusCode, value: &Value) -> Result<Response<String>, String> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(value).unwrap_or_default())
        .unwrap())
}

// ── MFA management ──────────────────────────────────────────

/// POST /api/users/:id/mfa/setup — generate TOTP secret and return QR URI.
pub async fn mfa_setup(auth: Option<&str>, user_id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    if user.totp_enabled {
        return Err("MFA is already enabled".into());
    }

    let secret = crate::totp::generate_secret();
    let issuer = crate::get_issuer();
    let otpauth_uri = crate::totp::otpauth_uri(&secret, &user.email, &issuer);

    // Store secret but don't enable yet (requires confirm step)
    store::update_user_rmw(user_id, |u| {
        u.totp_secret = Some(secret.clone());
        Ok(true)
    })
    .await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("mfa_setup_started", sub, user_id, "").await;

    json_ok(&serde_json::json!({
        "secret": secret,
        "otpauth_uri": otpauth_uri,
    }))
}

/// POST /api/users/:id/mfa/confirm — verify TOTP code and enable MFA.
pub async fn mfa_confirm(
    auth: Option<&str>,
    user_id: &str,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    #[derive(serde::Deserialize)]
    struct Req {
        code: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    let secret = user
        .totp_secret
        .as_deref()
        .ok_or("MFA setup not started — call /mfa/setup first")?;

    if !crate::totp::verify_totp(secret, req.code.trim()) {
        return Err("invalid TOTP code".into());
    }

    // Enable MFA and generate recovery codes
    let recovery_codes = crate::totp::generate_recovery_codes();
    store::update_user_rmw(user_id, |u| {
        u.totp_enabled = true;
        u.recovery_codes = recovery_codes.clone();
        Ok(true)
    })
    .await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("mfa_enabled", sub, user_id, "").await;

    json_ok(&serde_json::json!({
        "enabled": true,
        "recovery_codes": recovery_codes,
    }))
}

/// DELETE /api/users/:id/mfa — disable MFA for a user.
pub async fn mfa_disable(auth: Option<&str>, user_id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let _user = store::get_user(user_id).await?.ok_or("user not found")?;
    store::update_user_rmw(user_id, |u| {
        u.totp_secret = None;
        u.totp_enabled = false;
        u.recovery_codes.clear();
        Ok(true)
    })
    .await?;

    // Task 2.12: Revoke all sessions/tokens on MFA disable
    let _ = store::delete_user_refresh_tokens(user_id).await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("mfa_disabled", sub, user_id, "tokens revoked").await;

    json_ok(&serde_json::json!({"disabled": true}))
}

/// Check that the caller is the user themselves, or has superadmin role.
/// For security-critical global account operations, we don't allow tenant admins
/// to act on users unless they are superadmin.
fn require_self_or_superadmin(claims: &Value, user_id: &str) -> Result<(), String> {
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub == user_id {
        return Ok(());
    }
    if claims.get("role").and_then(|v| v.as_str()) == Some("superadmin") {
        return Ok(());
    }
    Err("forbidden: can only manage your own credentials, or requires superadmin role".into())
}

/// GET /api/users/:id/export — GDPR Art. 15/20 data portability.
/// Returns all first-party data for the user as JSON.
/// Accessible by the user themselves or a superadmin.
pub async fn export_user_data(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    let memberships = store::list_user_tenants(user_id).await.unwrap_or_default();

    let consents = store::list_user_consents(user_id).await.unwrap_or_default();

    // Strip sensitive credential material before export
    let export = serde_json::json!({
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "status": user.status,
        "created_at": user.created_at,
        "superadmin": user.superadmin,
        "totp_enabled": user.totp_enabled,
        "passkey_count": user.passkey_credentials.len(),
        "memberships": memberships.iter().map(|m| serde_json::json!({
            "tenant_id": m.tenant_id,
            "role": m.role,
        })).collect::<Vec<_>>(),
        "consents": consents.iter().map(|c| serde_json::json!({
            "client_id": c.client_id,
            "scopes": c.scopes,
            "granted_at": c.granted_at,
            "updated_at": c.updated_at,
        })).collect::<Vec<_>>(),
    });

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("user_data_exported", sub, user_id, "gdpr_export").await;

    json_response(StatusCode::OK, &export)
}

/// DELETE /api/users/:id — GDPR Art. 17 right to erasure.
/// Permanently deletes the user and all associated first-party data.
/// Accessible by the user themselves or a superadmin.
/// A superadmin cannot delete themselves this way (use the deactivation path).
pub async fn delete_user(auth: Option<&str>, user_id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");

    // Prevent superadmin self-deletion through the API to avoid accidental lockout
    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    if user.superadmin && sub == user_id {
        return Err("superadmin cannot delete their own account; transfer superadmin first".into());
    }

    // Revoke all active sessions and refresh tokens
    let _ = store::delete_user_refresh_tokens(user_id).await;
    let _ = store::revoke_user_sessions(user_id).await;

    // Perform deletion (users record + email index + memberships)
    store::delete_user(user_id).await?;

    let _ = store::log_audit("user_deleted", sub, user_id, "gdpr_erasure").await;

    json_response(
        StatusCode::OK,
        &serde_json::json!({"deleted": true, "id": user_id}),
    )
}

/// Check that the caller is the user themselves, or has admin/superadmin role.
#[allow(dead_code)]
async fn require_self_or_admin(claims: &Value, user_id: &str) -> Result<(), String> {
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub == user_id {
        return Ok(());
    }
    if has_admin_scope_over_user(claims, user_id).await? {
        return Ok(());
    }
    Err("forbidden: can only manage your own MFA, or requires admin role".into())
}

#[allow(dead_code)]
async fn has_admin_scope_over_user(claims: &Value, user_id: &str) -> Result<bool, String> {
    if claims.get("role").and_then(|v| v.as_str()) == Some("superadmin") {
        return Ok(true);
    }

    let memberships = store::list_user_tenants(user_id).await?;
    Ok(memberships
        .iter()
        .any(|membership| claim_has_tenant_role(claims, &membership.tenant_id, "admin")))
}

// ── Identity provider management ────────────────────────────

/// GET /api/identity-providers
pub async fn list_identity_providers(auth: Option<&str>) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let providers = store::list_identity_providers().await?;
    let list: Vec<Value> = providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "provider_type": p.provider_type,
                "client_id": p.client_id,
                "enabled": p.enabled,
                // Do not expose client_secret in list
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// POST /api/identity-providers
pub async fn create_identity_provider(
    auth: Option<&str>,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        provider_type: String,
        client_id: String,
        client_secret: String,
        #[serde(default = "default_true")]
        enabled: bool,
    }
    fn default_true() -> bool {
        true
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !["google", "github"].contains(&req.provider_type.as_str()) {
        return Err("unsupported provider_type (supported: google, github)".into());
    }
    if req.client_id.is_empty() || req.client_secret.is_empty() {
        return Err("client_id and client_secret are required".into());
    }

    let idp = IdentityProvider {
        id: store::random_hex(16),
        provider_type: req.provider_type,
        client_id: req.client_id,
        client_secret: req.client_secret,
        enabled: req.enabled,
        discovery_url: None,
        display_name: None,
    };
    store::save_identity_provider(&idp).await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "identity_provider_created",
        sub,
        &idp.id,
        &idp.provider_type,
    )
    .await;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": idp.id,
            "provider_type": idp.provider_type,
            "client_id": idp.client_id,
            "enabled": idp.enabled,
        }),
    )
}

/// DELETE /api/identity-providers/:id
pub async fn delete_identity_provider(
    auth: Option<&str>,
    id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    store::get_identity_provider(id)
        .await?
        .ok_or("identity provider not found")?;
    store::delete_identity_provider(id).await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("identity_provider_deleted", sub, id, "").await;

    json_ok(&serde_json::json!({"deleted": true}))
}

// ── Hook management (Rhai scripting) ────────────────────────

const VALID_TRIGGERS: &[&str] = &["post-login", "post-registration"];

/// GET /api/hooks — list all hooks (superadmin).
pub async fn list_hooks(auth: Option<&str>) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let hooks = store::list_hooks().await?;
    let list: Vec<Value> = hooks
        .iter()
        .map(|h| {
            serde_json::json!({
                "id": h.id,
                "name": h.name,
                "trigger": h.trigger,
                "script": h.script,
                "enabled": h.enabled,
                "priority": h.priority,
                "version": h.version,
                "script_hash": h.script_hash,
                "created_at": h.created_at,
                "updated_by": h.updated_by,
                "updated_at": h.updated_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// POST /api/hooks — create a new hook (superadmin).
pub async fn create_hook(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        trigger: String,
        script: String,
        #[serde(default = "hooks_default_true")]
        enabled: bool,
        #[serde(default)]
        priority: i32,
    }
    fn hooks_default_true() -> bool {
        true
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if req.name.is_empty() || req.name.len() > 128 {
        return Err("name must be 1-128 characters".into());
    }
    if !VALID_TRIGGERS.contains(&req.trigger.as_str()) {
        return Err(format!(
            "invalid trigger (valid: {})",
            VALID_TRIGGERS.join(", ")
        ));
    }
    if req.script.is_empty() || req.script.len() > 65536 {
        return Err("script must be 1-65536 characters".into());
    }

    // Validate script compiles
    if let Err(e) = crate::hooks::test_hook(&req.script, &req.trigger) {
        return Err(format!("script validation failed: {e}"));
    }

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let script_hash = store::sha256_hex(&req.script);
    let now = store::unix_now();

    let hook = store::Hook {
        id: store::random_hex(16),
        name: req.name,
        trigger: req.trigger,
        script: req.script,
        enabled: req.enabled,
        priority: req.priority,
        created_at: now,
        version: 1,
        script_hash: script_hash.clone(),
        updated_by: sub.to_string(),
        updated_at: now,
    };
    store::save_hook(&hook).await?;

    // Save immutable version snapshot
    let ver = store::HookVersion {
        hook_id: hook.id.clone(),
        version: 1,
        name: hook.name.clone(),
        trigger: hook.trigger.clone(),
        script: hook.script.clone(),
        script_hash: script_hash.clone(),
        enabled: hook.enabled,
        priority: hook.priority,
        changed_by: sub.to_string(),
        changed_at: now,
    };
    let _ = store::save_hook_version(&ver).await;

    let _ = store::log_audit(
        "hook_created",
        sub,
        &hook.id,
        &format!("name={} hash={} v={}", hook.name, script_hash, 1),
    )
    .await;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": hook.id,
            "name": hook.name,
            "trigger": hook.trigger,
            "enabled": hook.enabled,
            "priority": hook.priority,
            "version": hook.version,
            "script_hash": hook.script_hash,
        }),
    )
}

/// PUT /api/hooks/:id — update an existing hook (superadmin).
pub async fn update_hook(
    auth: Option<&str>,
    id: &str,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let mut hook = store::get_hook(id).await?.ok_or("hook not found")?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: Option<String>,
        trigger: Option<String>,
        script: Option<String>,
        enabled: Option<bool>,
        priority: Option<i32>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if let Some(name) = req.name {
        if name.is_empty() || name.len() > 128 {
            return Err("name must be 1-128 characters".into());
        }
        hook.name = name;
    }
    if let Some(trigger) = req.trigger {
        if !VALID_TRIGGERS.contains(&trigger.as_str()) {
            return Err(format!(
                "invalid trigger (valid: {})",
                VALID_TRIGGERS.join(", ")
            ));
        }
        hook.trigger = trigger;
    }
    if let Some(script) = req.script {
        if script.is_empty() || script.len() > 65536 {
            return Err("script must be 1-65536 characters".into());
        }
        if let Err(e) = crate::hooks::test_hook(&script, &hook.trigger) {
            return Err(format!("script validation failed: {e}"));
        }
        hook.script = script;
    }
    if let Some(enabled) = req.enabled {
        hook.enabled = enabled;
    }
    if let Some(priority) = req.priority {
        hook.priority = priority;
    }

    // Bump version, recompute hash, record who changed it
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    hook.version += 1;
    hook.script_hash = store::sha256_hex(&hook.script);
    hook.updated_by = sub.to_string();
    hook.updated_at = store::unix_now();

    store::save_hook(&hook).await?;

    // Save immutable version snapshot
    let ver = store::HookVersion {
        hook_id: hook.id.clone(),
        version: hook.version,
        name: hook.name.clone(),
        trigger: hook.trigger.clone(),
        script: hook.script.clone(),
        script_hash: hook.script_hash.clone(),
        enabled: hook.enabled,
        priority: hook.priority,
        changed_by: sub.to_string(),
        changed_at: hook.updated_at,
    };
    let _ = store::save_hook_version(&ver).await;

    let _ = store::log_audit(
        "hook_updated",
        sub,
        id,
        &format!(
            "name={} hash={} v={}",
            hook.name, hook.script_hash, hook.version
        ),
    )
    .await;

    json_ok(&serde_json::json!({
        "id": hook.id,
        "name": hook.name,
        "trigger": hook.trigger,
        "enabled": hook.enabled,
        "priority": hook.priority,
        "version": hook.version,
        "script_hash": hook.script_hash,
    }))
}

/// DELETE /api/hooks/:id — delete a hook (superadmin).
pub async fn delete_hook(auth: Option<&str>, id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let hook = store::get_hook(id).await?.ok_or("hook not found")?;
    store::delete_hook(id).await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "hook_deleted",
        sub,
        id,
        &format!(
            "name={} hash={} v={}",
            hook.name, hook.script_hash, hook.version
        ),
    )
    .await;

    json_ok(
        &serde_json::json!({"deleted": true, "last_version": hook.version, "script_hash": hook.script_hash}),
    )
}

/// POST /api/hooks/:id/test — dry-run a hook with sample data (superadmin).
pub async fn test_hook(auth: Option<&str>, id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let hook = store::get_hook(id).await?.ok_or("hook not found")?;

    match crate::hooks::test_hook(&hook.script, &hook.trigger) {
        Ok(outcome) => json_ok(&serde_json::json!({
            "success": true,
            "deny_reason": outcome.deny_reason,
            "set_superadmin": outcome.set_superadmin,
            "add_to_tenants": outcome.add_to_tenants.iter()
                .map(|(t, r)| serde_json::json!({"tenant_id": t, "role": r}))
                .collect::<Vec<_>>(),
            "extra_claims": outcome.extra_claims.iter()
                .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
                .collect::<Vec<_>>(),
            "log_messages": outcome.log_messages,
        })),
        Err(e) => json_ok(&serde_json::json!({
            "success": false,
            "error": e,
        })),
    }
}

/// GET /api/hooks/:id/versions — list all version snapshots for a hook (superadmin).
/// Returns the full script + metadata for every version ever saved,
/// enabling auditors to diff any two versions and trace exactly what changed.
pub async fn list_hook_versions(auth: Option<&str>, id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let versions = store::list_hook_versions(id).await?;
    let list: Vec<Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "hook_id": v.hook_id,
                "version": v.version,
                "name": v.name,
                "trigger": v.trigger,
                "script": v.script,
                "script_hash": v.script_hash,
                "enabled": v.enabled,
                "priority": v.priority,
                "changed_by": v.changed_by,
                "changed_at": v.changed_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

// ── Passkey management ──────────────────────────────────────

/// GET /api/users/:id/passkeys — list a user's registered passkeys.
pub async fn list_passkeys(auth: Option<&str>, user_id: &str) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    let list: Vec<Value> = user
        .passkey_credentials
        .iter()
        .map(|c| {
            serde_json::json!({
                "credential_id": c.credential_id,
                "name": c.name,
                "created_at": c.created_at,
                "sign_count": c.sign_count,
            })
        })
        .collect();

    json_ok(&Value::Array(list))
}

/// POST /api/users/:id/passkeys/register-options — start passkey registration.
pub async fn passkey_register_options(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let user = store::get_user(user_id).await?.ok_or("user not found")?;

    let challenge = crate::passkeys::generate_challenge();
    let existing_cred_ids: Vec<String> = user
        .passkey_credentials
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    let token = store::random_hex(32);
    let pc = store::PasskeyChallenge {
        challenge: challenge.clone(),
        purpose: "register".into(),
        user_id: user_id.to_string(),
        session_id: String::new(),
        expires_at: store::unix_now() + 300, // 5 minutes
    };
    store::save_passkey_challenge(&token, &pc).await?;

    let display_name = if user.name.is_empty() {
        &user.email
    } else {
        &user.name
    };
    let options = crate::passkeys::registration_options_json(
        user_id,
        &user.email,
        display_name,
        &challenge,
        &existing_cred_ids,
    );

    json_ok(&serde_json::json!({
        "token": token,
        "publicKey": options,
    }))
}

/// POST /api/users/:id/passkeys/register-complete — finish passkey registration.
pub async fn passkey_register_complete(
    auth: Option<&str>,
    user_id: &str,
    body: &[u8],
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    #[derive(serde::Deserialize)]
    struct Req {
        token: String,
        #[serde(rename = "clientDataJSON")]
        client_data_json: String,
        #[serde(rename = "attestationObject")]
        attestation_object: String,
        #[serde(default)]
        name: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    // Look up and validate the challenge
    let pc = store::get_passkey_challenge(&req.token)
        .await?
        .ok_or("invalid or expired registration token")?;
    if pc.purpose != "register" || pc.user_id != user_id {
        return Err("token mismatch".into());
    }
    if store::unix_now() > pc.expires_at {
        store::delete_passkey_challenge(&req.token).await?;
        return Err("registration token expired".into());
    }
    store::delete_passkey_challenge(&req.token).await?;

    let issuer = crate::get_issuer();

    let parsed = crate::passkeys::verify_registration(
        &req.client_data_json,
        &req.attestation_object,
        &pc.challenge,
        &issuer,
    )?;

    let credential_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.credential_id);
    let public_key =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.public_key_bytes);

    // Check for duplicate
    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    if user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == credential_id)
    {
        return Err("this passkey is already registered".into());
    }

    let name = if req.name.is_empty() {
        format!("Passkey {}", user.passkey_credentials.len() + 1)
    } else {
        req.name
    };

    let cred = store::PasskeyCredential {
        credential_id: credential_id.clone(),
        public_key,
        sign_count: parsed.sign_count,
        name: name.clone(),
        created_at: store::unix_now(),
    };
    store::update_user_rmw(user_id, |u| {
        u.passkey_credentials.push(cred.clone());
        Ok(true)
    })
    .await?;

    // Index for discoverable-credential lookup
    store::index_passkey_credential(&credential_id, user_id).await?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("passkey_registered", sub, user_id, &name).await;

    json_ok(&serde_json::json!({
        "credential_id": credential_id,
        "name": name,
    }))
}

/// DELETE /api/users/:id/passkeys/:cred_id — remove a passkey.
pub async fn delete_passkey(
    auth: Option<&str>,
    user_id: &str,
    cred_id: &str,
) -> Result<Response<String>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let user = store::get_user(user_id).await?.ok_or("user not found")?;
    let _before = user.passkey_credentials.len();
    if !user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == cred_id)
    {
        return Err("passkey not found".into());
    }
    let cred_id_owned = cred_id.to_string();
    store::update_user_rmw(user_id, |u| {
        u.passkey_credentials
            .retain(|c| c.credential_id != cred_id_owned);
        Ok(true)
    })
    .await?;

    // Remove from index
    let _ = store::unindex_passkey_credential(cred_id).await;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("passkey_deleted", sub, user_id, cred_id).await;

    json_ok(&serde_json::json!({"deleted": true}))
}

// ── Passkey authentication (public, no auth required) ───────

/// POST /passkeys/auth-options — start passkey authentication.
/// Called from the login page; no bearer token needed.
pub async fn passkey_auth_options() -> Result<Response<String>, String> {
    let challenge = crate::passkeys::generate_challenge();

    let token = store::random_hex(32);
    let pc = store::PasskeyChallenge {
        challenge: challenge.clone(),
        purpose: "authenticate".into(),
        user_id: String::new(),
        session_id: String::new(),
        expires_at: store::unix_now() + 300,
    };
    store::save_passkey_challenge(&token, &pc).await?;

    let options = crate::passkeys::authentication_options_json(&challenge, &[]);

    json_ok(&serde_json::json!({
        "token": token,
        "publicKey": options,
    }))
}

/// POST /passkeys/auth-complete — finish passkey authentication.
/// Verifies the assertion, finds the user, and completes the OIDC login.
pub async fn passkey_auth_complete(
    body: &[u8],
    remote_ip: &str,
) -> Result<Response<String>, String> {
    #[derive(serde::Deserialize)]
    struct Req {
        token: String,
        session_id: String,
        credential_id: String,
        #[serde(rename = "clientDataJSON")]
        client_data_json: String,
        #[serde(rename = "authenticatorData")]
        authenticator_data: String,
        signature: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    // Rate limit passkey auth: 10 attempts per token per 60 seconds
    if let Ok((false, _)) =
        crate::service_client::check_rate(&format!("passkey_auth:{}", req.token), 10, 60).await
    {
        return Err("too many passkey auth attempts".into());
    }

    // Atomically consume challenge — prevents replay across replicas
    let pc = store::consume_passkey_challenge(&req.token)
        .await?
        .ok_or("invalid or expired passkey auth token")?;
    if pc.purpose != "authenticate" {
        return Err("token purpose mismatch".into());
    }
    if store::unix_now() > pc.expires_at {
        return Err("passkey auth token expired".into());
    }

    // Find user by credential ID
    let user = store::get_user_by_passkey(&req.credential_id)
        .await?
        .ok_or("unknown passkey credential")?;

    if user.status != "active" {
        return Err("account is not active".into());
    }

    // Find the matching credential on the user
    let credential = user
        .passkey_credentials
        .iter()
        .find(|c| c.credential_id == req.credential_id)
        .ok_or("credential not found on user")?;

    let issuer = crate::get_issuer();

    // Verify the assertion
    let new_sign_count = crate::passkeys::verify_assertion(
        &req.client_data_json,
        &req.authenticator_data,
        &req.signature,
        &pc.challenge,
        &issuer,
        credential,
    )?;

    // Update sign counter atomically
    let cred_id_for_update = req.credential_id.clone();
    store::update_user_rmw(&user.id, |u| {
        if let Some(cred) = u
            .passkey_credentials
            .iter_mut()
            .find(|c| c.credential_id == cred_id_for_update)
        {
            cred.sign_count = new_sign_count;
            Ok(true)
        } else {
            Ok(false)
        }
    })
    .await?;

    let updated_user = store::get_user(&user.id).await?.unwrap_or(user.clone());

    let _ = store::log_audit(
        "passkey_auth_success",
        &user.id,
        &user.id,
        &req.credential_id,
    )
    .await;

    // Execute post-login hooks
    let outcome = crate::hooks::execute_hooks("post-login", &updated_user).await;
    if let Some(reason) = &outcome.deny_reason {
        let _ = store::log_audit("login_denied_by_hook", &user.id, &user.id, reason).await;
        return Err(format!("login denied: {reason}"));
    }
    let mut final_user = updated_user.clone();
    if let Err(e) = crate::hooks::apply_outcome(&mut final_user, &outcome).await {
        crate::logger::error_message("hooks.apply_failed", e);
    }

    // Suspicious login detection
    if store::check_and_record_ip(&final_user.id, remote_ip).await {
        let _ = store::log_audit(
            "suspicious_login",
            &final_user.id,
            &final_user.id,
            &format!("new_ip:{remote_ip}"),
        )
        .await;
    }

    let _ = store::clear_login_attempts(&final_user.id).await;
    let _ = store::log_audit("login_success", &final_user.id, &final_user.id, "passkey").await;
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", "passkey"), ("result", "success")],
    )
    .await;

    let session = store::get_auth_session(&req.session_id)
        .await?
        .ok_or("invalid or expired session")?;

    let amr = vec!["passkey".to_string()];
    let code = store::random_hex(32);
    let auth_time = store::unix_now();
    let auth_code = store::AuthCode {
        user_id: final_user.id.clone(),
        client_id: session.client_id.clone(),
        redirect_uri: session.redirect_uri.clone(),
        code_challenge: session.code_challenge.clone(),
        code_challenge_method: session.code_challenge_method.clone(),
        nonce: session.nonce.clone(),
        scope: session.scope.clone(),
        auth_time,
        amr: amr.clone(),
        acr: None,
        requested_id_token_claims: session.requested_id_token_claims.clone(),
        requested_userinfo_claims: session.requested_userinfo_claims.clone(),
        extra_claims: outcome.extra_claims.clone(),
        csrf_token: store::random_hex(16),
        expires_at: store::unix_now() + 300,
        state: session.state.clone(),
    };
    store::save_auth_code(&code, &auth_code).await?;
    let _ = store::delete_auth_session(&req.session_id).await;

    let issuer = crate::get_issuer();
    let redirect_url = crate::util::build_auth_code_redirect(
        &session.redirect_uri,
        &code,
        &session.state,
        &issuer,
    );

    // Return JSON with redirect URL (JS-initiated, can't use HTTP 302)
    // Also set account session cookie for /account access
    let body = serde_json::json!({ "redirect": redirect_url });
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json");
    if let Ok(cookie_val) = crate::account::create_session_cookie(&final_user.id).await {
        builder = builder.header("set-cookie", cookie_val);
    }
    if let Ok(cookie_val) =
        crate::account::create_idp_session_cookie(&final_user.id, &amr, auth_time).await
    {
        builder = builder.header("set-cookie", cookie_val);
    }
    Ok(builder.body(body_str.to_string()).unwrap())
}
