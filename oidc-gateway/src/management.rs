use http::{Response, StatusCode};
use serde_json::Value;

use crate::error::ApiError;
use crate::services::authz::{self, Caller};
use crate::services::{
    clients, hooks as hook_service, idps, settings as settings_service, tenants, users,
};
use crate::store::{self, Membership};

// ── Auth helpers ────────────────────────────────────────────

/// Extract and verify Bearer token, returning JWT claims.
pub(crate) async fn require_auth(auth_header: Option<&str>) -> Result<Value, ApiError> {
    let invalid = || ApiError::unauthorized("missing or invalid access token");
    let header = auth_header.ok_or_else(invalid)?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or_else(invalid)?;
    crate::service_client::verify_token_scoped(
        token,
        Some(&crate::get_issuer()),
        Some("lid-admin"),
        Some("access"),
    )
    .await
    .map_err(|e| invalid().with_detail(e))
}

/// Authenticate a management request and build the service-layer caller.
async fn require_caller(auth_header: Option<&str>) -> Result<Caller, ApiError> {
    let claims = require_auth(auth_header).await?;
    Ok(Caller::from_claims(&claims))
}

// ── Claims-based authz wrappers ─────────────────────────────
// Thin delegations onto the shared service-layer authorization so existing
// callers (and their tests) keep working against claims directly.

/// Check that claims have the "superadmin" role (no tenant scope).
pub(crate) fn require_superadmin(claims: &Value) -> Result<(), ApiError> {
    Caller::from_claims(claims).require_superadmin()
}

/// Check that the caller has at least the given role for a specific tenant.
#[allow(dead_code)]
pub(crate) fn require_tenant_role(
    claims: &Value,
    tenant_id: &str,
    min_role: &str,
) -> Result<(), ApiError> {
    Caller::from_claims(claims).require_tenant_role(tenant_id, min_role)
}

#[allow(dead_code)]
pub(crate) fn claim_has_tenant_role(claims: &Value, tenant_id: &str, min_role: &str) -> bool {
    let caller = Caller::from_claims(claims);
    authz::role_level(caller.tenant_role(tenant_id)) >= authz::role_level(min_role)
}

#[allow(dead_code)]
pub(crate) fn role_level(role: &str) -> u8 {
    authz::role_level(role)
}

#[allow(dead_code)]
pub(crate) fn get_caller_tenant_role(claims: &Value, tenant_id: &str) -> String {
    Caller::from_claims(claims)
        .tenant_role(tenant_id)
        .to_string()
}

/// Check that the caller is the user themselves, or has superadmin role.
/// For security-critical global account operations, we don't allow tenant admins
/// to act on users unless they are superadmin.
#[allow(dead_code)]
pub(crate) fn require_self_or_superadmin(claims: &Value, user_id: &str) -> Result<(), ApiError> {
    Caller::from_claims(claims).require_self_or_superadmin(user_id)
}

// ── Tenant endpoints ────────────────────────────────────────

/// GET /api/tenants
pub async fn list_tenants(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let tenants = store::list_tenants().await.map_err(ApiError::internal)?;
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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

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

    let events = store::list_audit_events(actor_id, target_id, event_type, since, until, limit)
        .await
        .map_err(ApiError::internal)?;
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
pub async fn create_tenant(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        display_name: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let tenant = tenants::create_tenant(&caller, &req.name, &req.display_name).await?;

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
pub async fn get_tenant(auth: Option<&str>, tenant_id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let tenant = store::get_tenant(tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("tenant not found"))?;
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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    tenants::delete_tenant(&caller, tenant_id).await?;
    json_ok(&serde_json::json!({"deleted": true}))
}

/// PATCH /api/tenants/:id — update display_name and/or status
pub async fn update_tenant(
    auth: Option<&str>,
    tenant_id: &str,
    body: &[u8],
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        display_name: Option<String>,
        status: Option<String>,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let tenant = tenants::update_tenant(
        &caller,
        tenant_id,
        tenants::UpdateTenantParams {
            display_name: req.display_name,
            status: req.status,
        },
    )
    .await?;

    json_ok(&serde_json::json!({
        "id": tenant.id,
        "name": tenant.name,
        "display_name": tenant.display_name,
        "status": tenant.status,
        "created_at": tenant.created_at,
    }))
}

// ── Tenant user/membership endpoints ────────────────────────

/// GET /api/tenants/:id/users
pub async fn list_tenant_users(
    auth: Option<&str>,
    tenant_id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_tenant_role(tenant_id, "manager")?;

    let members = store::list_tenant_members(tenant_id)
        .await
        .map_err(ApiError::internal)?;
    let mut users = Vec::new();
    for m in &members {
        if let Some(user) = store::get_user(&m.user_id)
            .await
            .map_err(ApiError::internal)?
        {
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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        user_id: String,
        role: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let membership = tenants::add_member(&caller, tenant_id, &req.user_id, &req.role).await?;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "tenant_id": membership.tenant_id,
            "user_id": membership.user_id,
            "role": membership.role,
        }),
    )
}

/// DELETE /api/tenants/:tid/users/:uid
pub async fn remove_tenant_user(
    auth: Option<&str>,
    tenant_id: &str,
    user_id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    tenants::remove_member(&caller, tenant_id, user_id).await?;
    json_ok(&serde_json::json!({"removed": true}))
}

/// POST /api/tenants/:id/users/invite
pub async fn invite_user(
    auth: Option<&str>,
    tenant_id: &str,
    body: &[u8],
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        email: String,
        role: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let invitation = tenants::invite_user(&caller, tenant_id, &req.email, &req.role).await?;

    let mut resp_json = serde_json::json!({
        "email": req.email,
        "role": req.role,
        "expires_at": invitation.expires_at,
    });
    if crate::is_dev_mode()
        && let Some(obj) = resp_json.as_object_mut()
    {
        obj.insert(
            "invite_token".to_string(),
            serde_json::Value::String(invitation.token),
        );
    }

    json_response(StatusCode::CREATED, &resp_json)
}

/// POST /api/invitations/accept — accept an invitation token
pub async fn accept_invitation(
    auth: Option<&str>,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Result<Response<String>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Req {
        token: String,
        user_id: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    // Rate limit invitation acceptance per token (5 attempts per 15 minutes).
    match crate::service_client::check_rate(&format!("accept_invite:{}", req.token), 5, 900).await {
        Ok((false, _)) => return Err(ApiError::too_many("too many invitation attempts")),
        Err(e) => {
            crate::logger::error_message("rate_limit.accept_invite_check_failed", e);
            return Err(ApiError::too_many("too many invitation attempts"));
        }
        _ => {}
    }

    // Require caller authentication matching req.user_id (either Bearer token or
    // active browser account session cookie) so an unauthenticated party or
    // tenant manager cannot force-bind an unverified user (OIDC-09).
    if auth.is_some() {
        let caller = require_caller(auth).await?;
        if !caller.is_superadmin && caller.user_id != req.user_id {
            return Err(ApiError::forbidden(
                "cannot accept invitation on behalf of another user",
            ));
        }
    } else if let Ok(Ok((session_user, _))) = crate::account::require_account_session(headers).await
    {
        if session_user.id != req.user_id {
            return Err(ApiError::forbidden(
                "cannot accept invitation on behalf of another user",
            ));
        }
    } else if !crate::is_dev_mode() {
        return Err(ApiError::unauthorized(
            "authentication required to accept invitation",
        ));
    }

    let inv = store::get_invitation(&req.token)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired invitation")?;

    if store::unix_now() > inv.expires_at {
        store::delete_invitation(&req.token)
            .await
            .map_err(ApiError::internal)?;
        return Err("invalid or expired invitation".into());
    }

    // Type-confusion guard: only tenant-membership invitations may be accepted
    // here. Email-verification (role "verify_email", tenant "system") and
    // password-reset (role "password_reset") rows live in the same store and
    // must never become memberships.
    if !authz::ASSIGNABLE_ROLES.contains(&inv.role.as_str()) {
        return Err("invalid or expired invitation".into());
    }

    // The invitation's tenant must still exist.
    store::get_tenant(&inv.tenant_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired invitation")?;

    // Verify user exists and email matches (return generic error to avoid user oracle)
    let user = store::get_user(&req.user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired invitation")?;
    if !user.email.eq_ignore_ascii_case(&inv.email) {
        return Err("invalid or expired invitation".into());
    }
    if user.status != "active" {
        return Err("account is not active".into());
    }

    // Do not overwrite an existing membership (e.g. downgrading owner/admin to member)
    if store::get_membership(&inv.tenant_id, &req.user_id)
        .await
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::conflict(
            "user is already a member of this tenant",
        ));
    }

    // Create membership
    let membership = Membership {
        tenant_id: inv.tenant_id.clone(),
        user_id: req.user_id.clone(),
        role: inv.role.clone(),
        joined_at: store::unix_now(),
    };
    store::add_membership(&membership)
        .await
        .map_err(ApiError::internal)?;
    store::delete_invitation(&req.token)
        .await
        .map_err(ApiError::internal)?;

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
pub async fn list_clients(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let clients = store::list_clients().await.map_err(ApiError::internal)?;
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
pub async fn create_client(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

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
        #[serde(default)]
        token_endpoint_auth_method: Option<String>,
        #[serde(default)]
        jwks: Option<serde_json::Value>,
        #[serde(default)]
        require_pushed_authorization_requests: bool,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let (client, raw_secret) = clients::create_client(
        &caller,
        clients::CreateClientParams {
            name: req.name,
            redirect_uris: req.redirect_uris,
            post_logout_redirect_uris: req.post_logout_redirect_uris.unwrap_or_default(),
            grant_types: req.grant_types,
            confidential: req.confidential,
            theme: req.theme,
            backchannel_logout_uri: req.backchannel_logout_uri,
            backchannel_logout_session_required: req.backchannel_logout_session_required,
            id_token_signed_response_alg: req.id_token_signed_response_alg,
            first_party: req.first_party,
            token_endpoint_auth_method: req.token_endpoint_auth_method,
            jwks: req.jwks,
            require_pushed_authorization_requests: req.require_pushed_authorization_requests,
        },
    )
    .await?;

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
    if let Some(raw_secret) = raw_secret {
        resp["client_secret"] = serde_json::json!(raw_secret);
    }

    json_response(StatusCode::CREATED, &resp)
}

/// GET /api/clients/:id
pub async fn get_client(auth: Option<&str>, id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let client = store::get_client(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("client not found"))?;
    let mut v = serde_json::to_value(&client).map_err(|e| ApiError::internal(e.to_string()))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("client_secret");
    }
    json_ok(&v)
}

/// DELETE /api/clients/:id
pub async fn delete_client(auth: Option<&str>, id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    clients::delete_client(&caller, id).await?;
    json_ok(&serde_json::json!({ "deleted": true, "client_id": id }))
}

/// POST /api/clients/:id/rotate-secret — rotate a confidential client's secret.
/// The raw secret is returned exactly once.
pub async fn rotate_client_secret(
    auth: Option<&str>,
    id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    let raw_secret = clients::rotate_client_secret(&caller, id).await?;
    json_ok(&serde_json::json!({
        "client_id": id,
        "client_secret": raw_secret,
    }))
}

/// PUT /api/clients/:id
pub async fn update_client(
    auth: Option<&str>,
    id: &str,
    body: &[u8],
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

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
        token_endpoint_auth_method: Option<String>,
        jwks: Option<serde_json::Value>,
        require_pushed_authorization_requests: Option<bool>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let client = clients::update_client(
        &caller,
        id,
        clients::UpdateClientParams {
            redirect_uris: req.redirect_uris,
            post_logout_redirect_uris: req.post_logout_redirect_uris,
            name: req.name,
            grant_types: req.grant_types,
            theme: req.theme,
            first_party: req.first_party,
            backchannel_logout_uri: req.backchannel_logout_uri,
            backchannel_logout_session_required: req.backchannel_logout_session_required,
            id_token_signed_response_alg: req.id_token_signed_response_alg,
            token_endpoint_auth_method: req.token_endpoint_auth_method,
            jwks: req.jwks,
            require_pushed_authorization_requests: req.require_pushed_authorization_requests,
        },
    )
    .await?;

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

// ── Signing key management ──────────────────────────────────

/// GET /api/keys — list signing keys (superadmin only).
/// Returns kid, alg, status and timestamps for every key in the ring
/// (current + retired). Private key material is never exposed.
pub async fn list_keys(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let keys = crate::key_manager::list_keys()
        .await
        .map_err(ApiError::internal)?;
    let list: Vec<Value> = keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "kid": k.kid,
                "alg": k.alg,
                "status": k.status,
                "version": k.version,
                "created_at": k.created_at,
                "retired_at": k.retired_at,
                "grace_expires_at": k.grace_expires_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!({ "keys": list }))
}

/// POST /api/keys/rotate — rotate the RSA+EC signing keys (superadmin only).
/// The outgoing pair is retired and stays in JWKS (verification only) for
/// `RETIRED_GRACE_SECS`; new tokens are signed with the new pair immediately.
pub async fn rotate_keys(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let outcome = crate::key_manager::rotate_keys().await.map_err(|e| {
        if e.contains("concurrent rotations") || e.contains("revision mismatch") {
            ApiError::conflict("rotation conflict: another rotation is in progress").with_detail(e)
        } else {
            ApiError::internal(e)
        }
    })?;

    let details = serde_json::to_string(&serde_json::json!({
        "version": outcome.version,
        "rsa_kid": outcome.rsa_kid,
        "ec_kid": outcome.ec_kid,
        "grace_expires_at": outcome.grace_expires_at,
    }))
    .unwrap_or_default();
    let _ = store::log_audit("keys_rotated", &caller.user_id, "signing-keys", &details).await;

    json_ok(&serde_json::json!({
        "rotated": true,
        "version": outcome.version,
        "current": {
            "rsa": { "kid": outcome.rsa_kid, "key": outcome.rsa_key_name },
            "ec": { "kid": outcome.ec_kid, "key": outcome.ec_key_name },
        },
        "retired": outcome.retired.iter().map(|r| serde_json::json!({
            "kid": r.kid,
            "alg": r.alg,
            "retired_at": r.retired_at,
        })).collect::<Vec<_>>(),
        "grace_expires_at": outcome.grace_expires_at,
    }))
}

// ── Password reset initiation ───────────────────────────────

/// POST /api/users/:id/password-reset
pub async fn initiate_password_reset(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    let user = users::initiate_password_reset(&caller, user_id).await?;

    json_ok(&serde_json::json!({
        "user_id": user_id,
        "email": user.email,
        "expires_in": 3600,
        "message": "Password reset email sent",
    }))
}

// ── Settings management ─────────────────────────────────────

fn settings_json(settings: &store::RuntimeSettings) -> Value {
    serde_json::json!({
        "allow_registration": settings.allow_registration,
        "default_theme": settings.default_theme,
        "idp_session_ttl_seconds": settings.idp_session_ttl_seconds,
    })
}

/// GET /api/settings — read current runtime settings (superadmin only)
pub async fn get_settings(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    let settings = settings_service::get_settings(&caller).await?;
    json_ok(&settings_json(&settings))
}

/// PUT /api/settings — update runtime settings (superadmin only)
pub async fn update_settings(
    auth: Option<&str>,
    body: &[u8],
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        #[serde(default)]
        allow_registration: Option<bool>,
        #[serde(default)]
        default_theme: Option<store::ClientTheme>,
        #[serde(default)]
        idp_session_ttl_seconds: Option<u64>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let settings = settings_service::update_settings(
        &caller,
        settings_service::SettingsPatch {
            allow_registration: req.allow_registration,
            default_theme: req.default_theme,
            idp_session_ttl_seconds: req.idp_session_ttl_seconds,
        },
    )
    .await?;

    json_ok(&settings_json(&settings))
}

// ── Response helpers ────────────────────────────────────────

fn json_ok(value: &Value) -> Result<Response<String>, ApiError> {
    json_response(StatusCode::OK, value)
}

fn json_response(status: StatusCode, value: &Value) -> Result<Response<String>, ApiError> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(value).unwrap_or_default())
        .unwrap())
}

// ── MFA management ──────────────────────────────────────────

/// POST /api/users/:id/mfa/setup — generate TOTP secret and return QR URI.
pub async fn mfa_setup(auth: Option<&str>, user_id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_self_or_superadmin(user_id)?;

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if user.totp_enabled {
        return Err(ApiError::conflict("MFA is already enabled"));
    }

    let secret = crate::totp::generate_secret();
    let issuer = crate::get_issuer();
    let otpauth_uri = crate::totp::otpauth_uri(&secret, &user.email, &issuer);

    // Store secret but don't enable yet (requires confirm step)
    store::update_user_rmw(user_id, |u| {
        u.totp_secret = Some(secret.clone());
        Ok(true)
    })
    .await
    .map_err(ApiError::internal)?;

    let _ = store::log_audit("mfa_setup_started", &caller.user_id, user_id, "").await;

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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_self_or_superadmin(user_id)?;

    #[derive(serde::Deserialize)]
    struct Req {
        code: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
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
    .await
    .map_err(ApiError::internal)?;

    let _ = store::log_audit("mfa_enabled", &caller.user_id, user_id, "").await;

    json_ok(&serde_json::json!({
        "enabled": true,
        "recovery_codes": recovery_codes,
    }))
}

/// DELETE /api/users/:id/mfa — disable MFA for a user.
pub async fn mfa_disable(auth: Option<&str>, user_id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    users::disable_mfa(&caller, user_id).await?;
    json_ok(&serde_json::json!({"disabled": true}))
}

/// GET /api/users/:id/export — GDPR Art. 15/20 data portability.
/// Returns all first-party data for the user as JSON.
/// Accessible by the user themselves or a superadmin.
pub async fn export_user_data(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_self_or_superadmin(user_id)?;

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
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

    let _ = store::log_audit(
        "user_data_exported",
        &caller.user_id,
        user_id,
        "gdpr_export",
    )
    .await;

    json_response(StatusCode::OK, &export)
}

/// DELETE /api/users/:id — GDPR Art. 17 right to erasure.
/// Permanently deletes the user and all associated first-party data.
/// Accessible by the user themselves or a superadmin.
/// A superadmin cannot delete themselves this way (use the deactivation path).
pub async fn delete_user(auth: Option<&str>, user_id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    users::delete_user(&caller, user_id).await?;

    json_response(
        StatusCode::OK,
        &serde_json::json!({"deleted": true, "id": user_id}),
    )
}

/// POST /api/users/:id/activate — activate a user account (superadmin only).
/// Intended for accounts stuck in `pending` (e.g. lost verification email).
pub async fn activate_user(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    users::activate_user(&caller, user_id).await?;
    json_ok(&serde_json::json!({"id": user_id, "status": "active"}))
}

/// GET /api/users?q=...&limit=... — global user list (superadmin only).
/// `q` is a case-insensitive substring filter on email and name.
pub async fn list_users(auth: Option<&str>, query: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let params = crate::util::parse_query(query);
    let get = |key: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    let q = get("q")
        .map(|value| value.to_lowercase())
        .filter(|value| !value.is_empty());
    let requested_limit = match get("limit") {
        Some(value) => value.parse::<usize>().map_err(|_| "invalid limit")?,
        None => 100,
    };
    if requested_limit == 0 {
        return Err("limit must be at least 1".into());
    }
    let limit = requested_limit.min(500);

    let all_users = store::list_users().await.map_err(ApiError::internal)?;
    let list: Vec<Value> = all_users
        .iter()
        .filter(|u| {
            q.as_ref().is_none_or(|query| {
                u.email.to_lowercase().contains(query.as_str())
                    || u.name.to_lowercase().contains(query.as_str())
            })
        })
        .take(limit)
        .map(|u| {
            serde_json::json!({
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "status": u.status,
                "created_at": u.created_at,
                "totp_enabled": u.totp_enabled,
                "superadmin": u.superadmin,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// GET /api/stats — dashboard aggregates (superadmin only).
pub async fn stats(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let tenants = store::list_tenants().await.map_err(ApiError::internal)?;
    let users = store::list_users().await.map_err(ApiError::internal)?;
    let clients = store::list_clients().await.map_err(ApiError::internal)?;
    let idps = store::list_identity_providers()
        .await
        .map_err(ApiError::internal)?;

    json_ok(&serde_json::json!({
        "tenants": tenants.len(),
        "users": users.len(),
        "clients": clients.len(),
        "identity_providers": idps.len(),
    }))
}

// ── Identity provider management ────────────────────────────

/// GET /api/identity-providers
pub async fn list_identity_providers(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let providers = store::list_identity_providers()
        .await
        .map_err(ApiError::internal)?;
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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

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

    let idp = idps::create_identity_provider(
        &caller,
        &req.provider_type,
        &req.client_id,
        &req.client_secret,
        req.enabled,
    )
    .await?;

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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    idps::delete_identity_provider(&caller, id).await?;
    json_ok(&serde_json::json!({"deleted": true}))
}

/// PUT /api/identity-providers/:id — update an identity provider.
/// Empty client_id/client_secret leave the stored values unchanged;
/// empty display_name/discovery_url clear the field.
pub async fn update_identity_provider(
    auth: Option<&str>,
    id: &str,
    body: &[u8],
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        client_id: Option<String>,
        client_secret: Option<String>,
        enabled: Option<bool>,
        display_name: Option<String>,
        discovery_url: Option<String>,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let idp = idps::update_identity_provider(
        &caller,
        id,
        idps::UpdateIdpParams {
            client_id: req.client_id,
            client_secret: req.client_secret,
            enabled: req.enabled,
            display_name: req.display_name,
            discovery_url: req.discovery_url,
        },
    )
    .await?;

    json_ok(&serde_json::json!({
        "id": idp.id,
        "provider_type": idp.provider_type,
        "client_id": idp.client_id,
        "enabled": idp.enabled,
        "display_name": idp.display_name,
        "discovery_url": idp.discovery_url,
        // client_secret is never exposed
    }))
}

// ── Hook management (Rhai scripting) ────────────────────────

/// GET /api/hooks — list all hooks (superadmin).
pub async fn list_hooks(auth: Option<&str>) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let hooks = store::list_hooks().await.map_err(ApiError::internal)?;
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
pub async fn create_hook(auth: Option<&str>, body: &[u8]) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

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

    let hook = hook_service::create_hook(
        &caller,
        hook_service::CreateHookParams {
            name: req.name,
            trigger: req.trigger,
            script: req.script,
            enabled: req.enabled,
            priority: req.priority,
        },
    )
    .await?;

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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: Option<String>,
        trigger: Option<String>,
        script: Option<String>,
        enabled: Option<bool>,
        priority: Option<i32>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let hook = hook_service::update_hook(
        &caller,
        id,
        hook_service::UpdateHookParams {
            name: req.name,
            trigger: req.trigger,
            script: req.script,
            enabled: req.enabled,
            priority: req.priority,
        },
    )
    .await?;

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
pub async fn delete_hook(auth: Option<&str>, id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    let hook = hook_service::delete_hook(&caller, id).await?;

    json_ok(
        &serde_json::json!({"deleted": true, "last_version": hook.version, "script_hash": hook.script_hash}),
    )
}

/// POST /api/hooks/:id/test — dry-run a hook with sample data (superadmin).
pub async fn test_hook(auth: Option<&str>, id: &str) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let hook = store::get_hook(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("hook not found"))?;

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
pub async fn list_hook_versions(
    auth: Option<&str>,
    id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_superadmin()?;

    let versions = store::list_hook_versions(id)
        .await
        .map_err(ApiError::internal)?;
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
pub async fn list_passkeys(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    caller.require_self_or_superadmin(user_id)?;

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    let (token, options) = users::passkey_register_options(&caller, user_id).await?;

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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;

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

    let (credential_id, name) = users::passkey_register_complete(
        &caller,
        user_id,
        users::PasskeyRegisterCompleteParams {
            token: req.token,
            client_data_json: req.client_data_json,
            attestation_object: req.attestation_object,
            name: req.name,
        },
    )
    .await?;

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
) -> Result<Response<String>, ApiError> {
    let caller = require_caller(auth).await?;
    users::delete_passkey(&caller, user_id, cred_id).await?;
    json_ok(&serde_json::json!({"deleted": true}))
}

// ── Passkey authentication (public, no auth required) ───────

/// POST /passkeys/auth-options — start passkey authentication.
/// Called from the login page; no bearer token needed.
pub async fn passkey_auth_options() -> Result<Response<String>, ApiError> {
    let challenge = crate::passkeys::generate_challenge();

    let token = store::random_hex(32);
    let pc = store::PasskeyChallenge {
        challenge: challenge.clone(),
        purpose: "authenticate".into(),
        user_id: String::new(),
        session_id: String::new(),
        expires_at: store::unix_now() + 300,
    };
    store::save_passkey_challenge(&token, &pc)
        .await
        .map_err(ApiError::internal)?;

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
    headers: &http::HeaderMap,
) -> Result<Response<String>, ApiError> {
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

    // Rate limit passkey auth: 10 attempts per token per 60 seconds.
    // Fail closed on limiter errors for authentication-critical paths.
    match crate::service_client::check_rate(&format!("passkey_auth:{}", req.token), 10, 60).await {
        Ok((false, _)) => {
            return Err(ApiError::too_many("too many passkey auth attempts"));
        }
        Err(e) => {
            crate::logger::error_message("rate_limit.passkey_auth_check_failed", e);
            return Err(ApiError::too_many("too many passkey auth attempts"));
        }
        _ => {}
    }

    // Browser binding (login CSRF): the lid_flow cookie set at /authorize or
    // /device must match this session (OIDC-07).
    let session = store::get_auth_session(&req.session_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired session")?;
    if !crate::account::flow_cookie_matches(headers, &req.session_id) {
        let _ = store::log_audit("passkey_flow_cookie_mismatch", "", "", remote_ip).await;
        return Err("sign-in session could not be verified".into());
    }
    if store::unix_now() > session.created_at + 600 {
        let _ = store::delete_auth_session(&req.session_id).await;
        return Err("sign-in session expired".into());
    }
    if session
        .acr_values
        .iter()
        .any(|v| v == "urn:lattice-id:mfa:totp")
    {
        return Err("session requires TOTP multi-factor authentication".into());
    }

    // Atomically consume challenge — prevents replay across replicas
    let pc = store::consume_passkey_challenge(&req.token)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired passkey auth token")?;
    if pc.purpose != "authenticate" {
        return Err("token purpose mismatch".into());
    }
    if store::unix_now() > pc.expires_at {
        return Err("passkey auth token expired".into());
    }

    // Find user by credential ID
    let user = store::get_user_by_passkey(&req.credential_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or("unknown passkey credential")?;

    if user.status != "active" {
        return Err("account is not active".into());
    }
    if store::is_account_locked(&user.id).await.unwrap_or(false) {
        return Err("account is temporarily locked".into());
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

    // Atomically consume the auth session so concurrent requests cannot mint
    // multiple authorization codes from the same session (OIDC-04).
    let session = store::consume_auth_session(&req.session_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired session")?;

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
    .await
    .map_err(ApiError::internal)?;

    let updated_user = store::get_user(&user.id)
        .await
        .map_err(ApiError::internal)?
        .unwrap_or(user.clone());

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
        return Err(format!("login denied: {reason}").into());
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

    let _ = store::log_audit("login_success", &final_user.id, &final_user.id, "passkey").await;
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", "passkey"), ("result", "success")],
    )
    .await;

    // UV is mandatory for passkey assertions (verify_assertion rejects
    // assertions without the UV flag), so the assertion itself is the second
    // factor: passkey (possession) + user verification → include "mfa".
    let amr = vec!["passkey".to_string(), "mfa".to_string()];
    let auth_time = store::unix_now();

    // ── Device authorization grant (RFC 8628) ──
    if session.code_challenge_method == "device" {
        let approval_token = crate::device::create_approval(&session, &final_user)
            .await
            .map_err(|e| {
                crate::logger::error_message("device.approval_token_save_failed", &e);
                ApiError::internal(e)
            })?;

        let body = serde_json::json!({
            "redirect": format!(
                "/device/confirm?token={}",
                crate::util::percent_encode(&approval_token)
            ),
        });
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
        return Ok(builder.body(body_str).unwrap());
    }

    // ── Consent screen check (OIDC-04 / OIDC-05) ──
    let force_consent = session.prompt.as_deref() == Some("consent");
    let needs_consent = if force_consent {
        true
    } else if session.needs_consent {
        let already_consented =
            store::has_user_consented(&final_user.id, &session.client_id, &session.scope)
                .await
                .unwrap_or(false);
        !already_consented
    } else {
        false
    };

    let code = store::random_hex(32);
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
        sid: session.sid.clone(),
        pending_consent: needs_consent,
    };
    store::save_auth_code(&code, &auth_code)
        .await
        .map_err(ApiError::internal)?;

    let redirect_url = if needs_consent {
        format!("/consent?code={}", crate::util::percent_encode(&code))
    } else {
        crate::util::build_auth_code_redirect(&session.redirect_uri, &code, &session.state, &issuer)
    };

    // Return JSON with redirect URL (JS-initiated, can't use HTTP 302)
    // Also set account session cookie for /account access
    let body = serde_json::json!({ "redirect": redirect_url });
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json");
    if needs_consent {
        builder = builder.header("set-cookie", crate::account::create_flow_cookie(&code));
    }
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
