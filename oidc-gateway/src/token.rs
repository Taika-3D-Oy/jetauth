use http::{Response, StatusCode};

use crate::{jwt, store, util};

/// RFC 6749 §5.2 compliant error response for the token endpoint.
fn token_error(status: StatusCode, error: &str, description: &str) -> Response<String> {
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache");
    if status == StatusCode::UNAUTHORIZED {
        builder = builder.header("www-authenticate", "Basic realm=\"lattice-id\"");
    }
    builder
        .body(serde_json::to_string(&body).unwrap_or_default())
        .unwrap()
}

/// Map an internal error string to a RFC 6749 §5.2 error response.
fn map_token_error(e: &str) -> Response<String> {
    if e.starts_with("invalid_dpop_proof") || e.contains("DPoP") {
        token_error(StatusCode::BAD_REQUEST, "invalid_dpop_proof", e)
    } else if e.contains("client_id")
        || e.contains("client_secret")
        || e.contains("client authentication")
        || e.contains("client_assertion")
        || e.contains("unregistered client")
        || e.contains("invalid client")
    {
        token_error(StatusCode::UNAUTHORIZED, "invalid_client", e)
    } else if e.contains("grant_type") || e.contains("not authorized to use") {
        token_error(StatusCode::BAD_REQUEST, "unauthorized_client", e)
    } else if e.contains("code")
        || e.contains("expired")
        || e.contains("PKCE")
        || e.contains("redirect_uri")
        || e.contains("refresh token")
        || e.contains("user not found")
        || e.contains("mismatch")
        || e.contains("consumed")
        || e.contains("revoked")
        || e.contains("replay")
    {
        token_error(StatusCode::BAD_REQUEST, "invalid_grant", e)
    } else if e.contains("rate") || e.contains("too many") {
        token_error(StatusCode::TOO_MANY_REQUESTS, "invalid_request", e)
    } else {
        token_error(StatusCode::BAD_REQUEST, "invalid_request", e)
    }
}

#[allow(unused_imports)]
pub use crate::client_auth::parse_basic_auth;

/// Handle POST /token — authorization_code, refresh_token, client_credentials, and device_code grants.
pub async fn handle(
    body_bytes: &[u8],
    issuer: &str,
    auth_header: Option<&str>,
    dpop_header: Option<&str>,
) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);

    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let grant_type = get("grant_type").ok_or("missing grant_type")?;

    // DPoP proof validation per RFC 9449
    let dpop_jkt = match dpop_header {
        Some(proof) => {
            match crate::dpop::validate_dpop_proof(proof, "POST", &format!("{issuer}/token"), None)
                .await
            {
                Ok(jkt) => Some(jkt),
                Err(e) => {
                    return Ok(token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_dpop_proof",
                        &e,
                    ));
                }
            }
        }
        None => None,
    };

    // Client authentication per RFC 6749 §2.3 and RFC 7523
    let auth_client =
        match crate::client_auth::authenticate_client(&form, auth_header, issuer, "/token").await {
            Ok(ac) => ac,
            Err(e) => {
                return Ok(map_token_error(&e));
            }
        };
    let client = auth_client.client;

    // Rate limit token endpoint per client_id: 100 requests per 60s
    let rate_key = format!("token:{}", client.client_id);
    match crate::service_client::check_rate(&rate_key, 100, 60).await {
        Ok((false, _)) => return Err("too many token requests. please try again later.".into()),
        Err(e) => crate::logger::error_message("rate_limit.token_check_failed", e),
        _ => {}
    }

    let result = match grant_type {
        "authorization_code" => {
            handle_code_exchange(&form, &client, dpop_jkt.as_deref(), issuer).await
        }
        "refresh_token" => handle_refresh(&form, &client, dpop_jkt.as_deref(), issuer).await,
        "client_credentials" => {
            handle_client_credentials(&form, &client, dpop_jkt.as_deref(), issuer).await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code(&form, &client, dpop_jkt.as_deref(), issuer).await
        }
        _ => {
            return Ok(token_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("unsupported grant_type: {grant_type}"),
            ));
        }
    };

    match result {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(map_token_error(&e)),
    }
}

async fn handle_code_exchange(
    form: &[(String, String)],
    client: &store::OidcClient,
    dpop_jkt: Option<&str>,
    issuer: &str,
) -> Result<Response<String>, String> {
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let code = get("code").ok_or("missing code")?;
    let code_verifier = get("code_verifier");
    let redirect_uri = get("redirect_uri").ok_or("missing redirect_uri")?;

    if !client
        .grant_types
        .contains(&"authorization_code".to_string())
    {
        return Err(format!(
            "client '{}' is not authorized to use grant_type 'authorization_code'",
            client.client_id
        ));
    }

    // CAS: get auth code with revision for atomic consumption
    let (auth_code, revision) = store::get_auth_code_cas(code)
        .await?
        .ok_or("invalid or expired code")?;

    if auth_code.client_id != client.client_id {
        return Err("client_id mismatch".into());
    }
    if auth_code.redirect_uri != redirect_uri {
        return Err("redirect_uri mismatch".into());
    }
    if store::unix_now() > auth_code.expires_at {
        return Err("authorization code expired".into());
    }

    // PKCE: required for public clients, optional for confidential clients
    if !auth_code.code_challenge.is_empty() {
        let verifier = code_verifier.ok_or("missing code_verifier (PKCE was initiated)")?;
        if !verify_pkce(
            verifier,
            &auth_code.code_challenge,
            &auth_code.code_challenge_method,
        ) {
            return Err("PKCE verification failed".into());
        }
    } else if client.client_secret.is_none() && client.jwks.is_none() {
        // Public client MUST have used PKCE
        return Err("PKCE required for public clients".into());
    }

    // CAS: atomically consume the auth code (prevents double-spend)
    store::consume_auth_code(code, revision)
        .await
        .map_err(|_| "authorization code already consumed".to_string())?;

    let user = store::get_user(&auth_code.user_id)
        .await?
        .ok_or("user not found")?;

    let nonce = if auth_code.nonce.is_empty() {
        None
    } else {
        Some(auth_code.nonce.as_str())
    };
    let auth_time = if auth_code.auth_time == 0 {
        store::unix_now()
    } else {
        auth_code.auth_time
    };
    let (access_claims, id_claims) = build_claims(
        issuer,
        &user,
        &client.client_id,
        nonce,
        auth_time,
        &auth_code.amr,
        auth_code.acr.as_deref(),
        &auth_code.scope,
        &auth_code.requested_id_token_claims,
        &auth_code.requested_userinfo_claims,
        &auth_code.extra_claims,
        dpop_jkt,
        auth_code.sid.as_deref(),
    )
    .await;

    // Sign tokens via key-manager component
    let access_token = jwt::sign(&access_claims).await?;

    // OIDC Core §3.1.3.6: at_hash is REQUIRED in id_token from the token endpoint
    let mut id_claims = id_claims;
    id_claims["at_hash"] = serde_json::json!(compute_at_hash(&access_token));
    let id_token = jwt::sign_id_token_for_client(&id_claims, client).await?;

    // Create refresh token
    let refresh_raw = store::random_hex(32);
    let refresh_hash = hex_sha256(&refresh_raw);
    let now = store::unix_now();
    let refresh_entry = store::RefreshEntry {
        user_id: user.id,
        client_id: client.client_id.clone(),
        expires_at: now + 86400 * 30,
        scope: auth_code.scope.clone(),
        version: now,
        auth_time,
        amr: auth_code.amr.clone(),
        acr: auth_code.acr.clone(),
        requested_id_token_claims: auth_code.requested_id_token_claims.clone(),
        requested_userinfo_claims: auth_code.requested_userinfo_claims.clone(),
        issued_at: now,
        sid: auth_code.sid.clone(),
    };
    store::save_refresh_token(&refresh_hash, &refresh_entry).await?;

    // Clean up consumed auth code
    let _ = store::delete_auth_code(code).await;

    // Record metrics
    for token_type in ["access", "id_token", "refresh_token"] {
        let _ = crate::service_client::increment_metric(
            "lattice_id_token_issued_total",
            &[
                ("grant_type", "authorization_code"),
                ("token_type", token_type),
            ],
        )
        .await;
    }

    // Only issue refresh token when offline_access scope is present or client is confidential
    let has_offline_access = auth_code.scope.split(' ').any(|s| s == "offline_access")
        || client.client_secret.is_some()
        || client.jwks.is_some();

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
    let mut response = serde_json::json!({
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": 3600,
        "id_token": id_token,
        "scope": auth_code.scope,
    });
    if has_offline_access {
        response["refresh_token"] = serde_json::json!(refresh_raw);
    } else {
        // Clean up the refresh token we just stored — it won't be used
        let _ = store::delete_refresh_token(&refresh_hash).await;
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&response).unwrap_or_default())
        .unwrap())
}

async fn handle_refresh(
    form: &[(String, String)],
    client: &store::OidcClient,
    dpop_jkt: Option<&str>,
    issuer: &str,
) -> Result<Response<String>, String> {
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let refresh_token = get("refresh_token").ok_or("missing refresh_token")?;

    if !client.grant_types.contains(&"refresh_token".to_string()) {
        return Err(format!(
            "client '{}' is not authorized to use grant_type 'refresh_token'",
            client.client_id
        ));
    }

    let refresh_hash = hex_sha256(refresh_token);

    // CAS: get refresh token with revision for atomic consumption
    let (entry, revision) = match store::get_refresh_token_cas(&refresh_hash).await? {
        Some(pair) => pair,
        None => {
            // Replay detection: check if token was previously consumed
            if let Ok(Some(user_id)) = store::get_consumed_refresh(&refresh_hash).await {
                let issuer = store::config_value("issuer_url")
                    .unwrap_or_else(|| "http://localhost".to_string());
                crate::backchannel::notify_all_clients(&user_id, &issuer, None).await;
                let _ = store::revoke_user_sessions(&user_id).await;
                let _ = store::delete_user_refresh_tokens(&user_id).await;
                let _ = crate::service_client::increment_metric(
                    "lattice_id_refresh_usage_total",
                    &[("result", "replay_detected")],
                )
                .await;
                return Err("refresh token replay detected — all sessions revoked".into());
            }
            let _ = crate::service_client::increment_metric(
                "lattice_id_refresh_usage_total",
                &[("result", "invalid")],
            )
            .await;
            return Err("invalid refresh token".into());
        }
    };

    if entry.client_id != client.client_id {
        return Err("client_id mismatch".into());
    }
    let now = store::unix_now();
    if now > entry.expires_at {
        let _ = store::delete_refresh_token(&refresh_hash).await;
        let _ = crate::service_client::increment_metric(
            "lattice_id_refresh_usage_total",
            &[("result", "expired")],
        )
        .await;
        return Err("refresh token expired".into());
    }
    // Enforce absolute lifetime cap (default 90 days from first issuance)
    let absolute_max = store::refresh_absolute_max_secs();
    let family_issued_at = if entry.issued_at > 0 {
        entry.issued_at
    } else {
        now
    };
    if now > family_issued_at + absolute_max {
        let _ = store::delete_refresh_token(&refresh_hash).await;
        let _ = crate::service_client::increment_metric(
            "lattice_id_refresh_usage_total",
            &[("result", "absolute_expired")],
        )
        .await;
        return Err("refresh token family has exceeded maximum lifetime".into());
    }

    // CAS: atomically consume the old refresh token
    store::consume_refresh_token(&refresh_hash, revision)
        .await
        .map_err(|_| "refresh token already consumed".to_string())?;

    let user = store::get_user(&entry.user_id)
        .await?
        .ok_or("user not found")?;

    let auth_time = if entry.auth_time == 0 {
        store::unix_now()
    } else {
        entry.auth_time
    };
    let (access_claims, id_claims) = build_claims(
        issuer,
        &user,
        &client.client_id,
        None,
        auth_time,
        &entry.amr,
        entry.acr.as_deref(),
        &entry.scope,
        &entry.requested_id_token_claims,
        &entry.requested_userinfo_claims,
        &[],
        dpop_jkt,
        entry.sid.as_deref(),
    )
    .await;

    let access_token = jwt::sign(&access_claims).await?;

    // OIDC Core §3.1.3.6: at_hash is REQUIRED in id_token from the token endpoint
    let mut id_claims = id_claims;
    id_claims["at_hash"] = serde_json::json!(compute_at_hash(&access_token));
    let id_token = jwt::sign_id_token_for_client(&id_claims, client).await?;

    // Issue new refresh token
    let new_refresh_raw = store::random_hex(32);
    let new_refresh_hash = hex_sha256(&new_refresh_raw);
    let new_entry = store::RefreshEntry {
        user_id: entry.user_id.clone(),
        client_id: client.client_id.clone(),
        // Sliding window capped at absolute max
        expires_at: (now + 86400 * 30).min(family_issued_at + absolute_max),
        scope: entry.scope.clone(),
        version: entry.version,
        auth_time,
        amr: entry.amr.clone(),
        acr: entry.acr.clone(),
        requested_id_token_claims: entry.requested_id_token_claims.clone(),
        requested_userinfo_claims: entry.requested_userinfo_claims.clone(),
        // Carry original issuance timestamp forward through the family
        issued_at: family_issued_at,
        sid: entry.sid.clone(),
    };
    store::save_refresh_token(&new_refresh_hash, &new_entry).await?;

    // Mark old token as consumed for replay detection, then delete
    store::mark_refresh_consumed(&refresh_hash, &entry.user_id).await?;
    let _ = store::delete_refresh_token(&refresh_hash).await;

    let _ = crate::service_client::increment_metric(
        "lattice_id_refresh_usage_total",
        &[("result", "success")],
    )
    .await;
    for token_type in ["access", "id_token", "refresh_token"] {
        let _ = crate::service_client::increment_metric(
            "lattice_id_token_issued_total",
            &[("grant_type", "refresh_token"), ("token_type", token_type)],
        )
        .await;
    }

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
    let response = serde_json::json!({
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": 3600,
        "id_token": id_token,
        "refresh_token": new_refresh_raw,
        "scope": entry.scope,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&response).unwrap_or_default())
        .unwrap())
}

/// Handle POST /token — client_credentials grant (RFC 6749 §4.4).
/// Issues a machine-to-machine access token; no user identity, no id_token.
async fn handle_client_credentials(
    form: &[(String, String)],
    client: &store::OidcClient,
    dpop_jkt: Option<&str>,
    issuer: &str,
) -> Result<Response<String>, String> {
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let scope = get("scope").unwrap_or("").to_string();

    // Only confidential clients may use client_credentials
    if client.client_secret.is_none() && client.jwks.is_none() {
        return Err("client_credentials grant requires confidential client".into());
    }
    if !client
        .grant_types
        .contains(&"client_credentials".to_string())
    {
        return Err(format!(
            "client '{}' is not authorized to use grant_type 'client_credentials'",
            client.client_id
        ));
    }

    let now = store::unix_now();
    let mut access_claims = serde_json::json!({
        "iss": issuer,
        "sub": client.client_id,
        "aud": client.client_id,
        "exp": now + 3600,
        "nbf": now - 30,
        "iat": now,
        "scope": scope,
        "token_type": "client_credentials",
        "client_id": client.client_id,
    });
    if let Some(jkt) = dpop_jkt {
        access_claims["cnf"] = serde_json::json!({ "jkt": jkt });
    }

    let access_token = jwt::sign(&access_claims).await?;

    let _ = crate::service_client::increment_metric(
        "lattice_id_token_issued_total",
        &[
            ("grant_type", "client_credentials"),
            ("token_type", "access"),
        ],
    )
    .await;

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
    let response = serde_json::json!({
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": 3600,
        "scope": scope,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&response).unwrap_or_default())
        .unwrap())
}

/// Handle POST /token — device_code grant (RFC 8628 §3.4).
/// Client polls here until user approves or the code expires.
async fn handle_device_code(
    form: &[(String, String)],
    client: &store::OidcClient,
    dpop_jkt: Option<&str>,
    issuer: &str,
) -> Result<Response<String>, String> {
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let device_code = get("device_code").ok_or("missing device_code")?;

    // Enforce minimum poll interval (5 s) per RFC 8628 §3.5
    let rate_key = format!("device_poll:{device_code}");
    match crate::service_client::check_rate(&rate_key, 1, 5).await {
        Ok((false, _)) => {
            return Ok(token_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "polling too fast, wait 5 seconds",
            ));
        }
        Err(e) => crate::logger::error_message("rate_limit.device_poll_failed", e),
        _ => {}
    }

    let dc = match store::get_device_code(device_code).await? {
        Some(dc) => dc,
        None => {
            return Ok(token_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device code not found or expired",
            ));
        }
    };

    if dc.client_id != client.client_id {
        return Ok(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        ));
    }
    if store::unix_now() > dc.expires_at {
        let _ = store::delete_device_code(device_code).await;
        return Ok(token_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "device code has expired",
        ));
    }

    match dc.status.as_str() {
        "pending" => Ok(token_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "user has not yet approved the device",
        )),
        "denied" => {
            let _ = store::delete_device_code(device_code).await;
            Ok(token_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "user denied the device request",
            ))
        }
        "approved" => {
            let user_id = dc
                .user_id
                .as_deref()
                .ok_or("approved device code missing user_id")?;
            let user = store::get_user(user_id).await?.ok_or("user not found")?;
            if user.status != "active" {
                return Ok(token_error(
                    StatusCode::BAD_REQUEST,
                    "access_denied",
                    "account not active",
                ));
            }

            let now = store::unix_now();
            let (access_claims, id_claims) = build_claims(
                issuer,
                &user,
                &client.client_id,
                None,
                now,
                &["device".to_string()],
                None,
                &dc.scope,
                &[],
                &[],
                &[],
                dpop_jkt,
                dc.sid.as_deref(),
            )
            .await;

            let access_token = jwt::sign(&access_claims).await?;
            let mut id_claims = id_claims;
            id_claims["at_hash"] = serde_json::json!(compute_at_hash(&access_token));
            let id_token = jwt::sign_id_token_for_client(&id_claims, client).await?;

            // Refresh token — only if offline_access requested
            let has_offline = dc.scope.split(' ').any(|s| s == "offline_access");
            let refresh_raw = store::random_hex(32);
            let refresh_hash = hex_sha256(&refresh_raw);
            let refresh_entry = store::RefreshEntry {
                user_id: user.id.clone(),
                client_id: client.client_id.clone(),
                expires_at: now + 86400 * 30,
                scope: dc.scope.clone(),
                version: now,
                auth_time: now,
                amr: vec!["device".to_string()],
                acr: None,
                requested_id_token_claims: vec![],
                requested_userinfo_claims: vec![],
                issued_at: now,
                sid: dc.sid.clone(),
            };
            store::save_refresh_token(&refresh_hash, &refresh_entry).await?;

            let _ = store::delete_device_code(device_code).await;

            let _ = crate::service_client::increment_metric(
                "lattice_id_token_issued_total",
                &[("grant_type", "device_code"), ("token_type", "access")],
            )
            .await;

            let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
            let mut response = serde_json::json!({
                "access_token": access_token,
                "token_type": token_type,
                "expires_in": 3600,
                "id_token": id_token,
                "scope": dc.scope,
            });
            if has_offline {
                response["refresh_token"] = serde_json::json!(refresh_raw);
            } else {
                let _ = store::delete_refresh_token(&refresh_hash).await;
            }

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("cache-control", "no-store")
                .header("pragma", "no-cache")
                .body(serde_json::to_string(&response).unwrap_or_default())
                .unwrap())
        }
        _ => Ok(token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "unknown device code status",
        )),
    }
}

/// Handle POST /token — token revocation (RFC 7009).
pub async fn handle_revoke(
    body_bytes: &[u8],
    issuer: &str,
    auth_header: Option<&str>,
) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let token = match get("token") {
        Some(t) => t,
        None => {
            return Ok(token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing token parameter",
            ));
        }
    };
    let token_type_hint = get("token_type_hint");

    // Authenticate the client (RFC 7009 §2.1 and RFC 7523).
    let auth_client =
        match crate::client_auth::authenticate_client(&form, auth_header, issuer, "/token/revoke")
            .await
        {
            Ok(ac) => ac,
            Err(_) => {
                return Ok(token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "client authentication failed",
                ));
            }
        };
    let client = auth_client.client;

    // Try to revoke as refresh token first (most common case).
    // Verify that the token was issued to the authenticated client (RFC 7009 §2.1).
    let revoked_refresh = if token_type_hint != Some("access_token") {
        let hash = hex_sha256(token);
        if let Some(entry) = store::get_refresh_token(&hash).await? {
            if entry.client_id == client.client_id {
                store::delete_refresh_token(&hash).await?;
                true
            } else {
                // Per RFC 7009 §2.2, if token belongs to another client, do not revoke.
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Per RFC 7009, always return 200 OK regardless of whether the token was found
    // (to prevent token existence probing).
    if revoked_refresh {
        let _ = store::log_audit("token_revoked", "", &client.client_id, "refresh_token").await;
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap())
}

/// Handle POST /token/introspect — RFC 7662 token introspection.
pub async fn handle_introspect(
    body_bytes: &[u8],
    issuer: &str,
    auth_header: Option<&str>,
) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let token = get("token").ok_or("missing token")?;

    let auth_client = match crate::client_auth::authenticate_client(
        &form,
        auth_header,
        issuer,
        "/token/introspect",
    )
    .await
    {
        Ok(ac) => ac,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/json")
                .header("cache-control", "no-store")
                .header("pragma", "no-cache")
                .header("www-authenticate", "Basic realm=\"token-introspection\"")
                .body(r#"{"error":"invalid_client"}"#.to_string())
                .unwrap());
        }
    };
    let client = auth_client.client;

    if client.client_secret.is_none() && client.jwks.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .header("pragma", "no-cache")
            .header("www-authenticate", "Basic realm=\"token-introspection\"")
            .body(
                r#"{"error":"invalid_client","error_description":"client must be confidential"}"#
                    .to_string(),
            )
            .unwrap());
    }

    match crate::service_client::check_rate(&format!("introspect:{}", client.client_id), 100, 60)
        .await
    {
        Ok((false, _)) => {
            return Ok(json_response(
                StatusCode::TOO_MANY_REQUESTS,
                &serde_json::json!({ "error": "rate_limit_exceeded" }),
            ));
        }
        Err(e) => crate::logger::error_message("rate_limit.introspection_check_failed", e),
        _ => {}
    }

    let response =
        match crate::service_client::verify_token_scoped(token, Some(issuer), None, None).await {
            Ok(claims) => build_introspection_response(&claims),
            Err(_) => serde_json::json!({ "active": false }),
        };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&response).unwrap_or_default())
        .unwrap())
}

fn build_introspection_response(claims: &serde_json::Value) -> serde_json::Value {
    let mut response = serde_json::json!({
        "active": true,
    });

    for key in [
        "iss",
        "sub",
        "exp",
        "iat",
        "nbf",
        "scope",
        "client_id",
        "username",
        "token_type",
        "email",
        "name",
        "tenant_id",
        "role",
        "auth_time",
    ] {
        if let Some(value) = claims.get(key) {
            response[key] = value.clone();
        }
    }

    if let Some(aud) = claims.get("aud") {
        response["aud"] = aud.clone();
        if response.get("client_id").is_none() {
            match aud {
                serde_json::Value::String(value) => {
                    response["client_id"] = serde_json::json!(value)
                }
                serde_json::Value::Array(values) if values.len() == 1 => {
                    if let Some(value) = values[0].as_str() {
                        response["client_id"] = serde_json::json!(value);
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(cnf) = claims.get("cnf") {
        response["cnf"] = cnf.clone();
        response["token_type"] = serde_json::json!("DPoP");
    }

    response
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<String> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(value).unwrap_or_default())
        .unwrap()
}

fn hex_sha256(input: &str) -> String {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute at_hash per OIDC Core §3.1.3.6:
/// base64url(left_half(SHA-256(access_token)))
fn compute_at_hash(access_token: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash[..16])
}

// ── Helpers ──────────────────────────────────────────────────

fn verify_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    if method != "S256" {
        return false;
    }

    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);

    computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
}

#[allow(clippy::too_many_arguments)]
async fn build_claims(
    issuer: &str,
    user: &store::User,
    client_id: &str,
    nonce: Option<&str>,
    auth_time: u64,
    amr: &[String],
    acr: Option<&str>,
    scope: &str,
    requested_id_token_claims: &[String],
    requested_userinfo_claims: &[String],
    extra_claims: &[(String, String)],
    dpop_jkt: Option<&str>,
    sid: Option<&str>,
) -> (serde_json::Value, serde_json::Value) {
    let now = store::unix_now();
    let memberships = store::list_user_tenants(&user.id).await.unwrap_or_default();

    let scopes: Vec<&str> = scope.split_whitespace().collect();
    let has_email_scope =
        scopes.contains(&"email") || requested_id_token_claims.iter().any(|c| c == "email");
    let has_profile_scope =
        scopes.contains(&"profile") || requested_id_token_claims.iter().any(|c| c == "name");

    let email_verified = user.status == "active";
    let mut access_claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id,
        "aud": client_id,
        "exp": now + 3600,
        "nbf": now - 30,
        "iat": now,
        "scope": scope,
        "auth_time": auth_time,
        "token_type": "access",
    });
    if has_email_scope {
        access_claims["email"] = serde_json::json!(user.email);
        access_claims["email_verified"] = serde_json::json!(email_verified);
    }
    if has_profile_scope {
        access_claims["name"] = serde_json::json!(user.name);
    }
    if let Some(jkt) = dpop_jkt {
        access_claims["cnf"] = serde_json::json!({ "jkt": jkt });
    }
    let mut id_claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id,
        "aud": client_id,
        "exp": now + 3600,
        "nbf": now - 30,
        "iat": now,
        "auth_time": auth_time,
    });
    if has_email_scope {
        id_claims["email"] = serde_json::json!(user.email);
        id_claims["email_verified"] = serde_json::json!(email_verified);
    }
    if has_profile_scope {
        id_claims["name"] = serde_json::json!(user.name);
    }
    if let Some(session_id) = sid {
        id_claims["sid"] = serde_json::json!(session_id);
    }

    if let Some(value) = nonce
        && !value.is_empty()
    {
        id_claims["nonce"] = serde_json::json!(value);
    }

    if !amr.is_empty() {
        access_claims["amr"] = serde_json::json!(amr);
        id_claims["amr"] = serde_json::json!(amr);
    }

    if let Some(value) = acr
        && !value.is_empty()
    {
        access_claims["acr"] = serde_json::json!(value);
        id_claims["acr"] = serde_json::json!(value);
    }

    if !requested_userinfo_claims.is_empty() {
        access_claims["lid_userinfo_claims"] = serde_json::json!(requested_userinfo_claims);
    }

    if user.superadmin {
        access_claims["role"] = serde_json::json!("superadmin");
        id_claims["role"] = serde_json::json!("superadmin");
    } else if memberships.len() == 1 {
        let membership = &memberships[0];
        access_claims["tenant_id"] = serde_json::json!(membership.tenant_id);
        access_claims["role"] = serde_json::json!(membership.role);
        id_claims["tenant_id"] = serde_json::json!(membership.tenant_id);
        id_claims["role"] = serde_json::json!(membership.role);
    } else if memberships.len() > 1 {
        let tenants: Vec<serde_json::Value> = memberships
            .iter()
            .map(|membership| {
                serde_json::json!({
                    "tenant_id": membership.tenant_id,
                    "role": membership.role,
                })
            })
            .collect();
        access_claims["tenants"] = serde_json::json!(tenants);
        id_claims["tenants"] = serde_json::json!(tenants);
    }

    // Add requested id_token claims from user profile
    for claim_name in requested_id_token_claims {
        add_derived_profile_claim(&mut id_claims, user, claim_name);
    }

    // Merge custom claims injected by Rhai hooks
    for (key, value) in extra_claims {
        access_claims[key] = serde_json::json!(value);
        id_claims[key] = serde_json::json!(value);
    }

    (access_claims, id_claims)
}

fn add_derived_profile_claim(claims: &mut serde_json::Value, user: &store::User, claim_name: &str) {
    match claim_name {
        "name" => claims["name"] = serde_json::json!(user.name),
        "given_name" => {
            if let Some(value) = user.name.split_whitespace().next()
                && !value.is_empty()
            {
                claims["given_name"] = serde_json::json!(value);
            }
        }
        "family_name" => {
            let mut parts = user.name.split_whitespace();
            let _ = parts.next();
            let remainder = parts.collect::<Vec<_>>().join(" ");
            if !remainder.is_empty() {
                claims["family_name"] = serde_json::json!(remainder);
            }
        }
        "preferred_username" => {
            let preferred = user.email.split('@').next().unwrap_or("");
            if !preferred.is_empty() {
                claims["preferred_username"] = serde_json::json!(preferred);
            }
        }
        "email" => claims["email"] = serde_json::json!(user.email),
        "email_verified" => claims["email_verified"] = serde_json::json!(user.status == "active"),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_at_hash_is_deterministic() {
        let token = "test-access-token";
        let hash1 = super::compute_at_hash(token);
        let hash2 = super::compute_at_hash(token);
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[test]
    fn test_at_hash_differs_for_different_tokens() {
        let hash1 = super::compute_at_hash("token-a");
        let hash2 = super::compute_at_hash("token-b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_at_hash_is_base64url() {
        let hash = super::compute_at_hash("any-token");
        assert!(
            hash.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn test_compute_at_hash_length() {
        // SHA-256 truncates to left half = 16 bytes → base64url → 22 chars (no pad)
        let hash = super::compute_at_hash("test");
        assert_eq!(hash.len(), 22);
    }

    #[test]
    fn test_hex_sha256_is_64_chars() {
        let hash = super::hex_sha256("test-input");
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hex_sha256_is_deterministic() {
        let hash1 = super::hex_sha256("same-input");
        let hash2 = super::hex_sha256("same-input");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hex_sha256_differs_for_different_inputs() {
        let hash1 = super::hex_sha256("input-a");
        let hash2 = super::hex_sha256("input-b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_parse_basic_auth_valid() {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "client-id:client-secret",
        );
        let result = super::parse_basic_auth(Some(&format!("Basic {encoded}")));
        assert_eq!(
            result,
            Some(("client-id".to_string(), "client-secret".to_string()))
        );
    }

    #[test]
    fn test_parse_basic_auth_missing_header() {
        assert!(super::parse_basic_auth(None).is_none());
    }

    #[test]
    fn test_parse_basic_auth_malformed() {
        assert!(super::parse_basic_auth(Some("Bearer token")).is_none());
    }

    #[test]
    fn test_token_error_response_format() {
        let resp = super::token_error(http::StatusCode::BAD_REQUEST, "invalid_grant", "test error");
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = serde_json::from_slice(resp.body().as_bytes()).unwrap();
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(body["error_description"], "test error");
    }

    #[test]
    fn test_verify_pkce_s256_valid() {
        let verifier = "valid-code-verifier-32-chars-minimum-length!!";
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);
        assert!(super::verify_pkce(verifier, &challenge, "S256"));
    }

    #[test]
    fn test_verify_pkce_wrong_verifier() {
        let challenge = "some-challenge-value";
        assert!(!super::verify_pkce("wrong-verifier", challenge, "S256"));
    }

    #[test]
    fn test_verify_pkce_wrong_method() {
        assert!(!super::verify_pkce("verifier", "challenge", "plain"));
    }

    #[test]
    fn test_constant_time_secret_comparison() {
        use subtle::ConstantTimeEq;
        crate::store::init_config_for_test(
            false,
            Some("test_pepper_123456789012345678901234567890"),
        );
        let raw_secret = "sufrb67tompp8k8t32qnzuzi39fktu6f";
        let hmac_hash = crate::store::hmac_client_secret(raw_secret);

        // 1. Matches when stored as HMAC hash
        let computed_hmac = crate::store::hmac_client_secret(raw_secret);
        let matches_hmac: bool = hmac_hash.as_bytes().ct_eq(computed_hmac.as_bytes()).into();
        assert!(matches_hmac);

        // 2. Matches when stored as legacy raw string
        let legacy_stored = raw_secret;
        let matches_legacy: bool = legacy_stored.as_bytes().ct_eq(raw_secret.as_bytes()).into();
        assert!(matches_legacy);

        // 3. Rejects incorrect secret
        let wrong_secret = "wrong_secret_12345678901234567890";
        let wrong_hmac = crate::store::hmac_client_secret(wrong_secret);
        let matches_wrong: bool = hmac_hash.as_bytes().ct_eq(wrong_hmac.as_bytes()).into();
        let matches_wrong_legacy: bool = legacy_stored
            .as_bytes()
            .ct_eq(wrong_secret.as_bytes())
            .into();
        assert!(!matches_wrong && !matches_wrong_legacy);
    }

    #[test]
    fn test_handle_revoke_missing_token() {
        futures::executor::block_on(async {
            crate::store::init_config_for_test(
                false,
                Some("test_pepper_123456789012345678901234567890"),
            );
            let body = b"client_id=test-client";
            let resp = super::handle_revoke(body, "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert_eq!(val["error"], "invalid_request");
        });
    }

    #[test]
    fn test_handle_revoke_missing_client_id() {
        futures::executor::block_on(async {
            crate::store::init_config_for_test(
                false,
                Some("test_pepper_123456789012345678901234567890"),
            );
            let body = b"token=some-token-value";
            let resp = super::handle_revoke(body, "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert_eq!(val["error"], "invalid_client");
        });
    }

    #[test]
    fn test_introspection_response_dpop() {
        let claims = serde_json::json!({
            "sub": "user_123",
            "iss": "https://auth.example.com",
            "aud": "test-client",
            "cnf": {
                "jkt": "0ZcOCORZTXcrgnRlOZjvzcGEQXO9RI1mNVZZY3wu_2k"
            }
        });
        let resp = super::build_introspection_response(&claims);
        assert_eq!(resp["active"], true);
        assert_eq!(resp["token_type"], "DPoP");
        assert_eq!(
            resp["cnf"]["jkt"],
            "0ZcOCORZTXcrgnRlOZjvzcGEQXO9RI1mNVZZY3wu_2k"
        );
    }

    #[test]
    fn test_handle_invalid_dpop_proof() {
        futures::executor::block_on(async {
            let body = b"grant_type=client_credentials&client_id=test-client";
            let resp = super::handle(
                body,
                "https://auth.example.com",
                None,
                Some("invalid.dpop.jwt"),
            )
            .await
            .unwrap();
            assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert_eq!(val["error"], "invalid_dpop_proof");
        });
    }

    #[test]
    fn test_build_claims_scope_gating() {
        futures::executor::block_on(async {
            let user = crate::store::User {
                id: "user-123".into(),
                email: "alice@example.com".into(),
                name: "Alice Smith".into(),
                password_hash: "hash".into(),
                status: "active".into(),
                created_at: 1000,
                superadmin: false,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: vec![],
                passkey_credentials: vec![],
            };

            // Case 1: scope = "openid" only (no email, no profile)
            let (access_claims, id_claims) = super::build_claims(
                "https://auth.example.com",
                &user,
                "test-client",
                Some("test-nonce"),
                1000,
                &[],
                None,
                "openid",
                &[],
                &[],
                &[],
                None,
                Some("test-session-id"),
            )
            .await;

            assert_eq!(id_claims["sub"], "user-123");
            assert_eq!(id_claims["sid"], "test-session-id");
            assert!(
                id_claims.get("email").is_none(),
                "email must not be in id_token without email scope"
            );
            assert!(
                id_claims.get("name").is_none(),
                "name must not be in id_token without profile scope"
            );
            assert!(
                access_claims.get("email").is_none(),
                "email must not be in access_token without email scope"
            );
            assert!(
                access_claims.get("name").is_none(),
                "name must not be in access_token without profile scope"
            );

            // Case 2: scope = "openid email profile"
            let (access_claims2, id_claims2) = super::build_claims(
                "https://auth.example.com",
                &user,
                "test-client",
                Some("test-nonce"),
                1000,
                &[],
                None,
                "openid email profile",
                &[],
                &[],
                &[],
                None,
                Some("test-session-id"),
            )
            .await;

            assert_eq!(id_claims2["email"], "alice@example.com");
            assert_eq!(id_claims2["email_verified"], true);
            assert_eq!(id_claims2["name"], "Alice Smith");
            assert_eq!(id_claims2["sid"], "test-session-id");
            assert_eq!(access_claims2["email"], "alice@example.com");
            assert_eq!(access_claims2["name"], "Alice Smith");
        });
    }
}
