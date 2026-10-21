//! User-account mutations shared by the management API and the admin panel.

use base64::Engine;

use crate::error::ApiError;
use crate::store::{self, Invitation, User};

use super::authz::Caller;

/// Activate a user account. Superadmin only (admin-panel operation).
pub async fn activate_user(caller: &Caller, user_id: &str) -> Result<(), ApiError> {
    caller.require_superadmin()?;

    let mut user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    user.status = "active".to_string();
    store::update_user(&user)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "user_activated_by_admin",
        &caller.user_id,
        &user.id,
        &format!("admin={}", caller.user_id),
    )
    .await;

    Ok(())
}

/// Permanently delete a user and all associated first-party data (GDPR Art. 17).
/// Accessible by the user themselves or a superadmin. A superadmin cannot
/// delete themselves this way (use the deactivation path).
pub async fn delete_user(caller: &Caller, user_id: &str) -> Result<User, ApiError> {
    caller.require_self_or_superadmin(user_id)?;

    // Prevent superadmin self-deletion through the API to avoid accidental lockout
    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if user.superadmin && caller.user_id == user_id {
        return Err("superadmin cannot delete their own account; transfer superadmin first".into());
    }

    // Revoke all active sessions and refresh tokens
    let _ = store::delete_user_refresh_tokens(user_id).await;
    let _ = store::revoke_user_sessions(user_id).await;

    // Perform deletion (users record + email index + memberships)
    store::delete_user(user_id)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit("user_deleted", &caller.user_id, user_id, "gdpr_erasure").await;

    Ok(user)
}

/// Initiate a password reset: create a reset token and send the reset email.
/// Rate limited to 3 per hour per user. Self or superadmin.
pub async fn initiate_password_reset(caller: &Caller, user_id: &str) -> Result<User, ApiError> {
    caller.require_self_or_superadmin(user_id)?;

    // Rate limit password reset initiation: 3 per hour per user_id
    match crate::service_client::check_rate(&format!("reset_init:{}", user_id), 3, 3600).await {
        Ok((false, _)) => {
            return Err(ApiError::too_many(
                "too many reset requests. please try again later.",
            ));
        }
        Err(e) => crate::logger::error_message("rate_limit.password_reset_init_check_failed", e),
        _ => {}
    }

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;

    let reset_token = store::random_hex(32);
    // Store as a short-lived invitation-like entry
    let inv = Invitation {
        tenant_id: String::new(),
        email: user.email.clone(),
        role: "password_reset".to_string(),
        token: reset_token.clone(),
        invited_by: if caller.user_id.is_empty() {
            "system".to_string()
        } else {
            caller.user_id.clone()
        },
        expires_at: store::unix_now() + 3600, // 1 hour
    };
    store::save_invitation(&inv)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "password_reset_initiated",
        &caller.user_id,
        user_id,
        &user.email,
    )
    .await;

    // Publish password reset email event
    crate::email::send_password_reset_email(
        &crate::get_issuer(),
        &user.email,
        &user.name,
        &reset_token,
    )
    .await;

    Ok(user)
}

/// Disable MFA for a user: clears the TOTP secret and recovery codes and
/// revokes all sessions/tokens. Self or superadmin.
pub async fn disable_mfa(caller: &Caller, user_id: &str) -> Result<(), ApiError> {
    caller.require_self_or_superadmin(user_id)?;

    store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    store::update_user_rmw(user_id, |u| {
        u.totp_secret = None;
        u.totp_enabled = false;
        u.recovery_codes.clear();
        Ok(true)
    })
    .await
    .map_err(ApiError::internal)?;

    // Revoke all sessions/tokens on MFA disable
    let _ = store::delete_user_refresh_tokens(user_id).await;
    let _ = store::revoke_user_sessions(user_id).await;

    let _ = store::log_audit("mfa_disabled", &caller.user_id, user_id, "tokens revoked").await;

    Ok(())
}

/// Remove a registered passkey from a user. Self or superadmin.
pub async fn delete_passkey(caller: &Caller, user_id: &str, cred_id: &str) -> Result<(), ApiError> {
    caller.require_self_or_superadmin(user_id)?;

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if !user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == cred_id)
    {
        return Err(ApiError::not_found("passkey not found"));
    }
    let cred_id_owned = cred_id.to_string();
    store::update_user_rmw(user_id, |u| {
        u.passkey_credentials
            .retain(|c| c.credential_id != cred_id_owned);
        Ok(true)
    })
    .await
    .map_err(ApiError::internal)?;

    // Remove from index
    let _ = store::unindex_passkey_credential(cred_id).await;

    let _ = store::log_audit("passkey_deleted", &caller.user_id, user_id, cred_id).await;

    Ok(())
}

// ── Passkey registration ────────────────────────────────────

/// Begin passkey registration for a user: creates the WebAuthn challenge and
/// returns (challenge token, `PublicKeyCredentialCreationOptions` JSON).
/// Self or superadmin.
pub async fn passkey_register_options(
    caller: &Caller,
    user_id: &str,
) -> Result<(String, serde_json::Value), ApiError> {
    caller.require_self_or_superadmin(user_id)?;

    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;

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
    store::save_passkey_challenge(&token, &pc)
        .await
        .map_err(ApiError::internal)?;

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

    Ok((token, options))
}

/// Fields for finishing passkey registration (JSON body of both surfaces).
pub struct PasskeyRegisterCompleteParams {
    pub token: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub name: String,
}

/// Finish passkey registration: consumes the challenge, verifies the
/// attestation, stores the credential, and indexes it for discoverable
/// lookup. Returns (credential_id, display name). Self or superadmin.
pub async fn passkey_register_complete(
    caller: &Caller,
    user_id: &str,
    params: PasskeyRegisterCompleteParams,
) -> Result<(String, String), ApiError> {
    caller.require_self_or_superadmin(user_id)?;

    // Atomically consume and validate the challenge
    let pc = store::consume_passkey_challenge(&params.token)
        .await
        .map_err(ApiError::internal)?
        .ok_or("invalid or expired registration token")?;
    if pc.purpose != "register" || pc.user_id != user_id {
        return Err("token mismatch".into());
    }
    if store::unix_now() > pc.expires_at {
        return Err("registration token expired".into());
    }

    let issuer = crate::get_issuer();

    let parsed = crate::passkeys::verify_registration(
        &params.client_data_json,
        &params.attestation_object,
        &pc.challenge,
        &issuer,
    )?;

    let credential_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.credential_id);
    let public_key =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.public_key_bytes);

    // Check for duplicate across any user in the global passkey index
    let user = store::get_user(user_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == credential_id)
        || store::get_user_by_passkey(&credential_id)
            .await
            .map_err(ApiError::internal)?
            .is_some()
    {
        return Err(ApiError::conflict("this passkey is already registered"));
    }

    let name = if params.name.is_empty() {
        format!("Passkey {}", user.passkey_credentials.len() + 1)
    } else {
        params.name
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
    .await
    .map_err(ApiError::internal)?;

    // Index for discoverable-credential lookup
    store::index_passkey_credential(&credential_id, user_id)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit("passkey_registered", &caller.user_id, user_id, &name).await;

    Ok((credential_id, name))
}
