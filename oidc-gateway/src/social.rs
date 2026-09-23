//! Generic OIDC federation — supports any standards-compliant OIDC provider.
//!
//! Configured via `IdentityProvider` records with `provider_type = "generic-oidc"`
//! and a `discovery_url` pointing to the provider's
//! `/.well-known/openid-configuration` endpoint.
//!
//! Google continues to use its own `google.rs` handler, but can also be
//! configured here via its discovery URL for custom applications that prefer
//! the generic path.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Response, StatusCode};
use num_bigint_dig::BigUint;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;

use crate::{store, util};

/// Handle GET /auth/social/{provider_id}?session_id=...
/// Redirects the user to the external provider's authorization endpoint.
pub async fn start(
    provider_id: &str,
    query: &str,
    issuer: &str,
) -> Result<Response<String>, String> {
    let params = util::parse_query(query);
    let session_id = params
        .iter()
        .find(|(k, _)| k == "session_id")
        .map(|(_, v)| v.as_str())
        .ok_or("missing session_id")?;

    let session = store::get_auth_session(session_id)
        .await?
        .ok_or("invalid or expired session")?;
    if store::unix_now() > session.created_at + 600 {
        return Err("auth session expired".into());
    }

    let idp = store::get_identity_provider(provider_id)
        .await?
        .ok_or_else(|| format!("identity provider '{provider_id}' not configured"))?;

    if !idp.enabled {
        return Err(format!("identity provider '{provider_id}' is disabled"));
    }

    let discovery_url = idp
        .discovery_url
        .as_deref()
        .ok_or("identity provider missing discovery_url")?;
    util::is_safe_external_url(discovery_url)
        .map_err(|e| format!("insecure discovery_url: {e}"))?;

    let discovery = fetch_discovery(discovery_url).await?;

    let auth_endpoint = discovery
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or("missing authorization_endpoint in provider discovery")?;
    util::is_safe_external_url(auth_endpoint)
        .map_err(|e| format!("insecure authorization_endpoint: {e}"))?;

    let csrf_token = store::random_hex(16);
    store::save_social_csrf(&csrf_token, session_id).await?;

    let callback_url = format!("{issuer}/auth/social/{provider_id}/callback");
    let mut auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={csrf_token}&prompt=select_account",
        auth_endpoint,
        util::percent_encode(&idp.client_id),
        util::percent_encode(&callback_url),
    );

    if !session.nonce.is_empty() {
        auth_url.push_str("&nonce=");
        auth_url.push_str(&util::percent_encode(&session.nonce));
    }

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &auth_url)
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap())
}

/// Handle GET /auth/social/{provider_id}/callback?code=...&state=...
pub async fn callback(
    provider_id: &str,
    query: &str,
    issuer: &str,
    remote_ip: &str,
) -> Result<Response<String>, String> {
    let params = util::parse_query(query);
    let get = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    let code = get("code").ok_or("missing code from provider")?;
    let state = get("state").ok_or("missing state")?;

    // Resolve CSRF → session_id (single-use)
    let session_id = store::consume_social_csrf(state)
        .await?
        .ok_or("invalid or expired OAuth state")?;

    let session = store::get_auth_session(&session_id)
        .await?
        .ok_or("invalid or expired session")?;
    if store::unix_now() > session.created_at + 600 {
        return Ok(crate::login::login_page(
            &session_id,
            Some("Auth session expired. Please start over."),
        )
        .await);
    }

    if let Some(error) = get("error") {
        return Ok(crate::login::login_page(
            &session_id,
            Some(&format!("Social login failed: {error}")),
        )
        .await);
    }

    let idp = store::get_identity_provider(provider_id)
        .await?
        .ok_or_else(|| format!("identity provider '{provider_id}' not configured"))?;

    let discovery_url = idp
        .discovery_url
        .as_deref()
        .ok_or("identity provider missing discovery_url")?;
    util::is_safe_external_url(discovery_url)
        .map_err(|e| format!("insecure discovery_url: {e}"))?;
    let discovery = fetch_discovery(discovery_url).await?;

    let token_endpoint = discovery
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or("missing token_endpoint in provider discovery")?;
    util::is_safe_external_url(token_endpoint)
        .map_err(|e| format!("insecure token_endpoint: {e}"))?;

    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or("missing jwks_uri in provider discovery")?;
    util::is_safe_external_url(jwks_uri).map_err(|e| format!("insecure jwks_uri: {e}"))?;

    let expected_issuer = discovery
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or("missing issuer in provider discovery")?;

    let callback_url = format!("{issuer}/auth/social/{provider_id}/callback");
    let token_body = format!(
        "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
        util::percent_encode(code),
        util::percent_encode(&idp.client_id),
        util::percent_encode(&idp.client_secret),
        util::percent_encode(&callback_url),
    );

    let (status, token_response) =
        crate::http_client::post_form_json(token_endpoint, &token_body).await?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "token exchange with provider returned HTTP {status}"
        ));
    }

    let id_token_str = token_response
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or("missing id_token from provider token response")?;

    let jwks = crate::http_client::get_json(jwks_uri, &[])
        .await
        .map_err(|e| format!("failed to fetch provider JWKS: {e}"))?;

    let provider_claims = verify_id_token(
        id_token_str,
        expected_issuer,
        &idp.client_id,
        &session.nonce,
        &jwks,
    )?;

    let provider_sub = provider_claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or("missing sub in provider id_token")?;
    let provider_email = provider_claims
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or("missing email in provider id_token")?;
    let provider_name = provider_claims
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(provider_email);
    let email_verified = provider_claims
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !email_verified {
        return Ok(crate::login::login_page(
            &session_id,
            Some("Provider account email is not verified"),
        )
        .await);
    }

    let provider_label = provider_id.to_string();

    let user = if let Some(si) = store::get_social_identity(provider_id, provider_sub).await? {
        store::get_user(&si.user_id)
            .await?
            .ok_or("linked user not found")?
    } else if let Some(existing_user) = store::get_user_by_email(provider_email).await? {
        let si = store::SocialIdentity {
            provider: provider_id.to_string(),
            provider_sub: provider_sub.to_string(),
            user_id: existing_user.id.clone(),
            email: provider_email.to_string(),
            linked_at: store::unix_now(),
        };
        store::save_social_identity(&si).await?;
        let _ = store::log_audit(
            "social_identity_linked",
            &existing_user.id,
            &existing_user.id,
            &provider_label,
        )
        .await;
        existing_user
    } else {
        if !crate::is_registration_allowed().await {
            return Ok(crate::login::login_page(
                &session_id,
                Some("Registration is currently closed"),
            )
            .await);
        }

        let password_hash = format!("social:{provider_id}:{provider_sub}");
        let mut user = store::User {
            id: store::random_hex(16),
            email: provider_email.to_string(),
            name: provider_name.to_string(),
            password_hash,
            status: "active".to_string(),
            created_at: store::unix_now(),
            superadmin: false,
            totp_secret: None,
            totp_enabled: false,
            recovery_codes: Vec::new(),
            passkey_credentials: Vec::new(),
        };
        store::create_user(&user).await?;

        let si = store::SocialIdentity {
            provider: provider_id.to_string(),
            provider_sub: provider_sub.to_string(),
            user_id: user.id.clone(),
            email: provider_email.to_string(),
            linked_at: store::unix_now(),
        };
        store::save_social_identity(&si).await?;
        let _ = store::log_audit(
            "user_registered_social",
            &user.id,
            &user.id,
            &provider_label,
        )
        .await;

        let boot = crate::hooks::execute_bootstrap_hook(&user).await;
        if let Some(reason) = &boot.deny_reason {
            let _ = store::log_audit(
                "registration_denied_by_bootstrap_hook",
                &user.id,
                &user.id,
                reason,
            )
            .await;
            return Ok(crate::login::login_page(&session_id, Some(reason)).await);
        }
        if let Err(e) = crate::hooks::apply_outcome(&mut user, &boot).await {
            crate::logger::error_message("bootstrap_hook.apply_failed", e);
        }

        let outcome = crate::hooks::execute_hooks("post-registration", &user).await;
        if let Some(reason) = &outcome.deny_reason {
            let _ =
                store::log_audit("registration_denied_by_hook", &user.id, &user.id, reason).await;
            return Ok(crate::login::login_page(&session_id, Some(reason)).await);
        }
        if let Err(e) = crate::hooks::apply_outcome(&mut user, &outcome).await {
            crate::logger::error_message("hooks.apply_failed", e);
        }

        user
    };

    if user.status != "active" {
        return Ok(crate::login::login_page(&session_id, Some("Account is not active")).await);
    }

    if user.totp_enabled {
        let mfa_token = store::random_hex(32);
        let pending = store::MfaPending {
            user_id: user.id.clone(),
            session_id: session_id.to_string(),
            primary_amr: Vec::new(),
            expires_at: store::unix_now() + 300,
            remote_ip: remote_ip.to_string(),
        };
        store::save_mfa_pending(&mfa_token, &pending).await?;
        return Ok(crate::login::mfa_page(&mfa_token, &session_id, None).await);
    }

    let _ = store::log_audit("login_success", &user.id, &user.id, &provider_label).await;
    crate::login::complete_login(&user, &session_id, provider_id, remote_ip).await
}

// ── Discovery document helpers ──────────────────────────────

/// Fetch and parse an OIDC discovery document.
async fn fetch_discovery(discovery_url: &str) -> Result<serde_json::Value, String> {
    crate::http_client::get_json(discovery_url, &[])
        .await
        .map_err(|e| format!("failed to fetch OIDC discovery from {discovery_url}: {e}"))
}

// ── id_token verification ────────────────────────────────────

/// Verify a provider's id_token: signature, iss, aud, exp, nonce.
/// Supports RS256 and ES256 keys in the provider JWKS.
fn verify_id_token(
    token: &str,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
    jwks: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }

    let header = decode_jwt_segment(parts[0], "header")?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let kid = header.get("kid").and_then(|v| v.as_str());

    match alg {
        "RS256" => verify_rs256(token, kid, jwks)?,
        "ES256" => verify_es256(token, kid, jwks)?,
        _ => return Err(format!("unsupported algorithm in provider token: {alg}")),
    }

    let claims = decode_jwt_segment(parts[1], "payload")?;
    validate_claims(&claims, expected_issuer, expected_audience, expected_nonce)?;
    Ok(claims)
}

fn verify_rs256(token: &str, kid: Option<&str>, jwks: &serde_json::Value) -> Result<(), String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("signature decode: {e}"))?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("bad RS256 signature: {e}"))?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or("invalid JWKS response")?;

    let candidates: Vec<&serde_json::Value> = keys
        .iter()
        .filter(|k| k.get("kty").and_then(|v| v.as_str()) == Some("RSA"))
        .filter(|k| kid.is_none() || k.get("kid").and_then(|v| v.as_str()) == kid)
        .collect();

    if candidates.is_empty() {
        return Err("no matching RSA key in provider JWKS".into());
    }

    for jwk in candidates {
        let n = decode_biguint(jwk.get("n").and_then(|v| v.as_str()).ok_or("missing n")?)?;
        let e = decode_biguint(jwk.get("e").and_then(|v| v.as_str()).ok_or("missing e")?)?;
        let pub_key =
            RsaPublicKey::new(n, e).map_err(|e| format!("invalid provider RSA key: {e}"))?;
        let verifier = VerifyingKey::<Sha256>::new(pub_key);
        if verifier.verify(message.as_bytes(), &sig).is_ok() {
            return Ok(());
        }
    }
    Err("provider RS256 signature verification failed".into())
}

fn verify_es256(token: &str, kid: Option<&str>, jwks: &serde_json::Value) -> Result<(), String> {
    use p256::ecdsa::{
        Signature as EcSig, VerifyingKey as EcVerifyingKey, signature::Verifier as EcVerifier,
    };

    let parts: Vec<&str> = token.splitn(3, '.').collect();
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("ES256 signature decode: {e}"))?;
    let sig = EcSig::from_der(&sig_bytes)
        .or_else(|_| EcSig::from_bytes(sig_bytes.as_slice().into()))
        .map_err(|e| format!("bad ES256 signature: {e}"))?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or("invalid JWKS response")?;

    let candidates: Vec<&serde_json::Value> = keys
        .iter()
        .filter(|k| k.get("kty").and_then(|v| v.as_str()) == Some("EC"))
        .filter(|k| k.get("crv").and_then(|v| v.as_str()) == Some("P-256"))
        .filter(|k| kid.is_none() || k.get("kid").and_then(|v| v.as_str()) == kid)
        .collect();

    if candidates.is_empty() {
        return Err("no matching EC P-256 key in provider JWKS".into());
    }

    for jwk in candidates {
        let x = URL_SAFE_NO_PAD
            .decode(jwk.get("x").and_then(|v| v.as_str()).unwrap_or(""))
            .map_err(|e| format!("decode x: {e}"))?;
        let y = URL_SAFE_NO_PAD
            .decode(jwk.get("y").and_then(|v| v.as_str()).unwrap_or(""))
            .map_err(|e| format!("decode y: {e}"))?;

        // Uncompressed EC point: 0x04 || x || y
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);

        if let Ok(vk) = EcVerifyingKey::from_sec1_bytes(&point)
            && EcVerifier::verify(&vk, message.as_bytes(), &sig).is_ok()
        {
            return Ok(());
        }
    }
    Err("provider ES256 signature verification failed".into())
}

fn validate_claims(
    claims: &serde_json::Value,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<(), String> {
    let issuer = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    if issuer != expected_issuer {
        return Err(format!(
            "invalid issuer: got {issuer}, expected {expected_issuer}"
        ));
    }

    let audience_ok = match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => aud == expected_audience,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|v| v.as_str() == Some(expected_audience))
        }
        _ => false,
    };
    if !audience_ok {
        return Err("invalid audience in provider id_token".into());
    }

    let now = store::unix_now();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or("missing exp")?;
    if now > exp + 30 {
        return Err("provider id_token expired".into());
    }

    if !expected_nonce.is_empty() {
        let nonce = claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or("missing nonce")?;
        if nonce != expected_nonce {
            return Err("provider id_token nonce mismatch".into());
        }
    }

    Ok(())
}

fn decode_jwt_segment(part: &str, label: &str) -> Result<serde_json::Value, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| format!("decode {label}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {label}: {e}"))
}

fn decode_biguint(value: &str) -> Result<BigUint, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| format!("base64 decode JWK integer: {e}"))?;
    Ok(BigUint::from_bytes_be(&bytes))
}
