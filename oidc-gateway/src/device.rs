//! RFC 8628 — OAuth 2.0 Device Authorization Grant.
//!
//! # Flow
//!
//! 1. Device: POST /device_authorization → (device_code, user_code, verification_uri)
//!    Confidential clients MUST authenticate (RFC 8628 §3.1, RFC 6749 §2.3).
//! 2. User: GET /device → simple HTML form; enters user_code
//! 3. User: authenticates normally via the existing login page
//!    (the auth session carries a device_code reference)
//! 4. User: sees an explicit confirmation page (client name + user_code) and
//!    approves or denies; approval requires a single-use approval token bound
//!    to the device auth session
//! 5. Device: polls POST /token with grant_type=urn:…:device_code until approved
//!
//! Device codes expire after 5 minutes.
//! Polling interval is enforced at 5 seconds via rate limiting in token.rs.

use crate::{store, util};
use http::{Response, StatusCode};

/// JSON error body for the machine-facing /device_authorization endpoint.
fn json_error(status: StatusCode, error: &str, description: &str) -> Response<String> {
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(serde_json::to_string(&body).unwrap_or_default())
        .unwrap()
}

/// POST /device_authorization — RFC 8628 §3.1.
pub async fn start(
    body_bytes: &[u8],
    issuer: &str,
    auth_header: Option<&str>,
) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

    // client_id comes from the form, or from the Basic authorization header
    // (RFC 6749 §2.3.1) when the client authenticates via client_secret_basic.
    let client_id = get("client_id")
        .map(str::to_string)
        .or_else(|| crate::client_auth::parse_basic_auth(auth_header).map(|(id, _)| id))
        .ok_or("missing client_id")?;
    let scope = get("scope").unwrap_or("openid email").to_string();

    // Rate limit: 20 device authorization requests per client_id per hour.
    // Fail closed on limiter errors: this endpoint mints user-codes that drive
    // a browser flow, so a broken limiter must not silently allow spraying.
    match crate::service_client::check_rate(&format!("device_authorization:{client_id}"), 20, 3600)
        .await
    {
        Ok((false, _)) => {
            return Ok(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "too many device authorization requests. please try again later.",
            ));
        }
        Err(e) => {
            crate::logger::error_message("rate_limit.device_authorization_check_failed", e);
            return Ok(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "too many device authorization requests. please try again later.",
            ));
        }
        _ => {}
    }

    if client_id == "lid-admin" {
        let _ = store::ensure_admin_client(issuer, false).await;
    }

    // RFC 8628 §3.1: the client authentication requirements of RFC 6749 §2.3
    // apply — confidential clients MUST authenticate. The same authenticator as
    // the token endpoint is used (client_secret_basic via the Authorization
    // header, client_secret_post / private_key_jwt via form parameters, "none"
    // for public clients).
    let auth = match crate::client_auth::authenticate_client(
        &form,
        auth_header,
        issuer,
        "/device_authorization",
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // Log the detail server-side; the client sees a generic message that
            // lib.rs maps to "invalid_client" (no client-existence leak).
            crate::logger::warn(
                "device_authorization.client_auth_failed",
                serde_json::json!({ "error": e }),
            );
            return Err("client authentication failed".into());
        }
    };
    let client = auth.client;

    // Defense in depth: a client that has a secret, registered JWKS, or a
    // non-"none" auth method must never be treated as public on this endpoint.
    let is_confidential = client.client_secret.is_some()
        || client.jwks.is_some()
        || client
            .token_endpoint_auth_method
            .as_deref()
            .is_some_and(|m| m != "none");
    if is_confidential && auth.auth_method == "none" {
        crate::logger::warn(
            "device_authorization.client_auth_failed",
            serde_json::json!({ "error": "confidential client presented no credentials" }),
        );
        return Err("client authentication failed".into());
    }

    if !client
        .grant_types
        .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string())
    {
        return Err(format!(
            "client '{}' is not authorized to use the device authorization grant",
            client.client_id
        ));
    }

    let device_code = store::random_hex(32);
    // Display form has a hyphen for human readability ("XXXX-XXXX") but the
    // canonical lookup key is the hyphen-stripped uppercase form so users can
    // type it either way (with/without separator).
    let user_code_display = generate_user_code();
    let user_code = user_code_display.replace('-', "");
    let expires_in: u64 = 300; // 5 minutes
    let interval: u64 = 5;

    let dc = store::DeviceCode {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: client.client_id.clone(),
        scope: scope.clone(),
        expires_at: store::unix_now() + expires_in,
        status: "pending".to_string(),
        user_id: None,
        sid: None,
    };
    store::save_device_code(&dc).await?;

    let verification_uri = format!("{issuer}/device");
    let verification_uri_complete = format!(
        "{issuer}/device?user_code={}",
        util::percent_encode(&user_code_display)
    );

    let response = serde_json::json!({
        "device_code": device_code,
        "user_code": user_code_display,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": expires_in,
        "interval": interval,
    });

    let _ = crate::service_client::increment_metric(
        "lattice_id_device_auth_total",
        &[("client_id", &client.client_id)],
    )
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&response).unwrap_or_default())
        .unwrap())
}

/// GET /device[?user_code=...] — HTML page where the user enters their user code.
pub async fn page(query: &str) -> Response<String> {
    let theme = crate::theme::resolve_global_theme().await;
    let params = util::parse_query(query);
    let prefilled_code = params
        .iter()
        .find(|(k, _)| k == "user_code")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    render_device_page(prefilled_code, None, &theme)
}

fn render_device_page(
    prefilled_code: &str,
    error: Option<&str>,
    theme: &store::ClientTheme,
) -> Response<String> {
    let app_name = util::html_escape(&theme.app_name);
    let head_tags = crate::theme::render_head_tags(theme);
    let css_vars = crate::theme::render_css_variables(theme);
    let logo_html = crate::theme::render_logo(theme);
    let footer_html = crate::theme::render_footer(theme, None);

    let error_html = match error {
        Some(e) => format!(r#"<div class="error">{}</div>"#, util::html_escape(e)),
        None => String::new(),
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device Activation — {app_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body {{ font-family: var(--font-family); background: var(--bg); color: var(--text); display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; padding:20px; }}
.card {{ background: var(--card-bg); border: var(--card-border); box-shadow: var(--card-shadow); backdrop-filter: blur(var(--card-backdrop-blur)); -webkit-backdrop-filter: blur(var(--card-backdrop-blur)); border-radius: var(--radius); padding:40px; max-width:420px; width:100%; }}
h1 {{ font-size:1.5rem; font-weight:700; color:var(--text); margin-bottom:8px; }}
p {{ color:var(--text-muted); margin-bottom:24px; font-size:.95rem; }}
input {{ width:100%; box-sizing:border-box; padding:14px; border:1px solid var(--input-border); border-radius:calc(var(--radius) * 0.7); background:var(--input-bg); color:var(--input-text); font-size:1.4rem; letter-spacing:.3em; text-align:center; text-transform:uppercase; outline:none; transition:all .15s ease; }}
input:focus {{ border-color:var(--primary); box-shadow:0 0 0 3px rgba(16,185,129,.25); }}
button {{ width:100%; margin-top:20px; padding:14px; border:none; border-radius:calc(var(--radius) * 0.7); background:var(--primary); color:var(--button-text); font-size:1rem; font-weight:600; cursor:pointer; transition:all .15s ease; }}
button:hover {{ background:var(--primary-hover); transform:translateY(-1px); }}
.error {{ background:rgba(239,68,68,.15); border:1px solid rgba(239,68,68,.3); color:#ef4444; border-radius:calc(var(--radius) * 0.6); padding:10px 14px; margin-top:16px; font-size:.9rem; text-align:center; }}
</style>
</head>
<body>
<div class="card">
  {logo_html}
  <h1>Device Activation</h1>
  <p>Enter the code displayed on your device to sign in to {app_name}.</p>
  <form method="POST" action="/device">
    <input type="text" name="user_code" value="{prefilled_code}" placeholder="XXXX-XXXX" autocomplete="off" spellcheck="false" maxlength="9" required>
    <button type="submit">Continue</button>
  </form>
  {error_html}
  {footer_html}
</div>
</body>
</html>"#,
        prefilled_code = util::html_escape(prefilled_code),
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// POST /device — either a user_code submission (start of the browser leg) or
/// an approve/deny decision from the device confirmation page.
pub async fn submit(body_bytes: &[u8], issuer: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

    // Confirmation page posts carry an approval token instead of a user code.
    if get("approval_token").is_some() {
        return handle_confirmation(&form).await;
    }

    let user_code = get("user_code")
        .ok_or("missing user_code")?
        .trim()
        .to_uppercase()
        .replace(['-', ' '], "");

    // Rate limit per user_code: 5 attempts per 15 minutes, fail closed.
    // When the limit is exceeded the underlying device request is denied so a
    // polling attacker device stops and the flow must be restarted.
    match crate::service_client::check_rate(&format!("device_user_code:{user_code}"), 5, 900).await
    {
        Ok((false, _)) => {
            if let Some(dc) = store::get_device_code_by_user_code(&user_code).await?
                && dc.status == "pending"
            {
                let _ =
                    store::update_device_code_status(&dc.device_code, "denied", None, None).await;
                let _ = store::log_audit(
                    "device_code_locked",
                    "",
                    &dc.client_id,
                    "user_code locked after too many attempts",
                )
                .await;
            }
            let theme = crate::theme::resolve_global_theme().await;
            return Ok(render_device_page(
                "",
                Some("Too many attempts. Please restart the sign-in on your device."),
                &theme,
            ));
        }
        Err(e) => {
            crate::logger::error_message("rate_limit.device_user_code_check_failed", e);
            let theme = crate::theme::resolve_global_theme().await;
            return Ok(render_device_page(
                "",
                Some("Too many attempts. Please wait and try again."),
                &theme,
            ));
        }
        _ => {}
    }

    let dc = store::get_device_code_by_user_code(&user_code)
        .await?
        .ok_or_else(|| "invalid or expired user code".to_string())?;

    let theme = crate::theme::resolve_global_theme().await;

    if store::unix_now() > dc.expires_at {
        return Ok(render_device_page(
            "",
            Some("Code has expired. Please restart on your device."),
            &theme,
        ));
    }
    if dc.status != "pending" {
        return Ok(render_device_page(
            "",
            Some("This code has already been used."),
            &theme,
        ));
    }

    // Create a normal OIDC auth session that also carries the device_code.
    // After login completes, the user lands on an explicit confirmation page;
    // the device code is only approved from there.
    let session_id = store::random_hex(32);
    let session = store::AuthSession {
        client_id: dc.client_id.clone(),
        redirect_uri: format!("{issuer}/device/complete"),
        code_challenge: String::new(),
        code_challenge_method: "device".to_string(), // sentinel: device flow
        state: dc.device_code.clone(),               // carry device_code in state
        scope: dc.scope.clone(),
        nonce: String::new(),
        max_age: None,
        acr_values: Vec::new(),
        requested_id_token_claims: Vec::new(),
        requested_userinfo_claims: Vec::new(),
        hinted_user_id: None,
        hinted_email: None,
        created_at: store::unix_now(),
        needs_consent: false,
        prompt: None,
        sid: Some(store::random_hex(16)),
    };
    store::save_auth_session(&session_id, &session).await?;

    // Redirect to the login page with browser-binding flow cookie
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", format!("/login?session_id={session_id}"))
        .header(
            "set-cookie",
            crate::account::create_flow_cookie(&session_id),
        )
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap())
}

/// Display form of a stored (hyphen-stripped) user code: "XXXX-XXXX".
fn display_user_code(user_code: &str) -> String {
    if user_code.len() == 8 {
        format!("{}-{}", &user_code[..4], &user_code[4..])
    } else {
        user_code.to_string()
    }
}

/// KV key for a single-use device approval token record.
fn approval_key(approval_token: &str) -> String {
    format!("device_approval:{approval_token}")
}

/// Mint the single-use approval token that binds the confirmation screen to a
/// device auth session. The record carries device_code + user_id + client_id +
/// sid, so the approval POST needs nothing the browser could have forged.
/// It substitutes for the lid_flow cookie, which device sessions deliberately
/// do not carry. Called by every login path (password, MFA, social, passkey)
/// after the user has authenticated — the device is NOT approved here.
pub async fn create_approval(
    session: &store::AuthSession,
    user: &store::User,
) -> Result<String, String> {
    let approval_token = store::random_hex(32);
    let record = serde_json::json!({
        "device_code": session.state,
        "user_id": user.id,
        "client_id": session.client_id,
        "sid": session.sid,
    });
    store::kv_cache_set(&approval_key(&approval_token), &record, 300).await?;
    Ok(approval_token)
}

/// GET /device/confirm?token=... — renders the confirmation page. Used by
/// JS-initiated login flows (passkeys) that receive a JSON redirect instead of
/// an HTML page. Rendering does not consume the token; the POST does.
pub async fn confirm_view(query: &str) -> Response<String> {
    let params = util::parse_query(query);
    let token = params
        .iter()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    confirm_page(token, None).await
}

/// Explicit device confirmation screen. Shows the client name, the user_code
/// and the requested scopes; the device is approved only when the user posts
/// the single-use approval token back with decision=approve.
pub async fn confirm_page(approval_token: &str, error: Option<&str>) -> Response<String> {
    let record = store::kv_cache_get::<serde_json::Value>(&approval_key(approval_token))
        .await
        .ok()
        .flatten();
    let Some(record) = record else {
        let theme = crate::theme::resolve_global_theme().await;
        return render_outcome_page(
            "Confirmation Unavailable",
            "This device confirmation has expired or was already used. Please restart on your device.",
            false,
            &theme,
        );
    };
    let client_id = record
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let device_code = record
        .get("device_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let user_id = record.get("user_id").and_then(|v| v.as_str()).unwrap_or("");

    let client = store::get_client(client_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let dc = store::get_device_code(device_code).await.ok().flatten();
    let user = store::get_user(user_id).await.ok().flatten();

    let settings = store::get_runtime_settings().await;
    let theme = crate::theme::resolve_effective_theme(client.theme.clone(), &settings);

    // Only render an actionable form while the underlying device code is still
    // pending and the authenticated user still exists.
    let actionable = dc
        .as_ref()
        .is_some_and(|d| d.status == "pending" && store::unix_now() <= d.expires_at)
        && user.is_some();
    let (Some(dc), Some(user)) = (dc, user) else {
        return render_outcome_page(
            "Confirmation Unavailable",
            "This device confirmation has expired or was already used. Please restart on your device.",
            false,
            &theme,
        );
    };
    if !actionable {
        return render_outcome_page(
            "Confirmation Unavailable",
            "This device confirmation has expired or was already used. Please restart on your device.",
            false,
            &theme,
        );
    }

    let client_name = util::html_escape(&client.name);
    let user_email = util::html_escape(&user.email);
    let user_code_html = util::html_escape(&display_user_code(&dc.user_code));
    let approval_token_html = util::html_escape(approval_token);

    let head_tags = crate::theme::render_head_tags(&theme);
    let css_vars = crate::theme::render_css_variables(&theme);
    let logo_html = crate::theme::render_logo(&theme);
    let footer_html = crate::theme::render_footer(&theme, None);

    let error_html = match error {
        Some(e) => format!(
            r#"<div class="error-banner">{}</div>"#,
            util::html_escape(e)
        ),
        None => String::new(),
    };

    let scope_descriptions: Vec<String> = dc
        .scope
        .split_whitespace()
        .map(|s| {
            let desc = match s {
                "openid" => "Verify your identity",
                "email" => "Read your email address",
                "profile" => "Read your name and profile info",
                "offline_access" => "Stay signed in on the device (refresh tokens)",
                other => other,
            };
            format!(
                r#"<li style="padding:8px 0;border-bottom:1px solid var(--input-border);color:var(--text)">{}</li>"#,
                util::html_escape(desc)
            )
        })
        .collect();
    let scopes_html = scope_descriptions.join("\n");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Device — {client_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body{{font-family:var(--font-family);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--text);padding:20px}}
.card{{background:var(--card-bg);border:var(--card-border);box-shadow:var(--card-shadow);backdrop-filter:blur(var(--card-backdrop-blur));-webkit-backdrop-filter:blur(var(--card-backdrop-blur));border-radius:var(--radius);padding:40px;width:100%;max-width:440px}}
h1{{font-size:22px;font-weight:700;color:var(--text);margin-bottom:6px}}
.sub{{color:var(--text-muted);font-size:14px;margin-bottom:24px}}
.code{{font-family:monospace;font-size:1.6rem;letter-spacing:.3em;text-align:center;background:var(--input-bg);border:1px solid var(--input-border);border-radius:calc(var(--radius) * 0.7);padding:14px;margin:0 0 20px;color:var(--text)}}
ul{{list-style:none;margin-bottom:24px;padding:0;border-top:1px solid var(--input-border)}}
.actions{{display:flex;gap:12px}}
button{{flex:1;padding:12px;border:none;border-radius:calc(var(--radius) * 0.7);font-size:15px;font-weight:600;cursor:pointer;transition:all .15s ease}}
.btn-approve{{background:var(--primary);color:var(--button-text)}}
.btn-approve:hover{{background:var(--primary-hover);transform:translateY(-1px)}}
.btn-deny{{background:transparent;color:var(--text);border:1px solid var(--input-border)}}
.btn-deny:hover{{background:rgba(255,255,255,.08)}}
.error-banner{{color:#ef4444;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);padding:10px 14px;border-radius:calc(var(--radius) * 0.6);margin-bottom:16px;font-size:14px}}
.warning{{color:#b45309;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);padding:10px 14px;border-radius:calc(var(--radius) * 0.6);margin-bottom:16px;font-size:13px}}
</style>
</head>
<body>
<div class="card">
{logo_html}
<h1>Authorize a device?</h1>
<p class="sub">Signed in as <strong>{user_email}</strong></p>
{error_html}
<p style="font-size:14px;color:var(--text-muted);margin-bottom:12px"><strong>{client_name}</strong> wants to sign in on a device. Confirm that the code below matches the one shown on that device:</p>
<div class="code">{user_code_html}</div>
<p style="font-size:13px;color:var(--text-muted);margin-bottom:12px">The device will get access to:</p>
<ul>
{scopes_html}
</ul>
<div class="warning">Only approve if you started this sign-in yourself on the device.</div>
<form method="POST" action="/device">
<input type="hidden" name="approval_token" value="{approval_token_html}">
<div class="actions">
<button type="submit" class="btn-approve" name="decision" value="approve">Authorize device</button>
<button type="submit" class="btn-deny" name="decision" value="deny">Deny</button>
</div>
</form>
{footer_html}
</div>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// Handle the approve/deny POST from the confirmation page.
async fn handle_confirmation(form: &[(String, String)]) -> Result<Response<String>, String> {
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let approval_token = get("approval_token").ok_or("missing approval_token")?;
    let decision = get("decision").unwrap_or("deny");

    let key = approval_key(approval_token);
    // Single-use: read, then delete immediately. A replayed or unknown token
    // never reaches the device code.
    let record: serde_json::Value = match store::kv_cache_get(&key).await? {
        Some(r) => r,
        None => {
            let theme = crate::theme::resolve_global_theme().await;
            return Ok(render_device_page(
                "",
                Some(
                    "This confirmation has expired or was already used. Please restart on your device.",
                ),
                &theme,
            ));
        }
    };
    let _ = store::kv_delete("cache", &key).await;

    let device_code = record
        .get("device_code")
        .and_then(|v| v.as_str())
        .ok_or("invalid approval record")?;
    let user_id = record
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or("invalid approval record")?;
    let sid = record.get("sid").and_then(|v| v.as_str());
    let client_id = record
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let dc = store::get_device_code(device_code)
        .await?
        .ok_or("device code not found or expired")?;

    let theme = crate::theme::resolve_global_theme().await;

    if store::unix_now() > dc.expires_at {
        return Ok(render_device_page(
            "",
            Some("Code has expired. Please restart on your device."),
            &theme,
        ));
    }
    if dc.status != "pending" {
        return Ok(render_device_page(
            "",
            Some("This code has already been used."),
            &theme,
        ));
    }

    if decision != "approve" {
        store::update_device_code_status(device_code, "denied", None, None).await?;
        let _ = store::log_audit("device_denied", user_id, client_id, "user denied device").await;
        return Ok(render_outcome_page(
            "Device Not Authorized",
            "You declined the device sign-in. Nothing was authorized on your account.",
            false,
            &theme,
        ));
    }

    store::update_device_code_status(device_code, "approved", Some(user_id), sid).await?;
    let _ = store::log_audit(
        "device_approved",
        user_id,
        client_id,
        "user approved device",
    )
    .await;
    Ok(render_outcome_page(
        "Device Activated!",
        "You can close this window. Your device is now signed in.",
        true,
        &theme,
    ))
}

/// Simple outcome page (success or denial) shown after the confirmation POST.
fn render_outcome_page(
    title: &str,
    message: &str,
    success: bool,
    theme: &store::ClientTheme,
) -> Response<String> {
    let app_name = util::html_escape(&theme.app_name);
    let title_html = util::html_escape(title);
    let message_html = util::html_escape(message);
    let head_tags = crate::theme::render_head_tags(theme);
    let css_vars = crate::theme::render_css_variables(theme);
    let logo_html = crate::theme::render_logo(theme);
    let footer_html = crate::theme::render_footer(theme, None);
    let (icon, color) = if success {
        ("✓", "var(--primary)")
    } else {
        ("✕", "#ef4444")
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_html} — {app_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body {{ font-family: var(--font-family); background: var(--bg); color: var(--text); display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; padding:20px; }}
.card {{ background: var(--card-bg); border: var(--card-border); box-shadow: var(--card-shadow); backdrop-filter: blur(var(--card-backdrop-blur)); -webkit-backdrop-filter: blur(var(--card-backdrop-blur)); border-radius: var(--radius); padding:40px; max-width:420px; width:100%; text-align:center; }}
.icon {{ font-size:3.5rem; color:{color}; margin-bottom:16px; }}
h1 {{ font-size:1.5rem; font-weight:700; color:var(--text); margin-bottom:8px; }}
p {{ color:var(--text-muted); font-size:.95rem; margin-bottom:24px; }}
</style>
</head>
<body>
<div class="card">
  {logo_html}
  <div class="icon">{icon}</div>
  <h1>{title_html}</h1>
  <p>{message_html}</p>
  {footer_html}
</div>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// GET /device/complete — legacy landing page kept for backward compatibility.
/// Approval now happens explicitly via the confirmation page and POST /device
/// with an approval token; this endpoint only renders an informational page.
pub async fn complete(_query: &str) -> Response<String> {
    let theme = crate::theme::resolve_global_theme().await;
    render_outcome_page(
        "Device Activated!",
        "You can close this window. Your device is now signed in.",
        true,
        &theme,
    )
}

#[cfg(test)]
fn page_with_error(error: &str) -> Response<String> {
    let theme = crate::theme::resolve_effective_theme(None, &store::RuntimeSettings::default());
    render_device_page("", Some(error), &theme)
}

/// Generate an 8-character user-facing code in XXXX-XXXX format.
/// Uses only unambiguous characters (no 0/O, 1/I/L).
fn generate_user_code() -> String {
    const CHARS: &[u8] = b"ACDEFGHJKMNPQRTVWXY2345679";
    let limit = 256 - (256 % CHARS.len()); // reject >= limit to avoid modulo bias
    let mut chars = Vec::with_capacity(8);
    let mut buf = [0u8; 1];
    while chars.len() < 8 {
        getrandom::getrandom(&mut buf).expect("random");
        let b = buf[0] as usize;
        if b < limit {
            chars.push(CHARS[b % CHARS.len()] as char);
        }
    }
    format!(
        "{}-{}",
        chars[..4].iter().collect::<String>(),
        chars[4..].iter().collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PEPPER: &str = "test_pepper_123456789012345678901234567890";
    const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

    fn test_client(
        client_id: &str,
        secret: Option<String>,
        auth_method: Option<&str>,
    ) -> store::OidcClient {
        store::OidcClient {
            client_id: client_id.to_string(),
            client_secret: secret,
            grant_types: vec![DEVICE_GRANT.to_string()],
            name: format!("Client {client_id}"),
            token_endpoint_auth_method: auth_method.map(|m| m.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_generate_user_code_format() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 4);
        assert_eq!(parts[1].len(), 4);
    }

    #[test]
    fn test_generate_user_code_uses_unambiguous_chars() {
        let code = generate_user_code();
        let allowed = "ACDEFGHJKMNPQRTVWXY2345679";
        for ch in code.chars() {
            if ch != '-' {
                assert!(allowed.contains(ch), "unexpected char '{ch}' in user code");
            }
        }
    }

    #[test]
    fn test_generate_user_code_is_unique() {
        let c1 = generate_user_code();
        let c2 = generate_user_code();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_page_with_error_renders_error_message() {
        let resp = page_with_error("Custom error message");
        assert_eq!(resp.status(), 200);
        let body = resp.body();
        assert!(body.contains("Device Activation"));
        assert!(body.contains("Custom error message"));
    }

    #[test]
    fn test_page_with_error_escapes_html() {
        let resp = page_with_error("<script>alert('xss')</script>");
        let body = resp.body();
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_display_user_code_inserts_hyphen() {
        assert_eq!(display_user_code("ABCDEFGH"), "ABCD-EFGH");
        assert_eq!(display_user_code("AB"), "AB");
    }

    #[test]
    fn test_start_rejects_confidential_client_without_secret() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let secret = "device-confidential-secret-xyz";
            let client = test_client(
                "dev-confidential-noauth",
                Some(store::hmac_client_secret(secret)),
                Some("client_secret_post"),
            );
            store::save_client(&client).await.unwrap();

            let body = format!("client_id={}&scope=openid", client.client_id);
            let result = start(body.as_bytes(), "https://auth.example.com", None).await;
            assert!(
                result.is_err(),
                "confidential client must not get a device code without authenticating"
            );
        });
    }

    #[test]
    fn test_start_accepts_confidential_client_with_secret() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let secret = "device-confidential-secret-abc";
            let client = test_client(
                "dev-confidential-auth",
                Some(store::hmac_client_secret(secret)),
                Some("client_secret_post"),
            );
            store::save_client(&client).await.unwrap();

            let body = format!(
                "client_id={}&client_secret={}&scope=openid",
                client.client_id, secret
            );
            let resp = start(body.as_bytes(), "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert!(val["device_code"].as_str().is_some());
            assert!(val["user_code"].as_str().is_some());
        });
    }

    #[test]
    fn test_start_accepts_client_secret_basic() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let secret = "device-basic-secret-123";
            let client = test_client(
                "dev-basic-auth",
                Some(store::hmac_client_secret(secret)),
                Some("client_secret_basic"),
            );
            store::save_client(&client).await.unwrap();

            let encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{}:{}", client.client_id, secret),
            );
            let header = format!("Basic {encoded}");

            // client_secret_basic: credentials in the Authorization header,
            // no client_id in the form body.
            let resp = start(b"scope=openid", "https://auth.example.com", Some(&header))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let val: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert!(val["device_code"].as_str().is_some());

            // Wrong secret must be rejected.
            let wrong_encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{}:wrong-secret", client.client_id),
            );
            let wrong_header = format!("Basic {wrong_encoded}");
            let result = start(
                b"scope=openid",
                "https://auth.example.com",
                Some(&wrong_header),
            )
            .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_start_accepts_public_client() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let client = test_client("dev-public-ok", None, Some("none"));
            store::save_client(&client).await.unwrap();

            let body = format!("client_id={}&scope=openid", client.client_id);
            let resp = start(body.as_bytes(), "https://auth.example.com", None)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_start_rejects_unknown_client() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let body = "client_id=dev-no-such-client";
            let result = start(body.as_bytes(), "https://auth.example.com", None).await;
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), "client authentication failed");
        });
    }

    fn device_auth_session(device_code: &str, client_id: &str) -> store::AuthSession {
        store::AuthSession {
            client_id: client_id.to_string(),
            redirect_uri: "https://auth.example.com/device/complete".into(),
            code_challenge: String::new(),
            code_challenge_method: "device".into(),
            state: device_code.to_string(),
            scope: "openid email".into(),
            nonce: String::new(),
            max_age: None,
            acr_values: Vec::new(),
            requested_id_token_claims: Vec::new(),
            requested_userinfo_claims: Vec::new(),
            hinted_user_id: None,
            hinted_email: None,
            created_at: store::unix_now(),
            needs_consent: false,
            prompt: None,
            sid: Some("testsid123".into()),
        }
    }

    fn test_user(user_id: &str) -> store::User {
        store::User {
            id: user_id.to_string(),
            email: format!("{user_id}@example.com"),
            name: "Device User".into(),
            password_hash: "hash".into(),
            status: "active".into(),
            created_at: 0,
            superadmin: false,
            totp_secret: None,
            totp_enabled: false,
            recovery_codes: Vec::new(),
            passkey_credentials: Vec::new(),
        }
    }

    async fn pending_device_code(device_code: &str, user_code: &str, client_id: &str) {
        let dc = store::DeviceCode {
            device_code: device_code.to_string(),
            user_code: user_code.to_string(),
            client_id: client_id.to_string(),
            scope: "openid email".into(),
            expires_at: store::unix_now() + 300,
            status: "pending".into(),
            user_id: None,
            sid: None,
        };
        store::save_device_code(&dc).await.unwrap();
    }

    #[test]
    fn test_confirm_page_shows_client_and_code() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let client = test_client("dev-confirm-render", None, Some("none"));
            store::save_client(&client).await.unwrap();
            pending_device_code("dc-confirm-render", "WXYZ2345", &client.client_id).await;

            let session = device_auth_session("dc-confirm-render", &client.client_id);
            let user = test_user("usr-confirm-render");
            store::create_user(&user).await.unwrap();
            let token = create_approval(&session, &user).await.unwrap();
            let resp = confirm_page(&token, None).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.body();
            assert!(body.contains("Client dev-confirm-render"));
            assert!(body.contains("WXYZ-2345"));
            assert!(body.contains(&token));
            assert!(body.contains("usr-confirm-render@example.com"));
            assert!(body.contains("name=\"decision\" value=\"approve\""));
            assert!(body.contains("name=\"decision\" value=\"deny\""));
        });
    }

    /// The passkey sign-in path (management::passkey_auth_complete) cannot
    /// return HTML — it redirects the JS client to GET /device/confirm, which
    /// must render the same confirmation page from the approval token alone.
    #[test]
    fn test_confirm_view_renders_from_token_and_approves() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let client = test_client("dev-passkey-handoff", None, Some("none"));
            store::save_client(&client).await.unwrap();
            pending_device_code("dc-passkey-handoff", "PSKY7777", &client.client_id).await;
            let user = test_user("usr-passkey-handoff");
            store::create_user(&user).await.unwrap();

            // This is exactly what the passkey device branch does.
            let session = device_auth_session("dc-passkey-handoff", &client.client_id);
            let token = create_approval(&session, &user).await.unwrap();

            // GET /device/confirm?token=... renders the confirmation page.
            let resp = confirm_view(&format!("token={token}")).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.body();
            assert!(body.contains("Authorize a device"));
            assert!(body.contains("Client dev-passkey-handoff"));
            assert!(body.contains("PSKY-7777"));
            // Rendering must NOT consume the token.
            assert!(
                store::kv_cache_get::<serde_json::Value>(&approval_key(&token))
                    .await
                    .unwrap()
                    .is_some()
            );

            // Unknown token renders the unavailable page, not the form.
            let bad = confirm_view("token=no-such-token").await;
            assert!(bad.body().contains("Confirmation Unavailable"));
            assert!(!bad.body().contains("name=\"decision\""));

            // Approve through the posted form: device code becomes approved.
            let form = format!("approval_token={token}&decision=approve");
            let resp = submit(form.as_bytes(), "https://auth.example.com")
                .await
                .unwrap();
            assert!(resp.body().contains("Device Activated!"));
            let dc = store::get_device_code("dc-passkey-handoff")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(dc.status, "approved");
            assert_eq!(dc.user_id.as_deref(), Some("usr-passkey-handoff"));
        });
    }

    /// A confirmation page must not render an actionable form once the
    /// underlying device code was already decided.
    #[test]
    fn test_confirm_view_unavailable_after_approval() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            let client = test_client("dev-stale-confirm", None, Some("none"));
            store::save_client(&client).await.unwrap();
            pending_device_code("dc-stale-confirm", "STAL9999", &client.client_id).await;
            store::update_device_code_status("dc-stale-confirm", "denied", None, None)
                .await
                .unwrap();
            let user = test_user("usr-stale-confirm");
            store::create_user(&user).await.unwrap();

            let session = device_auth_session("dc-stale-confirm", &client.client_id);
            let token = create_approval(&session, &user).await.unwrap();

            let resp = confirm_view(&format!("token={token}")).await;
            assert!(resp.body().contains("Confirmation Unavailable"));
            assert!(!resp.body().contains("name=\"decision\""));
        });
    }

    #[test]
    fn test_confirmation_approve_marks_device_approved() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            pending_device_code("dc-approve-1", "APRV1111", "dev-approve-client").await;
            store::kv_cache_set(
                "device_approval:tok-approve-1",
                &serde_json::json!({
                    "device_code": "dc-approve-1",
                    "user_id": "usr-approve-1",
                    "client_id": "dev-approve-client",
                    "sid": "sid-approve-1",
                }),
                300,
            )
            .await
            .unwrap();

            let form = "approval_token=tok-approve-1&decision=approve";
            let resp = submit(form.as_bytes(), "https://auth.example.com")
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(resp.body().contains("Device Activated!"));

            let dc = store::get_device_code("dc-approve-1")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(dc.status, "approved");
            assert_eq!(dc.user_id.as_deref(), Some("usr-approve-1"));
            assert_eq!(dc.sid.as_deref(), Some("sid-approve-1"));

            // The approval token is single-use: replaying it must not re-approve.
            let resp2 = submit(form.as_bytes(), "https://auth.example.com")
                .await
                .unwrap();
            assert!(resp2.body().contains("expired or was already used"));
        });
    }

    #[test]
    fn test_confirmation_deny_marks_device_denied() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, Some(TEST_PEPPER));
            pending_device_code("dc-deny-1", "DENY2222", "dev-deny-client").await;
            store::kv_cache_set(
                "device_approval:tok-deny-1",
                &serde_json::json!({
                    "device_code": "dc-deny-1",
                    "user_id": "usr-deny-1",
                    "client_id": "dev-deny-client",
                    "sid": null,
                }),
                300,
            )
            .await
            .unwrap();

            let form = "approval_token=tok-deny-1&decision=deny";
            let resp = submit(form.as_bytes(), "https://auth.example.com")
                .await
                .unwrap();
            assert!(resp.body().contains("Device Not Authorized"));

            let dc = store::get_device_code("dc-deny-1").await.unwrap().unwrap();
            assert_eq!(dc.status, "denied");
            assert!(dc.user_id.is_none());
        });
    }
}
