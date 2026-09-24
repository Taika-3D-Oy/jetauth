//! Server-rendered account self-service pages.
//!
//! These pages let authenticated users manage their own credentials
//! (passkeys, MFA) without needing the admin SPA. Auth is via a
//! short-lived `lid_account` HttpOnly cookie set during login.

use base64::Engine;
use http::{HeaderMap, Response, StatusCode};

use crate::store::{self, User};
use crate::util;

// ── Cookie helpers ──────────────────────────────────────────

const COOKIE_NAME: &str = "lid_account";
const SESSION_TTL: u64 = 1800; // 30 minutes

/// Create a new account session and return the Set-Cookie header value.
pub async fn create_session_cookie(user_id: &str) -> Result<String, String> {
    let token = store::random_hex(32);
    let csrf = store::random_hex(24);
    let now = store::unix_now();
    let session = store::AccountSession {
        user_id: user_id.to_string(),
        created_at: now,
        expires_at: now + SESSION_TTL,
        csrf_token: csrf,
    };
    store::save_account_session(&token, &session).await?;

    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    Ok(format!(
        "{COOKIE_NAME}={token}; HttpOnly;{secure} SameSite=Strict; Path=/account; Max-Age={SESSION_TTL}"
    ))
}

/// Extract and validate the account session from cookies. Returns (User, csrf_token).
/// On failure, returns Ok(Err(redirect_response)) so callers can propagate it.
async fn require_account_session(
    headers: &HeaderMap,
) -> Result<Result<(User, String), Response<String>>, String> {
    let token = match parse_cookie(headers, COOKIE_NAME) {
        Some(t) => t,
        None => {
            return Ok(Err(redirect_to_login(
                "Session expired. Please log in again.",
            )));
        }
    };

    let session = match store::get_account_session(&token).await? {
        Some(s) => s,
        None => {
            return Ok(Err(redirect_to_login(
                "Session expired. Please log in again.",
            )));
        }
    };

    if store::unix_now() > session.expires_at {
        let _ = store::delete_account_session(&token).await;
        return Ok(Err(redirect_to_login(
            "Session expired. Please log in again.",
        )));
    }

    match store::get_user(&session.user_id).await? {
        Some(u) => Ok(Ok((u, session.csrf_token))),
        None => Ok(Err(redirect_to_login("Account not found."))),
    }
}

/// Convenience: extract (user, csrf_token) or return redirect response directly.
macro_rules! get_user_or_redirect {
    ($headers:expr) => {
        match require_account_session($headers).await? {
            Ok(pair) => pair,
            Err(redirect) => return Ok(redirect),
        }
    };
}

fn parse_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get("cookie")?.to_str().ok()?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(name) {
            let value = value.strip_prefix('=')?;
            return Some(value.to_string());
        }
    }
    None
}

fn redirect_to_login(msg: &str) -> Response<String> {
    // Redirect to the IdP root; user will initiate a new OIDC flow
    let encoded = util::percent_encode(msg);
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", format!("/?account_hint={encoded}"))
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap()
}

// ── IdP session cookie (SSO / prompt=none) ──────────────────

const IDP_COOKIE_NAME: &str = "lid_session";

/// Create a new IdP browser session and return the Set-Cookie header value.
/// Called on every successful login; enables `prompt=none` and SSO for SPAs.
pub async fn create_idp_session_cookie(
    user_id: &str,
    amr: &[String],
    auth_time: u64,
) -> Result<String, String> {
    let token = store::random_hex(32);
    let ttl = store::get_idp_session_ttl().await;
    let session = store::IdpSession {
        user_id: user_id.to_string(),
        auth_time,
        expires_at: store::unix_now() + ttl,
        amr: amr.to_vec(),
    };
    store::save_idp_session(&token, &session).await?;
    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    Ok(format!(
        "{IDP_COOKIE_NAME}={token}; HttpOnly;{secure} SameSite=Lax; Path=/; Max-Age={ttl}"
    ))
}

/// Return the Set-Cookie header value that clears the IdP session cookie from the browser.
#[allow(dead_code)]
pub fn clear_idp_session_cookie() -> String {
    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    format!("{IDP_COOKIE_NAME}=; HttpOnly;{secure} SameSite=Lax; Path=/; Max-Age=0")
}

/// Append Set-Cookie headers to clear all auth and session cookies from the browser.
pub fn append_clear_all_cookies(headers: &mut HeaderMap) {
    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    let cookies = [
        format!("{COOKIE_NAME}=; HttpOnly;{secure} SameSite=Lax; Path=/; Max-Age=0"),
        format!("{COOKIE_NAME}=; HttpOnly;{secure} SameSite=Strict; Path=/account; Max-Age=0"),
        format!("{IDP_COOKIE_NAME}=; HttpOnly;{secure} SameSite=Lax; Path=/; Max-Age=0"),
        "lid_tenant=; HttpOnly; SameSite=Lax; Path=/admin; Max-Age=0".to_string(),
    ];
    for c in &cookies {
        if let Ok(val) = c.parse() {
            headers.append("set-cookie", val);
        }
    }
}

/// Extract the raw lid_session token from request cookies without validating it.
/// Used by the logout handler to delete the server-side session from NATS.
pub fn extract_idp_session_token(headers: &HeaderMap) -> Option<String> {
    parse_cookie(headers, IDP_COOKIE_NAME)
}

/// Look up and validate the IdP session from request cookies.
/// Returns `None` if the cookie is absent, the session is not found, or it has expired.
pub async fn get_idp_session_from_headers(headers: &HeaderMap) -> Option<store::IdpSession> {
    let token = parse_cookie(headers, IDP_COOKIE_NAME)?;
    let session = store::get_idp_session(&token).await.ok()??;
    if store::unix_now() > session.expires_at {
        let _ = store::delete_idp_session(&token).await;
        return None;
    }
    Some(session)
}

/// Slide the TTL of the existing IdP session and return a refreshed Set-Cookie header.
/// Returns `None` if there is no valid session to refresh.
pub async fn refresh_idp_session_cookie_header(headers: &HeaderMap) -> Option<String> {
    let token = parse_cookie(headers, IDP_COOKIE_NAME)?;
    let mut session = store::get_idp_session(&token).await.ok()??;
    if store::unix_now() > session.expires_at {
        return None;
    }
    let ttl = store::get_idp_session_ttl().await;
    session.expires_at = store::unix_now() + ttl;
    let _ = store::save_idp_session(&token, &session).await;
    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    Some(format!(
        "{IDP_COOKIE_NAME}={token}; HttpOnly;{secure} SameSite=Lax; Path=/; Max-Age={ttl}"
    ))
}

// ── Shared page chrome ──────────────────────────────────────

fn page_head(title: &str, theme: &crate::store::ClientTheme) -> String {
    let app_name = crate::util::html_escape(&theme.app_name);
    let head_tags = crate::theme::render_head_tags(theme);
    let css_vars = crate::theme::render_css_variables(theme);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — {app_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body{{font-family:var(--font-family);background:var(--bg);min-height:100vh;padding:24px;color:var(--text)}}
.container{{max-width:600px;margin:0 auto}}
.card{{background:var(--card-bg);border:var(--card-border);box-shadow:var(--card-shadow);backdrop-filter:blur(var(--card-backdrop-blur));-webkit-backdrop-filter:blur(var(--card-backdrop-blur));border-radius:var(--radius);padding:32px;margin-bottom:20px}}
h1{{font-size:24px;font-weight:700;color:var(--text);margin-bottom:8px}}
h2{{font-size:18px;font-weight:700;color:var(--text);margin-bottom:16px}}
.sub{{color:var(--text-muted);font-size:14px;margin-bottom:24px}}
.nav{{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}}
.nav a{{color:var(--primary);text-decoration:none;font-size:14px;font-weight:600}}
.nav a:hover{{text-decoration:underline}}
.nav a.active{{color:var(--text);font-weight:700;text-decoration:underline}}
label{{display:block;font-size:13px;font-weight:600;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em}}
input[type=text],input[type=password]{{width:100%;padding:12px 14px;border:1px solid var(--input-border);border-radius:calc(var(--radius) * 0.7);background:var(--input-bg);color:var(--input-text);font-size:15px;margin-bottom:16px;outline:none;transition:all .15s ease}}
input:focus{{border-color:var(--primary);box-shadow:0 0 0 3px rgba(16,185,129,.25)}}
.btn{{display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border-radius:calc(var(--radius) * 0.7);font-size:14px;font-weight:600;cursor:pointer;border:none;text-decoration:none;transition:all .15s ease}}
.btn-primary{{background:var(--primary);color:var(--button-text)}}.btn-primary:hover{{background:var(--primary-hover);transform:translateY(-1px)}}
.btn-danger{{background:#ef4444;color:#fff}}.btn-danger:hover{{background:#dc2626}}
.btn-outline{{background:transparent;color:var(--text);border:1px solid var(--input-border)}}.btn-outline:hover{{background:rgba(255,255,255,.08)}}
.badge{{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:12px;font-weight:600}}
.badge-ok{{background:rgba(16,185,129,.2);color:#10b981}}
.badge-off{{background:rgba(255,255,255,.1);color:var(--text-muted)}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{text-align:left;padding:8px 12px;border-bottom:2px solid var(--input-border);color:var(--text-muted);font-weight:600}}
td{{padding:8px 12px;border-bottom:1px solid var(--input-border);color:var(--text)}}
.msg-ok{{background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.3);color:#10b981;padding:10px 14px;border-radius:calc(var(--radius) * 0.6);margin-bottom:16px;font-size:14px}}
.msg-err{{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#ef4444;padding:10px 14px;border-radius:calc(var(--radius) * 0.6);margin-bottom:16px;font-size:14px}}
.detail-row{{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--input-border)}}
.detail-row:last-child{{border-bottom:none}}
.detail-label{{color:var(--text-muted);font-size:14px}}
.detail-value{{font-weight:600;color:var(--text);font-size:14px}}
.passkey-error{{color:#ef4444;font-size:13px;margin-top:8px;display:none}}
.footer{{text-align:center;margin-top:32px;font-size:13px;color:var(--text-muted)}}
</style>
</head>
<body>
<div class="container">"#
    )
}

fn page_nav(active: &str) -> String {
    let items = [
        ("Overview", "/account"),
        ("Passkeys", "/account/passkeys"),
        ("MFA", "/account/mfa"),
    ];
    let mut html = String::from(r#"<nav class="nav">"#);
    for (label, href) in &items {
        let cls = if *href == active {
            r#" class="active""#
        } else {
            ""
        };
        html.push_str(&format!(r#"<a href="{href}"{cls}>{label}</a>"#));
    }
    html.push_str(
        r#"<a href="/account/logout" style="margin-left:auto;color:#ef4444">Sign out</a>"#,
    );
    html.push_str("</nav>");
    html
}

fn page_foot(theme: &crate::store::ClientTheme) -> String {
    let footer_html = crate::theme::render_footer(theme, None);
    format!("{footer_html}</div></body></html>")
}

// ── GET /account ────────────────────────────────────────────

pub async fn dashboard(headers: &HeaderMap) -> Result<Response<String>, String> {
    let (user, _csrf) = get_user_or_redirect!(headers);
    let theme = crate::theme::resolve_global_theme().await;

    let passkey_count = user.passkey_credentials.len();
    let mfa_status = if user.totp_enabled {
        "Enabled"
    } else {
        "Not set up"
    };
    let mfa_badge = if user.totp_enabled {
        "badge-ok"
    } else {
        "badge-off"
    };
    let passkey_badge = if passkey_count > 0 {
        "badge-ok"
    } else {
        "badge-off"
    };

    let html = format!(
        r#"{head}
{nav}
<h1>My Account</h1>
<p class="sub">{email}</p>

<div class="card">
<div class="detail-row">
    <span class="detail-label">Name</span>
    <span class="detail-value">{name}</span>
</div>
<div class="detail-row">
    <span class="detail-label">Email</span>
    <span class="detail-value">{email}</span>
</div>
<div class="detail-row">
    <span class="detail-label">Passkeys</span>
    <span class="detail-value"><span class="badge {passkey_badge}">{passkey_count} registered</span></span>
</div>
<div class="detail-row">
    <span class="detail-label">Two-Factor Auth</span>
    <span class="detail-value"><span class="badge {mfa_badge}">{mfa_status}</span></span>
</div>
</div>
{foot}"#,
        head = page_head("My Account", &theme),
        nav = page_nav("/account"),
        email = util::html_escape(&user.email),
        name = util::html_escape(&user.name),
        foot = page_foot(&theme),
    );

    Ok(html_response(&html))
}

// ── GET /account/passkeys ───────────────────────────────────

pub async fn passkeys_page(
    headers: &HeaderMap,
    msg: Option<&str>,
    err: Option<&str>,
) -> Result<Response<String>, String> {
    let (user, csrf) = get_user_or_redirect!(headers);
    let theme = crate::theme::resolve_global_theme().await;

    let msg_html = match msg {
        Some(m) => format!(r#"<div class="msg-ok">{}</div>"#, util::html_escape(m)),
        None => String::new(),
    };
    let err_html = match err {
        Some(e) => format!(r#"<div class="msg-err">{}</div>"#, util::html_escape(e)),
        None => String::new(),
    };

    let rows: String = if user.passkey_credentials.is_empty() {
        r#"<tr><td colspan="4" style="color:#94a3b8;text-align:center;padding:24px">No passkeys registered yet.</td></tr>"#.to_string()
    } else {
        user.passkey_credentials
            .iter()
            .map(|pk| {
                let ts = api_format_timestamp(pk.created_at);
                format!(
                    r#"<tr>
<td>{name}</td>
<td>{ts}</td>
<td>{count}</td>
<td><form method="POST" action="/account/passkeys/delete" style="display:inline">
<input type="hidden" name="credential_id" value="{cred_id}">
<input type="hidden" name="csrf" value="{csrf_val}">
<button type="submit" class="btn btn-danger" style="padding:4px 12px;font-size:13px">Remove</button>
</form></td>
</tr>"#,
                    name = util::html_escape(&pk.name),
                    count = pk.sign_count,
                    cred_id = util::html_escape(&pk.credential_id),
                    csrf_val = util::html_escape(&csrf),
                )
            })
            .collect()
    };

    let challenge_token = store::random_hex(32);
    let challenge = crate::passkeys::generate_challenge();
    let existing_ids: Vec<String> = user
        .passkey_credentials
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();
    let display_name = if user.name.is_empty() {
        &user.email
    } else {
        &user.name
    };
    let options = crate::passkeys::registration_options_json(
        &user.id,
        &user.email,
        display_name,
        &challenge,
        &existing_ids,
    );

    let pc = store::PasskeyChallenge {
        challenge,
        purpose: "register".into(),
        user_id: user.id.clone(),
        session_id: String::new(),
        expires_at: store::unix_now() + 300,
    };
    // Failure to save challenge just means registration won't work; page still renders
    let _ = store::save_passkey_challenge(&challenge_token, &pc).await;

    let options_json = serde_json::to_string(&serde_json::json!({
        "publicKey": options,
    }))
    .unwrap_or_default();

    let html = format!(
        r##"{head}
{nav}
{msg_html}
{err_html}
<h1>Passkeys</h1>
<p class="sub">Manage your passkeys for passwordless sign-in.</p>

<div class="card">
<table>
<thead><tr><th>Name</th><th>Created</th><th>Uses</th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>

<div class="card" id="register-card">
<h2>Register a new passkey</h2>
<div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap">
<div style="flex:1;min-width:200px">
<label for="pk-name">Passkey name</label>
<input type="text" id="pk-name" placeholder="e.g. MacBook Touch ID" style="margin-bottom:0">
</div>
<button class="btn btn-primary" id="pk-register" onclick="registerPasskey()">Add Passkey</button>
</div>
<div class="passkey-error" id="pk-error"></div>
</div>

<script>
var CHALLENGE_TOKEN = '{challenge_token}';
var REG_OPTIONS = {options_json};

function b64url(buf) {{
    var s='',b=new Uint8Array(buf);
    for(var i=0;i<b.length;i++) s+=String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}}
function b64urlDecode(s) {{
    s=s.replace(/-/g,'+').replace(/_/g,'/');
    while(s.length%4) s+='=';
    var b=atob(s),a=new Uint8Array(b.length);
    for(var i=0;i<b.length;i++) a[i]=b.charCodeAt(i);
    return a.buffer;
}}

async function registerPasskey() {{
    var errEl = document.getElementById('pk-error');
    var btn = document.getElementById('pk-register');
    var nameInput = document.getElementById('pk-name');
    var name = (nameInput && nameInput.value.trim()) || 'My Passkey';
    errEl.style.display = 'none';
    btn.disabled = true;
    btn.textContent = 'Waiting for authenticator\u2026';

    try {{
        var opts = Object.assign({{}}, REG_OPTIONS.publicKey);
        opts.challenge = b64urlDecode(opts.challenge);
        opts.user = Object.assign({{}}, opts.user, {{ id: b64urlDecode(opts.user.id) }});
        if (opts.excludeCredentials) {{
            opts.excludeCredentials = opts.excludeCredentials.map(function(c) {{
                return Object.assign({{}}, c, {{ id: b64urlDecode(c.id) }});
            }});
        }}
        var cred = await navigator.credentials.create({{ publicKey: opts }});
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/account/passkeys/register';
        function addField(k, v) {{
            var i = document.createElement('input');
            i.type = 'hidden';
            i.name = k;
            i.value = v;
            form.appendChild(i);
        }}
        addField('token', CHALLENGE_TOKEN);
        addField('name', name);
        addField('clientDataJSON', b64url(cred.response.clientDataJSON));
        addField('attestationObject', b64url(cred.response.attestationObject));
        document.body.appendChild(form);
        form.submit();
    }} catch(e) {{
        errEl.textContent = 'Error: ' + (e.message || e);
        errEl.style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Add Passkey';
    }}
}}

if (!window.PublicKeyCredential) {{
    document.getElementById('register-card').innerHTML =
        '<p style="color:var(--text-muted)">Passkeys are not supported in this browser.</p>';
}}
</script>

{foot}"##,
        head = page_head("Passkeys", &theme),
        nav = page_nav("/account/passkeys"),
        foot = page_foot(&theme),
    );

    Ok(html_response(&html))
}

// ── POST /account/passkeys/register ─────────────────────────

pub async fn passkeys_register(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response<String>, String> {
    let (user, _csrf) = get_user_or_redirect!(headers);

    let form = util::parse_form(body);
    let token = util::form_value(&form, "token").ok_or("missing token")?;
    let name = util::form_value(&form, "name").unwrap_or("My passkey");
    let client_data_json =
        util::form_value(&form, "clientDataJSON").ok_or("missing clientDataJSON")?;
    let attestation_object =
        util::form_value(&form, "attestationObject").ok_or("missing attestationObject")?;

    // Validate challenge
    let pc = store::get_passkey_challenge(token)
        .await?
        .ok_or("invalid or expired registration token")?;
    if pc.purpose != "register" || pc.user_id != user.id {
        return Err("token mismatch".into());
    }
    if store::unix_now() > pc.expires_at {
        store::delete_passkey_challenge(token).await?;
        return passkeys_page(
            headers,
            None,
            Some("Registration token expired. Please try again."),
        )
        .await;
    }
    store::delete_passkey_challenge(token).await?;

    let issuer = crate::get_issuer();
    let parsed = match crate::passkeys::verify_registration(
        client_data_json,
        attestation_object,
        &pc.challenge,
        &issuer,
    ) {
        Ok(p) => p,
        Err(e) => {
            return passkeys_page(headers, None, Some(&format!("Registration failed: {e}"))).await;
        }
    };

    let credential_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.credential_id);
    let public_key =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.public_key_bytes);

    let user = store::get_user(&user.id).await?.ok_or("user not found")?;
    if user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == credential_id)
    {
        return passkeys_page(headers, None, Some("This passkey is already registered.")).await;
    }

    let name = if name.is_empty() {
        format!("Passkey {}", user.passkey_credentials.len() + 1)
    } else {
        name.to_string()
    };

    let cred = store::PasskeyCredential {
        credential_id: credential_id.clone(),
        public_key,
        sign_count: parsed.sign_count,
        name: name.clone(),
        created_at: store::unix_now(),
    };
    let user_id = user.id.clone();
    store::update_user_rmw(&user_id, |u| {
        u.passkey_credentials.push(cred.clone());
        Ok(true)
    })
    .await?;
    store::index_passkey_credential(&credential_id, &user_id).await?;

    let _ = store::log_audit("passkey_registered", &user.id, &user.id, &name).await;

    passkeys_page(
        headers,
        Some(&format!("Passkey \"{name}\" registered successfully!")),
        None,
    )
    .await
}

// ── POST /account/passkeys/delete ───────────────────────────

pub async fn passkeys_delete(headers: &HeaderMap, body: &[u8]) -> Result<Response<String>, String> {
    let (user, csrf) = get_user_or_redirect!(headers);

    let form = util::parse_form(body);
    // CSRF verification (defense in depth alongside SameSite=Strict cookie)
    let submitted_csrf = util::form_value(&form, "csrf").unwrap_or_default();
    if !csrf.is_empty() && submitted_csrf != csrf {
        return Err("invalid CSRF token".into());
    }
    let cred_id = util::form_value(&form, "credential_id").ok_or("missing credential_id")?;

    let user = store::get_user(&user.id).await?.ok_or("user not found")?;
    if !user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == cred_id)
    {
        return passkeys_page(headers, None, Some("Passkey not found.")).await;
    }
    let user_id = user.id.clone();
    let cred_id_owned = cred_id.to_string();
    store::update_user_rmw(&user_id, |u| {
        u.passkey_credentials
            .retain(|c| c.credential_id != cred_id_owned);
        Ok(true)
    })
    .await?;
    let _ = store::unindex_passkey_credential(cred_id).await;
    let _ = store::log_audit("passkey_deleted", &user_id, &user_id, cred_id).await;

    passkeys_page(headers, Some("Passkey removed."), None).await
}

// ── GET /account/mfa ────────────────────────────────────────

pub async fn mfa_page(
    headers: &HeaderMap,
    msg: Option<&str>,
    err: Option<&str>,
) -> Result<Response<String>, String> {
    let (user, csrf) = get_user_or_redirect!(headers);
    let theme = crate::theme::resolve_global_theme().await;

    let msg_html = match msg {
        Some(m) => format!(r#"<div class="msg-ok">{}</div>"#, util::html_escape(m)),
        None => String::new(),
    };
    let err_html = match err {
        Some(e) => format!(r#"<div class="msg-err">{}</div>"#, util::html_escape(e)),
        None => String::new(),
    };

    let content = if user.totp_enabled {
        format!(
            r#"<div class="card">
<h2>Two-Factor Authentication</h2>
<p style="margin-bottom:16px">TOTP is <span class="badge badge-ok">enabled</span> for your account.</p>
<p style="color:var(--text-muted);font-size:14px;margin-bottom:16px">Disabling MFA will revoke all your active sessions.</p>
<form method="POST" action="/account/mfa/disable">
<input type="hidden" name="csrf" value="{csrf_val}">
<label for="password">Enter your password to confirm</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
<button type="submit" class="btn btn-danger">Disable MFA</button>
</form>
</div>"#,
            csrf_val = util::html_escape(&csrf),
        )
    } else {
        format!(
            r#"<div class="card">
<h2>Two-Factor Authentication</h2>
<p style="margin-bottom:16px">MFA is <span class="badge badge-off">not set up</span>.</p>
<p style="color:var(--text-muted);font-size:14px;margin-bottom:16px">Add an extra layer of security with a TOTP authenticator app.</p>
<form method="POST" action="/account/mfa/setup">
<input type="hidden" name="csrf" value="{csrf_val}">
<button type="submit" class="btn btn-primary">Set up MFA</button>
</form>
</div>"#,
            csrf_val = util::html_escape(&csrf),
        )
    };

    let html = format!(
        "{head}\n{nav}\n{msg_html}\n{err_html}\n<h1>Two-Factor Authentication</h1>\n<p class=\"sub\">Protect your account with TOTP.</p>\n{content}\n{foot}",
        head = page_head("MFA", &theme),
        nav = page_nav("/account/mfa"),
        foot = page_foot(&theme),
    );

    Ok(html_response(&html))
}

// ── POST /account/mfa/setup ─────────────────────────────────

pub async fn mfa_setup(headers: &HeaderMap) -> Result<Response<String>, String> {
    let (user, _csrf) = get_user_or_redirect!(headers);
    let theme = crate::theme::resolve_global_theme().await;

    if user.totp_enabled {
        return mfa_page(headers, None, Some("MFA is already enabled.")).await;
    }

    let secret = crate::totp::generate_secret();
    let issuer = crate::get_issuer();
    let otpauth_uri = crate::totp::otpauth_uri(&secret, &user.email, &issuer);

    let user = store::get_user(&user.id).await?.ok_or("user not found")?;
    let user_id = user.id.clone();
    store::update_user_rmw(&user_id, |u| {
        u.totp_secret = Some(secret.clone());
        Ok(true)
    })
    .await?;

    let _ = store::log_audit("mfa_setup_started", &user.id, &user.id, "").await;

    // Render the setup page with QR URI and secret
    let html = format!(
        r#"{head}
{nav}
<h1>Set Up MFA</h1>
<p class="sub">Scan the QR code with your authenticator app, then enter the code to confirm.</p>

<div class="card">
<p style="margin-bottom:12px"><strong>Manual entry key:</strong></p>
<code style="background:var(--input-bg);border:1px solid var(--input-border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;word-break:break-all;display:block;margin-bottom:16px">{secret}</code>
<p style="margin-bottom:8px;font-size:14px;color:var(--text-muted)">Or scan this URI in your authenticator:</p>
<code style="background:var(--input-bg);border:1px solid var(--input-border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:12px;word-break:break-all;display:block;margin-bottom:24px">{otpauth_uri}</code>

<form method="POST" action="/account/mfa/confirm">
<label for="code">Enter the 6-digit code from your app</label>
<input type="text" id="code" name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" style="max-width:200px;text-align:center;letter-spacing:6px;font-family:monospace;font-size:20px" autofocus>
<button type="submit" class="btn btn-primary">Verify &amp; Enable</button>
</form>
</div>
{foot}"#,
        head = page_head("Set Up MFA", &theme),
        nav = page_nav("/account/mfa"),
        secret = util::html_escape(&secret),
        otpauth_uri = util::html_escape(&otpauth_uri),
        foot = page_foot(&theme),
    );

    Ok(html_response(&html))
}

// ── POST /account/mfa/confirm ───────────────────────────────

pub async fn mfa_confirm(headers: &HeaderMap, body: &[u8]) -> Result<Response<String>, String> {
    let (user, _csrf) = get_user_or_redirect!(headers);
    let theme = crate::theme::resolve_global_theme().await;

    let form = util::parse_form(body);
    let code = util::form_value(&form, "code").ok_or("missing code")?;

    let user = store::get_user(&user.id).await?.ok_or("user not found")?;
    let secret = user.totp_secret.as_deref().ok_or("MFA setup not started")?;

    if !crate::totp::verify_totp(secret, code.trim()) {
        // Re-render setup page with error. Secret is still saved on user.
        let issuer = crate::get_issuer();
        let otpauth_uri = crate::totp::otpauth_uri(secret, &user.email, &issuer);
        let html = format!(
            r#"{head}
{nav}
<div class="msg-err">Invalid code. Please try again.</div>
<h1>Set Up MFA</h1>
<p class="sub">Scan the QR code with your authenticator app, then enter the code to confirm.</p>

<div class="card">
<p style="margin-bottom:12px"><strong>Manual entry key:</strong></p>
<code style="background:var(--input-bg);border:1px solid var(--input-border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;word-break:break-all;display:block;margin-bottom:16px">{secret}</code>
<code style="background:var(--input-bg);border:1px solid var(--input-border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:12px;word-break:break-all;display:block;margin-bottom:24px">{otpauth_uri}</code>

<form method="POST" action="/account/mfa/confirm">
<label for="code">Enter the 6-digit code from your app</label>
<input type="text" id="code" name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" style="max-width:200px;text-align:center;letter-spacing:6px;font-family:monospace;font-size:20px" autofocus>
<button type="submit" class="btn btn-primary">Verify &amp; Enable</button>
</form>
</div>
{foot}"#,
            head = page_head("Set Up MFA", &theme),
            nav = page_nav("/account/mfa"),
            secret = util::html_escape(secret),
            otpauth_uri = util::html_escape(&otpauth_uri),
            foot = page_foot(&theme),
        );
        return Ok(html_response(&html));
    }

    // Enable MFA
    let recovery_codes = crate::totp::generate_recovery_codes();
    let user_id = user.id.clone();
    store::update_user_rmw(&user_id, |u| {
        u.totp_enabled = true;
        u.recovery_codes = recovery_codes.clone();
        Ok(true)
    })
    .await?;

    let _ = store::log_audit("mfa_enabled", &user.id, &user.id, "").await;

    // Show recovery codes (one-time display)
    let codes_html: String = recovery_codes
        .iter()
        .map(|c| {
            format!(r#"<li style="font-family:monospace;font-size:15px;padding:4px 0">{c}</li>"#)
        })
        .collect();

    let html = format!(
        r#"{head}
{nav}
<div class="msg-ok">MFA is now enabled!</div>
<h1>Recovery Codes</h1>
<p class="sub">Save these codes in a safe place. Each code can only be used once.</p>

<div class="card">
<ol style="padding-left:20px;margin-bottom:16px">{codes_html}</ol>
<p style="color:#ef4444;font-size:14px;font-weight:500">These codes will not be shown again.</p>
</div>

<a href="/account/mfa" class="btn btn-outline">Back to MFA settings</a>
{foot}"#,
        head = page_head("Recovery Codes", &theme),
        nav = page_nav("/account/mfa"),
        foot = page_foot(&theme),
    );

    Ok(html_response(&html))
}

// ── POST /account/mfa/disable ───────────────────────────────

pub async fn mfa_disable(headers: &HeaderMap, body: &[u8]) -> Result<Response<String>, String> {
    let (user, csrf) = get_user_or_redirect!(headers);

    let form = util::parse_form(body);
    // CSRF verification
    let submitted_csrf = util::form_value(&form, "csrf").unwrap_or_default();
    if !csrf.is_empty() && submitted_csrf != csrf {
        return Err("invalid CSRF token".into());
    }
    let password = util::form_value(&form, "password").unwrap_or_default();

    if password.is_empty() {
        return mfa_page(headers, None, Some("Password is required to disable MFA.")).await;
    }

    let user = store::get_user(&user.id).await?.ok_or("user not found")?;

    // Verify password before allowing MFA disable
    match crate::service_client::verify_password(password, &user.password_hash).await {
        Ok(true) => {}
        Ok(false) => {
            return mfa_page(headers, None, Some("Incorrect password.")).await;
        }
        Err(e) => {
            crate::logger::error_message("mfa_disable.password_verify_failed", e);
            return mfa_page(
                headers,
                None,
                Some("Could not verify password. Please try again."),
            )
            .await;
        }
    }

    let user_id = user.id.clone();
    store::update_user_rmw(&user_id, |u| {
        u.totp_secret = None;
        u.totp_enabled = false;
        u.recovery_codes.clear();
        Ok(true)
    })
    .await?;

    let _ = store::delete_user_refresh_tokens(&user.id).await;
    let _ = store::log_audit("mfa_disabled", &user.id, &user.id, "tokens revoked").await;

    mfa_page(
        headers,
        Some("MFA has been disabled. All sessions were revoked."),
        None,
    )
    .await
}

// ── GET /account/logout ─────────────────────────────────────

pub async fn logout(headers: &HeaderMap) -> Response<String> {
    if let Some(token) = parse_cookie(headers, COOKIE_NAME) {
        let _ = store::delete_account_session(&token).await;
    }
    if let Some(token) = extract_idp_session_token(headers) {
        let _ = store::delete_idp_session(&token).await;
    }

    let mut resp = Response::builder()
        .status(StatusCode::FOUND)
        .header("location", "/")
        .header("cache-control", "no-store, no-cache, must-revalidate")
        .header("pragma", "no-cache")
        .body(String::new())
        .unwrap();

    append_clear_all_cookies(resp.headers_mut());
    resp
}

// ── Helpers ─────────────────────────────────────────────────

fn html_response(html: &str) -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.to_string())
        .unwrap()
}

/// Simple timestamp display (same as admin-ui).
fn api_format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".into();
    }
    let days = ts / 86400;
    let years = 1970 + days / 365;
    let remaining = days % 365;
    let months = remaining / 30 + 1;
    let day = remaining % 30 + 1;
    let time_secs = ts % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    format!("{years}-{months:02}-{day:02} {hours:02}:{minutes:02}")
}
