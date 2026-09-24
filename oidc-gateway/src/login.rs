use crate::store::{self, ClientTheme};
use crate::util;
use http::{Response, StatusCode};

const ACR_TOTP_MFA: &str = "urn:lattice-id:mfa:totp";

fn primary_amr_for_flow(flow: &str) -> Vec<String> {
    match flow {
        "password" => vec!["pwd".to_string()],
        _ => Vec::new(),
    }
}

fn merge_amr(primary: &[String], additions: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for item in primary {
        if !values.iter().any(|existing| existing == item) {
            values.push(item.clone());
        }
    }
    for item in additions {
        if !values.iter().any(|existing| existing == item) {
            values.push((*item).to_string());
        }
    }
    values
}

fn select_acr(session: &store::AuthSession, amr: &[String]) -> Option<String> {
    let has_mfa = amr.iter().any(|value| value == "mfa") && amr.iter().any(|value| value == "otp");
    if has_mfa {
        return Some(ACR_TOTP_MFA.to_string());
    }

    if session.acr_values.iter().any(|value| value == ACR_TOTP_MFA) {
        return None;
    }

    None
}

/// Compute an ACR value from AMR claims alone (no full AuthSession needed).
/// Used when re-authenticating via an existing IdP browser session.
pub fn acr_from_amr(amr: &[String]) -> Option<String> {
    let has_mfa = amr.iter().any(|v| v == "mfa") && amr.iter().any(|v| v == "otp");
    if has_mfa {
        Some(ACR_TOTP_MFA.to_string())
    } else {
        None
    }
}

/// Resolve the theme for the current auth session's client.
async fn resolve_theme(session_id: &str) -> ClientTheme {
    crate::theme::resolve_theme_for_session(session_id).await
}

async fn hinted_email(session_id: &str) -> Option<String> {
    store::get_auth_session(session_id)
        .await
        .ok()
        .flatten()
        .and_then(|session| session.hinted_email)
}

/// Render the login page HTML with theming, optional Google button, and optional MFA.
pub async fn login_page(session_id: &str, error: Option<&str>) -> Response<String> {
    let theme = resolve_theme(session_id).await;
    let hinted_email = hinted_email(session_id).await.unwrap_or_default();
    let app_name = util::html_escape(&theme.app_name);
    let head_tags = crate::theme::render_head_tags(&theme);
    let css_vars = crate::theme::render_css_variables(&theme);
    let logo_html = crate::theme::render_logo(&theme);
    let footer_html = crate::theme::render_footer(
        &theme,
        Some(
            r#"<a href="/account" style="color:inherit;text-decoration:none">Manage your account</a>"#,
        ),
    );

    let error_html = match error {
        Some(msg) => format!(
            r#"<div class="error-banner">{}</div>"#,
            util::html_escape(msg)
        ),
        None => String::new(),
    };

    // Check if external identity providers are enabled
    let idps = store::list_identity_providers().await.unwrap_or_default();
    let enabled_idps: Vec<_> = idps.into_iter().filter(|i| i.enabled).collect();
    let mut idp_buttons = String::new();
    for idp in &enabled_idps {
        match idp.provider_type.as_str() {
            "google" => {
                idp_buttons.push_str(&format!(
                    r##"<a href="/auth/google?session_id={session_id}" class="google-btn" style="margin-top: 8px;">
<svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
Continue with Google
</a>"##
                ));
            }
            "github" => {
                idp_buttons.push_str(&format!(
                    r##"<a href="/auth/github?session_id={session_id}" class="google-btn" style="margin-top: 8px;">
<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
Continue with GitHub
</a>"##
                ));
            }
            "microsoft" => {
                idp_buttons.push_str(&format!(
                    r##"<a href="/auth/microsoft?session_id={session_id}" class="google-btn" style="margin-top: 8px;">
<svg width="18" height="18" viewBox="0 0 24 24"><path fill="#F25022" d="M1 1h10v10H1z"/><path fill="#7FBA00" d="M13 1h10v10H13z"/><path fill="#00A4EF" d="M1 13h10v10H1z"/><path fill="#FFB900" d="M13 13h10v10H13z"/></svg>
Continue with Microsoft
</a>"##
                ));
            }
            _ => {}
        }
    }
    let idp_html = if !idp_buttons.is_empty() {
        format!(r##"<div class="divider"><span>or</span></div>{idp_buttons}"##)
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In — {app_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body{{font-family:var(--font-family);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--text);padding:20px}}
.card{{background:var(--card-bg);border:var(--card-border);box-shadow:var(--card-shadow);backdrop-filter:blur(var(--card-backdrop-blur));-webkit-backdrop-filter:blur(var(--card-backdrop-blur));border-radius:var(--radius);padding:40px;width:100%;max-width:420px}}
h1{{font-size:24px;font-weight:700;color:var(--text);margin-bottom:6px}}
.sub{{color:var(--text-muted);font-size:14px;margin-bottom:24px}}
label{{display:block;font-size:13px;font-weight:600;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em}}
input[type=email],input[type=password]{{width:100%;padding:12px 14px;border:1px solid var(--input-border);border-radius:calc(var(--radius) * 0.7);background:var(--input-bg);color:var(--input-text);font-size:15px;margin-bottom:16px;outline:none;transition:all .15s ease}}
input:focus{{border-color:var(--primary);box-shadow:0 0 0 3px rgba(16,185,129,.25)}}
button,.passkey-btn{{width:100%;padding:12px;background:var(--primary);color:var(--button-text);border:none;border-radius:calc(var(--radius) * 0.7);font-size:15px;font-weight:600;cursor:pointer;transition:all .15s ease}}
button:hover,.passkey-btn:hover{{background:var(--primary-hover);transform:translateY(-1px)}}
.passkey-btn{{display:flex;align-items:center;justify-content:center;gap:8px;background:transparent;color:var(--text);border:1px solid var(--input-border)}}
.passkey-btn:hover{{background:rgba(255,255,255,.08)}}
.divider{{display:flex;align-items:center;margin:20px 0;color:var(--text-muted);font-size:13px}}
.divider::before,.divider::after{{content:'';flex:1;border-bottom:1px solid var(--input-border)}}
.divider span{{padding:0 12px}}
.google-btn{{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:11px;border:1px solid var(--input-border);border-radius:calc(var(--radius) * 0.7);font-size:15px;font-weight:500;color:var(--text);background:var(--input-bg);text-decoration:none;transition:all .15s ease;cursor:pointer}}
.google-btn:hover{{background:rgba(255,255,255,.08)}}
.error-banner{{color:#ef4444;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);padding:10px 14px;border-radius:calc(var(--radius) * 0.6);margin-bottom:16px;font-size:14px}}
.footer{{text-align:center;margin-top:24px;font-size:13px;color:var(--text-muted)}}
.passkey-error{{color:#ef4444;font-size:13px;margin-top:8px;display:none}}
</style>
</head>
<body>
<div class="card">
{logo_html}
<h1>Sign In</h1>
<p class="sub">{app_name}</p>
{error_html}
<form method="POST" action="/login" id="login-form">
<input type="hidden" name="session_id" value="{session_id}">
<label for="email">Email</label>
<input type="email" id="email" name="email" value="{hinted_email}" required autocomplete="email" autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
<button type="submit" id="login-btn">Sign In</button>
</form>
{idp_html}
<div id="passkey-section" style="display:none">
<div class="divider"><span>or</span></div>
<button type="button" class="passkey-btn" id="passkey-btn" onclick="startPasskeyAuth()">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
Sign in with passkey
</button>
<div class="passkey-error" id="passkey-error"></div>
</div>
{footer_html}
</div>
<script>
(function(){{
  if(!window.PublicKeyCredential)return;
  document.getElementById('passkey-section').style.display='block';

  function b64url(buf){{
    var s='',b=new Uint8Array(buf);
    for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }}
  function b64urlDecode(s){{
    s=s.replace(/-/g,'+').replace(/_/g,'/');
    while(s.length%4)s+='=';
    var b=atob(s),a=new Uint8Array(b.length);
    for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);
    return a.buffer;
  }}

  window.startPasskeyAuth=async function(){{
    var errEl=document.getElementById('passkey-error');
    var btn=document.getElementById('passkey-btn');
    errEl.style.display='none';
    btn.disabled=true;
    btn.textContent='Waiting for passkey\u2026';
    try{{
      var r=await fetch('/passkeys/auth-options',{{method:'POST',headers:{{'content-type':'application/json'}},body:'{{}}'}});
      if(!r.ok)throw new Error(await r.text());
      var d=await r.json();
      var opts=d.publicKey;
      opts.challenge=b64urlDecode(opts.challenge);
      if(opts.allowCredentials){{
        opts.allowCredentials=opts.allowCredentials.map(function(c){{
          c.id=b64urlDecode(c.id);return c;
        }});
      }}
      var cred=await navigator.credentials.get({{publicKey:opts}});
      var body=JSON.stringify({{
        token:d.token,
        session_id:'{session_id}',
        credential_id:b64url(cred.rawId),
        clientDataJSON:b64url(cred.response.clientDataJSON),
        authenticatorData:b64url(cred.response.authenticatorData),
        signature:b64url(cred.response.signature)
      }});
      var r2=await fetch('/passkeys/auth-complete',{{method:'POST',headers:{{'content-type':'application/json'}},body:body}});
      if(!r2.ok)throw new Error(await r2.text());
      var d2=await r2.json();
      if(d2.redirect){{window.location.href=d2.redirect;return;}}
      window.location.reload();
    }}catch(e){{
      if(e.name==='NotAllowedError'){{
        errEl.textContent='Passkey authentication was cancelled.';
      }}else{{
        errEl.textContent='Passkey error: '+(e.message||e);
      }}
      errEl.style.display='block';
      btn.disabled=false;
      btn.innerHTML='<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg> Sign in with passkey';
    }}
  }};
}})();
// Prevent double-submit on login form
var f=document.getElementById('login-form');
if(f)f.addEventListener('submit',function(){{
  var b=document.getElementById('login-btn');
  if(b){{b.disabled=true;b.textContent='Signing in\u2026';}}
}});
</script>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.to_string())
        .unwrap()
}

/// Render MFA challenge page (TOTP code input).
pub async fn mfa_page(mfa_token: &str, session_id: &str, error: Option<&str>) -> Response<String> {
    let theme = resolve_theme(session_id).await;
    let app_name = util::html_escape(&theme.app_name);
    let head_tags = crate::theme::render_head_tags(&theme);
    let css_vars = crate::theme::render_css_variables(&theme);
    let logo_html = crate::theme::render_logo(&theme);
    let footer_html = crate::theme::render_footer(&theme, None);

    let error_html = match error {
        Some(msg) => format!(
            r#"<div class="error-banner">{}</div>"#,
            util::html_escape(msg)
        ),
        None => String::new(),
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two-Factor Authentication — {app_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body{{font-family:var(--font-family);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--text);padding:20px}}
.card{{background:var(--card-bg);border:var(--card-border);box-shadow:var(--card-shadow);backdrop-filter:blur(var(--card-backdrop-blur));-webkit-backdrop-filter:blur(var(--card-backdrop-blur));border-radius:var(--radius);padding:40px;width:100%;max-width:420px}}
h1{{font-size:24px;font-weight:700;color:var(--text);margin-bottom:6px}}
.sub{{color:var(--text-muted);font-size:14px;margin-bottom:24px}}
label{{display:block;font-size:13px;font-weight:600;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em}}
input[type=text]{{width:100%;padding:12px 14px;border:1px solid var(--input-border);border-radius:calc(var(--radius) * 0.7);background:var(--input-bg);color:var(--input-text);font-size:20px;margin-bottom:16px;outline:none;text-align:center;letter-spacing:8px;font-family:monospace;transition:all .15s ease}}
input:focus{{border-color:var(--primary);box-shadow:0 0 0 3px rgba(16,185,129,.25)}}
button{{width:100%;padding:12px;background:var(--primary);color:var(--button-text);border:none;border-radius:calc(var(--radius) * 0.7);font-size:15px;font-weight:600;cursor:pointer;transition:all .15s ease}}
button:hover{{background:var(--primary-hover);transform:translateY(-1px)}}
.hint{{color:var(--text-muted);font-size:13px;margin-top:12px;text-align:center}}
.error-banner{{color:#ef4444;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);padding:10px 14px;border-radius:calc(var(--radius) * 0.6);margin-bottom:16px;font-size:14px}}
.footer{{text-align:center;margin-top:24px;font-size:13px;color:var(--text-muted)}}
</style>
</head>
<body>
<div class="card">
{logo_html}
<h1>Two-Factor Authentication</h1>
<p class="sub">Enter the code from your authenticator app</p>
{error_html}
<form method="POST" action="/login/mfa" id="mfa-form">
<input type="hidden" name="mfa_token" value="{mfa_token}">
<input type="hidden" name="session_id" value="{session_id}">
<label for="code">Authentication Code</label>
<input type="text" id="code" name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{{6,8}}" maxlength="8" autofocus>
<button type="submit" id="mfa-btn">Verify</button>
</form>
<p class="hint">You can also use a recovery code</p>
{footer_html}
</div>
<script>
var f=document.getElementById('mfa-form');
if(f)f.addEventListener('submit',function(){{
  var b=document.getElementById('mfa-btn');
  if(b){{b.disabled=true;b.textContent='Verifying\u2026';}}
}});
</script>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.to_string())
        .unwrap()
}

/// Handle POST /login — validate credentials, check MFA, issue auth code, redirect.
pub async fn handle_login(body_bytes: &[u8], remote_ip: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let session_id = util::form_value(&form, "session_id").ok_or("missing session_id")?;
    let email = util::form_value(&form, "email").ok_or("missing email")?;
    let password = util::form_value(&form, "password").ok_or("missing password")?;

    // Task 2.8: Suspicious login detection (Log IP)
    let _ = crate::store::log_audit(
        "login_attempt",
        "",
        "",
        &format!("email:{} ip:{}", email, remote_ip),
    )
    .await;

    // Rate limit: 10 login attempts per email per 60 seconds
    match crate::service_client::check_rate(&format!("login:{}", email.to_lowercase()), 10, 60)
        .await
    {
        Ok((false, _)) => {
            let _ = crate::service_client::increment_metric(
                "lattice_id_rate_limit_hits_total",
                &[("scope", "login")],
            )
            .await;
            return Ok(login_page(
                session_id,
                Some("Too many login attempts. Please wait and try again."),
            )
            .await);
        }
        Err(e) => {
            crate::logger::error_message("rate_limit.login_check_failed", e);
        }
        _ => {}
    }

    // Load auth session
    let session = crate::store::get_auth_session(session_id)
        .await?
        .ok_or("invalid or expired session")?;

    // Check auth session expiry (e.g., 10 minutes)
    if crate::store::unix_now() > session.created_at + 600 {
        return Ok(login_page(
            session_id,
            Some("Login session expired. Please start over."),
        )
        .await);
    }

    // Look up user by email.
    // Return the same generic error for non-existent AND pending users
    // to prevent email enumeration (CWE-200).
    let user = match crate::store::get_user_by_email(email).await? {
        Some(u) if u.status == "active" => u,
        _ => {
            // Cross-region redirect: if user not found locally, check remote regions
            if store::region_id().is_some() {
                let email_hash = store::hmac_email(&email.to_lowercase());
                if let Ok(Some(region)) = crate::service_client::lookup_region(&email_hash).await
                    && let Some(base_url) = store::region_domain(&region)
                {
                    // Redirect to the remote region's /authorize preserving OIDC params
                    let enc = crate::util::percent_encode;
                    let mut url = format!(
                        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method={}&state={}&scope={}&nonce={}&login_hint={}",
                        base_url,
                        enc(&session.client_id),
                        enc(&session.redirect_uri),
                        enc(&session.code_challenge),
                        enc(&session.code_challenge_method),
                        enc(&session.state),
                        enc(&session.scope),
                        enc(&session.nonce),
                        enc(email),
                    );
                    if let Some(max_age) = session.max_age {
                        url.push_str(&format!("&max_age={max_age}"));
                    }
                    // Clean up the local session
                    let _ = store::delete_auth_session(session_id).await;
                    return Ok(Response::builder()
                        .status(http::StatusCode::FOUND)
                        .header("location", &url)
                        .body(String::new())
                        .unwrap());
                }
            }

            // Perform a dummy password hash to prevent timing-based enumeration.
            let _ = crate::service_client::verify_password(
                password,
                "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ).await;
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            return Ok(login_page(session_id, Some("Invalid email or password")).await);
        }
    };

    // Check account lockout
    if crate::store::is_account_locked(&user.id).await? {
        // Perform a dummy password hash to prevent timing-based lockout enumeration.
        let _ = crate::service_client::verify_password(
            password,
            "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ).await;
        let _ = crate::store::log_audit("login_locked", &user.id, &user.id, "account locked").await;
        let _ = crate::service_client::increment_metric(
            "lattice_id_login_attempts_total",
            &[("flow", "password"), ("result", "failure")],
        )
        .await;
        return Ok(login_page(
            session_id,
            Some(
                "Account temporarily locked due to too many failed attempts. Please try again later.",
            ),
        ).await);
    }

    // Verify password via password-hasher
    match crate::service_client::verify_password(password, &user.password_hash).await {
        Ok(true) => {}
        Ok(false) => {
            let locked = crate::store::record_failed_login(&user.id)
                .await
                .unwrap_or(false);
            let _ = crate::store::log_audit("login_failure", &user.id, &user.id, email).await;
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            if locked {
                let _ = crate::store::log_audit(
                    "account_locked",
                    &user.id,
                    &user.id,
                    "locked after repeated failures",
                )
                .await;
                return Ok(login_page(
                    session_id,
                    Some("Account temporarily locked due to too many failed attempts."),
                )
                .await);
            }
            return Ok(login_page(session_id, Some("Invalid email or password")).await);
        }
        Err(_e) => {
            // Return the same generic message for all failures (including
            // social-only accounts whose password_hash isn't valid Argon2).
            // This prevents distinguishing social accounts from password accounts.
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            return Ok(login_page(session_id, Some("Invalid email or password")).await);
        }
    }

    // Password verified — check if MFA is required
    if user.totp_enabled {
        let mfa_token = store::random_hex(32);
        let pending = store::MfaPending {
            user_id: user.id.clone(),
            session_id: session_id.to_string(),
            primary_amr: primary_amr_for_flow("password"),
            expires_at: store::unix_now() + 300, // 5 minutes
            remote_ip: remote_ip.to_string(),
        };
        store::save_mfa_pending(&mfa_token, &pending).await?;
        return Ok(mfa_page(&mfa_token, session_id, None).await);
    }

    // No MFA — complete login
    complete_login(&user, session_id, "password", remote_ip).await
}

/// Handle POST /login/mfa — verify TOTP code and complete login.
pub async fn handle_mfa(body_bytes: &[u8], _remote_ip: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let mfa_token = util::form_value(&form, "mfa_token").ok_or("missing mfa_token")?;
    let session_id = util::form_value(&form, "session_id").ok_or("missing session_id")?;
    let code = util::form_value(&form, "code").ok_or("missing code")?;

    // Rate limit MFA: 5 attempts per token per 15 minutes
    match crate::service_client::check_rate(&format!("mfa:{}", mfa_token), 5, 900).await {
        Ok((false, _)) => {
            let _ = store::delete_mfa_pending(mfa_token).await;
            return Ok(login_page(
                session_id,
                Some("Too many MFA attempts. Session invalidated."),
            )
            .await);
        }
        Err(e) => crate::logger::error_message("rate_limit.mfa_check_failed", e),
        _ => {}
    }

    let pending = store::get_mfa_pending(mfa_token)
        .await?
        .ok_or("invalid or expired MFA session")?;
    if store::unix_now() > pending.expires_at {
        store::delete_mfa_pending(mfa_token).await?;
        return Ok(login_page(session_id, Some("MFA session expired, please log in again")).await);
    }

    let user = store::get_user(&pending.user_id)
        .await?
        .ok_or("user not found")?;

    let totp_secret = user
        .totp_secret
        .as_deref()
        .ok_or("MFA not configured for this user")?;

    // Try TOTP code first
    if let Some(step) = crate::totp::verify_totp_step(totp_secret, code.trim()) {
        let replay_key = format!("totp_used:{}:{}", user.id, step);
        if store::record_totp_used(&replay_key, 90)
            .await
            .unwrap_or(true)
        {
            store::delete_mfa_pending(mfa_token).await?;
            let _ = store::log_audit("mfa_success", &user.id, &user.id, "totp").await;
            let amr = merge_amr(&pending.primary_amr, &["otp", "mfa"]);
            return complete_login_with_amr(&user, session_id, "totp", amr, &pending.remote_ip)
                .await;
        } else {
            return Ok(login_page(
                session_id,
                Some("TOTP code already used. Please wait for the next code."),
            )
            .await);
        }
    }

    // Try recovery codes — use CAS to prevent double-use across replicas
    let code_trimmed = code.trim().to_lowercase();
    let user_id = user.id.clone();
    let code_for_closure = code_trimmed.clone();
    let rmw_result =
        store::update_user_rmw(&user_id, |u| {
            if let Some(pos) = u.recovery_codes.iter().position(|c| {
                crate::totp::constant_time_eq(c.as_bytes(), code_for_closure.as_bytes())
            }) {
                u.recovery_codes.remove(pos);
                Ok(true) // commit
            } else {
                Ok(false) // code not found, no change
            }
        })
        .await;

    match rmw_result {
        Ok(()) => {
            // Check if the code was actually found (re-read to confirm)
            let updated_user = store::get_user(&user_id).await?.ok_or("user not found")?;
            // If the code is no longer present, it was consumed by us (or another replica — either way it's gone)
            if !updated_user
                .recovery_codes
                .iter()
                .any(|c| crate::totp::constant_time_eq(c.as_bytes(), code_trimmed.as_bytes()))
                && user
                    .recovery_codes
                    .iter()
                    .any(|c| crate::totp::constant_time_eq(c.as_bytes(), code_trimmed.as_bytes()))
            {
                store::delete_mfa_pending(mfa_token).await?;
                let _ = store::log_audit(
                    "mfa_success",
                    &updated_user.id,
                    &updated_user.id,
                    "recovery_code",
                )
                .await;
                let amr = merge_amr(&pending.primary_amr, &["otp", "mfa"]);
                return complete_login_with_amr(
                    &updated_user,
                    session_id,
                    "recovery_code",
                    amr,
                    &pending.remote_ip,
                )
                .await;
            }
        }
        Err(e) => {
            crate::logger::error_message("mfa.recovery_code_update_failed", e);
        }
    }

    let _ = store::log_audit("mfa_failure", &user.id, &user.id, "").await;
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", "mfa"), ("result", "failure")],
    )
    .await;
    Ok(mfa_page(
        mfa_token,
        session_id,
        Some("Invalid code. Please try again."),
    )
    .await)
}

/// Complete login after password (and optional MFA) verification.
pub async fn complete_login(
    user: &store::User,
    session_id: &str,
    flow: &str,
    remote_ip: &str,
) -> Result<Response<String>, String> {
    complete_login_with_amr(
        user,
        session_id,
        flow,
        primary_amr_for_flow(flow),
        remote_ip,
    )
    .await
}

pub async fn complete_login_with_amr(
    user: &store::User,
    session_id: &str,
    flow: &str,
    amr: Vec<String>,
    remote_ip: &str,
) -> Result<Response<String>, String> {
    // Execute post-login hooks (Rhai scripting)
    let outcome = crate::hooks::execute_hooks("post-login", user).await;

    // If a hook denied the login, abort
    if let Some(reason) = &outcome.deny_reason {
        let _ = crate::store::log_audit("login_denied_by_hook", &user.id, &user.id, reason).await;
        return Ok(login_page(session_id, Some(reason)).await);
    }

    // Apply hook side-effects (superadmin promotion, tenant membership, etc.)
    let mut user = user.clone();
    if let Err(e) = crate::hooks::apply_outcome(&mut user, &outcome).await {
        crate::logger::error_message("hooks.apply_failed", e);
    }

    // Suspicious login detection: flag logins from previously-unseen IPs
    if store::check_and_record_ip(&user.id, remote_ip).await {
        let _ = store::log_audit(
            "suspicious_login",
            &user.id,
            &user.id,
            &format!("new_ip:{}", remote_ip),
        )
        .await;
    }

    let _ = crate::store::clear_login_attempts(&user.id).await;
    let _ = crate::store::log_audit("login_success", &user.id, &user.id, "").await;
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", flow), ("result", "success")],
    )
    .await;

    let session = crate::store::consume_auth_session(session_id)
        .await?
        .ok_or("Login already in progress. Please wait for the redirect.")?;
    let acr = select_acr(&session, &amr);

    // ── Device authorization grant (RFC 8628) ──
    // device::submit() creates an auth session with code_challenge_method = "device"
    // and state = device_code. Detect this and finalize the device code instead of
    // issuing an authorization code.
    if session.code_challenge_method == "device" {
        let device_code = &session.state;
        if let Err(e) = crate::store::update_device_code_status(
            device_code,
            "approved",
            Some(&user.id),
            session.sid.as_deref(),
        )
        .await
        {
            crate::logger::error_message("device.approve_failed", e);
            return Ok(login_page(
                session_id,
                Some("Failed to activate device. Please try again."),
            )
            .await);
        }
        let _ = crate::store::log_audit("device_approved", &user.id, &user.id, &session.client_id)
            .await;

        let mut builder = Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "/device/complete")
            .header("cache-control", "no-store");
        if let Ok(cookie) = crate::account::create_session_cookie(&user.id).await {
            builder = builder.header("set-cookie", cookie);
        }
        if let Ok(cookie) =
            crate::account::create_idp_session_cookie(&user.id, &amr, crate::store::unix_now())
                .await
        {
            builder = builder.header("set-cookie", cookie);
        }
        return Ok(builder.body(String::new()).unwrap());
    }

    // Generate auth code
    let code = crate::store::random_hex(32);
    let auth_time = crate::store::unix_now();
    let auth_code = crate::store::AuthCode {
        user_id: user.id.clone(),
        client_id: session.client_id.clone(),
        redirect_uri: session.redirect_uri.clone(),
        code_challenge: session.code_challenge.clone(),
        code_challenge_method: session.code_challenge_method.clone(),
        nonce: session.nonce.clone(),
        scope: session.scope.clone(),
        auth_time,
        amr: amr.clone(),
        acr: acr.clone(),
        requested_id_token_claims: session.requested_id_token_claims.clone(),
        requested_userinfo_claims: session.requested_userinfo_claims.clone(),
        extra_claims: outcome.extra_claims.clone(),
        csrf_token: crate::store::random_hex(16),
        expires_at: crate::store::unix_now() + 300,
        state: session.state.clone(),
        sid: session.sid.clone(),
    };

    // ── Consent screen ──────────────────────────────────────
    // If the session requires consent, check if the user has already approved
    // these scopes previously. If not (or if prompt=consent), show the consent page.
    let force_consent = session.prompt.as_deref() == Some("consent");
    let needs_consent = if force_consent {
        true
    } else if session.needs_consent {
        let already_consented =
            crate::store::has_user_consented(&user.id, &session.client_id, &session.scope)
                .await
                .unwrap_or(false);
        !already_consented
    } else {
        false
    };

    if needs_consent {
        // Store the pending auth code *before* consent so we can issue it
        // after approval without re-doing the whole login.
        crate::store::save_auth_code(&code, &auth_code).await?;

        let client = crate::store::get_client(&auth_code.client_id)
            .await?
            .unwrap_or_default();
        // Set lid_session before the consent page so it is established even
        // before the final redirect (the consent POST has no cookie to set).
        let mut resp = consent_page(&code, &auth_code, &client, &user).await;
        if let Ok(cookie) =
            crate::account::create_idp_session_cookie(&user.id, &amr, auth_time).await
        {
            let (mut parts, body) = resp.into_parts();
            if let Ok(val) = cookie.parse() {
                parts.headers.append("set-cookie", val);
            }
            resp = Response::from_parts(parts, body);
        }
        return Ok(resp);
    }

    crate::store::save_auth_code(&code, &auth_code).await?;

    let issuer = crate::get_issuer();
    let redirect_url = crate::util::build_auth_code_redirect(
        &session.redirect_uri,
        &code,
        &session.state,
        &issuer,
    );

    // Set account session cookie so the user can visit /account later
    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &redirect_url)
        .header("cache-control", "no-store");
    if let Ok(cookie) = crate::account::create_session_cookie(&user.id).await {
        builder = builder.header("set-cookie", cookie);
    }
    // Set IdP session cookie for SSO / prompt=none support
    if let Ok(cookie) = crate::account::create_idp_session_cookie(&user.id, &amr, auth_time).await {
        builder = builder.header("set-cookie", cookie);
    }

    Ok(builder.body(String::new()).unwrap())
}

/// Render the consent page shown to users for third-party / prompt=consent flows.
/// The page shows what scopes are requested and lets the user approve or deny.
pub async fn consent_page(
    code: &str,
    auth_code: &crate::store::AuthCode,
    client: &crate::store::OidcClient,
    user: &crate::store::User,
) -> Response<String> {
    let settings = store::get_runtime_settings().await;
    let theme = crate::theme::resolve_effective_theme(client.theme.clone(), &settings);
    let app_name = crate::util::html_escape(&client.name);
    let user_email = crate::util::html_escape(&user.email);
    let head_tags = crate::theme::render_head_tags(&theme);
    let css_vars = crate::theme::render_css_variables(&theme);
    let logo_html = crate::theme::render_logo(&theme);
    let footer_html = crate::theme::render_footer(&theme, None);

    let scope_list: Vec<&str> = auth_code
        .scope
        .split_whitespace()
        .filter(|s| *s != "openid")
        .collect();

    let scope_descriptions: Vec<String> = auth_code.scope.split_whitespace().map(|s| {
        let desc = match s {
            "openid"   => "Verify your identity",
            "email"    => "Read your email address",
            "profile"  => "Read your name and profile info",
            "offline_access" => "Stay signed in (refresh tokens)",
            other      => other,
        };
        format!(r#"<li style="padding:8px 0;border-bottom:1px solid var(--input-border);color:var(--text)">{}</li>"#,
            crate::util::html_escape(desc))
    }).collect();
    let scopes_html = scope_descriptions.join("\n");

    let _ = scope_list; // suppress warning

    let csrf_token = crate::util::html_escape(&auth_code.csrf_token);

    let logout_link = format!(
        "/logout?client_id={}&post_logout_redirect_uri={}",
        crate::util::percent_encode(&auth_code.client_id),
        crate::util::percent_encode(&auth_code.redirect_uri)
    );

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorise {app_name}</title>
{head_tags}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
{css_vars}
body{{font-family:var(--font-family);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--text);padding:20px}}
.card{{background:var(--card-bg);border:var(--card-border);box-shadow:var(--card-shadow);backdrop-filter:blur(var(--card-backdrop-blur));-webkit-backdrop-filter:blur(var(--card-backdrop-blur));border-radius:var(--radius);padding:40px;width:100%;max-width:440px}}
h1{{font-size:22px;font-weight:700;color:var(--text);margin-bottom:6px}}
.sub{{color:var(--text-muted);font-size:14px;margin-bottom:24px}}
.client-name{{font-weight:700;color:var(--text)}}
ul{{list-style:none;margin-bottom:24px;padding:0;border-top:1px solid var(--input-border)}}
.actions{{display:flex;gap:12px}}
button{{flex:1;padding:12px;border:none;border-radius:calc(var(--radius) * 0.7);font-size:15px;font-weight:600;cursor:pointer;transition:all .15s ease}}
.btn-approve{{background:var(--primary);color:var(--button-text)}}
.btn-approve:hover{{background:var(--primary-hover);transform:translateY(-1px)}}
.btn-deny{{background:transparent;color:var(--text);border:1px solid var(--input-border)}}
.btn-deny:hover{{background:rgba(255,255,255,.08)}}
.footer{{text-align:center;margin-top:24px;font-size:13px;color:var(--text-muted)}}
</style>
</head>
<body>
<div class="card">
{logo_html}
<h1>Authorise <span class="client-name">{app_name}</span></h1>
<p class="sub">Signed in as <strong>{user_email}</strong> &bull; <a href="{logout_link}" style="color:var(--primary);text-decoration:none">Switch account</a></p>

<p style="font-size:14px;color:var(--text-muted);margin-bottom:12px"><strong>{app_name}</strong> is requesting access to:</p>
<ul>
{scopes_html}
</ul>

<form method="POST" action="/consent">
<input type="hidden" name="code" value="{code}">
<input type="hidden" name="csrf_token" value="{csrf_token}">
<div class="actions">
<button type="submit" class="btn-approve" name="decision" value="approve">Allow access</button>
<button type="submit" class="btn-deny" name="decision" value="deny">Deny</button>
</div>
</form>

{footer_html}
</div>
</body>
</html>"#,
        code = crate::util::html_escape(code),
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// Handle POST /consent — user approves or denies.
pub async fn handle_consent(body_bytes: &[u8]) -> Result<Response<String>, String> {
    let form = crate::util::parse_form(body_bytes);
    let code = crate::util::form_value(&form, "code").ok_or("missing code")?;
    let submitted_csrf = crate::util::form_value(&form, "csrf_token").unwrap_or("");
    let decision = crate::util::form_value(&form, "decision").unwrap_or("deny");

    let auth_code = crate::store::get_auth_code(code)
        .await?
        .ok_or("invalid or expired authorisation code")?;

    if crate::store::unix_now() > auth_code.expires_at {
        let _ = crate::store::delete_auth_code(code).await;
        return Err("authorisation code expired".into());
    }
    if decision == "approve"
        && !auth_code.csrf_token.is_empty()
        && submitted_csrf != auth_code.csrf_token
    {
        return Err("invalid CSRF token".into());
    }

    if decision != "approve" {
        let _ = crate::store::delete_auth_code(code).await;
        // Redirect back to the client with access_denied
        let sep = if auth_code.redirect_uri.contains('?') {
            '&'
        } else {
            '?'
        };
        let issuer = crate::get_issuer();
        let mut loc = format!(
            "{}{}error=access_denied&error_description=user+denied+consent&iss={}",
            auth_code.redirect_uri,
            sep,
            crate::util::percent_encode(&issuer)
        );
        if !auth_code.state.is_empty() {
            loc.push_str(&format!(
                "&state={}",
                crate::util::percent_encode(&auth_code.state)
            ));
        }
        return Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header("location", &loc)
            .header("cache-control", "no-store")
            .body(String::new())
            .unwrap());
    }

    // Approved — redirect with the auth code
    let issuer = crate::get_issuer();
    let redirect = crate::util::build_auth_code_redirect(
        &auth_code.redirect_uri,
        code,
        &auth_code.state,
        &issuer,
    );

    // Persist user consent for this client and requested scopes
    let requested_scopes: Vec<String> = auth_code
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let _ = crate::store::save_user_consent(
        &auth_code.user_id,
        &auth_code.client_id,
        &requested_scopes,
    )
    .await;

    let _ = crate::store::log_audit(
        "consent_approved",
        &auth_code.user_id,
        &auth_code.client_id,
        &auth_code.scope,
    )
    .await;

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &redirect)
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primary_amr_for_password() {
        assert_eq!(primary_amr_for_flow("password"), vec!["pwd"]);
    }

    #[test]
    fn test_primary_amr_for_unknown_flow() {
        let amr: Vec<String> = Vec::new();
        assert_eq!(primary_amr_for_flow("unknown"), amr);
    }

    #[test]
    fn test_merge_amr_dedupes() {
        let result = merge_amr(&["pwd".to_string()], &["mfa", "otp"]);
        assert_eq!(result, vec!["pwd", "mfa", "otp"]);
    }

    #[test]
    fn test_merge_amr_handles_empty_primary() {
        let result = merge_amr(&[], &["mfa"]);
        assert_eq!(result, vec!["mfa"]);
    }

    #[test]
    fn test_select_acr_mfa() {
        let session = store::AuthSession {
            client_id: "test".into(),
            redirect_uri: "http://localhost".into(),
            code_challenge: "c".into(),
            code_challenge_method: "S256".into(),
            state: "s".into(),
            scope: "openid".into(),
            nonce: "n".into(),
            max_age: None,
            acr_values: vec![],
            requested_id_token_claims: vec![],
            requested_userinfo_claims: vec![],
            hinted_user_id: None,
            hinted_email: None,
            created_at: 0,
            needs_consent: false,
            prompt: None,
            sid: None,
        };
        let amr = vec!["pwd".to_string(), "mfa".to_string(), "otp".to_string()];
        assert_eq!(
            select_acr(&session, &amr),
            Some("urn:lattice-id:mfa:totp".to_string())
        );
    }

    #[test]
    fn test_select_acr_no_mfa() {
        let session = store::AuthSession {
            client_id: "test".into(),
            redirect_uri: "http://localhost".into(),
            code_challenge: "c".into(),
            code_challenge_method: "S256".into(),
            state: "s".into(),
            scope: "openid".into(),
            nonce: "n".into(),
            max_age: None,
            acr_values: vec![],
            requested_id_token_claims: vec![],
            requested_userinfo_claims: vec![],
            hinted_user_id: None,
            hinted_email: None,
            created_at: 0,
            needs_consent: false,
            prompt: None,
            sid: None,
        };
        let amr = vec!["pwd".to_string()];
        assert_eq!(select_acr(&session, &amr), None);
    }

    #[test]
    fn test_darken_hex() {
        let darkened = crate::theme::darken_hex("#2563eb");
        assert!(darkened.starts_with('#'));
        assert_eq!(darkened.len(), 7);
    }

    #[test]
    fn test_darken_hex_invalid_fallback() {
        let darkened = crate::theme::darken_hex("invalid");
        assert_eq!(darkened, "#1d4ed8");
    }

    #[test]
    fn test_acr_from_amr_with_mfa() {
        let amr = vec!["pwd".to_string(), "mfa".to_string(), "otp".to_string()];
        assert_eq!(
            acr_from_amr(&amr),
            Some("urn:lattice-id:mfa:totp".to_string())
        );
    }

    #[test]
    fn test_acr_from_amr_without_mfa() {
        let amr = vec!["pwd".to_string()];
        assert_eq!(acr_from_amr(&amr), None);
    }
}
