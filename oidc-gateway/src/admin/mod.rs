pub mod layout;
pub mod static_assets;
pub mod views;

use crate::admin::layout::AdminSession;
use crate::store::{
    self, AccountSession, ClientTheme, Hook, HookVersion, IdentityProvider, Invitation, Membership,
    OidcClient, Tenant, User,
};
use crate::util::{form_value, parse_form, parse_query};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, Method, Response, StatusCode};

pub async fn handle_admin_route(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Response<String> {
    // ── Static Assets (no auth required) ──
    if path == "/admin/style.css" || path == "/admin/style.css/" {
        return static_assets::serve_css();
    }
    if path == "/admin/htmx.min.js" || path == "/admin/htmx.min.js/" {
        return static_assets::serve_htmx();
    }

    // ── Bootstrap Check ──
    let has_admin = crate::hooks::has_superadmin().await;
    if !has_admin {
        if path == "/admin/bootstrap" && method == Method::POST {
            return handle_bootstrap_submit(body).await;
        }
        return views::bootstrap::render_bootstrap_page(None);
    }

    if path == "/admin/bootstrap" {
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("location", "/admin/login")
            .body(String::new())
            .unwrap();
    }

    // ── Public Auth Routes (Login, MFA, Logout) ──
    let path_no_query = path.split('?').next().unwrap_or(path);
    let clean_path = path_no_query.trim_end_matches('/');
    let p = if clean_path.is_empty() {
        "/admin"
    } else {
        clean_path
    };

    if p == "/admin/login" {
        if method == Method::POST {
            return handle_admin_login(body).await;
        }
        if resolve_admin_session(headers).await.is_ok() {
            return Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", "/admin")
                .body(String::new())
                .unwrap();
        }
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(
                "location",
                "/authorize?client_id=lid-admin&redirect_uri=/admin&response_type=code&scope=openid+email+profile&state=admin_login",
            )
            .body(String::new())
            .unwrap();
    }

    if p == "/admin/login/mfa" && method == Method::POST {
        return handle_admin_login_mfa(body).await;
    }

    if p == "/admin/logout" {
        return handle_admin_logout(headers).await;
    }

    // ── Authenticate Session ──
    let session = match resolve_admin_session(headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // ── CSRF Protection on state-mutating requests ──
    if *method == Method::POST || *method == Method::PUT || *method == Method::DELETE {
        if let Err(resp) = verify_admin_csrf(headers, body, &session) {
            return resp;
        }
    }

    // ── Route Dispatch ──
    let path_no_query = path.split('?').next().unwrap_or(path);
    let clean_path = path_no_query.trim_end_matches('/');
    let p = if clean_path.is_empty() {
        "/admin"
    } else {
        clean_path
    };

    match (method, p) {
        // ── Dashboard ──
        (&Method::GET, "/admin") => views::dashboard::render_dashboard(&session).await,

        // ── Tenant Switcher ──
        (&Method::POST, "/admin/tenant/switch") => {
            let form = parse_form(body);
            let tenant_id = form_value(&form, "tenant_id").unwrap_or("");
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", "/admin")
                .header("HX-Redirect", "/admin")
                .header(
                    "set-cookie",
                    format!("lid_tenant={tenant_id}; Path=/admin; SameSite=Lax; HttpOnly"),
                )
                .body(String::new())
                .unwrap()
        }

        // ── Tenants ──
        (&Method::GET, "/admin/tenants") => views::tenants::render_tenants_page(&session).await,
        (&Method::GET, "/admin/tenants/modal/new") => {
            html_response(views::tenants::render_new_tenant_modal().into_string())
        }
        (&Method::POST, "/admin/tenants") => {
            let form = parse_form(body);
            let display_name = form_value(&form, "display_name").unwrap_or("").trim();
            let name = form_value(&form, "name").unwrap_or("").trim();
            if display_name.is_empty() || name.is_empty() {
                return error_response(StatusCode::BAD_REQUEST, "Missing required tenant fields");
            }
            let tenant_id = format!("tenant_{}", &store::random_alphanumeric(12));
            let tenant = Tenant {
                id: tenant_id.clone(),
                name: name.to_string(),
                display_name: display_name.to_string(),
                status: "active".to_string(),
                created_at: store::unix_now(),
            };
            if let Err(e) = store::create_tenant(&tenant).await {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to save tenant: {e}"),
                );
            }
            // Add creator as owner
            let membership = Membership {
                user_id: session.user.id.clone(),
                tenant_id: tenant_id.clone(),
                role: "owner".to_string(),
                joined_at: store::unix_now(),
            };
            let _ = store::add_membership(&membership).await;
            redirect_response("/admin/tenants")
        }

        // ── Clients ──
        (&Method::GET, "/admin/clients") => views::clients::render_clients_page(&session).await,
        (&Method::GET, "/admin/clients/modal/new") => {
            html_response(views::clients::render_new_client_modal().into_string())
        }
        (&Method::POST, "/admin/clients") => {
            let form = parse_form(body);
            let name = form_value(&form, "name").unwrap_or("").trim();
            let client_type = form_value(&form, "client_type").unwrap_or("confidential");
            let uris_raw = form_value(&form, "redirect_uris").unwrap_or("");
            let post_logout_uris_raw = form_value(&form, "post_logout_redirect_uris").unwrap_or("");
            let first_party = form_value(&form, "first_party")
                .map(|v| v == "true" || v == "on")
                .unwrap_or(false);
            let id_token_signed_response_alg = form_value(&form, "id_token_signed_response_alg")
                .filter(|a| !a.trim().is_empty())
                .map(|a| a.trim().to_string());
            let backchannel_logout_uri = form_value(&form, "backchannel_logout_uri")
                .filter(|u| !u.trim().is_empty())
                .map(|u| u.trim().to_string());
            let mut grant_types: Vec<String> = crate::util::form_values(&form, "grant_types")
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            if grant_types.is_empty() {
                grant_types = vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ];
            }

            let app_name = form_value(&form, "app_name")
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(name)
                .to_string();
            let theme_preset = form_value(&form, "theme_preset")
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string());
            let logo_url = form_value(&form, "logo_url")
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string());
            let primary_color = form_value(&form, "primary_color")
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string());
            let background_color = form_value(&form, "background_color")
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string());

            if name.is_empty() {
                return error_response(StatusCode::BAD_REQUEST, "Client name is required");
            }

            let redirect_uris: Vec<String> = uris_raw
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();

            let post_logout_redirect_uris: Vec<String> = post_logout_uris_raw
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();

            let client_id = format!("client_{}", &store::random_alphanumeric(16));
            let (client_secret, raw_secret_opt) = if client_type == "confidential" {
                let raw = store::random_alphanumeric(32);
                let hashed = store::hmac_client_secret(&raw);
                (Some(hashed), Some(raw))
            } else {
                (None, None)
            };

            let theme = if logo_url.is_some()
                || primary_color.is_some()
                || background_color.is_some()
                || theme_preset.is_some()
                || app_name != name
            {
                Some(ClientTheme {
                    app_name,
                    theme_preset,
                    logo_url,
                    primary_color,
                    background_color,
                    ..Default::default()
                })
            } else {
                None
            };

            let client = OidcClient {
                client_id: client_id.clone(),
                client_secret,
                redirect_uris,
                post_logout_redirect_uris,
                grant_types,
                name: name.to_string(),
                first_party,
                id_token_signed_response_alg,
                backchannel_logout_uri,
                theme,
                ..Default::default()
            };

            if let Err(e) = store::save_client(&client).await {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to save client: {e}"),
                );
            }
            if let Some(raw_secret) = raw_secret_opt {
                views::clients::render_client_detail_page(&session, &client, Some(&raw_secret))
                    .await
            } else {
                redirect_response(&format!("/admin/clients/{client_id}"))
            }
        }

        // ── Users ──
        (&Method::GET, "/admin/users") => views::users::render_users_page(&session).await,
        (&Method::GET, "/admin/users/search") => {
            let query_str = path.split_once('?').map(|(_, qs)| qs).unwrap_or("");
            let q = parse_query(query_str);
            let query_term = form_value(&q, "q")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            let all_users = store::list_users().await.unwrap_or_default();
            let filtered: Vec<User> = if query_term.is_empty() {
                all_users
            } else {
                all_users
                    .into_iter()
                    .filter(|u| {
                        u.email.to_lowercase().contains(&query_term)
                            || u.name.to_lowercase().contains(&query_term)
                    })
                    .collect()
            };
            html_response(views::users::render_users_table(&filtered).into_string())
        }

        // ── Identity Providers ──
        (&Method::GET, "/admin/identity-providers") => {
            views::idps::render_idps_page(&session).await
        }
        (&Method::GET, "/admin/identity-providers/modal/new") => {
            html_response(views::idps::render_new_idp_modal().into_string())
        }
        (&Method::POST, "/admin/identity-providers") => {
            let form = parse_form(body);
            let provider_type = form_value(&form, "provider_type")
                .unwrap_or("google")
                .to_string();
            let client_id = form_value(&form, "client_id")
                .unwrap_or("")
                .trim()
                .to_string();
            let client_secret = form_value(&form, "client_secret")
                .unwrap_or("")
                .trim()
                .to_string();
            let enabled = form_value(&form, "enabled")
                .map(|v| v == "true" || v == "on")
                .unwrap_or(false);

            if client_id.is_empty() || client_secret.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Client ID and Client Secret required",
                );
            }

            let id = format!("idp_{}", &store::random_alphanumeric(12));
            let idp = IdentityProvider {
                id,
                provider_type,
                client_id,
                client_secret,
                enabled,
                discovery_url: None,
                display_name: None,
            };

            if let Err(e) = store::save_identity_provider(&idp).await {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to save IDP: {e}"),
                );
            }
            redirect_response("/admin/identity-providers")
        }

        // ── Hooks ──
        (&Method::GET, "/admin/hooks") => views::hooks::render_hooks_page(&session).await,
        (&Method::GET, "/admin/hooks/new") => {
            views::hooks::render_hook_editor_page(&session, None, &[]).await
        }
        (&Method::POST, "/admin/hooks") => {
            let form = parse_form(body);
            let name = form_value(&form, "name").unwrap_or("").trim();
            let trigger = form_value(&form, "trigger").unwrap_or("post-login");
            let priority: i32 = form_value(&form, "priority")
                .and_then(|p| p.parse().ok())
                .unwrap_or(100);
            let enabled = form_value(&form, "enabled")
                .map(|v| v == "true" || v == "on")
                .unwrap_or(false);
            let script = form_value(&form, "script").unwrap_or("");

            if name.is_empty() || script.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "Hook name and script cannot be empty",
                );
            }

            let id = format!("hook_{}", &store::random_alphanumeric(12));
            let hash = store::sha256_hex(script);
            let now = store::unix_now();
            let hook = Hook {
                id: id.clone(),
                name: name.to_string(),
                trigger: trigger.to_string(),
                script: script.to_string(),
                enabled,
                priority,
                created_at: now,
                version: 1,
                script_hash: hash.clone(),
                updated_by: session.user.id.clone(),
                updated_at: now,
            };

            if let Err(e) = store::save_hook(&hook).await {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to save hook: {e}"),
                );
            }

            let version_snapshot = HookVersion {
                hook_id: id.clone(),
                version: 1,
                name: hook.name.clone(),
                trigger: hook.trigger.clone(),
                script: hook.script.clone(),
                script_hash: hash,
                enabled: hook.enabled,
                priority: hook.priority,
                changed_by: session.user.email.clone(),
                changed_at: now,
            };
            let _ = store::save_hook_version(&version_snapshot).await;

            redirect_response(&format!("/admin/hooks/{id}"))
        }

        // ── Settings ──
        (&Method::GET, "/admin/settings") => views::settings::render_settings_page(&session).await,
        (&Method::POST, "/admin/settings") => {
            let form = parse_form(body);
            let allow_reg = form_value(&form, "allow_registration")
                .map(|v| v == "true" || v == "on")
                .unwrap_or(false);
            let mut settings = store::get_runtime_settings().await;
            settings.allow_registration = allow_reg;

            let mut def_theme = settings.default_theme.clone().unwrap_or_default();
            if let Some(app_name) = form_value(&form, "default_app_name") {
                def_theme.app_name = app_name.trim().to_string();
            }
            if let Some(preset) = form_value(&form, "default_theme_preset") {
                def_theme.theme_preset = if preset.is_empty() {
                    None
                } else {
                    Some(preset.to_string())
                };
            }
            if let Some(logo_url) = form_value(&form, "default_logo_url") {
                def_theme.logo_url = if logo_url.trim().is_empty() {
                    None
                } else {
                    Some(logo_url.trim().to_string())
                };
            }
            if let Some(color) = form_value(&form, "default_primary_color") {
                def_theme.primary_color = if color.trim().is_empty() {
                    None
                } else {
                    Some(color.trim().to_string())
                };
            }
            if let Some(pb) = form_value(&form, "default_powered_by_text") {
                def_theme.powered_by_text = if pb.trim().is_empty() {
                    None
                } else {
                    Some(pb.trim().to_string())
                };
            }
            if let Some(ft) = form_value(&form, "default_footer_text") {
                def_theme.footer_text = if ft.trim().is_empty() {
                    None
                } else {
                    Some(ft.trim().to_string())
                };
            }
            let hide_pb = form_value(&form, "default_hide_powered_by")
                .map(|v| v == "true" || v == "on")
                .unwrap_or(false);
            def_theme.hide_powered_by = hide_pb;
            if let Some(css) = form_value(&form, "default_custom_css") {
                def_theme.custom_css = if css.trim().is_empty() {
                    None
                } else {
                    Some(css.to_string())
                };
            }

            if let Some(days_str) = form_value(&form, "idp_session_ttl_days") {
                if let Ok(days) = days_str.trim().parse::<u64>() {
                    if days >= 1 && days <= 90 {
                        settings.idp_session_ttl_seconds = Some(days * 86400);
                    }
                }
            }

            settings.default_theme = Some(def_theme);
            let _ = store::save_runtime_settings(&settings).await;
            redirect_response("/admin/settings")
        }

        // ── Audit Log ──
        (&Method::GET, "/admin/audit") => {
            views::audit::render_audit_page(&session, None, None, None).await
        }
        (&Method::GET, "/admin/audit/table") => {
            let query_str = path.split_once('?').map(|(_, qs)| qs).unwrap_or("");
            let q = parse_query(query_str);
            let event_type = form_value(&q, "event_type").filter(|s| !s.is_empty());
            let actor_id = form_value(&q, "actor_id").filter(|s| !s.is_empty());
            let target_id = form_value(&q, "target_id").filter(|s| !s.is_empty());
            let events = store::list_audit_events(actor_id, target_id, event_type, None, None, 100)
                .await
                .unwrap_or_default();
            html_response(views::audit::render_audit_table(&events).into_string())
        }

        // ── My Account ──
        (&Method::GET, "/admin/account") => views::account::render_account_page(&session).await,
        (&Method::POST, "/admin/account/passkeys/register-options") => {
            handle_admin_passkey_register_options(&session).await
        }
        (&Method::POST, "/admin/account/passkeys/register-complete") => {
            handle_admin_passkey_register_complete(&session, body).await
        }

        // ── Parameterized Route Handling ──
        _ => handle_parameterized_route(method, p, headers, body, &session).await,
    }
}

async fn handle_parameterized_route(
    method: &Method,
    path: &str,
    _headers: &HeaderMap,
    body: &[u8],
    session: &AdminSession,
) -> Response<String> {
    // ── Single Tenant Detail & Subroutes ──
    if let Some(rest) = path.strip_prefix("/admin/tenants/") {
        if let Some((id, sub)) = rest.split_once('/') {
            // e.g. /admin/tenants/{id}/invite
            if sub == "invite" && method == Method::POST {
                let form = parse_form(body);
                let email = form_value(&form, "email").unwrap_or("").trim();
                let role = form_value(&form, "role").unwrap_or("member");
                if let Ok(Some(target_user)) = store::get_user_by_email(email).await {
                    let m = Membership {
                        tenant_id: id.to_string(),
                        user_id: target_user.id.clone(),
                        role: role.to_string(),
                        joined_at: store::unix_now(),
                    };
                    let _ = store::add_membership(&m).await;
                }
                let memberships = store::list_tenant_members(id).await.unwrap_or_default();
                let mut members = Vec::new();
                for m in memberships {
                    if let Ok(Some(u)) = store::get_user(&m.user_id).await {
                        members.push((m, u));
                    }
                }
                return html_response(
                    views::tenants::render_members_table(id, &members).into_string(),
                );
            }
            // e.g. /admin/tenants/{id}/members/{userId}
            if let Some(user_id) = sub.strip_prefix("members/") {
                if method == Method::DELETE {
                    let _ = store::remove_membership(id, user_id).await;
                    return Response::builder()
                        .status(StatusCode::OK)
                        .body(String::new())
                        .unwrap();
                }
            }
        } else {
            // /admin/tenants/{id}
            let id = rest;
            if method == Method::GET {
                if let Ok(Some(tenant)) = store::get_tenant(id).await {
                    let memberships = store::list_tenant_members(id).await.unwrap_or_default();
                    let mut members = Vec::new();
                    for m in memberships {
                        if let Ok(Some(u)) = store::get_user(&m.user_id).await {
                            members.push((m, u));
                        }
                    }
                    return views::tenants::render_tenant_detail_page(session, &tenant, &members)
                        .await;
                }
            } else if method == Method::DELETE {
                let _ = store::delete_tenant(id).await;
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("HX-Redirect", "/admin/tenants")
                    .body(String::new())
                    .unwrap();
            }
        }
    }

    // ── Single Client Detail & Subroutes ──
    if let Some(rest) = path.strip_prefix("/admin/clients/") {
        if let Some((id, sub)) = rest.split_once('/') {
            if sub == "rotate-secret" && method == Method::POST {
                if let Ok(Some(mut client)) = store::get_client(id).await {
                    let new_raw_secret = store::random_alphanumeric(32);
                    client.client_secret = Some(store::hmac_client_secret(&new_raw_secret));
                    let _ = store::save_client(&client).await;
                    return html_response(format!(
                        r#"<div class="alert alert-warning" style="margin-top: 12px; padding: 12px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: var(--radius);"><div style="font-weight: 600; color: #f59e0b; margin-bottom: 4px; font-size: 13px;">⚠️ Copy New Secret (Shown Once)</div><div style="display: flex; align-items: center; gap: 8px;"><span class="mono copy-chip" onclick="copyToClipboard(this, this.innerText)" style="font-size: 13px; font-weight: 600;">{}</span><button class="btn btn-xs btn-primary" onclick="copyToClipboard(this, this.previousElementSibling.innerText)">Copy</button></div></div>"#,
                        new_raw_secret
                    ));
                }
            }
            if (sub == "redirect-uris" || sub == "post-logout-redirect-uris")
                && method == Method::POST
            {
                let form = parse_form(body);
                if let Ok(Some(mut client)) = store::get_client(id).await {
                    if let Some(uris) = form_value(&form, "redirect_uris") {
                        client.redirect_uris = uris
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                    }
                    if let Some(uris) = form_value(&form, "post_logout_redirect_uris") {
                        client.post_logout_redirect_uris = uris
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                    }
                    let _ = store::save_client(&client).await;
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
            if sub == "settings" && method == Method::POST {
                let form = parse_form(body);
                if let Ok(Some(mut client)) = store::get_client(id).await {
                    if let Some(name) = form_value(&form, "name") {
                        if !name.trim().is_empty() {
                            client.name = name.trim().to_string();
                        }
                    }
                    let gts: Vec<String> = crate::util::form_values(&form, "grant_types")
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();
                    if !gts.is_empty() {
                        client.grant_types = gts;
                    }
                    let _ = store::save_client(&client).await;
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
            if sub == "backchannel-logout" && method == Method::POST {
                let form = parse_form(body);
                if let Ok(Some(mut client)) = store::get_client(id).await {
                    let uri = form_value(&form, "backchannel_logout_uri")
                        .filter(|u| !u.trim().is_empty())
                        .map(|u| u.trim().to_string());
                    client.backchannel_logout_uri = uri;
                    let req_sid = form_value(&form, "backchannel_logout_session_required")
                        .map(|v| v == "true" || v == "on")
                        .unwrap_or(false);
                    client.backchannel_logout_session_required = req_sid;
                    let _ = store::save_client(&client).await;
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
            if sub == "theme" && method == Method::POST {
                let form = parse_form(body);
                if let Ok(Some(mut client)) = store::get_client(id).await {
                    let mut theme = client.theme.clone().unwrap_or_default();
                    if let Some(an) = form_value(&form, "app_name") {
                        theme.app_name = an.trim().to_string();
                    }
                    if let Some(tp) = form_value(&form, "theme_preset") {
                        theme.theme_preset = if tp.is_empty() {
                            None
                        } else {
                            Some(tp.to_string())
                        };
                    }
                    if let Some(logo) = form_value(&form, "logo_url") {
                        theme.logo_url = if logo.trim().is_empty() {
                            None
                        } else {
                            Some(logo.trim().to_string())
                        };
                    }
                    if let Some(color) = form_value(&form, "primary_color") {
                        theme.primary_color = if color.trim().is_empty() {
                            None
                        } else {
                            Some(color.trim().to_string())
                        };
                    }
                    if let Some(bg) = form_value(&form, "background_color") {
                        theme.background_color = if bg.trim().is_empty() {
                            None
                        } else {
                            Some(bg.trim().to_string())
                        };
                    }
                    if let Some(bg_img) = form_value(&form, "background_image_url") {
                        theme.background_image_url = if bg_img.trim().is_empty() {
                            None
                        } else {
                            Some(bg_img.trim().to_string())
                        };
                    }
                    if let Some(ff) = form_value(&form, "font_family") {
                        theme.font_family = if ff.trim().is_empty() {
                            None
                        } else {
                            Some(ff.trim().to_string())
                        };
                    }
                    if let Some(fu) = form_value(&form, "font_url") {
                        theme.font_url = if fu.trim().is_empty() {
                            None
                        } else {
                            Some(fu.trim().to_string())
                        };
                    }
                    if let Some(pb) = form_value(&form, "powered_by_text") {
                        theme.powered_by_text = if pb.trim().is_empty() {
                            None
                        } else {
                            Some(pb.trim().to_string())
                        };
                    }
                    if let Some(ft) = form_value(&form, "footer_text") {
                        theme.footer_text = if ft.trim().is_empty() {
                            None
                        } else {
                            Some(ft.trim().to_string())
                        };
                    }
                    let hide_pb = form_value(&form, "hide_powered_by")
                        .map(|v| v == "true" || v == "on")
                        .unwrap_or(false);
                    theme.hide_powered_by = hide_pb;
                    if let Some(css) = form_value(&form, "custom_css") {
                        theme.custom_css = if css.trim().is_empty() {
                            None
                        } else {
                            Some(css.to_string())
                        };
                    }

                    client.theme = Some(theme);
                    let _ = store::save_client(&client).await;
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
        } else {
            let id = rest;
            if method == Method::GET {
                if let Ok(Some(client)) = store::get_client(id).await {
                    return views::clients::render_client_detail_page(session, &client, None).await;
                }
            } else if method == Method::POST {
                let form = parse_form(body);
                if let Ok(Some(mut client)) = store::get_client(id).await {
                    if let Some(name) = form_value(&form, "name") {
                        client.name = name.trim().to_string();
                    }
                    if let Some(uris) = form_value(&form, "redirect_uris") {
                        client.redirect_uris = uris
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                    }
                    if let Some(uris) = form_value(&form, "post_logout_redirect_uris") {
                        client.post_logout_redirect_uris = uris
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                    }
                    let _ = store::save_client(&client).await;
                    return redirect_response(&format!("/admin/clients/{id}"));
                }
            } else if method == Method::DELETE {
                let _ = store::delete_client(id).await;
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(String::new())
                    .unwrap();
            }
        }
    }

    // ── Single User Detail & Subroutes ──
    if let Some(rest) = path.strip_prefix("/admin/users/") {
        if let Some((id, sub)) = rest.split_once('/') {
            if sub == "password-reset" && method == Method::POST {
                if let Ok(Some(user)) = store::get_user(id).await {
                    let reset_token = store::random_hex(32);
                    let inv = Invitation {
                        tenant_id: String::new(),
                        email: user.email.clone(),
                        role: "password_reset".to_string(),
                        token: reset_token.clone(),
                        invited_by: session.user.id.clone(),
                        expires_at: store::unix_now() + 3600,
                    };
                    let _ = store::save_invitation(&inv).await;
                    crate::email::send_password_reset_email(
                        &crate::get_issuer(),
                        &user.email,
                        &user.name,
                        &reset_token,
                    )
                    .await;
                }
                return redirect_response(&format!("/admin/users/{id}"));
            }
            if sub == "disable-mfa" && method == Method::POST {
                if let Ok(Some(mut user)) = store::get_user(id).await {
                    user.totp_enabled = false;
                    user.totp_secret = None;
                    let _ = store::update_user(&user).await;
                }
                return redirect_response(&format!("/admin/users/{id}"));
            }
            if let Some(cred_id) = sub.strip_prefix("passkeys/") {
                if method == Method::DELETE {
                    if let Ok(Some(mut user)) = store::get_user(id).await {
                        user.passkey_credentials
                            .retain(|p| p.credential_id != cred_id);
                        let _ = store::update_user(&user).await;
                        let _ = store::unindex_passkey_credential(cred_id).await;
                    }
                    return Response::builder()
                        .status(StatusCode::OK)
                        .body(String::new())
                        .unwrap();
                }
            }
        } else {
            let id = rest;
            if method == Method::GET {
                if let Ok(Some(user)) = store::get_user(id).await {
                    let passkeys = user.passkey_credentials.clone();
                    return views::users::render_user_detail_page(session, &user, &passkeys).await;
                }
            } else if method == Method::DELETE {
                let _ = store::delete_user(id).await;
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("HX-Redirect", "/admin/users")
                    .body(String::new())
                    .unwrap();
            }
        }
    }

    // ── Identity Provider Subroutes ──
    if let Some(rest) = path.strip_prefix("/admin/identity-providers/") {
        if let Some((id, action)) = rest.split_once('/') {
            if action == "toggle" && method == Method::POST {
                if let Ok(Some(mut idp)) = store::get_identity_provider(id).await {
                    idp.enabled = !idp.enabled;
                    if let Err(e) = store::save_identity_provider(&idp).await {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Failed to update IDP: {e}"),
                        );
                    }
                    return html_response(views::idps::render_idp_row(&idp).into_string());
                } else {
                    return error_response(StatusCode::NOT_FOUND, "Identity provider not found");
                }
            } else if action == "modal/edit" && method == Method::GET {
                if let Ok(Some(idp)) = store::get_identity_provider(id).await {
                    return html_response(views::idps::render_edit_idp_modal(&idp).into_string());
                } else {
                    return error_response(StatusCode::NOT_FOUND, "Identity provider not found");
                }
            } else if action == "update" && method == Method::POST {
                let form = parse_form(body);
                let client_id = form_value(&form, "client_id")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let client_secret = form_value(&form, "client_secret")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let enabled = form_value(&form, "enabled")
                    .map(|v| v == "true" || v == "on")
                    .unwrap_or(false);

                if let Ok(Some(mut idp)) = store::get_identity_provider(id).await {
                    if !client_id.is_empty() {
                        idp.client_id = client_id;
                    }
                    if !client_secret.is_empty() {
                        idp.client_secret = client_secret;
                    }
                    idp.enabled = enabled;
                    if let Err(e) = store::save_identity_provider(&idp).await {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Failed to update IDP: {e}"),
                        );
                    }
                    return redirect_response("/admin/identity-providers");
                } else {
                    return error_response(StatusCode::NOT_FOUND, "Identity provider not found");
                }
            }
        } else {
            let id = rest;
            if method == Method::DELETE {
                let _ = store::delete_identity_provider(id).await;
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(String::new())
                    .unwrap();
            }
        }
    }

    // ── Single Hook Detail & Subroutes ──
    if let Some(rest) = path.strip_prefix("/admin/hooks/") {
        if let Some((id, sub)) = rest.split_once('/') {
            if sub == "test" && method == Method::POST {
                if let Ok(Some(hook)) = store::get_hook(id).await {
                    match crate::hooks::test_hook(&hook.script, &hook.trigger) {
                        Ok(outcome) => {
                            let text =
                                format!("Outcome: {:?}\nLogs: {:?}", outcome, outcome.log_messages);
                            return html_response(
                                views::hooks::render_test_result(&text, true).into_string(),
                            );
                        }
                        Err(e) => {
                            return html_response(
                                views::hooks::render_test_result(&e, false).into_string(),
                            );
                        }
                    }
                }
            }
        } else {
            let id = rest;
            if method == Method::GET {
                if let Ok(Some(hook)) = store::get_hook(id).await {
                    let versions = store::list_hook_versions(id).await.unwrap_or_default();
                    return views::hooks::render_hook_editor_page(session, Some(&hook), &versions)
                        .await;
                }
            } else if method == Method::POST {
                let form = parse_form(body);
                if let Ok(Some(mut hook)) = store::get_hook(id).await {
                    let name = form_value(&form, "name")
                        .unwrap_or(&hook.name)
                        .trim()
                        .to_string();
                    let trigger = form_value(&form, "trigger")
                        .unwrap_or(&hook.trigger)
                        .to_string();
                    let priority: i32 = form_value(&form, "priority")
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(hook.priority);
                    let enabled = form_value(&form, "enabled")
                        .map(|v| v == "true" || v == "on")
                        .unwrap_or(false);
                    let script = form_value(&form, "script")
                        .unwrap_or(&hook.script)
                        .to_string();

                    let now = store::unix_now();
                    // Save previous version
                    let prev_version = HookVersion {
                        hook_id: hook.id.clone(),
                        version: hook.version,
                        name: hook.name.clone(),
                        trigger: hook.trigger.clone(),
                        script: hook.script.clone(),
                        script_hash: hook.script_hash.clone(),
                        enabled: hook.enabled,
                        priority: hook.priority,
                        changed_by: hook.updated_by.clone(),
                        changed_at: hook.updated_at,
                    };
                    let _ = store::save_hook_version(&prev_version).await;

                    hook.name = name;
                    hook.trigger = trigger;
                    hook.priority = priority;
                    hook.enabled = enabled;
                    hook.script_hash = store::sha256_hex(&script);
                    hook.script = script;
                    hook.version += 1;
                    hook.updated_by = session.user.id.clone();
                    hook.updated_at = now;

                    let _ = store::save_hook(&hook).await;
                    return redirect_response(&format!("/admin/hooks/{id}"));
                }
            } else if method == Method::DELETE {
                let _ = store::delete_hook(id).await;
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(String::new())
                    .unwrap();
            }
        }
    }

    // ── My Account Passkey Deletion ──
    if let Some(cred_id) = path.strip_prefix("/admin/account/passkeys/") {
        if method == Method::DELETE {
            if let Ok(Some(mut user)) = store::get_user(&session.user.id).await {
                user.passkey_credentials
                    .retain(|p| p.credential_id != cred_id);
                let _ = store::update_user(&user).await;
                let _ = store::unindex_passkey_credential(cred_id).await;
            }
            return Response::builder()
                .status(StatusCode::OK)
                .body(String::new())
                .unwrap();
        }
    }

    error_response(StatusCode::NOT_FOUND, "Admin route not found")
}

// ── Session Resolver & CSRF Protection ──────────────────────────

fn verify_admin_csrf(
    headers: &HeaderMap,
    body: &[u8],
    session: &AdminSession,
) -> Result<(), Response<String>> {
    use subtle::ConstantTimeEq;

    // 1. Bearer token authenticated requests (API clients) are not vulnerable to browser CSRF
    if let Some(auth_hdr) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if auth_hdr.starts_with("Bearer ") || auth_hdr.starts_with("bearer ") {
            return Ok(());
        }
    }

    // 2. Check x-csrf-token or hx-csrf-token header (HTMX)
    let header_csrf = headers
        .get("x-csrf-token")
        .or_else(|| headers.get("hx-csrf-token"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !header_csrf.is_empty()
        && header_csrf.len() == session.csrf_token.len()
        && bool::from(header_csrf.as_bytes().ct_eq(session.csrf_token.as_bytes()))
    {
        return Ok(());
    }

    // 3. Check form body
    let form = parse_form(body);
    let form_csrf = form_value(&form, "csrf_token").unwrap_or("");
    if !form_csrf.is_empty()
        && form_csrf.len() == session.csrf_token.len()
        && bool::from(form_csrf.as_bytes().ct_eq(session.csrf_token.as_bytes()))
    {
        return Ok(());
    }

    Err(error_response(
        StatusCode::FORBIDDEN,
        "CSRF check failed: invalid or missing CSRF token",
    ))
}

async fn resolve_admin_session(headers: &HeaderMap) -> Result<AdminSession, Response<String>> {
    let mut user_opt: Option<User> = None;
    let mut csrf_token_opt: Option<String> = None;

    // Check Authorization: Bearer <jwt>
    if let Some(auth_hdr) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_hdr
            .strip_prefix("Bearer ")
            .or_else(|| auth_hdr.strip_prefix("bearer "))
        {
            if let Ok(claims) = crate::service_client::verify_token_scoped(
                token,
                Some(&crate::get_issuer()),
                None,
                Some("access"),
            )
            .await
            {
                if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
                    if let Ok(Some(u)) = store::get_user(sub).await {
                        user_opt = Some(u);
                        csrf_token_opt = Some(store::random_hex(24));
                    }
                }
            }
        }
    }

    // Check Cookies (lid_account or lid_session)
    if user_opt.is_none() {
        if let Some(cookie_hdr) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
            for cookie in cookie_hdr.split(';') {
                let cookie = cookie.trim();
                if let Some(val) = cookie.strip_prefix("lid_account=") {
                    if let Ok(Some(session_rec)) = store::get_account_session(val).await {
                        if store::unix_now() <= session_rec.expires_at {
                            if let Ok(Some(u)) = store::get_user(&session_rec.user_id).await {
                                user_opt = Some(u);
                                csrf_token_opt = Some(if !session_rec.csrf_token.is_empty() {
                                    session_rec.csrf_token
                                } else {
                                    store::sha256_hex(&format!("csrf:{val}"))[..24].to_string()
                                });
                                break;
                            }
                        }
                    }
                } else if let Some(val) = cookie.strip_prefix("lid_session=") {
                    if let Ok(Some(session_rec)) = store::get_idp_session(val).await {
                        if store::unix_now() <= session_rec.expires_at {
                            if let Ok(Some(u)) = store::get_user(&session_rec.user_id).await {
                                user_opt = Some(u);
                                csrf_token_opt = Some(
                                    store::sha256_hex(&format!("csrf:{val}"))[..24].to_string(),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    let user = match user_opt {
        Some(u) => u,
        None => {
            return Err(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(
                    "location",
                    "/authorize?client_id=lid-admin&redirect_uri=/admin&response_type=code&scope=openid+email+profile&state=admin_login",
                )
                .body(String::new())
                .unwrap());
        }
    };

    let is_super = user.superadmin;
    let memberships = store::list_user_tenants(&user.id).await.unwrap_or_default();
    let is_admin = is_super
        || memberships
            .iter()
            .any(|m| m.role == "owner" || m.role == "admin");

    if !is_admin {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Access denied: administrator privileges required.",
        ));
    }

    // Resolve tenant list
    let mut tenants = Vec::new();
    if is_super {
        tenants = store::list_tenants().await.unwrap_or_default();
    } else {
        for m in &memberships {
            if let Ok(Some(t)) = store::get_tenant(&m.tenant_id).await {
                tenants.push(t);
            }
        }
    }

    // Resolve current active tenant from cookie or first available
    let mut current_tenant = None;
    if let Some(cookie_hdr) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for cookie in cookie_hdr.split(';') {
            let cookie = cookie.trim();
            if let Some(tid) = cookie.strip_prefix("lid_tenant=") {
                current_tenant = tenants.iter().find(|t| t.id == tid).cloned();
                break;
            }
        }
    }
    if current_tenant.is_none() {
        current_tenant = tenants.first().cloned();
    }

    let csrf_token = csrf_token_opt.unwrap_or_else(|| store::random_hex(24));

    Ok(AdminSession {
        user,
        is_superadmin: is_super,
        current_tenant,
        tenants,
        csrf_token,
    })
}

// ── Bootstrap Handler ──────────────────────────────────────────

async fn handle_bootstrap_submit(body: &[u8]) -> Response<String> {
    if crate::hooks::has_superadmin().await {
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("location", "/admin/login")
            .body(String::new())
            .unwrap();
    }

    let form = parse_form(body);
    let email = form_value(&form, "email").unwrap_or("").trim();
    let password = form_value(&form, "password").unwrap_or("");
    let confirm_password = form_value(&form, "confirm_password").unwrap_or("");
    let name = form_value(&form, "name").unwrap_or("").trim();
    let org_name_raw = form_value(&form, "org_name").unwrap_or("").trim();
    let org_name = if org_name_raw.is_empty() {
        "Primary Organization"
    } else {
        org_name_raw
    };

    if email.is_empty() || password.len() < 8 || name.is_empty() {
        return views::bootstrap::render_bootstrap_page(Some(
            "Please complete all required fields. Password must be at least 8 characters.",
        ));
    }

    if password != confirm_password {
        return views::bootstrap::render_bootstrap_page(Some(
            "Passwords do not match. Please re-enter your password.",
        ));
    }

    let password_hash = match crate::service_client::hash_password(password).await {
        Ok(h) => h,
        Err(e) => {
            return views::bootstrap::render_bootstrap_page(Some(&format!("Hashing error: {e}")));
        }
    };

    let require_verification = crate::require_email_verification();
    let initial_status = if require_verification {
        "pending"
    } else {
        "active"
    };

    let user_id = format!("user_{}", &store::random_alphanumeric(16));
    let mut user = User {
        id: user_id.clone(),
        email: email.to_string(),
        name: name.to_string(),
        password_hash,
        status: initial_status.to_string(),
        created_at: store::unix_now(),
        superadmin: true,
        totp_secret: None,
        totp_enabled: false,
        recovery_codes: Vec::new(),
        passkey_credentials: Vec::new(),
    };

    // If a bootstrap hook is configured in deployment settings, enforce authorization
    if crate::get_bootstrap_hook().is_some() {
        let boot = crate::hooks::execute_bootstrap_hook(&user).await;
        if let Some(reason) = &boot.deny_reason {
            return views::bootstrap::render_bootstrap_page(Some(&format!(
                "Bootstrap denied: {reason}"
            )));
        }
        if boot.set_superadmin != Some(true) {
            return views::bootstrap::render_bootstrap_page(Some(
                "Access denied: This email address is not authorized to bootstrap the authority.",
            ));
        }
        let _ = crate::hooks::apply_outcome(&mut user, &boot).await;
    }

    if let Err(e) = store::create_user(&user).await {
        return views::bootstrap::render_bootstrap_page(Some(&format!("Failed to save user: {e}")));
    }

    let _ = store::set_superadmin_flag(true).await;

    // Ensure standard clients exist
    let issuer = crate::get_issuer();
    let _ = store::ensure_default_client().await;
    let _ = store::ensure_admin_client(&issuer, false).await;

    // Create Initial Organization
    let tenant_id = format!("tenant_{}", &store::random_alphanumeric(12));
    let tenant_slug = org_name
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>();
    let tenant = Tenant {
        id: tenant_id.clone(),
        name: if tenant_slug.is_empty() {
            "default".to_string()
        } else {
            tenant_slug
        },
        display_name: org_name.to_string(),
        status: "active".to_string(),
        created_at: store::unix_now(),
    };
    let _ = store::create_tenant(&tenant).await;

    let membership = Membership {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        role: "owner".to_string(),
        joined_at: store::unix_now(),
    };
    let _ = store::add_membership(&membership).await;

    let _ = store::log_audit(
        "bootstrap_completed",
        &user.id,
        &user.id,
        &format!(
            "Superadmin initialized: {} (status={})",
            user.email, user.status
        ),
    )
    .await;

    if require_verification {
        let verify_token = store::random_hex(32);
        let verify_inv = store::Invitation {
            tenant_id: "system".to_string(),
            email: user.email.clone(),
            role: "verify_email".to_string(),
            token: verify_token.clone(),
            invited_by: "system".to_string(),
            expires_at: store::unix_now() + 86400,
        };
        let _ = store::save_invitation(&verify_inv).await;
        let _ = store::log_audit(
            "email_verification_link_generated",
            &user.id,
            &user.id,
            &store::hmac_email(&verify_token),
        )
        .await;
        if crate::is_dev_mode() {
            crate::logger::info(
                &format!("LID_VERIFY: {} {}", user.email, verify_token),
                serde_json::json!({}),
            );
        }
        crate::email::send_verification_email(&issuer, &user.email, &user.name, &verify_token)
            .await;
        return views::bootstrap::render_bootstrap_pending_page(&user.email);
    }

    // Create session token and set cookie (only when verification not required)
    let session_token = store::random_hex(32);
    let session_rec = AccountSession {
        user_id: user.id.clone(),
        created_at: store::unix_now(),
        expires_at: store::unix_now() + 86400 * 7,
        csrf_token: store::random_hex(24),
    };
    let _ = store::save_account_session(&session_token, &session_rec).await;

    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/admin")
        .header("set-cookie", format!("lid_account={session_token}; Path=/; HttpOnly;{secure} SameSite=Lax; Max-Age=604800"))
        .body(String::new())
        .unwrap()
}

// ── Admin Login & Logout Handlers ──────────────────────────────

async fn handle_admin_login(body: &[u8]) -> Response<String> {
    let form = parse_form(body);
    let email = form_value(&form, "email").unwrap_or("").trim();
    let password = form_value(&form, "password").unwrap_or("");
    let return_to = form_value(&form, "return_to").unwrap_or("/admin");
    let return_target = if return_to.is_empty() {
        "/admin"
    } else {
        return_to
    };

    if email.is_empty() || password.is_empty() {
        return views::login::render_login_page(
            Some("Please enter both email and password."),
            return_target,
        );
    }

    let user = match store::get_user_by_email(email).await {
        Ok(Some(u)) => u,
        _ => {
            // Constant-time dummy check to prevent user enumeration
            let _ = crate::service_client::verify_password(
                password,
                "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ).await;
            return views::login::render_login_page(
                Some("Invalid email or password."),
                return_target,
            );
        }
    };

    if user.status != "active" {
        let _ = crate::service_client::verify_password(
            password,
            "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ).await;
        return views::login::render_login_page(
            Some("This account is not active. Please contact an administrator."),
            return_target,
        );
    }

    // Check account lockout
    if store::is_account_locked(&user.id).await.unwrap_or(false) {
        let _ = crate::service_client::verify_password(
            password,
            "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ).await;
        return views::login::render_login_page(
            Some(
                "Account temporarily locked due to repeated failed login attempts. Please try again later.",
            ),
            return_target,
        );
    }

    // Verify password via password-hasher
    match crate::service_client::verify_password(password, &user.password_hash).await {
        Ok(true) => {}
        _ => {
            let _ = store::record_failed_login(&user.id).await;
            let _ = store::log_audit("admin_login_failed", &user.id, &user.id, email).await;
            return views::login::render_login_page(
                Some("Invalid email or password."),
                return_target,
            );
        }
    }

    // Check admin permissions
    let is_super = user.superadmin;
    let memberships = store::list_user_tenants(&user.id).await.unwrap_or_default();
    let is_admin = is_super
        || memberships
            .iter()
            .any(|m| m.role == "owner" || m.role == "admin");

    if !is_admin {
        return views::login::render_login_page(
            Some("Access denied: Administrator privileges required."),
            return_target,
        );
    }

    // Check MFA
    if user.totp_enabled {
        let mfa_token = store::random_hex(32);
        let pending = store::MfaPending {
            user_id: user.id.clone(),
            session_id: "admin".to_string(),
            primary_amr: vec!["pwd".to_string()],
            expires_at: store::unix_now() + 300,
            remote_ip: "admin".to_string(),
        };
        let _ = store::save_mfa_pending(&mfa_token, &pending).await;
        return views::login::render_mfa_prompt(&user.email, &mfa_token, return_target, None);
    }

    let _ = store::clear_login_attempts(&user.id).await;
    let _ = store::log_audit("admin_login_success", &user.id, &user.id, &user.email).await;

    // Create session token and set cookie
    let session_token = store::random_hex(32);
    let session_rec = AccountSession {
        user_id: user.id.clone(),
        created_at: store::unix_now(),
        expires_at: store::unix_now() + 86400 * 7,
        csrf_token: store::random_hex(24),
    };
    let _ = store::save_account_session(&session_token, &session_rec).await;

    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", return_target)
        .header("set-cookie", format!("lid_account={session_token}; Path=/; HttpOnly;{secure} SameSite=Lax; Max-Age=604800"))
        .body(String::new())
        .unwrap()
}

async fn handle_admin_login_mfa(body: &[u8]) -> Response<String> {
    let form = parse_form(body);
    let mfa_token = form_value(&form, "mfa_token").unwrap_or("");
    let code = form_value(&form, "code").unwrap_or("").trim();
    let return_to = form_value(&form, "return_to").unwrap_or("/admin");
    let return_target = if return_to.is_empty() {
        "/admin"
    } else {
        return_to
    };

    let pending = match store::get_mfa_pending(mfa_token).await {
        Ok(Some(p)) if store::unix_now() <= p.expires_at => p,
        _ => {
            return views::login::render_login_page(
                Some("MFA session expired. Please sign in again."),
                return_target,
            );
        }
    };

    let user = match store::get_user(&pending.user_id).await {
        Ok(Some(u)) => u,
        _ => return views::login::render_login_page(Some("User not found."), return_target),
    };

    // Verify TOTP or recovery code
    let mut verified = false;
    if let Some(ref secret) = user.totp_secret {
        if let Some(step) = crate::totp::verify_totp_step(secret, code) {
            let replay_key = format!("totp_used:{}:{}", user.id, step);
            if store::record_totp_used(&replay_key, 90)
                .await
                .unwrap_or(true)
            {
                verified = true;
            } else {
                return views::login::render_mfa_prompt(
                    &user.email,
                    mfa_token,
                    return_target,
                    Some("TOTP code already used. Please wait for the next code."),
                );
            }
        }
    }

    if !verified && !user.recovery_codes.is_empty() {
        // Check recovery code
        let normalized = code.trim().to_lowercase();
        if user
            .recovery_codes
            .iter()
            .any(|c| c.to_lowercase() == normalized)
        {
            verified = true;
            let _ = store::update_user_rmw(&user.id, |u| {
                u.recovery_codes.retain(|c| c.to_lowercase() != normalized);
                Ok(true)
            })
            .await;
        }
    }

    if !verified {
        return views::login::render_mfa_prompt(
            &user.email,
            mfa_token,
            return_target,
            Some("Invalid authentication code. Please try again."),
        );
    }

    let _ = store::delete_mfa_pending(mfa_token).await;
    let _ = store::clear_login_attempts(&user.id).await;
    let _ = store::log_audit("admin_login_mfa_success", &user.id, &user.id, &user.email).await;

    // Create session token and set cookie
    let session_token = store::random_hex(32);
    let session_rec = AccountSession {
        user_id: user.id.clone(),
        created_at: store::unix_now(),
        expires_at: store::unix_now() + 86400 * 7,
        csrf_token: store::random_hex(24),
    };
    let _ = store::save_account_session(&session_token, &session_rec).await;

    let secure = if crate::is_dev_mode() { "" } else { " Secure;" };
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", return_target)
        .header("set-cookie", format!("lid_account={session_token}; Path=/; HttpOnly;{secure} SameSite=Lax; Max-Age=604800"))
        .body(String::new())
        .unwrap()
}

async fn handle_admin_logout(headers: &HeaderMap) -> Response<String> {
    if let Some(cookie_hdr) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for cookie in cookie_hdr.split(';') {
            let cookie = cookie.trim();
            if let Some(val) = cookie.strip_prefix("lid_account=") {
                let _ = store::delete_account_session(val).await;
            }
            if let Some(val) = cookie.strip_prefix("lid_session=") {
                let _ = store::delete_idp_session(val).await;
            }
        }
    }

    let mut resp = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/admin/login")
        .header("cache-control", "no-store, no-cache, must-revalidate")
        .header("pragma", "no-cache")
        .body(String::new())
        .unwrap();

    crate::account::append_clear_all_cookies(resp.headers_mut());
    resp
}

async fn handle_admin_passkey_register_options(session: &AdminSession) -> Response<String> {
    let user_id = &session.user.id;
    let user = match store::get_user(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return json_error_response(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => {
            return json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("database error: {e}"),
            );
        }
    };

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
        user_id: user_id.clone(),
        session_id: String::new(),
        expires_at: store::unix_now() + 300, // 5 minutes
    };
    if let Err(e) = store::save_passkey_challenge(&token, &pc).await {
        return json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to save challenge: {e}"),
        );
    }

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

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "token": token,
            "publicKey": options,
        }),
    )
}

async fn handle_admin_passkey_register_complete(
    session: &AdminSession,
    body: &[u8],
) -> Response<String> {
    let user_id = &session.user.id;

    #[derive(serde::Deserialize)]
    struct RegCompleteReq {
        token: String,
        #[serde(rename = "clientDataJSON")]
        client_data_json: String,
        #[serde(rename = "attestationObject")]
        attestation_object: String,
        #[serde(default)]
        name: String,
    }

    let req: RegCompleteReq = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return json_error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}"));
        }
    };

    let pc = match store::get_passkey_challenge(&req.token).await {
        Ok(Some(pc)) => pc,
        Ok(None) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid or expired registration token",
            );
        }
        Err(e) => {
            return json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("database error: {e}"),
            );
        }
    };

    if pc.purpose != "register" || pc.user_id != *user_id {
        return json_error_response(StatusCode::BAD_REQUEST, "token mismatch");
    }
    if store::unix_now() > pc.expires_at {
        let _ = store::delete_passkey_challenge(&req.token).await;
        return json_error_response(StatusCode::BAD_REQUEST, "registration token expired");
    }
    let _ = store::delete_passkey_challenge(&req.token).await;

    let issuer = crate::get_issuer();
    let parsed = match crate::passkeys::verify_registration(
        &req.client_data_json,
        &req.attestation_object,
        &pc.challenge,
        &issuer,
    ) {
        Ok(p) => p,
        Err(e) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                &format!("registration verification failed: {e}"),
            );
        }
    };

    let credential_id = URL_SAFE_NO_PAD.encode(&parsed.credential_id);
    let public_key = URL_SAFE_NO_PAD.encode(&parsed.public_key_bytes);

    let user = match store::get_user(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return json_error_response(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => {
            return json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("database error: {e}"),
            );
        }
    };

    if user
        .passkey_credentials
        .iter()
        .any(|c| c.credential_id == credential_id)
    {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "this passkey is already registered",
        );
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

    if let Err(e) = store::update_user_rmw(user_id, |u| {
        u.passkey_credentials.push(cred.clone());
        Ok(true)
    })
    .await
    {
        return json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to update user: {e}"),
        );
    }

    if let Err(e) = store::index_passkey_credential(&credential_id, user_id).await {
        return json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to index credential: {e}"),
        );
    }

    let _ = store::log_audit("passkey_registered", user_id, user_id, &name).await;

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "credential_id": credential_id,
            "name": name,
        }),
    )
}

// ── Helpers ───────────────────────────────────────────────────

fn html_response(html: String) -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(html)
        .unwrap()
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<String> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(value).unwrap_or_default())
        .unwrap()
}

fn json_error_response(status: StatusCode, error_description: &str) -> Response<String> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            serde_json::to_string(&serde_json::json!({
                "error": "invalid_request",
                "error_description": error_description,
            }))
            .unwrap_or_default(),
        )
        .unwrap()
}

fn redirect_response(location: &str) -> Response<String> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", location)
        .header("HX-Redirect", location)
        .body(String::new())
        .unwrap()
}

fn error_response(status: StatusCode, message: &str) -> Response<String> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(format!(
            r#"<div class="test-err" style="padding: 16px; margin: 16px; border-radius: 8px;"><strong>Error ({}):</strong> {}</div>"#,
            status.as_u16(),
            message
        ))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn test_verify_admin_csrf_with_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-jwt-token".parse().unwrap());
        let session = AdminSession {
            user: User {
                id: "user1".to_string(),
                email: "test@example.com".to_string(),
                name: "Test".to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
                created_at: 0,
                superadmin: true,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: vec![],
                passkey_credentials: vec![],
            },
            is_superadmin: true,
            current_tenant: None,
            tenants: vec![],
            csrf_token: "csrf-token-12345".to_string(),
        };

        // Bearer token requests should bypass CSRF validation
        assert!(verify_admin_csrf(&headers, b"name=value", &session).is_ok());
    }

    #[test]
    fn test_verify_admin_csrf_with_valid_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "valid-csrf-token-secret".parse().unwrap());
        let session = AdminSession {
            user: User {
                id: "user1".to_string(),
                email: "test@example.com".to_string(),
                name: "Test".to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
                created_at: 0,
                superadmin: true,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: vec![],
                passkey_credentials: vec![],
            },
            is_superadmin: true,
            current_tenant: None,
            tenants: vec![],
            csrf_token: "valid-csrf-token-secret".to_string(),
        };

        assert!(verify_admin_csrf(&headers, b"", &session).is_ok());
    }

    #[test]
    fn test_verify_admin_csrf_with_valid_form_body() {
        let headers = HeaderMap::new();
        let session = AdminSession {
            user: User {
                id: "user1".to_string(),
                email: "test@example.com".to_string(),
                name: "Test".to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
                created_at: 0,
                superadmin: true,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: vec![],
                passkey_credentials: vec![],
            },
            is_superadmin: true,
            current_tenant: None,
            tenants: vec![],
            csrf_token: "valid-csrf-token-secret".to_string(),
        };

        let body = b"name=acme&csrf_token=valid-csrf-token-secret";
        assert!(verify_admin_csrf(&headers, body, &session).is_ok());
    }

    #[test]
    fn test_verify_admin_csrf_rejects_invalid_or_missing() {
        let headers = HeaderMap::new();
        let session = AdminSession {
            user: User {
                id: "user1".to_string(),
                email: "test@example.com".to_string(),
                name: "Test".to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
                created_at: 0,
                superadmin: true,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: vec![],
                passkey_credentials: vec![],
            },
            is_superadmin: true,
            current_tenant: None,
            tenants: vec![],
            csrf_token: "valid-csrf-token-secret".to_string(),
        };

        // Missing CSRF token
        let res = verify_admin_csrf(&headers, b"name=acme", &session);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().status(), StatusCode::FORBIDDEN);

        // Wrong CSRF token in header
        let mut headers_wrong = HeaderMap::new();
        headers_wrong.insert("x-csrf-token", "wrong-csrf-token-secret".parse().unwrap());
        let res2 = verify_admin_csrf(&headers_wrong, b"", &session);
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err().status(), StatusCode::FORBIDDEN);

        // Wrong CSRF token in body
        let res3 = verify_admin_csrf(&headers, b"name=acme&csrf_token=wrong-csrf-token", &session);
        assert!(res3.is_err());
        assert_eq!(res3.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_admin_passkey_json_responses() {
        let ok_res = json_response(StatusCode::OK, &serde_json::json!({ "token": "abc" }));
        assert_eq!(ok_res.status(), StatusCode::OK);
        assert_eq!(
            ok_res.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(ok_res.body(), r#"{"token":"abc"}"#);

        let err_res = json_error_response(StatusCode::BAD_REQUEST, "invalid token");
        assert_eq!(err_res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            err_res.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body: serde_json::Value = serde_json::from_str(err_res.body()).unwrap();
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], "invalid token");
    }

    #[test]
    fn test_admin_passkey_register_complete_invalid_json() {
        futures::executor::block_on(async {
            let session = AdminSession {
                user: User {
                    id: "admin-user-pk-test-3".to_string(),
                    email: "admin-pk-3@example.com".to_string(),
                    name: "Admin User 3".to_string(),
                    password_hash: "hash".to_string(),
                    status: "active".to_string(),
                    created_at: 0,
                    superadmin: true,
                    totp_secret: None,
                    totp_enabled: false,
                    recovery_codes: vec![],
                    passkey_credentials: vec![],
                },
                is_superadmin: true,
                current_tenant: None,
                tenants: vec![],
                csrf_token: "csrf-token-12345".to_string(),
            };

            let res = handle_admin_passkey_register_complete(&session, b"not-a-json").await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value = serde_json::from_str(res.body()).unwrap();
            assert_eq!(body["error"], "invalid_request");
            assert!(
                body["error_description"]
                    .as_str()
                    .unwrap()
                    .contains("invalid JSON")
            );
        });
    }

    #[test]
    fn test_admin_passkey_csrf_validation() {
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "valid-csrf-token".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let session = AdminSession {
            user: User {
                id: "admin1".to_string(),
                email: "admin@example.com".to_string(),
                name: "Admin".to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
                created_at: 0,
                superadmin: true,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: vec![],
                passkey_credentials: vec![],
            },
            is_superadmin: true,
            current_tenant: None,
            tenants: vec![],
            csrf_token: "valid-csrf-token".to_string(),
        };

        // Valid CSRF token in header passes
        assert!(verify_admin_csrf(&headers, b"{}", &session).is_ok());

        // Wrong CSRF token in header fails
        let mut wrong_headers = HeaderMap::new();
        wrong_headers.insert("x-csrf-token", "wrong-token".parse().unwrap());
        assert!(verify_admin_csrf(&wrong_headers, b"{}", &session).is_err());
    }

    #[test]
    fn test_parse_redirect_uris_and_post_logout_uris() {
        let form_body = b"redirect_uris=https%3A%2F%2Fapp.com%2Fcb%0Ahttp%3A%2F%2Flocalhost%3A3000%2Fcb&post_logout_redirect_uris=https%3A%2F%2Fapp.com%2Flogout%0Ahttp%3A%2F%2Flocalhost%3A3000%2F";
        let form = parse_form(form_body);
        let uris_raw = form_value(&form, "redirect_uris").unwrap();
        let post_logout_raw = form_value(&form, "post_logout_redirect_uris").unwrap();

        let redirect_uris: Vec<String> = uris_raw
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let post_logout_uris: Vec<String> = post_logout_raw
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        assert_eq!(
            redirect_uris,
            vec!["https://app.com/cb", "http://localhost:3000/cb"]
        );
        assert_eq!(
            post_logout_uris,
            vec!["https://app.com/logout", "http://localhost:3000/"]
        );
    }
}
