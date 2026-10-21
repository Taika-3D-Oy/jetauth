pub mod layout;
pub mod static_assets;
pub mod views;

use crate::admin::layout::AdminSession;
use crate::services::authz::role_level;
use crate::services::{
    Caller, clients as client_service, hooks as hook_service, idps as idp_service,
    settings as settings_service, tenants as tenant_service, users as user_service,
};
use crate::store::{self, AccountSession, ClientTheme, User};
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

    // ── OIDC Authorization Code Callback (built-in lid-admin client) ──
    // The provider completes the admin login by redirecting to the registered
    // redirect_uri as `GET /admin?code=...&state=...`. handle_admin_route is
    // given the path with its query string intact, so the code exchange is
    // completed here.
    if method == Method::GET
        && let Some((base, qs)) = path.split_once('?')
    {
        let base = base.trim_end_matches('/');
        if base.is_empty() || base == "/admin" {
            let params = parse_query(qs);
            if form_value(&params, "code").is_some() || form_value(&params, "error").is_some() {
                return handle_admin_oidc_callback(&params).await;
            }
        }
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
        return admin_oidc_login_redirect().await;
    }

    if p == "/admin/login/mfa" && method == Method::POST {
        return handle_admin_login_mfa(body).await;
    }

    // ── Authenticate Session ──
    let session = match resolve_admin_session(headers).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // ── CSRF Protection on state-mutating requests ──
    if (*method == Method::POST || *method == Method::PUT || *method == Method::DELETE)
        && let Err(resp) = verify_admin_csrf(headers, body, &session)
    {
        return resp;
    }

    if p == "/admin/logout" && method == Method::POST {
        return handle_admin_logout(headers).await;
    }

    // ── Route Dispatch ──
    let path_no_query = path.split('?').next().unwrap_or(path);
    let clean_path = path_no_query.trim_end_matches('/');
    let p = if clean_path.is_empty() {
        "/admin"
    } else {
        clean_path
    };

    // ── Authorization: cross-tenant global state is superadmin-only ──
    const SUPERADMIN_PREFIXES: &[&str] = &[
        "/admin/hooks",
        "/admin/settings",
        "/admin/clients",
        "/admin/identity-providers",
        "/admin/audit",
    ];
    let is_global_route = SUPERADMIN_PREFIXES
        .iter()
        .any(|pre| p == *pre || p.strip_prefix(pre).is_some_and(|r| r.starts_with('/')))
        || p == "/admin/users"
        || p == "/admin/users/search"
        || p == "/admin/tenants/modal/new"
        || (p == "/admin/tenants" && *method == Method::POST);
    if is_global_route && !session.is_superadmin {
        return error_response(
            StatusCode::FORBIDDEN,
            "Access denied: superadmin privileges required.",
        );
    }

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
            let caller = Caller::from_admin_session(&session).await;
            let tenant = match tenant_service::create_tenant(&caller, name, display_name).await {
                Ok(t) => t,
                Err(e) => return service_error(e, "Failed to save the tenant."),
            };
            // Add creator as owner
            let _ = tenant_service::add_member(&caller, &tenant.id, &caller.user_id, "owner").await;
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

            let caller = Caller::from_admin_session(&session).await;
            let result = client_service::create_client(
                &caller,
                client_service::CreateClientParams {
                    name: name.to_string(),
                    redirect_uris,
                    post_logout_redirect_uris,
                    grant_types: Some(grant_types),
                    confidential: client_type == "confidential",
                    theme,
                    backchannel_logout_uri,
                    id_token_signed_response_alg,
                    first_party,
                    ..Default::default()
                },
            )
            .await;

            match result {
                Ok((client, raw_secret_opt)) => {
                    if let Some(raw_secret) = raw_secret_opt {
                        views::clients::render_client_detail_page(
                            &session,
                            &client,
                            Some(&raw_secret),
                        )
                        .await
                    } else {
                        redirect_response(&format!("/admin/clients/{}", client.client_id))
                    }
                }
                Err(e) => service_error(e, "Failed to save the client."),
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
            let mut user_tenants = std::collections::HashMap::new();
            for u in &filtered {
                let tenants = store::list_user_tenants(&u.id).await.unwrap_or_default();
                user_tenants.insert(u.id.clone(), tenants);
            }
            html_response(views::users::render_users_table(&filtered, &user_tenants).into_string())
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

            let caller = Caller::from_admin_session(&session).await;
            match idp_service::create_identity_provider(
                &caller,
                &provider_type,
                &client_id,
                &client_secret,
                enabled,
            )
            .await
            {
                Ok(_) => redirect_response("/admin/identity-providers"),
                Err(e) => service_error(e, "Failed to save the identity provider."),
            }
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

            let caller = Caller::from_admin_session(&session).await;
            match hook_service::create_hook(
                &caller,
                hook_service::CreateHookParams {
                    name: name.to_string(),
                    trigger: trigger.to_string(),
                    script: script.to_string(),
                    enabled,
                    priority,
                },
            )
            .await
            {
                Ok(hook) => redirect_response(&format!("/admin/hooks/{}", hook.id)),
                Err(e) => service_error(e, "Failed to save the hook."),
            }
        }

        // ── Settings ──
        (&Method::GET, "/admin/settings") => views::settings::render_settings_page(&session).await,
        (&Method::POST, "/admin/settings") => {
            let form = parse_form(body);
            let allow_reg = form_value(&form, "allow_registration")
                .map(|v| v == "true" || v == "on")
                .unwrap_or(false);

            let current = store::get_runtime_settings().await;
            let mut def_theme = current.default_theme.clone().unwrap_or_default();
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

            let idp_session_ttl_seconds = form_value(&form, "idp_session_ttl_days")
                .and_then(|days_str| days_str.trim().parse::<u64>().ok())
                .filter(|days| (1..=90).contains(days))
                .map(|days| days * 86400);

            let caller = Caller::from_admin_session(&session).await;
            match settings_service::update_settings(
                &caller,
                settings_service::SettingsPatch {
                    allow_registration: Some(allow_reg),
                    default_theme: Some(def_theme),
                    idp_session_ttl_seconds,
                },
            )
            .await
            {
                Ok(_) => redirect_response("/admin/settings"),
                Err(e) => service_error(e, "Failed to save the settings."),
            }
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
    headers: &HeaderMap,
    body: &[u8],
    session: &AdminSession,
) -> Response<String> {
    // ── Single Tenant Detail & Subroutes ──
    if let Some(rest) = path.strip_prefix("/admin/tenants/") {
        if let Some((id, sub)) = rest.split_once('/') {
            // e.g. /admin/tenants/{id}/invite
            if sub == "invite" && method == Method::POST {
                if let Err(resp) = require_tenant_admin(session, id).await {
                    return resp;
                }
                let form = parse_form(body);
                let email = form_value(&form, "email").unwrap_or("").trim();
                let role = form_value(&form, "role").unwrap_or("member").trim();
                let caller = Caller::from_admin_session(session).await;
                let invite_notice = match tenant_service::invite_user(&caller, id, email, role)
                    .await
                {
                    Ok(_) => format!(
                        r#"<div class="alert alert-success" style="margin-bottom: 12px; padding: 10px 14px; border: 1px solid rgba(34, 197, 94, 0.4); border-radius: var(--radius); font-size: 13px;">Invitation sent to {}.</div>"#,
                        crate::util::html_escape(email)
                    ),
                    Err(e) => return service_error(e, "Failed to send the invitation."),
                };
                let memberships = store::list_tenant_members(id).await.unwrap_or_default();
                let mut members = Vec::new();
                for m in memberships {
                    if let Ok(Some(u)) = store::get_user(&m.user_id).await {
                        members.push((m, u));
                    }
                }
                return html_response(format!(
                    "{}{}",
                    invite_notice,
                    views::tenants::render_members_table(id, &members).into_string()
                ));
            }
            // e.g. /admin/tenants/{id}/members/{userId}
            if let Some(user_id) = sub.strip_prefix("members/")
                && method == Method::DELETE
            {
                if let Err(resp) = require_tenant_admin(session, id).await {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = tenant_service::remove_member(&caller, id, user_id).await {
                    return service_error(e, "Failed to remove the member.");
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(String::new())
                    .unwrap();
            }
        } else {
            // /admin/tenants/{id}
            let id = rest;
            if method == Method::GET {
                if let Err(resp) = require_tenant_admin(session, id).await {
                    return resp;
                }
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
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = tenant_service::delete_tenant(&caller, id).await {
                    return service_error(e, "Failed to delete the tenant.");
                }
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
                let caller = Caller::from_admin_session(session).await;
                match client_service::rotate_client_secret(&caller, id).await {
                    Ok(new_raw_secret) => {
                        return html_response(format!(
                            r#"<div class="alert alert-warning" style="margin-top: 12px; padding: 12px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: var(--radius);"><div style="font-weight: 600; color: #f59e0b; margin-bottom: 4px; font-size: 13px;">⚠️ Copy New Secret (Shown Once)</div><div style="display: flex; align-items: center; gap: 8px;"><span class="mono copy-chip" onclick="copyToClipboard(this, this.innerText)" style="font-size: 13px; font-weight: 600;">{}</span><button class="btn btn-xs btn-primary" onclick="copyToClipboard(this, this.previousElementSibling.innerText)">Copy</button></div></div>"#,
                            new_raw_secret
                        ));
                    }
                    Err(e) => return service_error(e, "Failed to rotate the client secret."),
                }
            }
            if (sub == "redirect-uris" || sub == "post-logout-redirect-uris")
                && method == Method::POST
            {
                let form = parse_form(body);
                let mut params = client_service::UpdateClientParams::default();
                if let Some(uris) = form_value(&form, "redirect_uris") {
                    params.redirect_uris = Some(
                        uris.lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect(),
                    );
                }
                if let Some(uris) = form_value(&form, "post_logout_redirect_uris") {
                    params.post_logout_redirect_uris = Some(
                        uris.lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect(),
                    );
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = client_service::update_client(&caller, id, params).await {
                    return service_error(e, "Failed to update the client.");
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
            if sub == "settings" && method == Method::POST {
                let form = parse_form(body);
                let mut params = client_service::UpdateClientParams::default();
                if let Some(name) = form_value(&form, "name")
                    && !name.trim().is_empty()
                {
                    params.name = Some(name.trim().to_string());
                }
                let gts: Vec<String> = crate::util::form_values(&form, "grant_types")
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
                if !gts.is_empty() {
                    params.grant_types = Some(gts);
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = client_service::update_client(&caller, id, params).await {
                    return service_error(e, "Failed to update the client.");
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
            if sub == "backchannel-logout" && method == Method::POST {
                let form = parse_form(body);
                let uri = form_value(&form, "backchannel_logout_uri")
                    .filter(|u| !u.trim().is_empty())
                    .map(|u| u.trim().to_string());
                let req_sid = form_value(&form, "backchannel_logout_session_required")
                    .map(|v| v == "true" || v == "on")
                    .unwrap_or(false);
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = client_service::update_client(
                    &caller,
                    id,
                    client_service::UpdateClientParams {
                        // An empty string clears the URI.
                        backchannel_logout_uri: Some(uri.unwrap_or_default()),
                        backchannel_logout_session_required: Some(req_sid),
                        ..Default::default()
                    },
                )
                .await
                {
                    return service_error(e, "Failed to update the client.");
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            }
            if sub == "theme" && method == Method::POST {
                let form = parse_form(body);
                let current_theme = store::get_client(id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|c| c.theme);
                let mut theme = current_theme.unwrap_or_default();
                {
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
                }

                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = client_service::update_client(
                    &caller,
                    id,
                    client_service::UpdateClientParams {
                        theme: Some(Some(theme)),
                        ..Default::default()
                    },
                )
                .await
                {
                    return service_error(e, "Failed to update the client.");
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
                let mut params = client_service::UpdateClientParams::default();
                if let Some(name) = form_value(&form, "name") {
                    params.name = Some(name.trim().to_string());
                }
                if let Some(uris) = form_value(&form, "redirect_uris") {
                    params.redirect_uris = Some(
                        uris.lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect(),
                    );
                }
                if let Some(uris) = form_value(&form, "post_logout_redirect_uris") {
                    params.post_logout_redirect_uris = Some(
                        uris.lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect(),
                    );
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = client_service::update_client(&caller, id, params).await {
                    return service_error(e, "Failed to update the client.");
                }
                return redirect_response(&format!("/admin/clients/{id}"));
            } else if method == Method::DELETE {
                if id == "lid-admin" || id == "lid-default" {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "Cannot delete a built-in system client.",
                    );
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = client_service::delete_client(&caller, id).await {
                    return service_error(e, "Failed to delete the client.");
                }
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
            if sub == "activate" && method == Method::POST {
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = user_service::activate_user(&caller, id).await {
                    return service_error(e, "Failed to activate the user.");
                }
                let return_to = headers
                    .get("hx-current-url")
                    .or_else(|| headers.get("referer"))
                    .and_then(|h| h.to_str().ok())
                    .filter(|s| s.ends_with("/admin/users"))
                    .map(|_| "/admin/users")
                    .unwrap_or("");
                if return_to.is_empty() {
                    return redirect_response(&format!("/admin/users/{id}"));
                } else {
                    return redirect_response(return_to);
                }
            }
            if sub == "modal/add-tenant" && method == Method::GET {
                // Global user management is superadmin-only; the modal would
                // otherwise leak arbitrary users' name/email to tenant admins.
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                if let Ok(Some(user)) = store::get_user(id).await {
                    let tenants = store::list_tenants().await.unwrap_or_default();
                    return html_response(
                        views::users::render_add_user_tenant_modal(&user, &tenants).into_string(),
                    );
                }
            }
            if sub == "tenants" && method == Method::POST {
                let form = parse_form(body);
                let tenant_id = form_value(&form, "tenant_id").unwrap_or("").trim();
                let role = form_value(&form, "role").unwrap_or("member").trim();

                if !tenant_id.is_empty() {
                    if let Err(resp) = require_tenant_admin(session, tenant_id).await {
                        return resp;
                    }
                    let caller = Caller::from_admin_session(session).await;

                    // Only superadmins may implicitly create a tenant from a custom ID.
                    match store::get_tenant(tenant_id).await {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            if !caller.is_superadmin {
                                return error_response(StatusCode::NOT_FOUND, "Tenant not found.");
                            }
                            if let Err(e) = tenant_service::create_tenant_with_id(
                                &caller, tenant_id, tenant_id, tenant_id,
                            )
                            .await
                            {
                                return service_error(e, "Failed to create the tenant.");
                            }
                        }
                        Err(e) => {
                            crate::logger::error_message("admin.tenant_lookup_failed", &e);
                            return error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to look up the tenant.",
                            );
                        }
                    }

                    if let Err(e) = tenant_service::add_member(&caller, tenant_id, id, role).await {
                        return service_error(e, "Failed to add the user to the tenant.");
                    }
                }

                let return_to = headers
                    .get("hx-current-url")
                    .or_else(|| headers.get("referer"))
                    .and_then(|h| h.to_str().ok())
                    .filter(|s| s.ends_with("/admin/users"))
                    .map(|_| "/admin/users")
                    .unwrap_or("");
                if return_to.is_empty() {
                    return redirect_response(&format!("/admin/users/{id}"));
                } else {
                    return redirect_response(return_to);
                }
            }
            if let Some(tenant_id) = sub.strip_prefix("tenants/")
                && method == Method::DELETE
            {
                if let Err(resp) = require_tenant_admin(session, tenant_id).await {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = tenant_service::remove_member(&caller, tenant_id, id).await {
                    return service_error(e, "Failed to remove the member.");
                }
                let return_to = headers
                    .get("hx-current-url")
                    .or_else(|| headers.get("referer"))
                    .and_then(|h| h.to_str().ok())
                    .filter(|s| s.ends_with("/admin/users"))
                    .map(|_| "/admin/users")
                    .unwrap_or("");
                if return_to.is_empty() {
                    return redirect_response(&format!("/admin/users/{id}"));
                } else {
                    return redirect_response(return_to);
                }
            }
            if sub == "password-reset" && method == Method::POST {
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = user_service::initiate_password_reset(&caller, id).await {
                    return service_error(e, "Failed to initiate the password reset.");
                }
                return redirect_response(&format!("/admin/users/{id}"));
            }
            if sub == "disable-mfa" && method == Method::POST {
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = user_service::disable_mfa(&caller, id).await {
                    return service_error(e, "Failed to disable MFA.");
                }
                return redirect_response(&format!("/admin/users/{id}"));
            }
            if let Some(cred_id) = sub.strip_prefix("passkeys/")
                && method == Method::DELETE
            {
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = user_service::delete_passkey(&caller, id, cred_id).await {
                    return service_error(e, "Failed to delete the passkey.");
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(String::new())
                    .unwrap();
            }
        } else {
            let id = rest;
            if method == Method::GET {
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                if let Ok(Some(user)) = store::get_user(id).await {
                    let passkeys = user.passkey_credentials.clone();
                    return views::users::render_user_detail_page(session, &user, &passkeys).await;
                }
            } else if method == Method::DELETE {
                if let Err(resp) = require_superadmin(session) {
                    return resp;
                }
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = user_service::delete_user(&caller, id).await {
                    return service_error(e, "Failed to delete the user.");
                }
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
                match store::get_identity_provider(id).await {
                    Ok(Some(idp)) => {
                        let caller = Caller::from_admin_session(session).await;
                        match idp_service::update_identity_provider(
                            &caller,
                            id,
                            idp_service::UpdateIdpParams {
                                enabled: Some(!idp.enabled),
                                ..Default::default()
                            },
                        )
                        .await
                        {
                            Ok(updated) => {
                                return html_response(
                                    views::idps::render_idp_row(&updated).into_string(),
                                );
                            }
                            Err(e) => {
                                return service_error(e, "Failed to update the identity provider.");
                            }
                        }
                    }
                    Ok(None) => {
                        return error_response(
                            StatusCode::NOT_FOUND,
                            "Identity provider not found",
                        );
                    }
                    Err(e) => {
                        crate::logger::error_message("admin.idp_toggle_failed", &e);
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to update the identity provider.",
                        );
                    }
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

                let caller = Caller::from_admin_session(session).await;
                match idp_service::update_identity_provider(
                    &caller,
                    id,
                    idp_service::UpdateIdpParams {
                        client_id: Some(client_id),
                        client_secret: Some(client_secret),
                        enabled: Some(enabled),
                        ..Default::default()
                    },
                )
                .await
                {
                    Ok(_) => return redirect_response("/admin/identity-providers"),
                    Err(e) => return service_error(e, "Failed to update the identity provider."),
                }
            }
        } else {
            let id = rest;
            if method == Method::DELETE {
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = idp_service::delete_identity_provider(&caller, id).await {
                    return service_error(e, "Failed to delete the identity provider.");
                }
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
            if sub == "test"
                && method == Method::POST
                && let Ok(Some(hook)) = store::get_hook(id).await
            {
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
                let current = match store::get_hook(id).await {
                    Ok(Some(h)) => h,
                    _ => {
                        return error_response(StatusCode::NOT_FOUND, "Hook not found");
                    }
                };
                let name = form_value(&form, "name")
                    .unwrap_or(&current.name)
                    .trim()
                    .to_string();
                let trigger = form_value(&form, "trigger")
                    .unwrap_or(&current.trigger)
                    .to_string();
                let priority: i32 = form_value(&form, "priority")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(current.priority);
                let enabled = form_value(&form, "enabled")
                    .map(|v| v == "true" || v == "on")
                    .unwrap_or(false);
                let script = form_value(&form, "script")
                    .unwrap_or(&current.script)
                    .to_string();

                let caller = Caller::from_admin_session(session).await;
                match hook_service::update_hook(
                    &caller,
                    id,
                    hook_service::UpdateHookParams {
                        name: Some(name),
                        trigger: Some(trigger),
                        script: Some(script),
                        enabled: Some(enabled),
                        priority: Some(priority),
                    },
                )
                .await
                {
                    Ok(_) => return redirect_response(&format!("/admin/hooks/{id}")),
                    Err(e) => return service_error(e, "Failed to save the hook."),
                }
            } else if method == Method::DELETE {
                let caller = Caller::from_admin_session(session).await;
                if let Err(e) = hook_service::delete_hook(&caller, id).await {
                    return service_error(e, "Failed to delete the hook.");
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(String::new())
                    .unwrap();
            }
        }
    }

    // ── My Account Passkey Deletion ──
    if let Some(cred_id) = path.strip_prefix("/admin/account/passkeys/")
        && method == Method::DELETE
    {
        let caller = Caller::from_admin_session(session).await;
        if let Err(e) = user_service::delete_passkey(&caller, &session.user.id, cred_id).await {
            return service_error(e, "Failed to delete the passkey.");
        }
        return Response::builder()
            .status(StatusCode::OK)
            .body(String::new())
            .unwrap();
    }

    error_response(StatusCode::NOT_FOUND, "Admin route not found")
}

// ── Authorization Helpers ─────────────────────────────────────

/// Render a service-layer error as an admin HTML error response. Internal
/// details are logged, never shown; 500s display the caller-supplied message.
fn service_error(err: crate::error::ApiError, internal_msg: &str) -> Response<String> {
    if err.status == StatusCode::INTERNAL_SERVER_ERROR {
        crate::logger::error_message("admin.service_error", err.log_detail());
        error_response(StatusCode::INTERNAL_SERVER_ERROR, internal_msg)
    } else {
        error_response(err.status, &err.message)
    }
}

fn safe_return_to(raw: &str) -> &str {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.starts_with("/\\") {
        raw
    } else {
        "/admin"
    }
}

#[allow(clippy::result_large_err)]
fn require_superadmin(session: &AdminSession) -> Result<(), Response<String>> {
    if session.is_superadmin {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::FORBIDDEN,
            "Access denied: superadmin privileges required.",
        ))
    }
}

/// Role the session user effectively holds on the given tenant.
/// Superadmins are treated as owners of every tenant.
async fn session_tenant_role(session: &AdminSession, tenant_id: &str) -> String {
    if session.is_superadmin {
        return "owner".to_string();
    }
    store::get_membership(tenant_id, &session.user.id)
        .await
        .ok()
        .flatten()
        .map(|m| m.role)
        .unwrap_or_default()
}

/// Require the session user to hold owner/admin on the TARGET tenant
/// (or be superadmin). Returns the effective role on success.
async fn require_tenant_admin(
    session: &AdminSession,
    tenant_id: &str,
) -> Result<String, Response<String>> {
    let role = session_tenant_role(session, tenant_id).await;
    if role_level(&role) >= role_level("admin") {
        Ok(role)
    } else {
        Err(error_response(
            StatusCode::FORBIDDEN,
            "Access denied: owner or admin role on this tenant required.",
        ))
    }
}

// ── Session Resolver & CSRF Protection ──────────────────────────

#[allow(clippy::result_large_err)]
fn verify_admin_csrf(
    headers: &HeaderMap,
    body: &[u8],
    session: &AdminSession,
) -> Result<(), Response<String>> {
    use subtle::ConstantTimeEq;

    // 1. Bearer token authenticated requests (API clients) are not vulnerable to browser CSRF
    if let Some(auth_hdr) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && (auth_hdr.starts_with("Bearer ") || auth_hdr.starts_with("bearer "))
    {
        return Ok(());
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
    // If an Authorization header is present, never fall back to cookies,
    // because verify_admin_csrf exempts requests with a Bearer header.
    if let Some(auth_hdr) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_hdr
            .strip_prefix("Bearer ")
            .or_else(|| auth_hdr.strip_prefix("bearer "))
            && let Ok(claims) = crate::service_client::verify_token_scoped(
                token,
                Some(&crate::get_issuer()),
                Some("lid-admin"),
                Some("access"),
            )
            .await
            && let Some(sub) = claims.get("sub").and_then(|v| v.as_str())
        {
            let iat = claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
            if !store::is_user_revoked(sub, iat).await.unwrap_or(true)
                && let Ok(Some(u)) = store::get_user(sub).await
                && u.status == "active"
            {
                user_opt = Some(u);
                csrf_token_opt = Some(store::random_hex(24));
            }
        }
        if user_opt.is_none() {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "Invalid or expired Bearer token.",
            ));
        }
    }

    // Check Cookies (lid_account or lid_session)
    if user_opt.is_none()
        && let Some(cookie_hdr) = headers.get("cookie").and_then(|v| v.to_str().ok())
    {
        for cookie in cookie_hdr.split(';') {
            let cookie = cookie.trim();
            if let Some(val) = cookie.strip_prefix("lid_account=") {
                if let Ok(Some(session_rec)) = store::get_account_session(val).await
                    && store::unix_now() <= session_rec.expires_at
                    && !store::is_user_revoked(&session_rec.user_id, session_rec.created_at)
                        .await
                        .unwrap_or(true)
                    && let Ok(Some(u)) = store::get_user(&session_rec.user_id).await
                    && u.status == "active"
                {
                    user_opt = Some(u);
                    csrf_token_opt = Some(if !session_rec.csrf_token.is_empty() {
                        session_rec.csrf_token
                    } else {
                        store::sha256_hex(&format!("csrf:{val}"))[..24].to_string()
                    });
                    break;
                }
            } else if let Some(val) = cookie.strip_prefix("lid_session=")
                && let Ok(Some(session_rec)) = store::get_idp_session(val).await
                && store::unix_now() <= session_rec.expires_at
                && !store::is_user_revoked(&session_rec.user_id, session_rec.auth_time)
                    .await
                    .unwrap_or(true)
                && let Ok(Some(u)) = store::get_user(&session_rec.user_id).await
                && u.status == "active"
            {
                user_opt = Some(u);
                csrf_token_opt = Some(store::sha256_hex(&format!("csrf:{val}"))[..24].to_string());
                break;
            }
        }
    }

    let user = match user_opt {
        Some(u) => u,
        None => {
            return Err(admin_oidc_login_redirect().await);
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

    let admin_tenant_ids = if is_super {
        std::collections::HashSet::new()
    } else {
        memberships
            .iter()
            .filter(|m| m.role == "owner" || m.role == "admin")
            .map(|m| m.tenant_id.clone())
            .collect()
    };

    Ok(AdminSession {
        user,
        is_superadmin: is_super,
        current_tenant,
        tenants,
        admin_tenant_ids,
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

    // Rate limit bootstrap attempts per email.
    match crate::service_client::check_rate(
        &format!("admin_bootstrap:{}", email.to_lowercase()),
        5,
        3600,
    )
    .await
    {
        Ok((false, _)) => {
            return views::bootstrap::render_bootstrap_page(Some(
                "Too many attempts. Please try again later.",
            ));
        }
        Err(e) => {
            // Fail closed: when the limiter is unavailable, deny the attempt.
            crate::logger::error_message("rate_limit.admin_bootstrap_check_failed", e);
            return views::bootstrap::render_bootstrap_page(Some(
                "Too many attempts. Please try again later.",
            ));
        }
        _ => {}
    }

    if password != confirm_password {
        return views::bootstrap::render_bootstrap_page(Some(
            "Passwords do not match. Please re-enter your password.",
        ));
    }

    let password_hash = match crate::service_client::hash_password(password).await {
        Ok(h) => h,
        Err(e) => {
            crate::logger::error_message("admin.bootstrap_hash_failed", &e);
            return views::bootstrap::render_bootstrap_page(Some(
                "Bootstrap is temporarily unavailable. Please try again.",
            ));
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

    // Serialize concurrent bootstraps (incl. across regions): the first writer
    // of this key wins; a conflict means bootstrap already completed elsewhere.
    match store::kv_create_raw("sessions", "meta:bootstrap_done", b"1", None).await {
        Ok(()) => {}
        Err(e) if e.contains("already exists") => {
            return Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", "/admin/login")
                .body(String::new())
                .unwrap();
        }
        Err(e) => {
            crate::logger::error_message("admin.bootstrap_claim_failed", &e);
            return views::bootstrap::render_bootstrap_page(Some(
                "Bootstrap is temporarily unavailable. Please try again.",
            ));
        }
    }

    if let Err(e) = store::create_user(&user).await {
        crate::logger::error_message("admin.bootstrap_create_user_failed", &e);
        return views::bootstrap::render_bootstrap_page(Some(
            "Failed to create the administrator account. Please contact the operator.",
        ));
    }

    let _ = store::set_superadmin_flag(true).await;

    // Ensure standard clients exist
    let issuer = crate::get_issuer();
    let _ = store::ensure_default_client().await;
    let _ = store::ensure_admin_client(&issuer, false).await;

    // Create Initial Organization
    let tenant_slug = org_name
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>();
    let bootstrap_caller = Caller {
        user_id: user.id.clone(),
        is_superadmin: true,
        tenant_roles: Vec::new(),
    };
    let tenant_id = match tenant_service::create_tenant(
        &bootstrap_caller,
        if tenant_slug.is_empty() {
            "default"
        } else {
            &tenant_slug
        },
        org_name,
    )
    .await
    {
        Ok(t) => t.id,
        Err(e) => {
            crate::logger::error_message("admin.bootstrap_tenant_failed", e.log_detail());
            return views::bootstrap::render_bootstrap_page(Some(
                "Failed to create the initial organization. Please contact the operator.",
            ));
        }
    };

    let _ = tenant_service::add_member(&bootstrap_caller, &tenant_id, &user.id, "owner").await;

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

/// Generate an S256 PKCE pair: (code_verifier, code_challenge).
/// The verifier is 64 hex chars — inside the RFC 7636 §4.1 length/charset bounds.
fn generate_pkce_pair() -> (String, String) {
    use sha2::{Digest, Sha256};
    let verifier = store::random_hex(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Start the admin UI's own OIDC authorization-code flow against this provider
/// using the built-in public client `lid-admin` (S256 PKCE, no client secret).
/// The verifier is stored server-side, keyed by the random OAuth `state`, and
/// consumed by handle_admin_oidc_callback when the provider redirects back.
async fn admin_oidc_login_redirect() -> Response<String> {
    let state = store::random_hex(32);
    let (verifier, challenge) = generate_pkce_pair();
    if let Err(e) = store::save_admin_pkce_verifier(&state, &verifier).await {
        crate::logger::error_message("admin.oidc_pkce_save_failed", &e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Sign-in is temporarily unavailable. Please try again.",
        );
    }
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            "location",
            format!(
                "/authorize?client_id=lid-admin&redirect_uri=/admin&response_type=code&scope=openid+email+profile&state={state}&code_challenge={challenge}&code_challenge_method=S256"
            ),
        )
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap()
}

/// Handle `GET /admin?code=...&state=...` — the authorization-code callback of
/// the built-in `lid-admin` client. The code is exchanged at this provider's
/// own token endpoint (in-process) as a public client: no secret, with the
/// S256 PKCE verifier bound to the login attempt's `state`.
async fn handle_admin_oidc_callback(params: &[(String, String)]) -> Response<String> {
    // /authorize redirects back with an error when the flow cannot complete
    // (e.g. prompt=none without a session).
    if let Some(err) = form_value(params, "error") {
        let desc = form_value(params, "error_description").unwrap_or(err);
        let msg = format!("Sign-in failed: {desc}");
        return views::login::render_login_page(Some(&msg), "/admin");
    }

    let code = form_value(params, "code").unwrap_or("");
    let state = form_value(params, "state").unwrap_or("");
    if code.is_empty() || state.is_empty() {
        return views::login::render_login_page(
            Some("Invalid sign-in response. Please try again."),
            "/admin",
        );
    }

    // Consume the PKCE verifier for this login attempt (single-use). An
    // unknown state means the attempt expired or was already completed.
    let verifier = match store::consume_admin_pkce_verifier(state).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return views::login::render_login_page(
                Some("Your sign-in session expired. Please try again."),
                "/admin",
            );
        }
        Err(e) => {
            crate::logger::error_message("admin.oidc_pkce_consume_failed", &e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Sign-in is temporarily unavailable. Please try again.",
            );
        }
    };

    let issuer = crate::get_issuer();
    let token_req = format!(
        "grant_type=authorization_code&code={}&redirect_uri=/admin&client_id=lid-admin&code_verifier={}",
        crate::util::percent_encode(code),
        crate::util::percent_encode(&verifier),
    );
    let token_resp = match crate::token::handle(token_req.as_bytes(), &issuer, None, None).await {
        Ok(r) => r,
        Err(e) => {
            crate::logger::error_message("admin.oidc_token_exchange_failed", &e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Sign-in is temporarily unavailable. Please try again.",
            );
        }
    };
    if token_resp.status() != StatusCode::OK {
        crate::logger::warn(
            "admin.oidc_token_exchange_rejected",
            serde_json::json!({ "status": token_resp.status().as_u16() }),
        );
        return views::login::render_login_page(
            Some("Sign-in failed. Please try again."),
            "/admin",
        );
    }

    let tokens: serde_json::Value = serde_json::from_str(token_resp.body()).unwrap_or_default();
    let user_id = tokens
        .get("access_token")
        .and_then(|t| t.as_str())
        .and_then(decode_jwt_sub);
    let Some(user_id) = user_id else {
        crate::logger::error_message("admin.oidc_token_exchange_failed", "missing sub claim");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Sign-in is temporarily unavailable. Please try again.",
        );
    };

    let _ = store::log_audit("admin_oidc_login_success", &user_id, &user_id, "lid-admin").await;

    // Establish the admin session cookie (same shape as direct-password login).
    let session_token = store::random_hex(32);
    let session_rec = AccountSession {
        user_id,
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

/// Extract the `sub` claim from a JWT payload without verifying the signature.
/// Only used for tokens issued by this component's own token endpoint within
/// the same request, where the issuer is trusted by construction.
fn decode_jwt_sub(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

async fn handle_admin_login(body: &[u8]) -> Response<String> {
    let form = parse_form(body);
    let email = form_value(&form, "email").unwrap_or("").trim();
    let password = form_value(&form, "password").unwrap_or("");
    let return_to = form_value(&form, "return_to").unwrap_or("/admin");
    let return_target = safe_return_to(return_to);

    if email.is_empty() || password.is_empty() {
        return views::login::render_login_page(
            Some("Please enter both email and password."),
            return_target,
        );
    }

    // Rate limit admin login attempts per email.
    match crate::service_client::check_rate(
        &format!("admin_login:{}", email.to_lowercase()),
        10,
        60,
    )
    .await
    {
        Ok((false, _)) => {
            return views::login::render_login_page(
                Some("Too many login attempts. Please try again later."),
                return_target,
            );
        }
        Err(e) => {
            // Fail closed: when the limiter is unavailable, deny the attempt.
            crate::logger::error_message("rate_limit.admin_login_check_failed", e);
            return views::login::render_login_page(
                Some("Too many login attempts. Please try again later."),
                return_target,
            );
        }
        _ => {}
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
        return views::login::render_login_page(Some("Invalid email or password."), return_target);
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
    let return_target = safe_return_to(return_to);

    if mfa_token.is_empty() {
        return views::login::render_login_page(
            Some("MFA session expired. Please sign in again."),
            return_target,
        );
    }

    if !matches!(
        crate::service_client::check_rate(&format!("mfa:{mfa_token}"), 5, 900).await,
        Ok((true, _))
    ) {
        let _ = store::delete_mfa_pending(mfa_token).await;
        return views::login::render_login_page(
            Some("Too many MFA attempts. Please sign in again."),
            return_target,
        );
    }

    let pending = match store::get_mfa_pending(mfa_token).await {
        Ok(Some(p)) if store::unix_now() <= p.expires_at && p.session_id == "admin" => p,
        _ => {
            return views::login::render_login_page(
                Some("MFA session expired. Please sign in again."),
                return_target,
            );
        }
    };

    let user = match store::get_user(&pending.user_id).await {
        Ok(Some(u)) if u.status == "active" => u,
        _ => return views::login::render_login_page(Some("User not found."), return_target),
    };

    // Check admin permissions before accepting MFA
    let is_super = user.superadmin;
    let memberships = store::list_user_tenants(&user.id).await.unwrap_or_default();
    let is_admin = is_super
        || memberships
            .iter()
            .any(|m| m.role == "owner" || m.role == "admin");
    if !is_admin {
        let _ = store::delete_mfa_pending(mfa_token).await;
        return views::login::render_login_page(
            Some("Access denied: Administrator privileges required."),
            return_target,
        );
    }

    // Verify TOTP or recovery code
    let mut verified = false;
    if let Some(ref secret) = user.totp_secret
        && let Some(step) = crate::totp::verify_totp_step(secret, code)
    {
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

    if !verified && !user.recovery_codes.is_empty() {
        // Check recovery code inside CAS retry loop with constant-time comparison
        use subtle::ConstantTimeEq;
        let normalized = code.trim().to_lowercase();
        let mut code_found = false;
        let rmw_res = store::update_user_rmw(&user.id, |u| {
            code_found = false;
            let mut matched_idx = None;
            for (idx, stored_code) in u.recovery_codes.iter().enumerate() {
                let stored_lower = stored_code.to_lowercase();
                if stored_lower.len() == normalized.len()
                    && bool::from(stored_lower.as_bytes().ct_eq(normalized.as_bytes()))
                {
                    matched_idx = Some(idx);
                }
            }
            if let Some(idx) = matched_idx {
                u.recovery_codes.remove(idx);
                code_found = true;
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .await;
        if rmw_res.is_ok() && code_found {
            verified = true;
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
    let caller = Caller::from_admin_session(session).await;
    match user_service::passkey_register_options(&caller, &session.user.id).await {
        Ok((token, options)) => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "token": token,
                "publicKey": options,
            }),
        ),
        Err(e) => json_error_response(e.status, &e.message),
    }
}

async fn handle_admin_passkey_register_complete(
    session: &AdminSession,
    body: &[u8],
) -> Response<String> {
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

    let caller = Caller::from_admin_session(session).await;
    match user_service::passkey_register_complete(
        &caller,
        &session.user.id,
        user_service::PasskeyRegisterCompleteParams {
            token: req.token,
            client_data_json: req.client_data_json,
            attestation_object: req.attestation_object,
            name: req.name,
        },
    )
    .await
    {
        Ok((credential_id, name)) => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "credential_id": credential_id,
                "name": name,
            }),
        ),
        Err(e) => {
            if e.status == StatusCode::INTERNAL_SERVER_ERROR {
                crate::logger::error_message("admin.passkey_register_failed", e.log_detail());
            }
            json_error_response(e.status, &e.message)
        }
    }
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
            crate::util::html_escape(message)
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
            admin_tenant_ids: Default::default(),
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
            admin_tenant_ids: Default::default(),
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
            admin_tenant_ids: Default::default(),
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
            admin_tenant_ids: Default::default(),
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
                admin_tenant_ids: Default::default(),
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
            admin_tenant_ids: Default::default(),
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
    fn test_safe_return_to() {
        assert_eq!(safe_return_to("/admin/users"), "/admin/users");
        assert_eq!(safe_return_to("/admin"), "/admin");
        assert_eq!(safe_return_to(""), "/admin");
        assert_eq!(safe_return_to("https://evil.com"), "/admin");
        assert_eq!(safe_return_to("//evil.com"), "/admin");
        assert_eq!(safe_return_to("/\\evil.com"), "/admin");
    }

    #[test]
    fn test_generate_pkce_pair_s256() {
        use sha2::{Digest, Sha256};
        let (verifier, challenge) = generate_pkce_pair();
        // RFC 7636: verifier 43-128 chars from the unreserved set
        assert!(verifier.len() >= 43 && verifier.len() <= 128);
        assert!(verifier.bytes().all(|b| b.is_ascii_hexdigit()));
        // challenge = BASE64URL-NOPAD(SHA256(verifier)), 43 chars
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        assert_eq!(challenge.len(), 43);
        // Distinct per call
        let (v2, c2) = generate_pkce_pair();
        assert_ne!(verifier, v2);
        assert_ne!(challenge, c2);
    }

    #[test]
    fn test_decode_jwt_sub() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user_123","aud":"lid-admin"}"#);
        let token = format!("header.{payload}.signature");
        assert_eq!(decode_jwt_sub(&token).as_deref(), Some("user_123"));

        assert!(decode_jwt_sub("not-a-jwt").is_none());
        let no_sub = URL_SAFE_NO_PAD.encode(br#"{"aud":"lid-admin"}"#);
        assert!(decode_jwt_sub(&format!("h.{no_sub}.s")).is_none());
        let empty_sub = URL_SAFE_NO_PAD.encode(br#"{"sub":""}"#);
        assert!(decode_jwt_sub(&format!("h.{empty_sub}.s")).is_none());
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
