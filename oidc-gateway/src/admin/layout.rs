use crate::store::{Tenant, User};
use http::{Response, StatusCode};
use maud::{DOCTYPE, Markup, html};

#[derive(Clone, Debug)]
pub struct AdminSession {
    pub user: User,
    pub is_superadmin: bool,
    pub current_tenant: Option<Tenant>,
    pub tenants: Vec<Tenant>,
    pub csrf_token: String,
}

pub fn render_layout(
    session: &AdminSession,
    active_nav: &str,
    title: &str,
    content: Markup,
) -> Response<String> {
    let issuer = crate::get_issuer();
    let user_name = if !session.user.name.is_empty() {
        session.user.name.clone()
    } else {
        session.user.email.clone()
    };
    let initial = user_name
        .chars()
        .next()
        .unwrap_or('A')
        .to_uppercase()
        .to_string();

    let markup = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (title) " — Taika ID Admin" }
                link rel="stylesheet" href="/admin/style.css";
                script src="/admin/htmx.min.js" {}
            }
            body class="app-shell" hx-headers=(format!(r#"{{"x-csrf-token": "{}"}}"#, session.csrf_token)) {
                // ── Topbar ──
                header class="topbar" {
                    a href="/admin" class="topbar-brand" { "⬡ Taika ID" }

                    @if !session.tenants.is_empty() {
                        div class="tenant-switcher" {
                            span class="text-muted" style="font-size:11px" { "Tenant:" }
                            select name="tenant_id"
                                   hx-post="/admin/tenant/switch"
                                   hx-trigger="change"
                                   hx-target="body" {
                                @for t in &session.tenants {
                                    @let is_selected = session.current_tenant.as_ref().map(|ct| ct.id == t.id).unwrap_or(false);
                                    option value=(t.id) selected[is_selected] { (t.display_name) }
                                }
                            }
                        }
                    }

                    span class="topbar-spacer" {}
                    span class="topbar-issuer" { (issuer) }

                    div class="user-avatar" title=(session.user.email) { (initial) }
                    span style="font-size:13px; font-weight:500;" { (user_name) }

                    a href="/admin/logout" class="topbar-btn" style="text-decoration:none;" { "Sign out" }
                }

                // ── Sidebar ──
                nav class="sidebar" {
                    div class="sidebar-section-label" { "Overview" }
                    a href="/admin" class={"sidebar-link" @if active_nav == "dashboard" { " active" }} {
                        "Dashboard"
                    }

                    div class="sidebar-divider" {}
                    div class="sidebar-section-label" { "Tenant" }
                    @if let Some(ref ct) = session.current_tenant {
                        a href={"/admin/tenants/" (ct.id)} class={"sidebar-link" @if active_nav == "tenant_members" { " active" }} {
                            "Members"
                        }
                    } @else {
                        span class="sidebar-link text-muted" style="font-style:italic" { "No tenant selected" }
                    }

                    @if session.is_superadmin {
                        div class="sidebar-divider" {}
                        div class="sidebar-section-label" { "Global" }
                        a href="/admin/tenants" class={"sidebar-link" @if active_nav == "tenants" { " active" }} {
                            "Tenants"
                        }
                        a href="/admin/clients" class={"sidebar-link" @if active_nav == "clients" { " active" }} {
                            "Clients"
                        }
                        a href="/admin/identity-providers" class={"sidebar-link" @if active_nav == "idps" { " active" }} {
                            "Identity Providers"
                        }
                        a href="/admin/hooks" class={"sidebar-link" @if active_nav == "hooks" { " active" }} {
                            "Hooks"
                        }
                        a href="/admin/settings" class={"sidebar-link" @if active_nav == "settings" { " active" }} {
                            "Settings"
                        }
                        a href="/admin/audit" class={"sidebar-link" @if active_nav == "audit" { " active" }} {
                            "Audit Log"
                        }
                    }

                    div class="sidebar-divider" {}
                    div class="sidebar-section-label" { "Account" }
                    a href="/admin/account" class={"sidebar-link" @if active_nav == "account" { " active" }} {
                        "My Account"
                    }
                }

                // ── Main content ──
                main class="main-content" id="admin-main" {
                    (content)
                }

                // ── Containers for toasts and modals ──
                div id="toast-container" class="toast-container" {}
                div id="modal-container" {}

                // ── Global Helper Scripts ──
                script {
                    (maud::PreEscaped(r#"
                    document.body.addEventListener('showToast', function(evt) {
                        const t = evt.detail;
                        const tc = document.getElementById('toast-container');
                        if (!tc) return;
                        const div = document.createElement('div');
                        div.className = 'toast toast-' + (t.kind || 'info');
                        const span = document.createElement('span');
                        span.textContent = t.message || '';
                        const btn = document.createElement('button');
                        btn.className = 'toast-close';
                        btn.textContent = '×';
                        btn.onclick = function() { div.remove(); };
                        div.appendChild(span);
                        div.appendChild(btn);
                        tc.appendChild(div);
                        setTimeout(() => div.remove(), 4500);
                    });
                    function closeModal() {
                        const m = document.getElementById('modal-container');
                        if (m) m.innerHTML = '';
                    }
                    function copyToClipboard(btn, text) {
                        navigator.clipboard.writeText(text).then(() => {
                            const orig = btn.innerText;
                            btn.innerText = 'Copied!';
                            setTimeout(() => { btn.innerText = orig; }, 2000);
                        });
                    }
                    "#))
                }
            }
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(markup.into_string())
        .unwrap()
}
