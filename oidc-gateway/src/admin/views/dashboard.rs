use crate::admin::layout::{AdminSession, render_layout};
use crate::admin::views::{format_timestamp, relative_time};
use crate::store::{self, AuditEvent};
use http::Response;
use maud::{Markup, html};

pub async fn render_dashboard(session: &AdminSession) -> Response<String> {
    let tenants_count = session.tenants.len();
    let users_count = if session.is_superadmin {
        store::list_users().await.map(|u| u.len()).unwrap_or(0)
    } else if let Some(tenant) = session.current_tenant.as_ref() {
        store::list_tenant_members(&tenant.id)
            .await
            .map(|members| members.len())
            .unwrap_or(0)
    } else {
        0
    };
    let clients_count = if session.is_superadmin {
        store::list_clients().await.map(|c| c.len()).unwrap_or(0)
    } else {
        0
    };
    let idps_count = if session.is_superadmin {
        store::list_identity_providers()
            .await
            .map(|i| i.len())
            .unwrap_or(0)
    } else {
        0
    };

    let audit_events = if session.is_superadmin {
        store::list_audit_events(None, None, None, None, None, 10)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Dashboard" }
                p class="page-subtitle" {
                    @if session.is_superadmin {
                        "Authority health, security overview, and system metrics."
                    } @else {
                        "Tenant administration overview."
                    }
                }
            }
        }

        // ── Stat Tiles ──
        div class="stats-grid" {
            div class="stat-tile" {
                div class="stat-tile-label" { "Tenants" }
                div class="stat-tile-value" { (tenants_count) }
                div class="stat-tile-sub" { "Active organizations" }
            }
            div class="stat-tile" {
                div class="stat-tile-label" { @if session.is_superadmin { "Total Users" } @else { "Tenant Members" } }
                div class="stat-tile-value" { (users_count) }
                div class="stat-tile-sub" { @if session.is_superadmin { "Identities registered" } @else { "Members in current tenant" } }
            }
            @if session.is_superadmin {
                div class="stat-tile" {
                    div class="stat-tile-label" { "OAuth Clients" }
                    div class="stat-tile-value" { (clients_count) }
                    div class="stat-tile-sub" { "Applications" }
                }
                div class="stat-tile" {
                    div class="stat-tile-label" { "Identity Providers" }
                    div class="stat-tile-value" { (idps_count) }
                    div class="stat-tile-sub" { "Federated providers" }
                }
            } @else {
                div class="stat-tile" {
                    div class="stat-tile-label" { "Current Tenant" }
                    div class="stat-tile-value" {
                        (session.current_tenant.as_ref().map(|tenant| tenant.display_name.as_str()).unwrap_or("—"))
                    }
                    div class="stat-tile-sub" { "Active management scope" }
                }
            }
        }

        // ── Quick Actions ──
        div class="quick-actions" {
            @if session.is_superadmin {
                button class="btn btn-primary"
                       hx-get="/admin/tenants/modal/new"
                       hx-target="#modal-container" {
                    "Create Tenant"
                }
                button class="btn"
                       hx-get="/admin/clients/modal/new"
                       hx-target="#modal-container" {
                    "Register Client"
                }
                a href="/admin/hooks" class="btn" { "Configure Hooks" }
                a href="/admin/audit" class="btn" { "View Audit Trail" }
            } @else if let Some(ref tenant) = session.current_tenant {
                a href={"/admin/tenants/" (tenant.id)} class="btn btn-primary" { "Manage Members" }
                a href="/admin/account" class="btn" { "My Account" }
            } @else {
                a href="/admin/account" class="btn btn-primary" { "My Account" }
            }
        }

        @if session.is_superadmin {
            // ── Recent Activity ──
            div class="card" {
                div class="card-header" {
                    span class="card-title" { "Recent Audit Activity" }
                    span class="card-spacer" {}
                    a href="/admin/audit" class="btn btn-sm btn-ghost" { "All Events →" }
                }
                (render_audit_table(&audit_events))
            }
        }
    };

    render_layout(session, "dashboard", "Dashboard", content)
}

pub fn render_audit_table(events: &[AuditEvent]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Time" }
                        th { "Event" }
                        th { "Actor" }
                        th { "Target / Detail" }
                    }
                }
                tbody {
                    @if events.is_empty() {
                        tr {
                            td colspan="4" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No audit events recorded yet."
                            }
                        }
                    } @else {
                        @for ev in events {
                            tr {
                                td class="mono-sm" title=(format_timestamp(ev.timestamp)) {
                                    (relative_time(ev.timestamp))
                                }
                                td {
                                    span class="badge badge-accent" { (ev.event_type) }
                                }
                                td class="mono" { (ev.actor_id) }
                                td {
                                    @if !ev.target_id.is_empty() {
                                        span class="mono" { (ev.target_id) }
                                        @if !ev.details.is_empty() { " — " }
                                    }
                                    span class="text-muted" { (ev.details) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
