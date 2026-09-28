use crate::admin::layout::{AdminSession, render_layout};
use crate::admin::views::{format_timestamp, relative_time, render_status_badge};
use crate::store::{self, Membership, Tenant, User};
use http::Response;
use maud::{Markup, html};

pub async fn render_tenants_page(session: &AdminSession) -> Response<String> {
    let tenants = store::list_tenants().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Tenants" }
                p class="page-subtitle" { "Manage multi-tenant organizations and workspaces." }
            }
            div class="page-actions" {
                button class="btn btn-primary"
                       hx-get="/admin/tenants/modal/new"
                       hx-target="#modal-container" {
                    "+ Create Tenant"
                }
            }
        }

        div class="card" {
            (render_tenants_table(&tenants))
        }
    };

    render_layout(session, "tenants", "Tenants", content)
}

pub fn render_tenants_table(tenants: &[Tenant]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Display Name" }
                        th { "Slug / Name" }
                        th { "Tenant ID" }
                        th { "Status" }
                        th { "Created" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="tenants-table-body" {
                    @if tenants.is_empty() {
                        tr {
                            td colspan="6" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No tenants found. Click 'Create Tenant' to add one."
                            }
                        }
                    } @else {
                        @for t in tenants {
                            tr id={"tenant-row-" (t.id)} {
                                td {
                                    a href={"/admin/tenants/" (t.id)} style="font-weight:600; text-decoration:none; color:inherit;" {
                                        (t.display_name)
                                    }
                                }
                                td class="mono" { (t.name) }
                                td class="mono-sm" { (t.id) }
                                td { (render_status_badge(&t.status)) }
                                td class="mono-sm" { (relative_time(t.created_at)) }
                                td class="actions" {
                                    a href={"/admin/tenants/" (t.id)} class="btn btn-xs" { "Manage →" }
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/tenants/" (t.id)}
                                           hx-confirm={"Are you sure you want to delete tenant '" (t.display_name) "'?"}
                                           hx-target={"#tenant-row-" (t.id)}
                                           hx-swap="outerHTML" {
                                        "Delete"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn render_new_tenant_modal() -> Markup {
    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal" {
                h2 class="modal-title" { "Create New Tenant" }
                form hx-post="/admin/tenants" hx-target="body" {
                    div class="form-group" {
                        label for="display_name" { "Display Name" }
                        input type="text" id="display_name" name="display_name" required placeholder="Acme Corp";
                    }
                    div class="form-group" {
                        label for="name" { "Slug / Identifier" }
                        input type="text" id="name" name="name" required placeholder="acme";
                        div class="form-hint" { "Lower-case letters, numbers, and hyphens." }
                    }
                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Create Tenant" }
                    }
                }
            }
        }
    }
}

pub async fn render_tenant_detail_page(
    session: &AdminSession,
    tenant: &Tenant,
    members: &[(Membership, User)],
) -> Response<String> {
    let content = html! {
        div class="breadcrumb" {
            @if session.is_superadmin {
                a href="/admin/tenants" { "Tenants" }
            } @else {
                a href="/admin" { "Dashboard" }
            }
            span { "/" }
            span { (tenant.display_name) }
        }

        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { (tenant.display_name) }
                p class="page-subtitle" { "Tenant ID: " span class="mono" { (tenant.id) } " • Slug: " span class="mono" { (tenant.name) } }
            }
        }

        // ── Members Section ──
        div class="card" id="member-list-panel" {
            div class="card-header" {
                span class="card-title" { "Members (" (members.len()) ")" }
            }
            (render_members_table(&tenant.id, members))
        }

        // ── Invite Member ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Invite New Member" }
            }
            form hx-post={"/admin/tenants/" (tenant.id) "/invite"}
                  hx-target="#member-list-panel"
                  hx-swap="innerHTML"
                  style="display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap;" {
                div class="form-group" style="flex: 2; min-width: 200px; margin-bottom: 0;" {
                    label for="invite-email" { "User Email" }
                    input type="email" id="invite-email" name="email" required placeholder="colleague@example.com";
                }
                div class="form-group" style="flex: 1; min-width: 140px; margin-bottom: 0;" {
                    label for="invite-role" { "Role" }
                    select id="invite-role" name="role" {
                        option value="member" { "Member" }
                        option value="manager" { "Manager" }
                        option value="admin" { "Admin" }
                        option value="owner" { "Owner" }
                    }
                }
                button type="submit" class="btn btn-primary" style="height: 38px;" { "Send Invite" }
            }
        }

        @if session.is_superadmin {
            // ── Danger Zone ──
            div class="danger-zone" {
                div class="danger-zone-title" { "Danger Zone" }
                div class="danger-zone-row" {
                    div class="danger-zone-desc" {
                        h4 { "Delete this tenant" }
                        p { "Permanently remove this organization, all client bindings, and member associations." }
                    }
                    button class="btn btn-danger"
                           hx-delete={"/admin/tenants/" (tenant.id)}
                           hx-confirm={"Permanently delete tenant '" (tenant.display_name) "'?"}
                           hx-target="body" {
                        "Delete Tenant"
                    }
                }
            }
        }
    };

    render_layout(
        session,
        "tenants",
        &format!("Tenant: {}", tenant.display_name),
        content,
    )
}

pub fn render_members_table(tenant_id: &str, members: &[(Membership, User)]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "User" }
                        th { "Email" }
                        th { "Role" }
                        th { "Joined" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody {
                    @if members.is_empty() {
                        tr {
                            td colspan="5" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No members found in this tenant."
                            }
                        }
                    } @else {
                        @for (m, u) in members {
                            tr id={"member-row-" (u.id)} {
                                td style="font-weight: 500;" { (u.name) }
                                td class="mono" { (u.email) }
                                td {
                                    span class={"badge badge-" @if m.role == "owner" { "accent" } @else { "muted" }} {
                                        (m.role)
                                    }
                                }
                                td class="mono-sm" { (format_timestamp(m.joined_at)) }
                                td class="actions" {
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/tenants/" (tenant_id) "/members/" (u.id)}
                                           hx-confirm={"Remove " (u.email) " from this tenant?"}
                                           hx-target={"#member-row-" (u.id)}
                                           hx-swap="outerHTML" {
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
