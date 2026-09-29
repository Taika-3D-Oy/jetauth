use crate::admin::layout::{render_layout, AdminSession};
use crate::admin::views::{format_timestamp, relative_time, render_status_badge};
use crate::store::{self, Membership, PasskeyCredential, Tenant, User};
use http::Response;
use maud::{html, Markup};
use std::collections::HashMap;

pub async fn render_users_page(session: &AdminSession) -> Response<String> {
    let users = store::list_users().await.unwrap_or_default();
    let mut user_tenants = HashMap::new();
    for u in &users {
        let tenants = store::list_user_tenants(&u.id).await.unwrap_or_default();
        user_tenants.insert(u.id.clone(), tenants);
    }

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Users" }
                p class="page-subtitle" { "Manage user accounts, tenant memberships, credentials, MFA, and passkeys." }
            }
            div class="page-actions" {
                input type="search"
                       name="q"
                       placeholder="Search users..."
                       hx-get="/admin/users/search"
                       hx-trigger="keyup changed delay:250ms"
                       hx-target="#users-table-container"
                       style="min-width: 240px;";
            }
        }

        div class="card" id="users-table-container" {
            (render_users_table(&users, &user_tenants))
        }
    };

    render_layout(session, "users", "Users", content)
}

pub fn render_users_table(
    users: &[User],
    user_tenants: &HashMap<String, Vec<Membership>>,
) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "User" }
                        th { "Email" }
                        th { "Status" }
                        th { "Tenants" }
                        th { "MFA" }
                        th { "Created" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="users-table-body" {
                    @if users.is_empty() {
                        tr {
                            td colspan="7" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No users found."
                            }
                        }
                    } @else {
                        @for u in users {
                            @let initial = u.name.chars().next().unwrap_or(u.email.chars().next().unwrap_or('U')).to_uppercase().to_string();
                            @let memberships = user_tenants.get(&u.id).map(|v| v.as_slice()).unwrap_or(&[]);
                            tr id={"user-row-" (u.id)} {
                                td {
                                    div class="flex" {
                                        div class="user-avatar" { (initial) }
                                        a href={"/admin/users/" (u.id)} style="font-weight:600; text-decoration:none; color:inherit;" {
                                            (u.name)
                                        }
                                    }
                                }
                                td class="mono" { (u.email) }
                                td { (render_status_badge(&u.status)) }
                                td {
                                    @if memberships.is_empty() {
                                        span class="text-muted" style="font-size: 11px; font-style: italic;" { "None" }
                                    } @else {
                                        div class="flex" style="flex-wrap: wrap; gap: 4px;" {
                                            @for m in memberships {
                                                span class="badge badge-muted" title={"Role: " (m.role)} {
                                                    (m.tenant_id)
                                                }
                                            }
                                        }
                                    }
                                }
                                td {
                                    @if u.totp_enabled {
                                        span class="badge badge-success" { "TOTP Enabled" }
                                    } @else {
                                        span class="badge badge-muted" { "Off" }
                                    }
                                }
                                td class="mono-sm" { (relative_time(u.created_at)) }
                                td class="actions" {
                                    @if u.status != "active" {
                                        button class="btn btn-xs btn-success"
                                               hx-post={"/admin/users/" (u.id) "/activate"}
                                               hx-confirm={"Activate user account for '" (u.email) "'?"}
                                               hx-target="body" {
                                            "Activate"
                                        }
                                    }
                                    button class="btn btn-xs"
                                           hx-get={"/admin/users/" (u.id) "/modal/add-tenant"}
                                           hx-target="#modal-container" {
                                        "+ Tenant"
                                    }
                                    a href={"/admin/users/" (u.id)} class="btn btn-xs" { "Manage →" }
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/users/" (u.id)}
                                           hx-confirm={"Permanently delete user '" (u.email) "'?"}
                                           hx-target={"#user-row-" (u.id)}
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

pub fn render_add_user_tenant_modal(user: &User, tenants: &[Tenant]) -> Markup {
    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal" {
                h2 class="modal-title" { "Add User to Tenant" }
                form hx-post={"/admin/users/" (user.id) "/tenants"}
                     hx-target="body" {
                    div class="form-group" {
                        label { "User" }
                        input type="text" value={ (user.name) " (" (user.email) ")" } disabled;
                    }
                    div class="form-group" {
                        label for="tenant_id" { "Tenant ID" }
                        input type="text"
                               name="tenant_id"
                               id="tenant_id"
                               list="existing-tenants-list"
                               placeholder="Select or enter tenant ID (e.g. tenant_abc123)..."
                               required;
                        @if !tenants.is_empty() {
                            datalist id="existing-tenants-list" {
                                @for t in tenants {
                                    option value=(t.id) {
                                        (t.display_name)
                                    }
                                }
                            }
                        }
                        p class="text-muted" style="font-size:12px; margin-top:4px;" {
                            "Pick an existing tenant from suggestions or enter any tenant ID."
                        }
                    }
                    div class="form-group" {
                        label for="role" { "Role in Tenant" }
                        select name="role" id="role" {
                            option value="member" selected { "Member (Standard user access)" }
                            option value="admin" { "Admin (Tenant administrator)" }
                            option value="manager" { "Manager (Operational manager)" }
                            option value="owner" { "Owner (Full tenant ownership)" }
                        }
                    }
                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Add to Tenant" }
                    }
                }
            }
        }
    }
}

pub async fn render_user_detail_page(
    session: &AdminSession,
    user: &User,
    passkeys: &[PasskeyCredential],
) -> Response<String> {
    let user_tenants = store::list_user_tenants(&user.id).await.unwrap_or_default();

    let content = html! {
        div class="breadcrumb" {
            a href="/admin/users" { "Users" }
            span { "/" }
            span { (user.email) }
        }

        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { (user.name) }
                p class="page-subtitle" { "User ID: " span class="mono" { (user.id) } }
            }
        }

        // ── Profile Information ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "User Profile" }
            }
            div class="detail-grid" {
                div class="label" { "Email" }
                div class="value mono" { (user.email) }

                div class="label" { "Full Name" }
                div class="value" { (user.name) }

                div class="label" { "Status" }
                div class="value" { (render_status_badge(&user.status)) }

                div class="label" { "Account Created" }
                div class="value mono-sm" { (format_timestamp(user.created_at)) }
            }
        }

        // ── Tenant Memberships ──
        div class="card" id="tenant-memberships-section" {
            div class="card-header" style="display: flex; justify-content: space-between; align-items: center;" {
                span class="card-title" { "Tenant Memberships (" (user_tenants.len()) ")" }
                button class="btn btn-sm btn-primary"
                       hx-get={"/admin/users/" (user.id) "/modal/add-tenant"}
                       hx-target="#modal-container" {
                    "+ Add to Tenant"
                }
            }
            div class="table-wrap" {
                table {
                    thead {
                        tr {
                            th { "Tenant ID" }
                            th { "Role" }
                            th { "Joined" }
                            th class="actions" { "Actions" }
                        }
                    }
                    tbody {
                        @if user_tenants.is_empty() {
                            tr {
                                td colspan="4" class="text-muted" style="text-align:center; padding: 20px;" {
                                    "This user does not belong to any tenant."
                                }
                            }
                        } @else {
                            @for m in &user_tenants {
                                tr id={"membership-row-" (m.tenant_id)} {
                                    td class="mono" { (m.tenant_id) }
                                    td {
                                        span class="badge badge-primary" { (m.role) }
                                    }
                                    td class="mono-sm" { (format_timestamp(m.joined_at)) }
                                    td class="actions" {
                                        button class="btn btn-xs btn-danger"
                                               hx-delete={"/admin/users/" (user.id) "/tenants/" (m.tenant_id)}
                                               hx-confirm={"Remove user from tenant '" (m.tenant_id) "'?"}
                                               hx-target="body" {
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

        // ── Security & Authentication ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Security Actions" }
            }
            div style="display: flex; gap: 12px; flex-wrap: wrap;" {
                @if user.status != "active" {
                    button class="btn btn-success"
                           hx-post={"/admin/users/" (user.id) "/activate"}
                           hx-confirm={"Activate user account for " (user.email) "?"}
                           hx-target="body" {
                        "Activate Account"
                    }
                }

                button class="btn"
                       hx-post={"/admin/users/" (user.id) "/password-reset"}
                       hx-confirm={"Send password reset email to " (user.email) "?"}
                       hx-target="body" {
                    "Send Password Reset Email"
                }

                @if user.totp_enabled {
                    button class="btn btn-danger"
                           hx-post={"/admin/users/" (user.id) "/disable-mfa"}
                           hx-confirm="Disable TOTP Multi-Factor Authentication for this user?"
                           hx-target="body" {
                        "Disable TOTP MFA"
                    }
                }
            }
        }

        // ── Passkeys Section ──
        div class="card" id="passkey-section" {
            div class="card-header" {
                span class="card-title" { "Registered Passkeys (" (passkeys.len()) ")" }
            }
            div class="table-wrap" {
                table {
                    thead {
                        tr {
                            th { "Credential Name" }
                            th { "Credential ID" }
                            th { "Created" }
                            th { "Sign Count" }
                            th class="actions" { "Actions" }
                        }
                    }
                    tbody {
                        @if passkeys.is_empty() {
                            tr {
                                td colspan="5" class="text-muted" style="text-align:center; padding: 20px;" {
                                    "No WebAuthn passkeys registered."
                                }
                            }
                        } @else {
                            @for p in passkeys {
                                tr id={"passkey-row-" (p.credential_id)} {
                                    td style="font-weight: 500;" { (p.name) }
                                    td class="mono-sm" {
                                        span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (p.credential_id) }
                                    }
                                    td class="mono-sm" { (format_timestamp(p.created_at)) }
                                    td class="mono" { (p.sign_count) }
                                    td class="actions" {
                                        button class="btn btn-xs btn-danger"
                                               hx-delete={"/admin/users/" (user.id) "/passkeys/" (p.credential_id)}
                                               hx-confirm="Revoke this passkey credential?"
                                               hx-target={"#passkey-row-" (p.credential_id)}
                                               hx-swap="outerHTML" {
                                            "Revoke"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Danger Zone ──
        div class="danger-zone" {
            div class="danger-zone-title" { "Danger Zone" }
            div class="danger-zone-row" {
                div class="danger-zone-desc" {
                    h4 { "Delete this user" }
                    p { "Permanently delete account, sessions, MFA credentials, and tenant memberships." }
                }
                button class="btn btn-danger"
                       hx-delete={"/admin/users/" (user.id)}
                       hx-confirm={"Permanently delete " (user.email) "?"}
                       hx-target="body" {
                    "Delete User"
                }
            }
        }
    };

    render_layout(session, "users", &format!("User: {}", user.email), content)
}
