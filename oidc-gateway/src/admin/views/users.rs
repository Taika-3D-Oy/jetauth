use crate::admin::layout::{AdminSession, render_layout};
use crate::admin::views::{format_timestamp, relative_time, render_status_badge};
use crate::store::{self, PasskeyCredential, User};
use http::Response;
use maud::{Markup, html};

pub async fn render_users_page(session: &AdminSession) -> Response<String> {
    let users = store::list_users().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Users" }
                p class="page-subtitle" { "Manage user accounts, credentials, MFA, and passkeys." }
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
            (render_users_table(&users))
        }
    };

    render_layout(session, "users", "Users", content)
}

pub fn render_users_table(users: &[User]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "User" }
                        th { "Email" }
                        th { "Status" }
                        th { "MFA" }
                        th { "Created" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="users-table-body" {
                    @if users.is_empty() {
                        tr {
                            td colspan="6" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No users found."
                            }
                        }
                    } @else {
                        @for u in users {
                            @let initial = u.name.chars().next().unwrap_or(u.email.chars().next().unwrap_or('U')).to_uppercase().to_string();
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
                                    @if u.totp_enabled {
                                        span class="badge badge-success" { "TOTP Enabled" }
                                    } @else {
                                        span class="badge badge-muted" { "Off" }
                                    }
                                }
                                td class="mono-sm" { (relative_time(u.created_at)) }
                                td class="actions" {
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

pub async fn render_user_detail_page(
    session: &AdminSession,
    user: &User,
    passkeys: &[PasskeyCredential],
) -> Response<String> {
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

        // ── Security & Authentication ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Security Actions" }
            }
            div style="display: flex; gap: 12px; flex-wrap: wrap;" {
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
