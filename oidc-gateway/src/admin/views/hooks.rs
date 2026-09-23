use crate::admin::layout::{AdminSession, render_layout};
use crate::admin::views::format_timestamp;
use crate::store::{self, Hook, HookVersion};
use http::Response;
use maud::{Markup, html};

pub async fn render_hooks_page(session: &AdminSession) -> Response<String> {
    let hooks = store::list_hooks().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Auth Lifecycle Hooks" }
                p class="page-subtitle" { "Execute custom Rhai scripts during auth events." }
            }
            div class="page-actions" {
                a href="/admin/hooks/new" class="btn btn-primary" {
                    "+ New Hook"
                }
            }
        }

        div class="card" {
            (render_hooks_table(&hooks))
        }
    };

    render_layout(session, "hooks", "Lifecycle Hooks", content)
}

pub fn render_hooks_table(hooks: &[Hook]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Hook Name" }
                        th { "Trigger Event" }
                        th { "Priority" }
                        th { "Version" }
                        th { "Status" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="hooks-table-body" {
                    @if hooks.is_empty() {
                        tr {
                            td colspan="6" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No hooks configured. Create a hook to intercept logins, registrations, or token claims."
                            }
                        }
                    } @else {
                        @for h in hooks {
                            tr id={"hook-row-" (h.id)} {
                                td {
                                    a href={"/admin/hooks/" (h.id)} style="font-weight:600; text-decoration:none; color:inherit;" {
                                        (h.name)
                                    }
                                }
                                td {
                                    span class="badge badge-accent" { (h.trigger) }
                                }
                                td class="mono" { (h.priority) }
                                td class="mono-sm" { "v" (h.version) }
                                td {
                                    @if h.enabled {
                                        span class="badge badge-success" { "Enabled" }
                                    } @else {
                                        span class="badge badge-muted" { "Disabled" }
                                    }
                                }
                                td class="actions" {
                                    a href={"/admin/hooks/" (h.id)} class="btn btn-xs" { "Edit →" }
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/hooks/" (h.id)}
                                           hx-confirm={"Delete hook '" (h.name) "'?"}
                                           hx-target={"#hook-row-" (h.id)}
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

pub async fn render_hook_editor_page(
    session: &AdminSession,
    hook: Option<&Hook>,
    versions: &[HookVersion],
) -> Response<String> {
    let is_new = hook.is_none();
    let id = hook.map(|h| h.id.as_str()).unwrap_or("");
    let name = hook.map(|h| h.name.as_str()).unwrap_or("");
    let trigger = hook.map(|h| h.trigger.as_str()).unwrap_or("post-login");
    let priority = hook.map(|h| h.priority).unwrap_or(100);
    let enabled = hook.map(|h| h.enabled).unwrap_or(true);
    let script = hook.map(|h| h.script.as_str()).unwrap_or(
        "// Rhai Hook Script\n// Available in script: user (map), event (string), tenants (array)\n// Functions: set_superadmin(bool), add_to_tenant(id, role), create_tenant(id, name, display), deny(msg), log(msg)\n\nif user.email.ends_with(\"@example.com\") {\n    set_superadmin(true);\n    log(\"Promoted user from example.com\");\n}\n"
    );

    let title = if is_new {
        "New Lifecycle Hook"
    } else {
        "Edit Hook"
    };

    let content = html! {
        div class="breadcrumb" {
            a href="/admin/hooks" { "Hooks" }
            span { "/" }
            span { (title) }
        }

        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { (title) }
                @if !is_new {
                    p class="page-subtitle" { "Hook ID: " span class="mono" { (id) } " • Hash: " span class="mono-sm" { (hook.unwrap().script_hash) } }
                }
            }
        }

        div class="split-pane" {
            // ── Editor Form ──
            div class="card" {
                form method="POST" action={@if is_new { "/admin/hooks" } @else { (format!("/admin/hooks/{}", id)) }} {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    div class="form-row" {
                        label for="name" { "Hook Name" }
                        input type="text" id="name" name="name" required value=(name) placeholder="Enrich Company Claims";
                    }

                    div class="form-row" {
                        label for="trigger" { "Trigger Event" }
                        select id="trigger" name="trigger" {
                            option value="post-login" selected[trigger == "post-login"] { "post-login (After successful login)" }
                            option value="post-registration" selected[trigger == "post-registration"] { "post-registration (After user creation)" }
                        }
                    }

                    div class="form-row" {
                        label for="priority" { "Priority (Order)" }
                        input type="number" id="priority" name="priority" value=(priority.to_string()) style="max-width: 120px;";
                    }

                    div class="form-row" {
                        label { "Status" }
                        label style="text-align:left; font-size: 13px; color: var(--fg); cursor: pointer;" {
                            input type="checkbox" name="enabled" value="true" checked[enabled];
                            span style="margin-left: 6px;" { "Enabled" }
                        }
                    }

                    div class="form-group" style="margin-top: 16px;" {
                        label for="script" { "Rhai Hook Script" }
                        div class="code-editor-wrap" {
                            textarea id="script" name="script" class="code-editor-area" rows="14" required {
                                (script)
                            }
                        }
                    }

                    div class="form-actions" {
                        button type="submit" class="btn btn-primary" {
                            @if is_new { "Create Hook" } @else { "Save Hook Changes" }
                        }
                        a href="/admin/hooks" class="btn btn-ghost" { "Cancel" }
                    }
                }
            }

            // ── Right Sidebar: Test Runner & Version History ──
            div {
                @if !is_new {
                    div class="card" {
                        div class="card-header" {
                            span class="card-title" { "Test Simulation" }
                        }
                        p class="form-hint" style="margin-bottom: 12px;" {
                            "Simulate hook execution against sample test payload."
                        }
                        button class="btn btn-sm btn-primary"
                               hx-post={"/admin/hooks/" (id) "/test"}
                               hx-target="#test-output-panel" {
                            "▶ Run Test Simulation"
                        }

                        div id="test-output-panel" style="margin-top: 12px;" {
                            div class="test-output text-muted" {
                                "Click 'Run Test Simulation' to execute the script against a test user."
                            }
                        }
                    }

                    div class="card" {
                        div class="card-header" {
                            span class="card-title" { "Version History" }
                        }
                        @if versions.is_empty() {
                            p class="text-muted" style="font-size: 12px;" { "No previous versions saved." }
                        } @else {
                            @for v in versions {
                                div class="version-item" {
                                    span class="version-num" { "v" (v.version) }
                                    div class="version-meta" {
                                        div class="mono-sm" { (format_timestamp(v.changed_at)) }
                                        div style="font-size: 11px;" { "by " (v.changed_by) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    render_layout(session, "hooks", title, content)
}

pub fn render_test_result(result_text: &str, is_success: bool) -> Markup {
    html! {
        div class="test-output" {
            @if is_success {
                div class="test-ok" { "✔ Execution Succeeded" }
            } @else {
                div class="test-err" { "✖ Execution Denied or Errored" }
            }
            pre style="margin-top: 6px; white-space: pre-wrap;" { (result_text) }
        }
    }
}
