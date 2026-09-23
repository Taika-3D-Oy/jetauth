use crate::admin::layout::{AdminSession, render_layout};
use crate::store::{self, IdentityProvider};
use http::Response;
use maud::{Markup, html};

pub async fn render_idps_page(session: &AdminSession) -> Response<String> {
    let idps = store::list_identity_providers().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Identity Providers" }
                p class="page-subtitle" { "Federated social and external OpenID Connect identity sources." }
            }
            div class="page-actions" {
                button class="btn btn-primary"
                       hx-get="/admin/identity-providers/modal/new"
                       hx-target="#modal-container" {
                    "+ Add Identity Provider"
                }
            }
        }

        div class="card" {
            (render_idps_table(&idps))
        }
    };

    render_layout(session, "idps", "Identity Providers", content)
}

pub fn render_idps_table(idps: &[IdentityProvider]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Provider" }
                        th { "Client ID" }
                        th { "Status" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="idps-table-body" {
                    @if idps.is_empty() {
                        tr {
                            td colspan="4" class="text-muted" style="text-align:center; padding: 32px;" {
                                "No external identity providers configured yet."
                            }
                        }
                    } @else {
                        @for idp in idps {
                            (render_idp_row(idp))
                        }
                    }
                }
            }
        }
    }
}

pub fn render_idp_row(idp: &IdentityProvider) -> Markup {
    let (icon_svg, provider_title) = match idp.provider_type.as_str() {
        "google" => (
            html! {
                svg width="18" height="18" viewBox="0 0 48 48" style="vertical-align: middle; margin-right: 8px; flex-shrink: 0;" {
                    path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z";
                    path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z";
                    path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z";
                    path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z";
                }
            },
            "Google",
        ),
        "github" => (
            html! {
                svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="vertical-align: middle; margin-right: 8px; flex-shrink: 0;" {
                    path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z";
                }
            },
            "GitHub",
        ),
        "microsoft" => (
            html! {
                svg width="18" height="18" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 8px; flex-shrink: 0;" {
                    path fill="#F25022" d="M1 1h10v10H1z";
                    path fill="#7FBA00" d="M13 1h10v10H13z";
                    path fill="#00A4EF" d="M1 13h10v10H1z";
                    path fill="#FFB900" d="M13 13h10v10H13z";
                }
            },
            "Microsoft",
        ),
        _ => (
            html! {
                svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 8px; flex-shrink: 0;" {
                    circle cx="12" cy="12" r="10";
                    line x1="2" y1="12" x2="22" y2="12";
                    path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z";
                }
            },
            "OpenID Connect",
        ),
    };

    html! {
        tr id={"idp-row-" (idp.id)} {
            td style="font-weight:600; display:flex; align-items:center;" {
                (icon_svg)
                span { (provider_title) }
            }
            td class="mono" {
                span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (idp.client_id) }
            }
            td {
                div style="display:flex; align-items:center; gap:8px;" {
                    label class="switch" title="Toggle active status" {
                        input type="checkbox"
                               checked[idp.enabled]
                               hx-post={"/admin/identity-providers/" (idp.id) "/toggle"}
                               hx-target={"#idp-row-" (idp.id)}
                               hx-swap="outerHTML";
                        span class="slider" {}
                    }
                    @if idp.enabled {
                        span class="badge badge-success" { "Active" }
                    } @else {
                        span class="badge badge-muted" { "Disabled" }
                    }
                }
            }
            td class="actions" {
                button class="btn btn-xs"
                       hx-get={"/admin/identity-providers/" (idp.id) "/modal/edit"}
                       hx-target="#modal-container" {
                    "Edit"
                }
                button class="btn btn-xs btn-danger"
                       hx-delete={"/admin/identity-providers/" (idp.id)}
                       hx-confirm={"Delete identity provider '" (provider_title) "'?"}
                       hx-target={"#idp-row-" (idp.id)}
                       hx-swap="outerHTML" {
                    "Delete"
                }
            }
        }
    }
}

pub fn render_new_idp_modal() -> Markup {
    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal" {
                h2 class="modal-title" { "Add External Identity Provider" }
                form hx-post="/admin/identity-providers" hx-target="body" {
                    div class="form-group" {
                        label for="provider_type" { "Provider" }
                        select id="provider_type" name="provider_type" {
                            option value="google" { "Google" }
                            option value="github" { "GitHub" }
                            option value="microsoft" { "Microsoft" }
                            option value="oidc" { "Generic OpenID Connect" }
                        }
                    }
                    div class="form-group" {
                        label for="client_id" { "Client ID" }
                        input type="text" id="client_id" name="client_id" required placeholder="OAuth client identifier";
                    }
                    div class="form-group" {
                        label for="client_secret" { "Client Secret" }
                        input type="password" id="client_secret" name="client_secret" required placeholder="OAuth client secret";
                    }
                    div class="form-group" {
                        label {
                            input type="checkbox" name="enabled" value="true" checked;
                            span style="margin-left: 6px;" { "Enable provider immediately" }
                        }
                    }
                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Add Provider" }
                    }
                }
            }
        }
    }
}

pub fn render_edit_idp_modal(idp: &IdentityProvider) -> Markup {
    let provider_title = match idp.provider_type.as_str() {
        "google" => "Google",
        "github" => "GitHub",
        "microsoft" => "Microsoft",
        _ => "OpenID Connect",
    };

    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal" {
                h2 class="modal-title" { "Edit " (provider_title) " Provider" }
                form hx-post={"/admin/identity-providers/" (idp.id) "/update"} hx-target="body" {
                    div class="form-group" {
                        label { "Provider Type" }
                        input type="text" value=(provider_title) disabled style="opacity:0.75;";
                    }
                    div class="form-group" {
                        label for="client_id" { "Client ID" }
                        input type="text" id="client_id" name="client_id" value=(idp.client_id) required;
                    }
                    div class="form-group" {
                        label for="client_secret" { "Client Secret (leave blank to keep current secret)" }
                        input type="password" id="client_secret" name="client_secret" placeholder="••••••••••••";
                    }
                    div class="form-group" {
                        label {
                            input type="checkbox" name="enabled" value="true" checked[idp.enabled];
                            span style="margin-left: 6px;" { "Provider is enabled" }
                        }
                    }
                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Save Changes" }
                    }
                }
            }
        }
    }
}
