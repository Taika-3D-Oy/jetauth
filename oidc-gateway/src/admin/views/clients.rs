use maud::{html, Markup};
use crate::admin::layout::{render_layout, AdminSession};
use crate::store::{self, OidcClient};
use http::Response;

pub async fn render_clients_page(session: &AdminSession) -> Response<String> {
    let clients = store::list_clients().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "OAuth Clients" }
                p class="page-subtitle" { "Manage applications, redirect URIs, and authentication secrets." }
            }
            div class="page-actions" {
                button class="btn btn-primary"
                       hx-get="/admin/clients/modal/new"
                       hx-target="#modal-container" {
                    "+ Register Client"
                }
            }
        }

        div class="card" {
            (render_clients_table(&clients))
        }
    };

    render_layout(session, "clients", "OAuth Clients", content)
}

pub fn render_clients_table(clients: &[OidcClient]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Client Name" }
                        th { "Client ID" }
                        th { "Trust & Type" }
                        th { "Signing Alg" }
                        th { "Redirect URIs" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="clients-table-body" {
                    @if clients.is_empty() {
                        tr {
                            td colspan="6" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No OAuth clients registered yet."
                            }
                        }
                    } @else {
                        @for c in clients {
                            @let is_confidential = c.client_secret.is_some();
                            tr id={"client-row-" (c.client_id)} {
                                td {
                                    a href={"/admin/clients/" (c.client_id)} style="font-weight:600; text-decoration:none; color:inherit;" {
                                        (c.name)
                                    }
                                }
                                td class="mono" {
                                    span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (c.client_id) }
                                }
                                td {
                                    div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;" {
                                        @if c.first_party {
                                            span class="badge badge-accent" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);" { "First-Party" }
                                        } @else {
                                            span class="badge badge-muted" { "3rd-Party" }
                                        }
                                        @if is_confidential {
                                            span class="badge badge-accent" { "Confidential" }
                                        } @else {
                                            span class="badge badge-muted" { "Public (PKCE)" }
                                        }
                                    }
                                }
                                td class="mono-sm" {
                                    span class="badge badge-muted" { (c.id_token_signed_response_alg.as_deref().unwrap_or("RS256")) }
                                }
                                td class="mono-sm" {
                                    (c.redirect_uris.len()) " login"
                                    @if !c.post_logout_redirect_uris.is_empty() {
                                        ", " (c.post_logout_redirect_uris.len()) " logout"
                                    }
                                }
                                td class="actions" {
                                    a href={"/admin/clients/" (c.client_id)} class="btn btn-xs" { "Configure →" }
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/clients/" (c.client_id)}
                                           hx-confirm={"Delete client application '" (c.name) "'?"}
                                           hx-target={"#client-row-" (c.client_id)}
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

pub fn render_new_client_modal() -> Markup {
    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal modal-lg" {
                h2 class="modal-title" { "Register OAuth Client Application" }
                form hx-post="/admin/clients" hx-target="body" {
                    div class="form-group" {
                        label for="name" { "Application Name" }
                        input type="text" id="name" name="name" required placeholder="Dashboard Web App";
                    }
                    div class="form-group" {
                        label for="redirect_uris" { "Login Redirect URIs (one per line)" }
                        textarea id="redirect_uris" name="redirect_uris" required placeholder="https://app.example.com/oauth/callback&#10;http://localhost:3000/callback" {}
                    }
                    div class="form-group" {
                        label for="post_logout_redirect_uris" { "Post-Logout Redirect URIs (optional, one per line)" }
                        textarea id="post_logout_redirect_uris" name="post_logout_redirect_uris" placeholder="https://app.example.com/&#10;http://localhost:3000/" {}
                        div class="form-hint" { "Allowed destination URLs after OpenID Connect RP-Initiated logout." }
                    }
                    div class="form-group" {
                        label for="client_type" { "Client Type" }
                        select id="client_type" name="client_type" {
                            option value="confidential" { "Confidential (Generates Client Secret for server-side apps)" }
                            option value="public" { "Public (SPA / Native Mobile App with PKCE)" }
                        }
                    }

                    div class="form-group" style="margin-bottom: 16px; padding: 12px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: var(--radius);" {
                        label class="checkbox-label" style="display:flex; align-items:flex-start; gap:8px; cursor:pointer;" {
                            input type="checkbox" id="first_party" name="first_party" value="true";
                            div {
                                span style="font-weight:600;" { "First-Party / Trusted Application" }
                                p class="text-muted" style="margin:2px 0 0; font-size:12px; line-height:1.4;" {
                                    "Skip user consent screen on authorization. Recommended for official in-house apps (NERD, Foot Generator, AFO)."
                                }
                            }
                        }
                    }

                    div class="form-group" style="margin-bottom: 16px;" {
                        label { "Allowed Grant Types" }
                        div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px;" {
                            label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                                input type="checkbox" name="grant_types" value="authorization_code" checked;
                                span { "Authorization Code" }
                            }
                            label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                                input type="checkbox" name="grant_types" value="refresh_token" checked;
                                span { "Refresh Token" }
                            }
                            label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                                input type="checkbox" name="grant_types" value="client_credentials";
                                span { "Client Credentials" }
                            }
                            label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                                input type="checkbox" name="grant_types" value="urn:ietf:params:oauth:grant-type:device_code";
                                span { "Device Code (RFC 8628)" }
                            }
                        }
                    }

                    div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;" {
                        div class="form-group" {
                            label for="id_token_signed_response_alg" { "ID Token Signing Alg" }
                            select id="id_token_signed_response_alg" name="id_token_signed_response_alg" {
                                option value="RS256" { "RS256 (RSA SHA-256)" }
                                option value="ES256" { "ES256 (ECDSA P-256)" }
                            }
                        }
                        div class="form-group" {
                            label for="backchannel_logout_uri" { "Back-Channel Logout URI" }
                            input type="text" id="backchannel_logout_uri" name="backchannel_logout_uri" placeholder="https://app.example.com/backchannel-logout";
                        }
                    }

                    h3 style="margin-top: 20px; margin-bottom: 8px;" { "Branding & Customization (Optional)" }
                    div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;" {
                        div class="form-group" {
                            label for="app_name" { "Display Title" }
                            input type="text" id="app_name" name="app_name" placeholder="Custom Login Title";
                        }
                        div class="form-group" {
                            label for="theme_preset" { "Theme Preset" }
                            select id="theme_preset" name="theme_preset" {
                                option value="" { "(Inherit System Default)" }
                                option value="taika-dark" { "Taika Dark" }
                                option value="taika-light" { "Taika Light" }
                                option value="glassmorphic" { "Glassmorphic" }
                                option value="cyberpunk" { "Cyberpunk" }
                                option value="minimal-noir" { "Minimal Noir" }
                                option value="neo-brutalist" { "Neo-Brutalist" }
                            }
                        }
                    }

                    div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;" {
                        div class="form-group" {
                            label for="logo_url" { "Logo URL" }
                            input type="text" id="logo_url" name="logo_url" placeholder="https://example.com/logo.svg";
                        }
                        div class="form-group" {
                            label for="primary_color" { "Brand Color (HEX)" }
                            input type="text" id="primary_color" name="primary_color" placeholder="#10b981";
                        }
                    }

                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Register Application" }
                    }
                }
            }
        }
    }
}

pub async fn render_client_detail_page(
    session: &AdminSession,
    client: &OidcClient,
    new_created_secret: Option<&str>,
) -> Response<String> {
    let redirect_uris_text = client.redirect_uris.join("\n");
    let post_logout_redirect_uris_text = client.post_logout_redirect_uris.join("\n");
    let is_confidential = client.client_secret.is_some();
    let theme = client.theme.clone().unwrap_or_default();
    let current_preset = theme.theme_preset.as_deref().unwrap_or("");

    let content = html! {
        div class="breadcrumb" {
            a href="/admin/clients" { "Clients" }
            span { "/" }
            span { (client.name) }
        }

        @if let Some(raw_secret) = new_created_secret {
            div class="alert alert-warning" style="margin-bottom: 20px; padding: 16px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: var(--radius);" {
                div style="font-weight: 600; color: #f59e0b; margin-bottom: 6px; font-size: 14px;" {
                    "⚠️ Make sure to copy your Client Secret now"
                }
                p style="margin: 0 0 10px; font-size: 13px; color: var(--text-secondary);" {
                    "For security reasons, client secrets are hashed with HMAC-SHA256 and cannot be retrieved again."
                }
                div class="reveal-field" style="background: var(--bg-card); padding: 8px 12px; border: 1px solid var(--border-color); border-radius: var(--radius); display: flex; align-items: center; gap: 8px;" {
                    span class="mono copy-chip" onclick="copyToClipboard(this, this.innerText)" style="font-size: 14px; font-weight: 600;" { (raw_secret) }
                    button class="btn btn-xs btn-primary" onclick="copyToClipboard(this, this.previousElementSibling.innerText)" { "Copy Secret" }
                }
            }
        }

        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { (client.name) }
                p class="page-subtitle" {
                    "Client ID: " span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (client.client_id) }
                }
            }
        }

        // ── Credentials Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Client Credentials" }
            }
            div class="detail-grid" {
                div class="label" { "Client ID" }
                div class="value" {
                    span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (client.client_id) }
                }

                div class="label" { "Client Type" }
                div class="value" {
                    @if is_confidential {
                        span class="badge badge-accent" { "Confidential" }
                    } @else {
                        span class="badge badge-muted" { "Public (PKCE)" }
                    }
                }

                div class="label" { "Trust Level" }
                div class="value" {
                    @if client.first_party {
                        span class="badge badge-accent" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);" { "First-Party (Consent Bypassed)" }
                    } @else {
                        span class="badge badge-muted" { "Third-Party (Consent Required)" }
                    }
                }

                @if client.client_secret.is_some() {
                    div class="label" { "Client Secret" }
                    div class="value" {
                        div class="reveal-field" style="display: flex; align-items: center; gap: 8px;" {
                            span class="mono text-muted" style="font-size: 13px;" { "•••••••••••••••••••••••••••••••• (HMAC-SHA256 Protected)" }
                            button class="btn btn-xs btn-danger"
                                   hx-post={"/admin/clients/" (client.client_id) "/rotate-secret"}
                                   hx-confirm="Rotate secret? A new secret will be generated and shown once. Any services using the old secret will fail immediately."
                                   hx-target="#secret-reveal-container" {
                                "Rotate Secret"
                            }
                        }
                        div id="secret-reveal-container" {}
                    }
                }
            }
        }

        // ── General & OAuth Configuration Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "OAuth & Trust Settings" }
            }
            form hx-post={"/admin/clients/" (client.client_id) "/settings"} hx-target="body" {
                div class="form-group" style="margin-bottom: 16px;" {
                    label for="name" { "Application Name" }
                    input type="text" id="name" name="name" value=(client.name) required;
                }

                div class="form-group" style="margin-bottom: 16px; padding: 14px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: var(--radius);" {
                    label class="checkbox-label" style="display:flex; align-items:flex-start; gap:8px; cursor:pointer;" {
                        input type="checkbox" id="first_party" name="first_party" value="true" checked[client.first_party];
                        div {
                            span style="font-weight:600; color: var(--text);" { "First-Party / Trusted Application" }
                            p class="text-muted" style="margin:4px 0 0; font-size:12px; line-height:1.4;" {
                                "When enabled, users authenticating with this client will not be prompted with the consent screen (unless prompt=consent is explicitly requested). Recommended for official apps (NERD, Foot Generator, AFO)."
                            }
                        }
                    }
                }

                div class="form-group" style="margin-bottom: 16px;" {
                    label for="id_token_signed_response_alg" { "ID Token Signing Algorithm" }
                    select id="id_token_signed_response_alg" name="id_token_signed_response_alg" {
                        @let current_alg = client.id_token_signed_response_alg.as_deref().unwrap_or("RS256");
                        option value="RS256" selected[current_alg == "RS256"] { "RS256 (RSA SHA-256 - Default)" }
                        option value="ES256" selected[current_alg == "ES256"] { "ES256 (ECDSA P-256 SHA-256)" }
                    }
                    div class="form-hint" { "Algorithm used to sign OIDC ID Tokens issued to this application." }
                }

                div class="form-group" style="margin-bottom: 20px;" {
                    label { "Allowed Grant Types" }
                    div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 6px;" {
                        label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                            input type="checkbox" name="grant_types" value="authorization_code" checked[client.grant_types.contains(&"authorization_code".to_string())];
                            span { "Authorization Code" }
                        }
                        label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                            input type="checkbox" name="grant_types" value="refresh_token" checked[client.grant_types.contains(&"refresh_token".to_string())];
                            span { "Refresh Token" }
                        }
                        label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                            input type="checkbox" name="grant_types" value="client_credentials" checked[client.grant_types.contains(&"client_credentials".to_string())];
                            span { "Client Credentials" }
                        }
                        label class="checkbox-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" {
                            input type="checkbox" name="grant_types" value="urn:ietf:params:oauth:grant-type:device_code" checked[client.grant_types.contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string())];
                            span { "Device Code (RFC 8628)" }
                        }
                    }
                }

                button type="submit" class="btn btn-primary" { "Save OAuth Settings" }
            }
        }

        // ── Redirect & Logout URIs Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Allowed Redirect & Logout URIs" }
            }
            form hx-post={"/admin/clients/" (client.client_id) "/redirect-uris"} hx-target="body" {
                div class="form-group" {
                    label { "Login Redirect URIs (OAuth 2.0 / OIDC Authorization Code Flow)" }
                    textarea name="redirect_uris" rows="3" { (redirect_uris_text) }
                    div class="form-hint" { "One URL per line. Destination URLs where authorization codes can be returned." }
                }
                div class="form-group" style="margin-top: 16px;" {
                    label { "Post-Logout Redirect URIs (RP-Initiated Logout 1.0)" }
                    textarea name="post_logout_redirect_uris" rows="3" { (post_logout_redirect_uris_text) }
                    div class="form-hint" { "One URL per line. Destination URLs permitted for post_logout_redirect_uri per OpenID Connect RP-Initiated Logout 1.0." }
                }
                button type="submit" class="btn btn-primary" style="margin-top: 8px;" { "Save Redirect URIs" }
            }
        }

        // ── Back-Channel Logout Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Back-Channel Logout (OpenID Connect)" }
            }
            p class="text-muted" style="margin-bottom: 16px; font-size: 13px;" {
                "Notify this application via a direct server-to-server POST request when a user signs out."
            }
            form hx-post={"/admin/clients/" (client.client_id) "/backchannel-logout"} hx-target="body" {
                div class="form-group" style="margin-bottom: 16px;" {
                    label for="backchannel_logout_uri" { "Back-Channel Logout Endpoint URL" }
                    input type="text" id="backchannel_logout_uri" name="backchannel_logout_uri" value=(client.backchannel_logout_uri.clone().unwrap_or_default()) placeholder="https://app.example.com/api/backchannel-logout";
                }
                div class="form-group" style="margin-bottom: 16px;" {
                    label class="checkbox-label" style="display:flex; align-items:center; gap:8px; cursor:pointer;" {
                        input type="checkbox" name="backchannel_logout_session_required" value="true" checked[client.backchannel_logout_session_required];
                        span { "Include session ID (sid claim) in logout token" }
                    }
                }
                button type="submit" class="btn btn-primary" { "Save Logout Settings" }
            }
        }

        // ── Theme & White-Labeling Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Theme & White-Labeling Override" }
            }
            p class="text-muted" style="margin-bottom: 20px; font-size: 13px;" {
                "Customize the login, registration, and consent screens shown to users authenticating with this client application."
            }
            form hx-post={"/admin/clients/" (client.client_id) "/theme"} hx-target="body" {
                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="app_name" { "Custom Brand Name" }
                        input type="text" id="app_name" name="app_name" value=(theme.app_name) placeholder="Taika ID / My App";
                    }
                    div class="form-group" {
                        label for="theme_preset" { "Theme Preset" }
                        select id="theme_preset" name="theme_preset" {
                            option value="" selected[current_preset.is_empty()] { "(Inherit System Default)" }
                            option value="taika-dark" selected[current_preset == "taika-dark"] { "Taika Dark (Emerald & Slate)" }
                            option value="taika-light" selected[current_preset == "taika-light"] { "Taika Light (Clean Minimalist)" }
                            option value="glassmorphic" selected[current_preset == "glassmorphic"] { "Glassmorphic (Frosted Glass)" }
                            option value="cyberpunk" selected[current_preset == "cyberpunk"] { "Cyberpunk (Neon Cyan & Pink)" }
                            option value="minimal-noir" selected[current_preset == "minimal-noir"] { "Minimal Noir (Monochrome)" }
                            option value="neo-brutalist" selected[current_preset == "neo-brutalist"] { "Neo-Brutalist (Bold Borders & Shadows)" }
                        }
                    }
                }

                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="logo_url" { "Logo URL" }
                        input type="text" id="logo_url" name="logo_url" value=(theme.logo_url.unwrap_or_default()) placeholder="https://example.com/logo.svg";
                    }
                    div class="form-group" {
                        label for="primary_color" { "Brand Primary Color (HEX)" }
                        input type="text" id="primary_color" name="primary_color" value=(theme.primary_color.unwrap_or_default()) placeholder="#10b981";
                    }
                }

                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="background_color" { "Background Color" }
                        input type="text" id="background_color" name="background_color" value=(theme.background_color.unwrap_or_default()) placeholder="#0b0f19";
                    }
                    div class="form-group" {
                        label for="background_image_url" { "Background Image URL" }
                        input type="text" id="background_image_url" name="background_image_url" value=(theme.background_image_url.unwrap_or_default()) placeholder="https://example.com/wallpaper.jpg";
                    }
                }

                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="font_family" { "Font Family" }
                        input type="text" id="font_family" name="font_family" value=(theme.font_family.unwrap_or_default()) placeholder="'Inter', sans-serif";
                    }
                    div class="form-group" {
                        label for="font_url" { "Web Font Stylesheet URL" }
                        input type="text" id="font_url" name="font_url" value=(theme.font_url.unwrap_or_default()) placeholder="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap";
                    }
                }

                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="powered_by_text" { "Footer 'Powered by' Text" }
                        input type="text" id="powered_by_text" name="powered_by_text" value=(theme.powered_by_text.unwrap_or_default()) placeholder="Powered by Taika ID";
                    }
                    div class="form-group" {
                        label for="footer_text" { "Custom Footer / Copyright Notice" }
                        input type="text" id="footer_text" name="footer_text" value=(theme.footer_text.unwrap_or_default()) placeholder="© 2026 My App. All rights reserved.";
                    }
                }

                div class="form-group" style="margin-bottom: 16px;" {
                    label class="checkbox-label" style="display:flex; align-items:center; gap:8px; cursor:pointer;" {
                        input type="checkbox" name="hide_powered_by" value="true" checked[theme.hide_powered_by];
                        span { "Hide 'Powered by' footer branding" }
                    }
                }

                div class="form-group" style="margin-bottom: 20px;" {
                    label for="custom_css" { "Custom CSS Overrides" }
                    textarea id="custom_css" name="custom_css" rows="3" placeholder=":root { --radius: 20px; }" { (theme.custom_css.unwrap_or_default()) }
                    div class="form-hint" { "Custom styling rules injected directly into this client's authentication view." }
                }

                button type="submit" class="btn btn-primary" { "Save Client Theme" }
            }
        }

        // ── Danger Zone ──
        div class="danger-zone" {
            div class="danger-zone-title" { "Danger Zone" }
            div class="danger-zone-row" {
                div class="danger-zone-desc" {
                    h4 { "Delete this OAuth client" }
                    p { "Permanently revoke client credentials. Applications will not be able to authenticate users." }
                }
                button class="btn btn-danger"
                       hx-delete={"/admin/clients/" (client.client_id)}
                       hx-confirm={"Permanently delete client '" (client.name) "'?"}
                       hx-target="body" {
                    "Delete Client"
                }
            }
        }
    };

    render_layout(session, "clients", &format!("Client: {}", client.name), content)
}
