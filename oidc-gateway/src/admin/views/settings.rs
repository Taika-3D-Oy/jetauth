use crate::admin::layout::{AdminSession, render_layout};
use crate::store;
use http::Response;
use maud::html;

pub async fn render_settings_page(session: &AdminSession) -> Response<String> {
    let settings = store::get_runtime_settings().await;
    let default_theme = settings.default_theme.clone().unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "System Settings" }
                p class="page-subtitle" { "Configure global authentication policies, default branding, and white-labeling." }
            }
        }

        div class="card" {
            div class="card-header" {
                span class="card-title" { "Global White-Labeling & Theme Defaults" }
            }
            p class="text-muted" style="margin-bottom: 20px; font-size: 13px;" {
                "Configure default branding and appearance across all authentication pages, portals, and emails. Individual OAuth clients can optionally override these settings."
            }

            form hx-post="/admin/settings" hx-target="body" {
                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="default_app_name" { "Application / Brand Name" }
                        input type="text" id="default_app_name" name="default_app_name" value=(default_theme.app_name) placeholder="Taika ID";
                        div class="form-hint" { "Replaces default name in page titles and headers." }
                    }
                    div class="form-group" {
                        label for="default_theme_preset" { "Base Theme Preset" }
                        select id="default_theme_preset" name="default_theme_preset" {
                            @let preset = default_theme.theme_preset.as_deref().unwrap_or("taika-dark");
                            option value="taika-dark" selected[preset == "taika-dark"] { "Taika Dark (Emerald & Slate)" }
                            option value="taika-light" selected[preset == "taika-light"] { "Taika Light (Clean Minimalist)" }
                            option value="glassmorphic" selected[preset == "glassmorphic"] { "Glassmorphic (Frosted Glass & Vibrant Glow)" }
                            option value="cyberpunk" selected[preset == "cyberpunk"] { "Cyberpunk (Neon Cyan, Pink & Dark Grid)" }
                            option value="minimal-noir" selected[preset == "minimal-noir"] { "Minimal Noir (High-contrast Monochrome)" }
                            option value="neo-brutalist" selected[preset == "neo-brutalist"] { "Neo-Brutalist (Bold Borders & Sharp Drop Shadows)" }
                        }
                    }
                }

                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="default_logo_url" { "Default Logo URL" }
                        input type="text" id="default_logo_url" name="default_logo_url" value=(default_theme.logo_url.unwrap_or_default()) placeholder="https://example.com/logo.svg";
                    }
                    div class="form-group" {
                        label for="default_primary_color" { "Brand Primary Color (HEX)" }
                        input type="text" id="default_primary_color" name="default_primary_color" value=(default_theme.primary_color.unwrap_or_default()) placeholder="#10b981";
                    }
                }

                div class="form-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;" {
                    div class="form-group" {
                        label for="default_powered_by_text" { "Footer 'Powered by' Text" }
                        input type="text" id="default_powered_by_text" name="default_powered_by_text" value=(default_theme.powered_by_text.unwrap_or_default()) placeholder="Powered by Taika ID";
                    }
                    div class="form-group" {
                        label for="default_footer_text" { "Custom Footer / Copyright Notice" }
                        input type="text" id="default_footer_text" name="default_footer_text" value=(default_theme.footer_text.unwrap_or_default()) placeholder="© 2026 Taika 3D. All rights reserved.";
                    }
                }

                div class="form-group" style="margin-bottom: 16px;" {
                    label class="checkbox-label" style="display:flex; align-items:center; gap:8px; cursor:pointer;" {
                        input type="checkbox" name="default_hide_powered_by" value="true" checked[default_theme.hide_powered_by];
                        span { "Hide 'Powered by' branding link completely" }
                    }
                }

                div class="form-group" style="margin-bottom: 20px;" {
                    label for="default_custom_css" { "Global Custom CSS" }
                    textarea id="default_custom_css" name="default_custom_css" rows="3" placeholder=":root { --radius: 16px; }" { (default_theme.custom_css.unwrap_or_default()) }
                    div class="form-hint" { "CSS rules injected into all authentication pages." }
                }

                div class="form-divider" style="border-top: 1px solid var(--border-color); margin: 24px 0;" {}

                div class="toggle-row" {
                    div class="toggle-label" {
                        h3 { "Public End-User Registration" }
                        p { "When enabled, unauthenticated visitors can create new user accounts via /register." }
                    }
                    label class="toggle-switch" {
                        input type="checkbox" name="allow_registration" value="true" checked[settings.allow_registration];
                        span class="toggle-track" {}
                    }
                }

                div class="form-divider" style="border-top: 1px solid var(--border-color); margin: 24px 0;" {}

                div class="toggle-row" {
                    div class="toggle-label" {
                        h3 { "OAuth 2.0 Dynamic Client Registration (RFC 7591)" }
                        p { "Allows external applications to dynamically register via POST /connect/register. Gated via runtime configuration (client_registration_mode)." }
                    }
                    @let reg_mode = store::client_registration_mode();
                    div style="display:flex; align-items:center;" {
                        @match reg_mode.as_str() {
                            "open" => span class="badge badge-success" style="font-size:12px; padding:4px 10px;" { "● Open (Public)" },
                            "protected" => span class="badge badge-accent" style="font-size:12px; padding:4px 10px;" { "● Protected (Bearer Token)" },
                            _ => span class="badge badge-muted" style="font-size:12px; padding:4px 10px;" { "● Disabled (Default)" },
                        }
                    }
                }

                div class="form-divider" style="border-top: 1px solid var(--border-color); margin: 24px 0;" {}

                h3 style="margin-bottom: 8px;" { "Authentication & Session Lifetimes" }
                p class="text-muted" style="margin-bottom: 16px; font-size: 13px;" {
                    "Configure session longevity for Single Sign-On (SSO) and persistent browser authentication across applications."
                }

                div class="form-group" style="max-width: 360px; margin-bottom: 16px;" {
                    label for="idp_session_ttl_days" { "IdP SSO Browser Session Duration (Days)" }
                    @let days = settings.idp_session_ttl_seconds.map(|s| s / 86400).unwrap_or(7);
                    input type="number" id="idp_session_ttl_days" name="idp_session_ttl_days" min="1" max="90" value=(days) required;
                    div class="form-hint" { "Default: 7 days. Rolling expiration extended automatically on user activity." }
                }

                div class="form-actions" style="margin-top: 24px;" {
                    button type="submit" class="btn btn-primary" { "Save System Settings" }
                }
            }
        }
    };

    render_layout(session, "settings", "Settings", content)
}
