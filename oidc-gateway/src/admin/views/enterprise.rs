use maud::{Markup, html};

use crate::admin::layout::{AdminSession, render_layout};
use crate::store::{self, SamlServiceProvider, ScimConnection};

pub async fn render_saml_page(session: &AdminSession) -> http::Response<String> {
    let providers = store::list_saml_service_providers()
        .await
        .unwrap_or_default();
    let content = html! {
        div class="page-header" {
            div { h1 class="page-title" { "SAML Applications" }
                p class="page-subtitle" { "Downstream SAML 2.0 service providers. Enable the SAML protocol with saml_enabled=true." }
            }
            div class="page-actions" {
                form method="post" action="/admin/saml/rotate-key" {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    button class="btn" type="submit" { "Rotate signing key" }
                }
                a class="btn btn-primary" href="/admin/saml/new" { "+ Add application" }
            }
        }
        div class="card" {
            p { "IdP metadata: " code { "/saml/metadata" } " · SSO: " code { "/saml/sso" } }
            table {
                thead { tr { th { "Name" } th { "Entity ID" } th { "NameID" } th { "Status" } th { "Actions" } } }
                tbody {
                    @if providers.is_empty() { tr { td colspan="5" { "No SAML applications configured." } } }
                    @for sp in providers { (saml_row(session, &sp)) }
                }
            }
        }
    };
    render_layout(session, "saml", "SAML Applications", content)
}

fn saml_row(session: &AdminSession, sp: &SamlServiceProvider) -> Markup {
    html! {
        tr {
            td { (sp.name) }
            td class="mono" { (sp.entity_id) }
            td { (sp.name_id_format) }
            td { @if sp.enabled { span class="badge badge-success" { "Enabled" } } @else { span class="badge badge-muted" { "Disabled" } } }
            td class="actions" {
                a class="btn btn-xs" href={"/admin/saml/edit?id=" (sp.id)} { "Edit" }
                form method="post" action="/admin/saml/toggle" style="display:inline" {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    input type="hidden" name="id" value=(sp.id);
                    button class="btn btn-xs" type="submit" { @if sp.enabled { "Disable" } @else { "Enable" } }
                }
                form method="post" action="/admin/saml/delete" style="display:inline" {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    input type="hidden" name="id" value=(sp.id);
                    button class="btn btn-xs btn-danger" type="submit" { "Delete" }
                }
            }
        }
    }
}

pub fn render_saml_form(
    session: &AdminSession,
    sp: Option<&SamlServiceProvider>,
) -> http::Response<String> {
    let editing = sp.is_some();
    let (id, name, entity_id, acs, name_id, mappings, certificate) = if let Some(sp) = sp {
        (
            sp.id.clone(),
            sp.name.clone(),
            sp.entity_id.clone(),
            sp.acs_urls.join("\n"),
            sp.name_id_format.clone(),
            sp.attribute_mappings
                .iter()
                .map(|(name, source)| format!("{name}={source}"))
                .collect::<Vec<_>>()
                .join("\n"),
            sp.request_signing_certificate.clone().unwrap_or_default(),
        )
    } else {
        Default::default()
    };
    let content = html! {
        h1 class="page-title" { @if editing { "Edit SAML application" } @else { "Add SAML application" } }
        div class="card" {
            form method="post" action={@if editing { "/admin/saml/update" } @else { "/admin/saml" }} {
                input type="hidden" name="csrf_token" value=(session.csrf_token);
                input type="hidden" name="id" value=(id);
                div class="form-group" { label for="name" { "Display name" } input id="name" name="name" value=(name) required; }
                div class="form-group" { label for="entity_id" { "SP entity ID" } input id="entity_id" name="entity_id" value=(entity_id) required readonly[editing]; }
                div class="form-group" { label for="acs_urls" { "Assertion consumer service URLs (one per line)" } textarea id="acs_urls" name="acs_urls" rows="4" required { (acs) } }
                div class="form-group" { label for="name_id_format" { "NameID format" }
                    select id="name_id_format" name="name_id_format" {
                        option value="email" selected[name_id != "persistent"] { "Email address" }
                        option value="persistent" selected[name_id == "persistent"] { "Persistent user ID" }
                    }
                }
                div class="form-group" { label for="attribute_mappings" { "Attributes (Name=source, one per line)" }
                    textarea id="attribute_mappings" name="attribute_mappings" rows="4" placeholder="email=email\nname=name\nroles=roles" { (mappings) }
                    small { "Sources: email, name, user_id, tenant_id, role, roles" }
                }
                div class="form-group" { label for="request_signing_certificate" { "Optional AuthnRequest signing certificate (PEM)" }
                    textarea id="request_signing_certificate" name="request_signing_certificate" rows="5" { (certificate) }
                }
                button class="btn btn-primary" type="submit" { "Save" }
                a class="btn btn-ghost" href="/admin/saml" { "Cancel" }
            }
        }
    };
    render_layout(session, "saml", "SAML application", content)
}

pub async fn render_scim_page(session: &AdminSession) -> http::Response<String> {
    let connections = store::list_scim_connections().await.unwrap_or_default();
    let tenants = store::list_tenants().await.unwrap_or_default();
    let content = html! {
        div class="page-header" {
            div { h1 class="page-title" { "SCIM Provisioning" }
                p class="page-subtitle" { "Inbound SCIM 2.0 Users API. Enable it with scim_enabled=true. Tokens are shown only once." }
            }
            a class="btn btn-primary" href="/admin/scim/new" { "+ Add connection" }
        }
        div class="card" {
            p { "SCIM base URL: " code { "/scim/v2" } }
            table {
                thead { tr { th { "Name" } th { "Tenant" } th { "Default role" } th { "Status" } th { "Actions" } } }
                tbody {
                    @if connections.is_empty() { tr { td colspan="5" { "No SCIM connections configured." } } }
                    @for connection in connections { (scim_row(session, &connection)) }
                }
            }
        }
        @if !tenants.is_empty() { }
    };
    render_layout(session, "scim", "SCIM Provisioning", content)
}

fn scim_row(session: &AdminSession, connection: &ScimConnection) -> Markup {
    html! {
        tr {
            td { (connection.name) }
            td class="mono" { (connection.tenant_id) }
            td { (connection.default_role) }
            td { @if connection.enabled { span class="badge badge-success" { "Enabled" } } @else { span class="badge badge-muted" { "Disabled" } } }
            td class="actions" {
                form method="post" action="/admin/scim/toggle" style="display:inline" {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    input type="hidden" name="id" value=(connection.id);
                    button class="btn btn-xs" type="submit" { @if connection.enabled { "Disable" } @else { "Enable" } }
                }
                form method="post" action="/admin/scim/rotate-token" style="display:inline" {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    input type="hidden" name="id" value=(connection.id);
                    button class="btn btn-xs" type="submit" { "Rotate token" }
                }
                form method="post" action="/admin/scim/delete" style="display:inline" {
                    input type="hidden" name="csrf_token" value=(session.csrf_token);
                    input type="hidden" name="id" value=(connection.id);
                    button class="btn btn-xs btn-danger" type="submit" { "Delete" }
                }
            }
        }
    }
}

pub async fn render_scim_form(session: &AdminSession) -> http::Response<String> {
    let tenants = store::list_tenants().await.unwrap_or_default();
    let content = html! {
        h1 class="page-title" { "Add SCIM connection" }
        div class="card" {
            form method="post" action="/admin/scim" {
                input type="hidden" name="csrf_token" value=(session.csrf_token);
                div class="form-group" { label for="name" { "Display name" } input id="name" name="name" required; }
                div class="form-group" { label for="tenant_id" { "Tenant" }
                    select id="tenant_id" name="tenant_id" required {
                        @for tenant in tenants { option value=(tenant.id) { (tenant.display_name) " (" (tenant.id) ")" } }
                    }
                }
                div class="form-group" { label for="default_role" { "Default membership role" }
                    select id="default_role" name="default_role" {
                        option value="member" { "Member" }
                        option value="manager" { "Manager" }
                        option value="admin" { "Admin" }
                    }
                }
                button class="btn btn-primary" type="submit" { "Create connection" }
                a class="btn btn-ghost" href="/admin/scim" { "Cancel" }
            }
        }
    };
    render_layout(session, "scim", "Add SCIM connection", content)
}

pub fn render_scim_token(
    session: &AdminSession,
    connection: &ScimConnection,
    token: &str,
) -> http::Response<String> {
    let content = html! {
        h1 class="page-title" { "SCIM token created" }
        div class="card" {
            p { "Copy this token now. It will not be shown again for " (connection.name) "." }
            div class="form-group" { label for="token" { "Bearer token" } input id="token" readonly value=(token); }
            p { "Use it as " code { "Authorization: Bearer <token>" } " against " code { "/scim/v2" } "." }
            a class="btn btn-primary" href="/admin/scim" { "Done" }
        }
    };
    render_layout(session, "scim", "SCIM token", content)
}
