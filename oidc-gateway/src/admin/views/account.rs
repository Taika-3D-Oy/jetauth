use crate::admin::layout::{AdminSession, render_layout};
use crate::admin::views::format_timestamp;
use http::Response;
use maud::html;

pub async fn render_account_page(session: &AdminSession) -> Response<String> {
    let passkeys = &session.user.passkey_credentials;

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "My Account" }
                p class="page-subtitle" { "Manage your administrator profile, password, and hardware passkeys." }
            }
        }

        // ── Profile Information ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Profile Details" }
            }
            div class="detail-grid" {
                div class="label" { "Email" }
                div class="value mono" { (session.user.email) }

                div class="label" { "Name" }
                div class="value" { (session.user.name) }

                div class="label" { "Role" }
                div class="value" {
                    @if session.is_superadmin {
                        span class="badge badge-accent" { "Superadmin" }
                    } @else {
                        span class="badge badge-muted" { "Administrator" }
                    }
                }
            }
        }

        // ── Passkeys Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Hardware Passkeys / WebAuthn" }
                span class="card-spacer" {}
                button class="btn btn-sm btn-primary" onclick="registerAdminPasskey()" {
                    "+ Register Passkey"
                }
            }
            div class="table-wrap" {
                table {
                    thead {
                        tr {
                            th { "Key Name" }
                            th { "Credential ID" }
                            th { "Created" }
                            th class="actions" { "Actions" }
                        }
                    }
                    tbody {
                        @if passkeys.is_empty() {
                            tr {
                                td colspan="4" class="text-muted" style="text-align:center; padding: 20px;" {
                                "No passkeys registered yet. Add a FIDO2/TouchID passkey for passwordless sign-in."
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
                                    td class="actions" {
                                        button class="btn btn-xs btn-danger"
                                               hx-delete={"/admin/account/passkeys/" (p.credential_id)}
                                               hx-confirm="Remove this passkey?"
                                               hx-target={"#passkey-row-" (p.credential_id)}
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

        // ── WebAuthn Registration Script ──
        script {
            (maud::PreEscaped(format!(r#"
            async function registerAdminPasskey() {{
                const name = prompt("Enter a name for this passkey (e.g. YubiKey 5, MacBook TouchID):", "Admin Key");
                if (!name) return;
                try {{
                    const resp = await fetch("/admin/account/passkeys/register-options", {{
                        method: "POST",
                        headers: {{
                            "Content-Type": "application/json",
                            "x-csrf-token": "{csrf_token}"
                        }},
                        body: "{{}}"
                    }});
                    if (!resp.ok) {{
                        const errText = await resp.text();
                        let msg = errText;
                        try {{
                            const errObj = JSON.parse(errText);
                            msg = errObj.error_description || errObj.error || errText;
                        }} catch(_) {{}}
                        throw new Error(msg);
                    }}
                    const data = await resp.json();
                    
                    function base64UrlToBuffer(b64) {{
                        const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
                        const bytes = new Uint8Array(bin.length);
                        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
                        return bytes.buffer;
                    }}
                    function bufferToBase64Url(buf) {{
                        const bin = String.fromCharCode(...new Uint8Array(buf));
                        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
                    }}

                    const publicKey = {{
                        ...data.publicKey,
                        challenge: base64UrlToBuffer(data.publicKey.challenge),
                        user: {{
                            ...data.publicKey.user,
                            id: base64UrlToBuffer(data.publicKey.user.id)
                        }}
                    }};
                    if (publicKey.excludeCredentials) {{
                        publicKey.excludeCredentials = publicKey.excludeCredentials.map(c => ({{
                            ...c,
                            id: base64UrlToBuffer(c.id)
                        }}));
                    }}

                    const credential = await navigator.credentials.create({{ publicKey }});
                    const completeResp = await fetch("/admin/account/passkeys/register-complete", {{
                        method: "POST",
                        headers: {{
                            "Content-Type": "application/json",
                            "x-csrf-token": "{csrf_token}"
                        }},
                        body: JSON.stringify({{
                            token: data.token,
                            clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                            attestationObject: bufferToBase64Url(credential.response.attestationObject),
                            name: name
                        }})
                    }});
                    if (!completeResp.ok) {{
                        const errText = await completeResp.text();
                        let msg = errText;
                        try {{
                            const errObj = JSON.parse(errText);
                            msg = errObj.error_description || errObj.error || errText;
                        }} catch(_) {{}}
                        throw new Error(msg);
                    }}
                    window.location.reload();
                }} catch (e) {{
                    alert("Passkey registration failed: " + e.message);
                }}
            }}
            "#, csrf_token = session.csrf_token)))
        }
    };

    render_layout(session, "account", "My Account", content)
}
