use http::{Response, StatusCode};
use maud::{DOCTYPE, html};

pub fn render_login_page(error: Option<&str>, return_to: &str) -> Response<String> {
    let return_target = if return_to.is_empty() {
        "/admin"
    } else {
        return_to
    };
    let markup = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Sign In — Lattice-ID Admin" }
                link rel="stylesheet" href="/admin/style.css";
                script src="/admin/htmx.min.js" {}
            }
            body class="center-screen" {
                div class="bootstrap-box" {
                    div style="text-align: center; margin-bottom: 24px;" {
                        h1 style="font-size: 24px; font-weight: 700; margin-bottom: 6px;" { "⬡ Lattice ID" }
                        p style="color: var(--color-muted); font-size: 14px;" { "Sign in to access the Administration Console" }
                    }

                    @if let Some(err) = error {
                        div class="msg-error" style="margin-bottom: 16px;" { (err) }
                    }

                    form method="POST" action="/admin/login" {
                        input type="hidden" name="return_to" value=(return_target);

                        div class="form-group" {
                            label for="email" { "Email Address" }
                            input type="email" id="email" name="email" required autofocus placeholder="admin@example.com";
                        }
                        div class="form-group" {
                            label for="password" { "Password" }
                            input type="password" id="password" name="password" required placeholder="••••••••••••";
                        }

                        div class="form-actions" style="margin-top: 24px;" {
                            button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center;" {
                                "Sign In"
                            }
                        }
                    }

                    div style="text-align: center; margin-top: 24px; font-size: 13px; color: var(--color-muted);" {
                        a href="/" style="color: var(--color-muted); text-decoration: none;" { "← Back to Home" }
                    }
                }
            }
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(markup.into_string())
        .unwrap()
}

pub fn render_mfa_prompt(
    email: &str,
    mfa_token: &str,
    return_to: &str,
    error: Option<&str>,
) -> Response<String> {
    let return_target = if return_to.is_empty() {
        "/admin"
    } else {
        return_to
    };
    let markup = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Two-Factor Authentication — Lattice-ID Admin" }
                link rel="stylesheet" href="/admin/style.css";
                script src="/admin/htmx.min.js" {}
            }
            body class="center-screen" {
                div class="bootstrap-box" {
                    div style="text-align: center; margin-bottom: 24px;" {
                        h1 style="font-size: 24px; font-weight: 700; margin-bottom: 6px;" { "Two-Factor Authentication" }
                        p style="color: var(--color-muted); font-size: 14px;" { "Enter the 6-digit code or recovery code for " (email) }
                    }

                    @if let Some(err) = error {
                        div class="msg-error" style="margin-bottom: 16px;" { (err) }
                    }

                    form method="POST" action="/admin/login/mfa" {
                        input type="hidden" name="mfa_token" value=(mfa_token);
                        input type="hidden" name="return_to" value=(return_target);

                        div class="form-group" {
                            label for="code" { "Authentication Code" }
                            input type="text" id="code" name="code" required autofocus autocomplete="one-time-code" placeholder="123456" style="text-align: center; font-size: 20px; letter-spacing: 4px; font-family: monospace;";
                        }

                        div class="form-actions" style="margin-top: 24px;" {
                            button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center;" {
                                "Verify & Continue"
                            }
                        }
                    }

                    div style="text-align: center; margin-top: 24px; font-size: 13px; color: var(--color-muted);" {
                        a href="/admin/login" style="color: var(--color-muted); text-decoration: none;" { "← Cancel and Sign In Again" }
                    }
                }
            }
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(markup.into_string())
        .unwrap()
}
