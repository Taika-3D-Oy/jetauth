use http::{Response, StatusCode};
use maud::{DOCTYPE, html};

pub fn render_bootstrap_page(error: Option<&str>) -> Response<String> {
    let markup = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Bootstrap — Lattice-ID Admin" }
                link rel="stylesheet" href="/admin/style.css";
                script src="/admin/htmx.min.js" {}
            }
            body class="center-screen" {
                div class="bootstrap-box" {
                    h1 { "Initialize Lattice ID" }
                    p { "Create the primary superadministrator account to set up your identity authority." }

                    @if let Some(err) = error {
                        div class="msg-error" { (err) }
                    }

                    form method="POST" action="/admin/bootstrap" {
                        div class="form-group" {
                            label for="name" { "Full Name" }
                            input type="text" id="name" name="name" required placeholder="Alice Admin";
                        }
                        div class="form-group" {
                            label for="email" { "Email Address" }
                            input type="email" id="email" name="email" required placeholder="admin@example.com";
                        }
                        div class="form-group" {
                            label for="org_name" { "Organization Name (optional)" }
                            input type="text" id="org_name" name="org_name" placeholder="Primary Organization";
                        }
                        div class="form-group" {
                            label for="password" { "Password" }
                            input type="password" id="password" name="password" required minlength="8" placeholder="••••••••••••";
                        }
                        div class="form-group" {
                            label for="confirm_password" { "Confirm Password" }
                            input type="password" id="confirm_password" name="confirm_password" required minlength="8" placeholder="••••••••••••";
                        }

                        div class="form-actions" style="margin-top: 24px;" {
                            button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center;" {
                                "Complete Setup"
                            }
                        }
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

pub fn render_bootstrap_pending_page(email: &str) -> Response<String> {
    let markup = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Verification Required — Lattice-ID Admin" }
                link rel="stylesheet" href="/admin/style.css";
            }
            body class="center-screen" {
                div class="bootstrap-box" {
                    h1 { "Check Your Inbox" }
                    p { "Bootstrap initialization is almost complete. A verification link has been sent to:" }
                    div class="msg-info" style="margin: 16px 0; font-weight: 600; text-align: center; word-break: break-all;" {
                        (email)
                    }
                    p {
                        "Please click the link in your email to verify your email address and activate your superadministrator account."
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
