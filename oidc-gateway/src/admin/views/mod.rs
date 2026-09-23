pub mod account;
pub mod audit;
pub mod bootstrap;
pub mod clients;
pub mod dashboard;
pub mod hooks;
pub mod idps;
pub mod login;
pub mod settings;
pub mod tenants;
pub mod users;

use maud::{Markup, html};

pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "—".into();
    }
    let total_secs = ts;
    let days = total_secs / 86400;
    let years = 1970 + days / 365;
    let remaining = days % 365;
    let months = remaining / 30 + 1;
    let day = remaining % 30 + 1;
    let time_secs = total_secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    format!("{years}-{months:02}-{day:02} {hours:02}:{minutes:02}")
}

pub fn relative_time(ts: u64) -> String {
    if ts == 0 {
        return "—".into();
    }
    let now = crate::store::unix_now();
    let diff = now.saturating_sub(ts);
    if diff < 60 {
        "just now".into()
    } else if diff < 3_600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86_400 {
        format!("{}h ago", diff / 3_600)
    } else if diff < 2_592_000 {
        format!("{}d ago", diff / 86_400)
    } else {
        format_timestamp(ts)
    }
}

pub fn render_status_badge(status: &str) -> Markup {
    let (cls, label) = match status {
        "active" => ("badge badge-success", "Active"),
        "pending" => ("badge badge-warning", "Pending"),
        "locked" | "suspended" | "disabled" => ("badge badge-danger", status),
        _ => ("badge badge-muted", status),
    };
    html! {
        span class=(cls) { (label) }
    }
}
