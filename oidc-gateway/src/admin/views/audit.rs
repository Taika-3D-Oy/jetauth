use crate::admin::layout::{AdminSession, render_layout};
use crate::admin::views::{format_timestamp, relative_time};
use crate::store::{self, AuditEvent};
use http::Response;
use maud::{Markup, html};

pub async fn render_audit_page(
    session: &AdminSession,
    actor_id: Option<&str>,
    target_id: Option<&str>,
    event_type: Option<&str>,
) -> Response<String> {
    let events = store::list_audit_events(actor_id, target_id, event_type, None, None, 100)
        .await
        .unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Audit Log" }
                p class="page-subtitle" { "Immutable trail of system events, authentication requests, and administrative actions." }
            }
        }

        div class="audit-layout" {
            // ── Filter Panel ──
            div class="filter-panel" {
                h3 { "Filter Events" }
                form hx-get="/admin/audit/table"
                      hx-trigger="input changed delay:250ms"
                      hx-target="#audit-table-wrap" {
                    div class="form-group" {
                        label for="filter-event-type" { "Event Type" }
                        input type="text"
                               id="filter-event-type"
                               name="event_type"
                               placeholder="e.g. user.login"
                               value=(event_type.unwrap_or(""));
                    }
                    div class="form-group" {
                        label for="filter-actor" { "Actor ID" }
                        input type="text"
                               id="filter-actor"
                               name="actor_id"
                               placeholder="User or client ID"
                               value=(actor_id.unwrap_or(""));
                    }
                    div class="form-group" {
                        label for="filter-target" { "Target ID" }
                        input type="text"
                               id="filter-target"
                               name="target_id"
                               placeholder="Target entity ID"
                               value=(target_id.unwrap_or(""));
                    }
                }
            }

            // ── Events Table ──
            div class="card" id="audit-table-wrap" {
                (render_audit_table(&events))
            }
        }
    };

    render_layout(session, "audit", "Audit Log", content)
}

pub fn render_audit_table(events: &[AuditEvent]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Time" }
                        th { "Event Type" }
                        th { "Actor" }
                        th { "Target" }
                        th { "Details" }
                    }
                }
                tbody id="audit-table-body" {
                    @if events.is_empty() {
                        tr {
                            td colspan="5" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No audit events matching criteria."
                            }
                        }
                    } @else {
                        @for ev in events {
                            tr {
                                td class="mono-sm" title=(format_timestamp(ev.timestamp)) {
                                    (relative_time(ev.timestamp))
                                }
                                td {
                                    span class="badge badge-accent" { (ev.event_type) }
                                }
                                td class="mono-sm" { (ev.actor_id) }
                                td class="mono-sm" { (ev.target_id) }
                                td class="text-muted" style="font-size: 12px;" { (ev.details) }
                            }
                        }
                    }
                }
            }
        }
    }
}
