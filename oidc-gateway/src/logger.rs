use http::{HeaderMap, Method};
use serde_json::{Map, Value, json};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Clone)]
struct RequestContext {
    trace_id: String,
    method: String,
    path: String,
    remote_ip: String,
    started_at: Instant,
}

fn request_context() -> &'static Mutex<Option<RequestContext>> {
    static REQUEST_CONTEXT: OnceLock<Mutex<Option<RequestContext>>> = OnceLock::new();
    REQUEST_CONTEXT.get_or_init(|| Mutex::new(None))
}

/// Client IP for logging/rate-limiting. Uses the LAST x-forwarded-for entry
/// (appended by the nearest trusted proxy); earlier entries are client-supplied
/// and trivially spoofable. Note: no `trust_xff` config gating — last-entry
/// behavior is applied unconditionally.
pub fn request_remote_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').map(str::trim).rfind(|p| !p.is_empty()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn begin_request(headers: &HeaderMap, method: &Method, path: &str, remote_ip: &str) -> String {
    // Never log query strings: they can carry tokens and other secrets.
    let path = path.split('?').next().unwrap_or(path);
    let trace_id = extract_trace_id(headers).unwrap_or_else(generate_trace_id);
    let ctx = RequestContext {
        trace_id: trace_id.clone(),
        method: method.to_string(),
        path: path.to_string(),
        remote_ip: remote_ip.to_string(),
        started_at: Instant::now(),
    };

    if let Ok(mut slot) = request_context().lock() {
        *slot = Some(ctx);
    }

    info(
        "http.request.started",
        json!({
            "method": method.to_string(),
            "path": path,
            "remote_ip": remote_ip,
        }),
    );

    trace_id
}

pub fn finish_request(status: u16) {
    let snapshot = request_context().lock().ok().and_then(|slot| slot.clone());
    let duration_ms = snapshot
        .as_ref()
        .map(|ctx| ctx.started_at.elapsed().as_millis() as u64)
        .unwrap_or(0);

    info(
        "http.request.completed",
        json!({
            "status": status,
            "duration_ms": duration_ms,
        }),
    );
}

pub fn clear_request() {
    if let Ok(mut slot) = request_context().lock() {
        *slot = None;
    }
}

#[allow(dead_code)]
pub fn current_trace_id() -> Option<String> {
    request_context()
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|ctx| ctx.trace_id.clone()))
}

pub fn info(event: &str, fields: Value) {
    log("info", event, fields);
}

pub fn warn(event: &str, fields: Value) {
    log("warn", event, fields);
}

pub fn error(event: &str, fields: Value) {
    log("error", event, fields);
}

pub fn error_message(event: &str, err: impl ToString) {
    error(event, json!({ "error": err.to_string() }));
}

fn log(level: &str, event: &str, fields: Value) {
    let snapshot = request_context().lock().ok().and_then(|slot| slot.clone());
    let mut entry = Map::new();
    entry.insert("timestamp".to_string(), json!(crate::store::unix_now()));
    entry.insert("level".to_string(), json!(level));
    entry.insert("service".to_string(), json!("oidc-gateway"));
    entry.insert("event".to_string(), json!(event));
    entry.insert(
        "trace_id".to_string(),
        snapshot
            .as_ref()
            .map(|ctx| Value::String(ctx.trace_id.clone()))
            .unwrap_or(Value::Null),
    );

    if let Some(ctx) = snapshot {
        entry.insert("http_method".to_string(), json!(ctx.method));
        entry.insert("http_path".to_string(), json!(ctx.path));
        entry.insert("remote_ip".to_string(), json!(ctx.remote_ip));
    }

    match fields {
        Value::Object(map) => {
            for (key, value) in map {
                entry.insert(key, value);
            }
        }
        Value::Null => {}
        other => {
            entry.insert("details".to_string(), other);
        }
    }

    eprintln!("{}", Value::Object(entry));
}

fn extract_trace_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_traceparent)
        .or_else(|| {
            headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .and_then(sanitize_request_id)
        })
}

fn parse_traceparent(value: &str) -> Option<String> {
    let mut parts = value.trim().split('-');
    let _version = parts.next()?;
    let trace_id = parts.next()?;
    let _parent_id = parts.next()?;
    let _flags = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if trace_id.chars().all(|c| c == '0') {
        return None;
    }
    Some(trace_id.to_ascii_lowercase())
}

fn sanitize_request_id(value: &str) -> Option<String> {
    let candidate = value.trim();
    if candidate.is_empty() || candidate.len() > 64 {
        return None;
    }
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return None;
    }
    Some(candidate.to_string())
}

fn generate_trace_id() -> String {
    crate::store::random_hex(16)
}

#[cfg(test)]
mod tests {
    use super::{parse_traceparent, sanitize_request_id};

    #[test]
    fn parses_valid_traceparent() {
        let trace_id = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        assert_eq!(
            trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }

    #[test]
    fn rejects_invalid_traceparent() {
        assert!(
            parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none()
        );
        assert!(parse_traceparent("bogus").is_none());
    }

    #[test]
    fn sanitizes_request_id() {
        assert_eq!(
            sanitize_request_id("req-123_abc"),
            Some("req-123_abc".to_string())
        );
        assert!(sanitize_request_id("bad value").is_none());
    }
}
