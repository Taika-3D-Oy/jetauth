//! Outgoing HTTP client helpers built on standard WASI 0.2 HTTP outgoing-handler.

use crate::bindings::wasi::http::outgoing_handler;
use crate::bindings::wasi::http::types::{
    Fields, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
};

/// Send an HTTP request and return status code and response body bytes.
pub async fn send_request(request: http::Request<String>) -> Result<(u16, Vec<u8>), String> {
    let headers_vec: Vec<(String, Vec<u8>)> = request
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();

    let fields = Fields::from_list(&headers_vec).map_err(|e| format!("headers: {e:?}"))?;
    let outgoing = OutgoingRequest::new(fields);

    let method = match *request.method() {
        http::Method::GET => Method::Get,
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::DELETE => Method::Delete,
        http::Method::HEAD => Method::Head,
        _ => Method::Get,
    };
    let _ = outgoing.set_method(&method);

    if let Some(pq) = request.uri().path_and_query() {
        let _ = outgoing.set_path_with_query(Some(pq.as_str()));
    }
    if let Some(authority) = request.uri().authority() {
        let _ = outgoing.set_authority(Some(authority.as_str()));
    }
    if let Some(scheme) = request.uri().scheme_str() {
        let s = match scheme {
            "https" => Scheme::Https,
            _ => Scheme::Http,
        };
        let _ = outgoing.set_scheme(Some(&s));
    }

    let req_body = request.body();
    if !req_body.is_empty()
        && let Ok(out_body) = outgoing.body()
    {
        if let Ok(stream) = out_body.write() {
            let _ = stream.blocking_write_and_flush(req_body.as_bytes());
            drop(stream);
        }
        let _ = OutgoingBody::finish(out_body, None);
    }

    let opts = RequestOptions::new();
    let fut = outgoing_handler::handle(outgoing, Some(opts))
        .map_err(|e| format!("outgoing_handler: {e:?}"))?;
    let pollable = fut.subscribe();
    pollable.block();
    drop(pollable);

    let incoming = fut
        .get()
        .ok_or_else(|| "no response".to_string())?
        .map_err(|e| format!("http error: {e:?}"))?
        .map_err(|e| format!("response error: {e:?}"))?;

    let status = incoming.status();
    let mut body_bytes = Vec::new();
    if let Ok(inc_body) = incoming.consume()
        && let Ok(in_stream) = inc_body.stream()
    {
        loop {
            match in_stream.blocking_read(65536) {
                Ok(chunk) if !chunk.is_empty() => body_bytes.extend_from_slice(&chunk),
                _ => break,
            }
        }
    }
    Ok((status, body_bytes))
}

/// Send an HTTP GET request and return the response body as bytes.
pub async fn get_bytes(url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), String> {
    let mut builder = http::Request::builder().method(http::Method::GET).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder
        .body(String::new())
        .map_err(|e| format!("build request: {e}"))?;
    send_request(request).await
}

/// Send an HTTP GET request and return parsed JSON.
pub async fn get_json(url: &str, headers: &[(&str, &str)]) -> Result<serde_json::Value, String> {
    let mut all_headers = vec![("accept", "application/json")];
    all_headers.extend_from_slice(headers);
    let (status, body) = get_bytes(url, &all_headers).await?;
    if !(200..300).contains(&status) {
        return Err(format!("http {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| format!("parse JSON: {e}"))
}

/// Send an HTTP POST request with JSON body and return status + raw bytes.
pub async fn post_json(
    url: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let request = builder
        .body(body.to_string())
        .map_err(|e| format!("build request: {e}"))?;
    send_request(request).await
}

/// Send an HTTP POST request with form body and return parsed JSON.
pub async fn post_form_json(url: &str, body: &str) -> Result<(u16, serde_json::Value), String> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body.to_string())
        .map_err(|e| format!("build request: {e}"))?;

    let (status, bytes) = send_request(request).await?;
    let json = serde_json::from_slice(&bytes).map_err(|e| format!("parse response: {e}"))?;
    Ok((status, json))
}
