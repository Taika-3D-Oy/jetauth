use crate::error::{CliError, Result};
use reqwest::{Client, Method, StatusCode};
use serde_json::Value;
use url::Url;

pub struct ApiResponse {
    pub status: StatusCode,
    pub value: Value,
}

pub fn endpoint(issuer: &str, path: &str) -> Result<Url> {
    if !path.starts_with("/api/") && path != "/api" {
        return Err(CliError::Input(
            "API path must start with /api/; absolute URLs are not allowed".into(),
        ));
    }
    if path.contains('#') || path.split('/').any(|part| part == "..") {
        return Err(CliError::Input("invalid API path".into()));
    }
    Url::parse(&format!("{issuer}{path}"))
        .map_err(|error| CliError::Input(format!("invalid API path: {error}")))
}

pub fn segment(value: &str) -> String {
    let mut url = Url::parse("http://localhost/").expect("static URL is valid");
    url.path_segments_mut()
        .expect("static URL accepts path segments")
        .push(value);
    url.path().trim_start_matches('/').to_string()
}

pub fn query_path(path: &str, parameters: &[(&str, String)]) -> Result<String> {
    let mut url = endpoint("http://localhost", path)?;
    if !parameters.is_empty() {
        url.query_pairs_mut().extend_pairs(parameters.iter());
    }
    Ok(format!(
        "{}{}",
        url.path(),
        url.query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    ))
}

pub async fn request(
    http: &Client,
    issuer: &str,
    token: &str,
    method: Method,
    path: &str,
    body: Option<&Value>,
    verbose: bool,
) -> Result<ApiResponse> {
    let url = endpoint(issuer, path)?;
    if verbose {
        eprintln!("> {method} {path}");
    }
    let mut builder = http
        .request(method, url)
        .bearer_auth(token)
        .header("accept", "application/json");
    if let Some(body) = body {
        builder = builder.json(body);
    }
    let response = builder.send().await?;
    let status = response.status();
    if verbose {
        eprintln!("< {status}");
    }
    let text = response.text().await?;
    let value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    if !status.is_success() {
        return Err(api_error(status, &value));
    }
    Ok(ApiResponse { status, value })
}

fn api_error(status: StatusCode, value: &Value) -> CliError {
    let detail = value
        .get("error_description")
        .or_else(|| value.get("message"))
        .or_else(|| value.get("error"))
        .and_then(|value| match value {
            Value::String(message) => Some(message.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
        .unwrap_or_else(|| value.to_string());
    let message = format!("Management API returned {status}: {detail}");
    match status {
        StatusCode::UNAUTHORIZED => CliError::Auth(message),
        StatusCode::FORBIDDEN => CliError::Permission(message),
        StatusCode::NOT_FOUND => CliError::NotFound(message),
        StatusCode::CONFLICT => CliError::Conflict(message),
        _ => CliError::Api(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_api_cannot_send_credentials_to_another_origin() {
        assert!(endpoint("https://auth.example.com", "https://evil.example.com").is_err());
        assert!(endpoint("https://auth.example.com", "/token").is_err());
    }

    #[test]
    fn identifiers_are_encoded_as_one_path_segment() {
        assert_eq!(segment("a/b?c"), "a%2Fb%3Fc");
    }
}
