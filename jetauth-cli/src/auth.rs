use crate::config::normalize_issuer;
use crate::credentials::{CredentialBackend, CredentialStore, Credentials};
use crate::error::{CliError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub const ADMIN_CLIENT_ID: &str = "lid-admin";

#[derive(Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub token_endpoint: String,
    pub device_authorization_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: u64,
    #[serde(default)]
    scope: String,
}

impl TokenResponse {
    fn into_credentials(self) -> Credentials {
        Credentials {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            id_token: self.id_token,
            expires_at: unix_now().saturating_add(self.expires_in),
            scope: self.scope,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

pub fn http_client() -> Result<Client> {
    Client::builder()
        .user_agent(concat!("jetauth-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(CliError::from)
}

pub async fn discover(http: &Client, issuer: &str) -> Result<Discovery> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let response = http.get(&url).send().await.map_err(|error| {
        CliError::Network(format!("cannot discover JetAuth at {issuer}: {error}"))
    })?;
    if !response.status().is_success() {
        return Err(CliError::Network(format!(
            "OIDC discovery at {url} returned {}",
            response.status()
        )));
    }
    let discovery: Discovery = response
        .json()
        .await
        .map_err(|error| CliError::Network(format!("invalid OIDC discovery response: {error}")))?;
    let discovered_issuer = normalize_issuer(&discovery.issuer)?;
    if discovered_issuer != issuer {
        return Err(CliError::Auth(format!(
            "OIDC issuer mismatch: configured '{issuer}', discovered '{discovered_issuer}'"
        )));
    }
    validate_endpoint(issuer, &discovery.token_endpoint)?;
    validate_endpoint(issuer, &discovery.device_authorization_endpoint)?;
    Ok(discovery)
}

fn validate_endpoint(issuer: &str, endpoint: &str) -> Result<()> {
    let issuer_url = Url::parse(issuer)
        .map_err(|error| CliError::Input(format!("invalid issuer URL: {error}")))?;
    let endpoint_url = Url::parse(endpoint)
        .map_err(|_| CliError::Auth("OIDC discovery returned an invalid endpoint".into()))?;
    let same_origin = issuer_url.scheme() == endpoint_url.scheme()
        && issuer_url.host_str() == endpoint_url.host_str()
        && issuer_url.port_or_known_default() == endpoint_url.port_or_known_default();
    if !same_origin {
        return Err(CliError::Auth(
            "OIDC discovery returned an endpoint on a different origin".into(),
        ));
    }
    Ok(())
}

pub async fn login(
    http: &Client,
    issuer: &str,
    store: &CredentialStore,
    no_browser: bool,
    no_refresh: bool,
) -> Result<(Credentials, CredentialBackend)> {
    let discovery = discover(http, issuer).await?;
    let scope = if no_refresh {
        "openid email profile"
    } else {
        "openid email profile offline_access"
    };
    let response = http
        .post(&discovery.device_authorization_endpoint)
        .form(&[("client_id", ADMIN_CLIENT_ID), ("scope", scope)])
        .send()
        .await?;
    let device: DeviceAuthorization = response
        .json()
        .await
        .map_err(|error| CliError::Auth(format!("cannot start device authorization: {error}")))?;
    let verification_url = device
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device.verification_uri);
    validate_endpoint(issuer, verification_url)?;

    eprintln!("To sign in, open:\n{verification_url}\n");
    eprintln!("Verification code: {}", device.user_code);
    if !no_browser && let Err(error) = crate::browser::open(verification_url) {
        eprintln!("warning: could not open the browser: {error}");
    }
    eprintln!("Waiting for approval…");

    let mut interval = device.interval.unwrap_or(5).max(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(device.expires_in);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(CliError::Auth(
                "device authorization expired; run `jetauth login` again".into(),
            ));
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let response = http
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", ADMIN_CLIENT_ID),
                ("device_code", &device.device_code),
            ])
            .send()
            .await?;
        if response.status().is_success() {
            let credentials = response
                .json::<TokenResponse>()
                .await
                .map_err(|error| CliError::Auth(format!("invalid token response: {error}")))?
                .into_credentials();
            let backend = store.save(&credentials)?;
            return Ok((credentials, backend));
        }
        let oauth_error = response.json::<OAuthError>().await.map_err(|error| {
            CliError::Auth(format!("invalid device authorization response: {error}"))
        })?;
        match oauth_error.error.as_str() {
            "authorization_pending" => {}
            "slow_down" => interval = interval.saturating_add(5),
            "access_denied" => {
                return Err(CliError::Auth("device authorization was denied".into()));
            }
            "expired_token" => {
                return Err(CliError::Auth(
                    "device authorization expired; run `jetauth login` again".into(),
                ));
            }
            _ => {
                return Err(CliError::Auth(oauth_message(
                    "device authorization failed",
                    oauth_error,
                )));
            }
        }
    }
}

pub async fn refresh(
    http: &Client,
    issuer: &str,
    credentials: &Credentials,
) -> Result<Credentials> {
    let refresh_token = credentials
        .refresh_token
        .as_deref()
        .ok_or_else(|| CliError::Auth("access token expired; run `jetauth login` again".into()))?;
    let discovery = discover(http, issuer).await?;
    let response = http
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", ADMIN_CLIENT_ID),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?;
    if !response.status().is_success() {
        let message = match response.json::<OAuthError>().await {
            Ok(error) => oauth_message("token refresh failed", error),
            Err(_) => "token refresh failed".into(),
        };
        return Err(CliError::Auth(format!(
            "{message}; run `jetauth login` again"
        )));
    }
    let refreshed = response
        .json::<TokenResponse>()
        .await
        .map_err(|error| CliError::Auth(format!("invalid refresh response: {error}")))?;
    let refresh_token = refreshed
        .refresh_token
        .clone()
        .or_else(|| credentials.refresh_token.clone());
    let mut credentials = refreshed.into_credentials();
    credentials.refresh_token = refresh_token;
    Ok(credentials)
}

fn oauth_message(context: &str, error: OAuthError) -> String {
    match error.error_description {
        Some(description) => format!("{context}: {}: {description}", error.error),
        None => format!("{context}: {}", error.error),
    }
}

pub fn claims(token: &str) -> Result<Value> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| CliError::Auth("stored token is not a JWT".into()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CliError::Auth("stored token has an invalid JWT payload".into()))?;
    serde_json::from_slice(&decoded)
        .map_err(|_| CliError::Auth("stored token has an invalid JWT claims document".into()))
}

pub fn identity(credentials: &Credentials) -> Value {
    let claims = credentials
        .id_token
        .as_deref()
        .and_then(|token| claims(token).ok())
        .or_else(|| claims(&credentials.access_token).ok())
        .unwrap_or_else(|| json!({}));
    json!({
        "email": claims.get("email"),
        "name": claims.get("name"),
        "role": claims.get("role"),
        "subject": claims.get("sub"),
    })
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn needs_refresh(credentials: &Credentials) -> bool {
    credentials.expires_at <= unix_now().saturating_add(60)
}

pub fn token_error_status(status: StatusCode) -> bool {
    status == StatusCode::UNAUTHORIZED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unverified_claims_for_display() {
        let token = format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(br#"{"email":"admin@example.com","role":"superadmin"}"#)
        );
        assert_eq!(claims(&token).unwrap()["role"], "superadmin");
    }
}
