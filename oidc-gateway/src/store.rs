use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Cached config values (initialized once per request via init_config)
thread_local! {
    static CONFIG_CACHE: RefCell<Option<OidcConfigCache>> = const { RefCell::new(None) };
}

// ── Session consistency tracking (lattice-db 1.6.0) ─────────────────────────
// Tracks per-table revision watermarks within a single request lifetime.
// Reads inject `consistency.min_revision`; write responses update the map
// from `session.revisions`.
//
// The data epoch prevents stale cookies from causing errors after a NATS data
// wipe/restore. If the cookie's epoch doesn't match the server's epoch, the
// seeded revisions are discarded on the first response.
thread_local! {
    static SESSION_REVISIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
    /// Epoch from the inbound cookie/header (may be stale).
    static INBOUND_EPOCH: RefCell<Option<String>> = const { RefCell::new(None) };
    /// Epoch from the latest lattice-db response (authoritative).
    static SERVER_EPOCH: RefCell<Option<String>> = const { RefCell::new(None) };
    /// Set to true once we've validated inbound epoch against server epoch.
    static EPOCH_VALIDATED: RefCell<bool> = const { RefCell::new(false) };
}

/// Seed session revisions from an external source (e.g. inbound consistency cookie/header).
pub fn seed_session_revisions(revisions: HashMap<String, u64>, epoch: Option<String>) {
    INBOUND_EPOCH.with(|ie| {
        *ie.borrow_mut() = epoch;
    });
    SESSION_REVISIONS.with(|sr| {
        let mut map = sr.borrow_mut();
        for (table, rev) in revisions {
            let entry = map.entry(table).or_insert(0);
            if rev > *entry {
                *entry = rev;
            }
        }
    });
}

/// Called after receiving a response with a server epoch. If the inbound epoch
/// doesn't match, clear all seeded revisions (they're from a different dataset).
fn validate_epoch(server_epoch: &str) {
    SERVER_EPOCH.with(|se| {
        *se.borrow_mut() = Some(server_epoch.to_string());
    });
    let already_validated = EPOCH_VALIDATED.with(|ev| *ev.borrow());
    if already_validated {
        return;
    }
    EPOCH_VALIDATED.with(|ev| *ev.borrow_mut() = true);

    let inbound = INBOUND_EPOCH.with(|ie| ie.borrow().clone());
    if let Some(inbound_epoch) = inbound {
        if inbound_epoch != server_epoch {
            // Epoch mismatch — data was wiped/restored. Discard stale revisions.
            SESSION_REVISIONS.with(|sr| sr.borrow_mut().clear());
        }
    }
}

/// Export current session revisions so the gateway can propagate them to the caller.
pub fn get_session_revisions() -> HashMap<String, u64> {
    SESSION_REVISIONS.with(|sr| sr.borrow().clone())
}

/// Export the current data epoch (from latest lattice-db response).
pub fn get_session_epoch() -> Option<String> {
    SERVER_EPOCH.with(|se| se.borrow().clone())
}

struct OidcConfigCache {
    ldb_instance: String,
    lockout_threshold: Option<String>,
    lockout_duration_secs: Option<String>,
    keys_bucket: Option<String>,
    tenant_bucket: Option<String>,
    region_id: Option<String>,
    internal_auth_secret: Option<String>,
    region_domains: Option<String>,
    region_internal_urls: Option<String>,
    issuer_url: Option<String>,
    dev_mode: Option<String>,
    require_email_verification: Option<String>,
    allow_registration: Option<String>,
    bootstrap_hook: Option<String>,
    refresh_absolute_max_secs: Option<String>,
    email_pepper: Option<String>,
    client_secret_pepper: Option<String>,
    client_registration_mode: Option<String>,
    client_registration_token: Option<String>,
}

/// Must be called once at startup / per request to load config values.
pub async fn init_config() {
    let ldb_instance = config_value_async("ldb_instance")
        .await
        .unwrap_or_else(|| "lid".to_string());
    let lockout_threshold = config_value_async("lockout_threshold").await;
    let lockout_duration_secs = config_value_async("lockout_duration_secs").await;
    let keys_bucket = config_value_async("keys_bucket").await;
    let tenant_bucket = config_value_async("tenant_bucket").await;
    let region_id = config_value_async("region_id").await;
    let internal_auth_secret = config_value_async("internal_auth_secret").await;
    let region_domains = config_value_async("region_domains").await;
    let region_internal_urls = config_value_async("region_internal_urls").await;
    let issuer_url = config_value_async("issuer_url").await;
    let dev_mode = config_value_async("dev_mode").await;
    let require_email_verification = config_value_async("require_email_verification").await;
    let allow_registration = config_value_async("allow_registration").await;
    let bootstrap_hook = config_value_async("bootstrap_hook").await;
    let refresh_absolute_max_secs = config_value_async("refresh_absolute_max_secs").await;
    let email_pepper = config_value_async("email_pepper").await;
    let client_secret_pepper = config_value_async("client_secret_pepper").await;
    let client_registration_mode = config_value_async("client_registration_mode").await;
    let client_registration_token = config_value_async("client_registration_token").await;

    CONFIG_CACHE.with(|c| {
        *c.borrow_mut() = Some(OidcConfigCache {
            ldb_instance,
            lockout_threshold,
            lockout_duration_secs,
            keys_bucket,
            tenant_bucket,
            region_id,
            internal_auth_secret,
            region_domains,
            region_internal_urls,
            issuer_url,
            dev_mode,
            require_email_verification,
            allow_registration,
            bootstrap_hook,
            refresh_absolute_max_secs,
            email_pepper,
            client_secret_pepper,
            client_registration_mode,
            client_registration_token,
        });
    });
}

#[cfg(test)]
pub fn init_config_for_test(dev_mode: bool, client_secret_pepper: Option<&str>) {
    CONFIG_CACHE.with(|c| {
        *c.borrow_mut() = Some(OidcConfigCache {
            ldb_instance: "lid".to_string(),
            lockout_threshold: None,
            lockout_duration_secs: None,
            keys_bucket: None,
            tenant_bucket: None,
            region_id: None,
            internal_auth_secret: None,
            region_domains: None,
            region_internal_urls: None,
            issuer_url: None,
            dev_mode: if dev_mode {
                Some("true".to_string())
            } else {
                None
            },
            require_email_verification: None,
            allow_registration: None,
            bootstrap_hook: None,
            refresh_absolute_max_secs: None,
            email_pepper: None,
            client_secret_pepper: client_secret_pepper.map(|s| s.to_string()),
            client_registration_mode: None,
            client_registration_token: None,
        });
    });
}

#[cfg(test)]
pub fn init_registration_config_for_test(mode: &str, token: Option<&str>) {
    CONFIG_CACHE.with(|c| {
        *c.borrow_mut() = Some(OidcConfigCache {
            ldb_instance: "lid".to_string(),
            lockout_threshold: None,
            lockout_duration_secs: None,
            keys_bucket: None,
            tenant_bucket: None,
            region_id: None,
            internal_auth_secret: None,
            region_domains: None,
            region_internal_urls: None,
            issuer_url: None,
            dev_mode: None,
            require_email_verification: None,
            allow_registration: None,
            bootstrap_hook: None,
            refresh_absolute_max_secs: None,
            email_pepper: None,
            client_secret_pepper: Some("test_pepper_123456789012345678901234567890".to_string()),
            client_registration_mode: Some(mode.to_string()),
            client_registration_token: token.map(|s| s.to_string()),
        });
    });
}

fn with_config<T>(f: impl FnOnce(&OidcConfigCache) -> T) -> Option<T> {
    CONFIG_CACHE.with(|c| {
        let borrow = c.borrow();
        borrow.as_ref().map(f)
    })
}

async fn config_value_async(key: &str) -> Option<String> {
    crate::bindings::wasi::config::store::get(key)
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn config_value(key: &str) -> Option<String> {
    with_config(|c| match key {
        "ldb_instance" => Some(c.ldb_instance.clone()),
        "lockout_threshold" => c.lockout_threshold.clone(),
        "lockout_duration_secs" => c.lockout_duration_secs.clone(),
        "keys_bucket" => c.keys_bucket.clone(),
        "tenant_bucket" => c.tenant_bucket.clone(),
        "region_id" => c.region_id.clone(),
        "internal_auth_secret" => c.internal_auth_secret.clone(),
        "region_domains" => c.region_domains.clone(),
        "region_internal_urls" => c.region_internal_urls.clone(),
        "issuer_url" => c.issuer_url.clone(),
        "dev_mode" => c.dev_mode.clone(),
        "require_email_verification" => c.require_email_verification.clone(),
        "allow_registration" => c.allow_registration.clone(),
        "bootstrap_hook" => c.bootstrap_hook.clone(),
        "refresh_absolute_max_secs" => c.refresh_absolute_max_secs.clone(),
        "email_pepper" => c.email_pepper.clone(),
        "client_secret_pepper" => c.client_secret_pepper.clone(),
        "client_registration_mode" => c.client_registration_mode.clone(),
        "client_registration_token" => c.client_registration_token.clone(),
        _ => None,
    })
    .flatten()
}

/// Dynamic client registration mode: "disabled" (default), "open", or "protected".
pub fn client_registration_mode() -> String {
    config_value("client_registration_mode")
        .unwrap_or_else(|| "disabled".to_string())
        .to_lowercase()
}

/// Optional Bearer token required for RFC 7591 dynamic client registration when mode is "protected".
pub fn client_registration_token() -> Option<String> {
    config_value("client_registration_token").filter(|s| !s.trim().is_empty())
}

/// Maximum absolute lifetime of a refresh token family (regardless of rotation).
/// Default: 90 days. Configurable via `refresh_absolute_max_secs`.
pub fn refresh_absolute_max_secs() -> u64 {
    config_value("refresh_absolute_max_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(86400 * 90) // 90 days
}

// Task 2.7: Configurable account lockout policy
fn max_login_failures() -> u32 {
    config_value("lockout_threshold")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

fn lockout_duration() -> u64 {
    config_value("lockout_duration_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(900) // 15 minutes
}

// ── Data types ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub status: String,
    pub created_at: u64,
    #[serde(default)]
    pub superadmin: bool,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub recovery_codes: Vec<String>,
    #[serde(default)]
    pub passkey_credentials: Vec<PasskeyCredential>,
}

/// A stored WebAuthn/passkey credential (ES256 / P-256).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasskeyCredential {
    /// Base64url-encoded credential ID.
    pub credential_id: String,
    /// Base64url-encoded COSE public key (uncompressed P-256).
    pub public_key: String,
    /// Signature counter for clone detection.
    pub sign_count: u32,
    /// Human-readable label (e.g. "MacBook Touch ID").
    pub name: String,
    /// Unix timestamp of registration.
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AuthSession {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub scope: String,
    pub nonce: String,
    #[serde(default)]
    pub max_age: Option<u64>,
    #[serde(default)]
    pub acr_values: Vec<String>,
    #[serde(default)]
    pub requested_id_token_claims: Vec<String>,
    #[serde(default)]
    pub requested_userinfo_claims: Vec<String>,
    #[serde(default)]
    pub hinted_user_id: Option<String>,
    #[serde(default)]
    pub hinted_email: Option<String>,
    pub created_at: u64,
    /// Whether a consent screen must be shown before the auth code is issued.
    #[serde(default)]
    pub needs_consent: bool,
    /// The prompt parameter from authorize request (e.g., "consent", "login", "none").
    #[serde(default)]
    pub prompt: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct UserConsent {
    pub user_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub granted_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AuthCode {
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub auth_time: u64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub requested_id_token_claims: Vec<String>,
    #[serde(default)]
    pub requested_userinfo_claims: Vec<String>,
    /// Custom claims injected by Rhai hooks (key-value pairs).
    #[serde(default)]
    pub extra_claims: Vec<(String, String)>,
    pub expires_at: u64,
    /// CSRF token for the consent form (defense in depth).
    #[serde(default)]
    pub csrf_token: String,
    /// OAuth2 state param, carried through consent flow.
    #[serde(default)]
    pub state: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RefreshEntry {
    pub user_id: String,
    pub client_id: String,
    pub expires_at: u64,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub auth_time: u64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub requested_id_token_claims: Vec<String>,
    #[serde(default)]
    pub requested_userinfo_claims: Vec<String>,
    /// Unix timestamp when this refresh token family was originally issued.
    /// Carried forward on every rotation to enforce an absolute lifetime cap.
    #[serde(default)]
    pub issued_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OidcClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub name: String,
    #[serde(default)]
    pub theme: Option<ClientTheme>,
    /// OIDC Back-Channel Logout URI (RFC 8613).
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// If true, the `sid` claim will be included in the logout token.
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// JWS algorithm used to sign id_tokens for this client. "RS256" (default) or "ES256".
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    /// First-party clients skip the consent screen. Defaults to false.
    /// The built-in `lid-admin` and `lid-default` clients are implicitly first-party.
    #[serde(default)]
    pub first_party: bool,
    /// RFC 7591 / RFC 7523: Client authentication method (e.g. "client_secret_basic", "client_secret_post", "private_key_jwt", "none")
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// RFC 7523: Client public keys (JWKS) for private_key_jwt authentication
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// RFC 9126: Whether this client requires pushed authorization requests
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
}

impl Default for OidcClient {
    fn default() -> Self {
        OidcClient {
            client_id: String::new(),
            client_secret: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            grant_types: Vec::new(),
            name: "Unknown".to_string(),
            theme: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            id_token_signed_response_alg: None,
            first_party: false,
            token_endpoint_auth_method: None,
            jwks: None,
            require_pushed_authorization_requests: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTheme {
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub logo_height: Option<String>,
    #[serde(default)]
    pub favicon_url: Option<String>,
    #[serde(default)]
    pub theme_preset: Option<String>,
    #[serde(default)]
    pub primary_color: Option<String>,
    #[serde(default)]
    pub primary_hover_color: Option<String>,
    #[serde(default)]
    pub background_color: Option<String>,
    #[serde(default)]
    pub background_image_url: Option<String>,
    #[serde(default)]
    pub card_background: Option<String>,
    #[serde(default)]
    pub card_border: Option<String>,
    #[serde(default)]
    pub card_shadow: Option<String>,
    #[serde(default)]
    pub card_backdrop_blur: Option<String>,
    #[serde(default)]
    pub text_color: Option<String>,
    #[serde(default)]
    pub text_muted_color: Option<String>,
    #[serde(default)]
    pub input_background: Option<String>,
    #[serde(default)]
    pub input_border_color: Option<String>,
    #[serde(default)]
    pub input_text_color: Option<String>,
    #[serde(default)]
    pub button_text_color: Option<String>,
    #[serde(default)]
    pub border_radius: Option<String>,
    #[serde(default)]
    pub font_family: Option<String>,
    #[serde(default)]
    pub font_url: Option<String>,
    #[serde(default)]
    pub footer_text: Option<String>,
    #[serde(default)]
    pub powered_by_text: Option<String>,
    #[serde(default)]
    pub hide_powered_by: bool,
    #[serde(default)]
    pub terms_url: Option<String>,
    #[serde(default)]
    pub privacy_url: Option<String>,
    #[serde(default)]
    pub help_url: Option<String>,
    #[serde(default)]
    pub custom_css: Option<String>,
}

/// External identity provider configuration (Google, GitHub, any OIDC provider).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityProvider {
    pub id: String,
    pub provider_type: String, // "google", "generic-oidc", etc.
    pub client_id: String,
    pub client_secret: String,
    pub enabled: bool,
    /// OIDC discovery URL (e.g. https://example.com/.well-known/openid-configuration).
    /// Required for generic OIDC providers; optional for Google (uses hardcoded defaults).
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Human-readable display name shown on the login button.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Links an external social identity to a Lattice-ID user.
#[derive(Serialize, Deserialize)]
pub struct SocialIdentity {
    pub provider: String,
    pub provider_sub: String,
    pub user_id: String,
    pub email: String,
    pub linked_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Membership {
    pub tenant_id: String,
    pub user_id: String,
    pub role: String, // "owner", "admin", "manager", "member"
    pub joined_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Invitation {
    pub tenant_id: String,
    pub email: String,
    pub role: String,
    pub token: String,
    pub invited_by: String,
    pub expires_at: u64,
}

/// RFC 8628 Device Authorization Grant — device code record.
#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceCode {
    /// Opaque device verification code given to the device.
    pub device_code: String,
    /// Short user-facing code the user types at the verification URI.
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: u64,
    /// "pending" | "approved" | "denied"
    pub status: String,
    /// Set when status = "approved".
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginAttempts {
    pub failures: u32,
    pub locked_until: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEvent {
    pub event_type: String,
    pub actor_id: String,
    pub target_id: String,
    pub details: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub value: T,
    pub expires_at: u64,
}

/// A Rhai scripting hook — Auth0-style "Action" that runs at lifecycle points.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Hook {
    pub id: String,
    pub name: String,
    /// "post-login" or "post-registration"
    pub trigger: String,
    /// Rhai source code
    pub script: String,
    pub enabled: bool,
    /// Execution order (lower runs first)
    pub priority: i32,
    pub created_at: u64,
    /// Monotonically incrementing version (1 = initial, +1 per update)
    #[serde(default = "default_version")]
    pub version: u32,
    /// SHA-256 hex digest of the script content
    #[serde(default)]
    pub script_hash: String,
    /// Who last modified this hook (actor user_id)
    #[serde(default)]
    pub updated_by: String,
    /// Timestamp of last modification
    #[serde(default)]
    pub updated_at: u64,
}

fn default_version() -> u32 {
    1
}

/// Immutable snapshot of a hook version, stored for audit trail.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HookVersion {
    pub hook_id: String,
    pub version: u32,
    pub name: String,
    pub trigger: String,
    pub script: String,
    pub script_hash: String,
    pub enabled: bool,
    pub priority: i32,
    pub changed_by: String,
    pub changed_at: u64,
}

/// Compute SHA-256 hex digest of a string.
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Helpers ─────────────────────────────────────────────────

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_alphanumeric(n: usize) -> String {
    let charset = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let limit = 256 - (256 % charset.len()); // = 252; reject >= 252 to avoid modulo bias
    let mut result = String::with_capacity(n);
    let mut buf = [0u8; 1];
    while result.len() < n {
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        let b = buf[0] as usize;
        if b < limit {
            result.push(charset[b % charset.len()] as char);
        }
    }
    result
}

// Component instances are fresh per request — config loaded once via init_config.
/// Check if an email hash exists in this region's user-idx store.
pub async fn email_hash_exists(email_hash: &str) -> Result<bool, String> {
    let key = format!("email:{}", email_hash);
    kv_exists(&store_name("user-idx"), &key).await
}

/// HMAC-SHA256 of the lowercased email using the configured pepper.
///
/// This is the canonical form used as the KV index key (`email:{hash}`)
/// and in cross-region lookups. Without the pepper an attacker with NATS
/// read access cannot enumerate or rainbow-table user emails.
///
/// The pepper must be set via the `email_pepper` config key (32+ random
/// bytes, base64 or hex). In dev mode with no pepper configured the raw
/// lowercased email is used so existing local setups keep working.
/// In production (`dev_mode` absent or false) a missing pepper panics at
/// the first call so the misconfiguration is caught immediately.
pub fn hmac_email(email: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let email_lower = email.to_lowercase();
    match config_value("email_pepper") {
        Some(pepper) if !pepper.is_empty() => {
            let mut mac = Hmac::<Sha256>::new_from_slice(pepper.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(email_lower.as_bytes());
            let result = mac.finalize();
            result
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
        _ => {
            let is_dev = config_value("dev_mode")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            if is_dev {
                crate::logger::warn(
                    "email_pepper.not_configured",
                    serde_json::json!({ "msg": "email_pepper not set; email index is not HMAC-protected (dev mode only)" }),
                );
                email_lower
            } else {
                panic!(
                    "email_pepper config key is required in production. \
                     Set email_pepper to a 32+ byte random value, or enable dev_mode=true for local development."
                );
            }
        }
    }
}

/// Hash a client secret with HMAC-SHA256 using the configured pepper.
/// High-entropy secrets (32+ random hex chars) do not need key-stretching —
/// HMAC-SHA256 is sufficient and much faster than Argon2 for this use case.
/// Returns the hex-encoded MAC, or the raw secret in dev mode if no pepper
/// is configured (with a logged warning).
pub fn hmac_client_secret(secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    match config_value("client_secret_pepper") {
        Some(pepper) if !pepper.is_empty() => {
            let mut mac = Hmac::<Sha256>::new_from_slice(pepper.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(secret.as_bytes());
            let result = mac.finalize();
            result
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }
        _ => {
            let is_dev = config_value("dev_mode")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            if is_dev {
                crate::logger::warn(
                    "client_secret_pepper.not_configured",
                    serde_json::json!({ "msg": "client_secret_pepper not set; client secrets stored without HMAC (dev mode only)" }),
                );
                secret.to_string()
            } else {
                panic!(
                    "client_secret_pepper config key is required in production. \
                     Set client_secret_pepper to a 32+ byte random value, or enable dev_mode=true for local development."
                );
            }
        }
    }
}

/// Shared secret for authenticating cross-region `/internal/*` HTTP requests.
pub fn internal_auth_secret() -> Option<String> {
    config_value("internal_auth_secret")
}

/// This instance's region identifier (e.g., "us", "eu"). Empty = single-region.
pub fn region_id() -> Option<String> {
    config_value("region_id")
}

/// Get the base URL for a remote region.
pub fn region_domain(region: &str) -> Option<String> {
    let json_str = config_value("region_domains")?;
    let map: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    map.get(region)?
        .as_str()
        .map(|s| s.trim_end_matches('/').to_string())
}

/// Get internal URLs for all regions.
pub fn region_internal_urls() -> Vec<(String, String)> {
    let json_str = match config_value("region_internal_urls") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&json_str).unwrap_or_default();
    map.into_iter().collect()
}

fn store_name(suffix: &str) -> String {
    suffix.to_string()
}

fn users_store() -> String {
    store_name("users")
}
fn user_idx_store() -> String {
    store_name("user-idx")
}
fn sessions_store() -> String {
    store_name("sessions")
}
fn clients_store() -> String {
    config_value("client_bucket").unwrap_or_else(|| store_name("clients"))
}
pub fn clients_store_name() -> String {
    clients_store()
}
fn tenants_store() -> String {
    config_value("tenant_bucket").unwrap_or_else(|| store_name("tenants"))
}
pub fn tenants_store_name() -> String {
    tenants_store()
}
fn memberships_store() -> String {
    store_name("memberships")
}
fn audit_store() -> String {
    store_name("audit")
}

// ── TTL constants (seconds) ─────────────────────────────────

const TTL_AUTH_CODE: u64 = 300; // 5 min
const TTL_AUTH_SESSION: u64 = 600; // 10 min
const TTL_REFRESH_TOKEN: u64 = 86400 * 30; // 30 days
const TTL_CONSUMED_MARKER: u64 = 86400 * 30; // 30 days
const TTL_REVOCATION_MARKER: u64 = 86400 * 30; // 30 days
const TTL_MFA_PENDING: u64 = 300; // 5 min
const TTL_ACCOUNT_SESSION: u64 = 1800; // 30 min
pub const DEFAULT_IDP_SESSION_TTL: u64 = 86400 * 7; // 7 days (604,800s)
const TTL_IDP_SESSION: u64 = DEFAULT_IDP_SESSION_TTL;
const TTL_PASSKEY_CHALLENGE: u64 = 300; // 5 min
const TTL_LOCKOUT: u64 = 3600; // 1 hour (generous buffer over default 15 min lock)
const TTL_INVITATION: u64 = 86400 * 7; // 7 days
const TTL_AUDIT: u64 = 86400 * 90; // 90 days
pub const TTL_PAR_REQUEST: u64 = 90; // 90 seconds (RFC 9126 §2.2)
pub const TTL_JTI: u64 = 300; // 5 min (replay prevention window)

// ── lattice-db via localhost TCP (co-located service) ──

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

const LDB_TCP_PORT: u16 = 4080;

#[cfg(test)]
static TEST_KV: std::sync::Mutex<Option<std::collections::HashMap<String, (String, u64)>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn handle_test_ldb_request(
    op: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut guard = TEST_KV.lock().unwrap();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let table = payload.get("table").and_then(|v| v.as_str()).unwrap_or("");
    let key = payload.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let full_key = format!("{table}:{key}");

    match op {
        "get" => {
            if let Some((val_b64, rev)) = map.get(&full_key) {
                Ok(serde_json::json!({ "value": val_b64, "revision": rev }))
            } else {
                Err("not found".into())
            }
        }
        "put" => {
            let val_b64 = payload
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let rev = map.get(&full_key).map(|(_, r)| r + 1).unwrap_or(1);
            map.insert(full_key, (val_b64.to_string(), rev));
            Ok(serde_json::json!({ "ok": true, "revision": rev }))
        }
        "create" => {
            if map.contains_key(&full_key) {
                return Err("already exists".into());
            }
            let val_b64 = payload
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            map.insert(full_key, (val_b64.to_string(), 1));
            Ok(serde_json::json!({ "ok": true, "revision": 1 }))
        }
        "cas" => {
            let expected_rev = payload
                .get("revision")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let val_b64 = payload
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            if let Some((_, current_rev)) = map.get(&full_key) {
                if *current_rev != expected_rev {
                    return Err("revision mismatch".into());
                }
            } else if expected_rev != 0 {
                return Err("revision mismatch".into());
            }
            let new_rev = expected_rev + 1;
            map.insert(full_key, (val_b64.to_string(), new_rev));
            Ok(serde_json::json!({ "ok": true, "revision": new_rev }))
        }
        "delete" => {
            map.remove(&full_key);
            Ok(serde_json::json!({ "ok": true }))
        }
        "exists" => {
            let exists = map.contains_key(&full_key);
            Ok(serde_json::json!({ "exists": exists }))
        }
        "keys" => {
            let prefix = format!("{table}:");
            let mut keys = Vec::new();
            for k in map.keys() {
                if let Some(stripped) = k.strip_prefix(&prefix) {
                    keys.push(stripped.to_string());
                }
            }
            Ok(serde_json::json!({ "keys": keys, "next_cursor": "" }))
        }
        _ => Err(format!("unsupported test op {op}")),
    }
}

/// Send a request to lattice-db via localhost TCP.
/// Wire protocol:
/// - Request: [4-byte total_len][1-byte op_len][op][payload]
/// - Response: [4-byte total_len][2-byte status_code][payload]
pub(crate) async fn ldb_request(
    op: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    #[cfg(test)]
    {
        return handle_test_ldb_request(op, payload);
    }
    // Build payload with consistency context.
    let mut payload = payload.clone();

    if let Some(table) = payload.get("table").and_then(|t| t.as_str()) {
        let min_rev = SESSION_REVISIONS.with(|sr| sr.borrow().get(table).copied());
        if let Some(rev) = min_rev {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "consistency".to_string(),
                    serde_json::json!({ "min_revision": rev }),
                );
            }
        }
    }

    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {e}"))?;

    // Direct localhost TCP loopback to co-located storage-service (127.0.0.1:4080)
    let val: serde_json::Value = try_ldb_tcp(op, &payload_bytes)
        .await
        .map_err(|e| format!("ldb_request error on {op} (tcp): {e}"))?;

    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }

    // Track session revisions for consistency.
    if let Some(revisions) = val.get("revisions").and_then(|r| r.as_object()) {
        SESSION_REVISIONS.with(|sr| {
            let mut map = sr.borrow_mut();
            for (table, rev) in revisions {
                if let Some(rev_u64) = rev.as_u64() {
                    let entry = map.entry(table.clone()).or_insert(0);
                    if rev_u64 > *entry {
                        *entry = rev_u64;
                    }
                }
            }
        });
    }

    if let Some(server_epoch) = val.get("epoch").and_then(|e| e.as_str()) {
        validate_epoch(server_epoch);
    }

    Ok(val)
}

async fn try_ldb_tcp(op: &str, body: &[u8]) -> Result<serde_json::Value, String> {
    use crate::bindings::wasi::sockets::instance_network::instance_network;
    use crate::bindings::wasi::sockets::network::{
        IpAddressFamily, IpSocketAddress, Ipv4SocketAddress,
    };
    use crate::bindings::wasi::sockets::tcp_create_socket::create_tcp_socket;

    let port = std::env::var("LDB_TCP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(LDB_TCP_PORT);

    let addr = IpSocketAddress::Ipv4(Ipv4SocketAddress {
        port,
        address: (127, 0, 0, 1),
    });

    let mut last_err = String::new();
    let mut streams = None;

    for attempt in 0..15 {
        if attempt > 0 {
            let delay_ns = (5_000_000 * (attempt as u64)).min(50_000_000);
            let p = crate::bindings::wasi::clocks::monotonic_clock::subscribe_duration(delay_ns);
            p.block();
            drop(p);
        }

        let network = instance_network();
        let socket = match create_tcp_socket(IpAddressFamily::Ipv4) {
            Ok(s) => s,
            Err(e) => {
                last_err = format!("tcp create: {e:?}");
                drop(network);
                continue;
            }
        };

        match socket.start_connect(&network, addr) {
            Ok(()) => {}
            Err(e) => {
                last_err = format!("start_connect: {e:?}");
                drop(socket);
                drop(network);
                continue;
            }
        }
        drop(network);

        let mut connected = false;
        for _ in 0..10 {
            let pollable = socket.subscribe();
            pollable.block();
            drop(pollable);

            match socket.finish_connect() {
                Ok((in_s, out_s)) => {
                    streams = Some((in_s, out_s, socket));
                    connected = true;
                    break;
                }
                Err(e) => {
                    let err_str = format!("{e:?}");
                    if err_str.contains("WouldBlock")
                        || err_str.contains("InProgress")
                        || err_str.contains("would-block")
                        || err_str.contains("in-progress")
                    {
                        continue;
                    }
                    last_err = format!("finish_connect: {e:?}");
                    break;
                }
            }
        }

        if connected {
            break;
        }
    }

    let (in_stream, out_stream, socket) =
        streams.ok_or_else(|| format!("tcp connect failed after retries: {last_err}"))?;

    // Write request frame: [4-byte total_len] [1-byte op_len] [op bytes] [payload]
    let op_bytes = op.as_bytes();
    let total_len = (1 + op_bytes.len() + body.len()) as u32;
    let mut frame = Vec::with_capacity(4 + 1 + op_bytes.len() + body.len());
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.push(op_bytes.len() as u8);
    frame.extend_from_slice(op_bytes);
    frame.extend_from_slice(body);

    out_stream
        .blocking_write_and_flush(&frame)
        .map_err(|e| format!("tcp send: {e:?}"))?;

    // Read response frame: 4-byte length prefix
    let mut buf = Vec::with_capacity(4);
    while buf.len() < 4 {
        let chunk = in_stream
            .blocking_read((4 - buf.len()) as u64)
            .map_err(|e| format!("tcp read (length): {e:?}"))?;
        if chunk.is_empty() {
            return Err("tcp connection closed by peer before length".into());
        }
        buf.extend_from_slice(&chunk);
    }
    let total_resp_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if total_resp_len < 2 {
        return Err("response frame too short".into());
    }

    buf.clear();
    buf.reserve(total_resp_len);

    while buf.len() < total_resp_len {
        let needed = (total_resp_len - buf.len()) as u64;
        let to_read = needed.min(65536);
        let chunk = in_stream
            .blocking_read(to_read)
            .map_err(|e| format!("tcp read (body): {e:?}"))?;
        if chunk.is_empty() {
            return Err("tcp connection closed by peer mid-body".into());
        }
        buf.extend_from_slice(&chunk);
    }

    drop(in_stream);
    drop(out_stream);
    drop(socket);

    let status_code = u16::from_be_bytes([buf[0], buf[1]]);
    let resp_payload = &buf[2..];

    let val: serde_json::Value =
        serde_json::from_slice(resp_payload).map_err(|e| format!("parse response: {e}"))?;

    if status_code != 0 {
        if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
            return Err(err.to_string());
        }
        return Err(format!("error {status_code}"));
    }

    Ok(val)
}

/// Check if a lattice-db error indicates "not found".
fn is_not_found(e: &str) -> bool {
    e.contains("not found")
}

async fn kv_get<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
) -> Result<Option<T>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request("get", &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let val = serde_json::from_slice(&bytes).map_err(|e| format!("deserialize: {e}"))?;
            Ok(Some(val))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

pub(crate) async fn kv_get_raw(store_name: &str, key: &str) -> Result<Option<Vec<u8>>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request("get", &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            Ok(Some(bytes))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

pub(crate) async fn kv_get_raw_with_revision(
    store_name: &str,
    key: &str,
) -> Result<Option<(Vec<u8>, u64)>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request("get", &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(Some((bytes, revision)))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

/// Get a value along with its revision (for CAS).
async fn kv_get_revision<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
) -> Result<Option<(T, u64)>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request("get", &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let val = serde_json::from_slice(&bytes).map_err(|e| format!("deserialize: {e}"))?;
            let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(Some((val, revision)))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

pub async fn kv_set<T: Serialize>(store_name: &str, key: &str, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    ldb_request("put", &payload).await?;
    Ok(())
}

pub(crate) async fn kv_set_raw(store_name: &str, key: &str, value: &[u8]) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    ldb_request("put", &payload).await?;
    Ok(())
}

/// Atomic create — returns Err containing "already exists" if key is present.
pub(crate) async fn kv_create_raw(
    store_name: &str,
    key: &str,
    value: &[u8],
    ttl_secs: Option<u64>,
) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let mut payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    if let Some(ttl) = ttl_secs {
        payload
            .as_object_mut()
            .unwrap()
            .insert("ttl_seconds".into(), ttl.into());
    }
    ldb_request("create", &payload).await?;
    Ok(())
}

/// CAS update — returns Err containing "revision mismatch" if revision is stale.
pub(crate) async fn kv_cas_raw(
    store_name: &str,
    key: &str,
    value: &[u8],
    revision: u64,
    ttl_seconds: Option<u64>,
) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let mut payload = serde_json::json!({
        "table": store_name,
        "key": key,
        "value": value_b64,
        "revision": revision,
    });
    if let Some(ttl) = ttl_seconds {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("ttl_seconds".to_string(), serde_json::json!(ttl));
        }
    }
    ldb_request("cas", &payload).await?;
    Ok(())
}

/// Check whether a key exists (without fetching the value).
pub(crate) async fn kv_exists(store_name: &str, key: &str) -> Result<bool, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request("exists", &payload).await {
        Ok(resp) => Ok(resp
            .get("exists")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)),
        Err(e) => Err(e),
    }
}

async fn kv_set_with_ttl(
    store_name: &str,
    key: &str,
    value: &[u8],
    ttl_secs: u64,
) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "ttl_seconds": ttl_secs });
    ldb_request("put", &payload).await?;
    Ok(())
}

async fn kv_set_ttl<T: Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    ttl_secs: u64,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "ttl_seconds": ttl_secs });
    ldb_request("put", &payload).await?;
    Ok(())
}

async fn kv_set_raw_ttl(
    store_name: &str,
    key: &str,
    value: &[u8],
    ttl_secs: u64,
) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "ttl_seconds": ttl_secs });
    ldb_request("put", &payload).await?;
    Ok(())
}

pub async fn kv_delete(store_name: &str, key: &str) -> Result<(), String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    ldb_request("delete", &payload).await?;
    Ok(())
}

async fn kv_list_keys(store_name: &str) -> Result<Vec<String>, String> {
    let mut all_keys = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut payload = serde_json::json!({ "table": store_name });
        if let Some(ref c) = cursor {
            payload["cursor"] = serde_json::Value::String(c.clone());
        }
        let resp = ldb_request("keys", &payload).await?;
        if let Some(keys) = resp.get("keys").and_then(|v| v.as_array()) {
            for k in keys {
                if let Some(s) = k.as_str() {
                    all_keys.push(s.to_string());
                }
            }
        }
        match resp.get("next_cursor").and_then(|v| v.as_str()) {
            Some(c) if !c.is_empty() => cursor = Some(c.to_string()),
            _ => break,
        }
    }
    Ok(all_keys)
}

/// Atomically swap a value if the revision matches.
async fn kv_cas_swap<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    revision: u64,
) -> Result<u64, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "revision": revision });
    let resp = ldb_request("cas", &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically swap a value if the revision matches, with TTL.
async fn kv_cas_swap_ttl<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    revision: u64,
    ttl_secs: u64,
) -> Result<u64, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "revision": revision, "ttl_seconds": ttl_secs });
    let resp = ldb_request("cas", &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically create a key only if it doesn't exist.
async fn kv_cas_create<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
) -> Result<u64, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    let resp = ldb_request("create", &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically create a raw key only if it doesn't exist.
async fn kv_cas_create_raw(store_name: &str, key: &str, value: &[u8]) -> Result<u64, String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    let resp = ldb_request("create", &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically delete a key only if the revision matches.
async fn kv_cas_delete(store_name: &str, key: &str, revision: u64) -> Result<(), String> {
    let payload = serde_json::json!({ "table": store_name, "key": key, "revision": revision });
    ldb_request("cas_delete", &payload).await?;
    Ok(())
}

/// Get a raw value with its revision for CAS operations.
#[allow(dead_code)]
async fn kv_get_raw_revision(
    store_name: &str,
    key: &str,
) -> Result<Option<(Vec<u8>, u64)>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request("get", &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(Some((bytes, revision)))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

pub async fn kv_cache_get<T: serde::de::DeserializeOwned>(key: &str) -> Result<Option<T>, String> {
    match kv_get_raw(&store_name("cache"), key).await? {
        Some(bytes) => {
            let cached: CacheEntry<T> =
                serde_json::from_slice(&bytes).map_err(|e| format!("cache deserialize: {e}"))?;
            if cached.expires_at > unix_now() {
                Ok(Some(cached.value))
            } else {
                let _ = kv_delete(&store_name("cache"), key).await;
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

pub async fn kv_cache_set<T: Serialize>(key: &str, value: &T, ttl_secs: u64) -> Result<(), String> {
    let entry = CacheEntry {
        value,
        expires_at: unix_now() + ttl_secs,
    };
    let bytes = serde_json::to_vec(&entry).map_err(|e| format!("cache serialize: {e}"))?;
    kv_set_with_ttl(&store_name("cache"), key, &bytes, ttl_secs).await
}

// ── User operations ─────────────────────────────────────────

pub async fn create_user(user: &User) -> Result<(), String> {
    // Store user record first (random UUID key, no conflict risk)
    let mut u = user.clone();
    if u.status == "active" && !u.superadmin && crate::require_email_verification() {
        u.status = "pending".to_string();
    }
    kv_set(&users_store(), &format!("user:{}", u.id), &u).await?;

    // Atomically create email → user_id index (fails if email already taken)
    let email_key = format!("email:{}", hmac_email(&u.email));
    match kv_cas_create_raw(&user_idx_store(), &email_key, u.id.as_bytes()).await {
        Ok(_) => Ok(()),
        Err(e) if e.contains("already exists") => {
            // Roll back user record
            let _ = kv_delete(&users_store(), &format!("user:{}", u.id)).await;
            Err("email already registered".into())
        }
        Err(e) => Err(e),
    }
}

pub async fn get_user(id: &str) -> Result<Option<User>, String> {
    kv_get(&users_store(), &format!("user:{id}")).await
}

/// Get a user with its KV revision for CAS updates.
pub async fn get_user_cas(id: &str) -> Result<Option<(User, u64)>, String> {
    kv_get_revision(&users_store(), &format!("user:{id}")).await
}

/// Update a user with CAS — fails with "revision mismatch" if another
/// writer changed the record since it was read.
pub async fn update_user_cas(user: &User, revision: u64) -> Result<u64, String> {
    kv_cas_swap(&users_store(), &format!("user:{}", user.id), user, revision).await
}

/// Read-modify-write a user with automatic CAS retry.
/// The `modify` closure receives a mutable user and returns Ok(true) to
/// commit the change, Ok(false) to skip (no-op), or Err to abort.
pub async fn update_user_rmw<F>(user_id: &str, mut modify: F) -> Result<(), String>
where
    F: FnMut(&mut User) -> Result<bool, String>,
{
    const MAX_RETRIES: usize = 5;
    for attempt in 0..MAX_RETRIES {
        let (mut user, revision) = get_user_cas(user_id).await?.ok_or("user not found")?;
        if !modify(&mut user)? {
            return Ok(()); // no change needed
        }
        match update_user_cas(&user, revision).await {
            Ok(_) => return Ok(()),
            Err(e) if e.contains("revision mismatch") && attempt < MAX_RETRIES - 1 => {
                continue; // retry
            }
            Err(e) => return Err(e),
        }
    }
    Err("update_user_rmw: too many retries".into())
}

/// Legacy non-CAS update — only use for fields where races are harmless.
#[allow(dead_code)]
pub async fn update_user(user: &User) -> Result<(), String> {
    kv_set(&users_store(), &format!("user:{}", user.id), user).await
}

/// Permanently delete a user and all associated first-party data (GDPR Art. 17).
/// Caller is responsible for revoking active sessions before calling this.
pub async fn delete_user(user_id: &str) -> Result<(), String> {
    // Fetch user to get email for index removal
    let user = match kv_get::<User>(&users_store(), &format!("user:{user_id}")).await? {
        Some(u) => u,
        None => return Ok(()), // already gone
    };

    // Remove email → user_id index
    let _ = kv_delete(
        &user_idx_store(),
        &format!("email:{}", hmac_email(&user.email)),
    )
    .await;

    // Remove user record
    kv_delete(&users_store(), &format!("user:{user_id}")).await?;

    // Remove all tenant memberships for this user
    let store_name = memberships_store();
    let keys = kv_list_keys(&store_name).await.unwrap_or_default();
    for key in keys {
        // Forward keys: tenant:{tid}:user:{uid}
        // Reverse keys: user:{uid}:tenant:{tid}
        if key.contains(&format!(":user:{user_id}")) || key.starts_with(&format!("user:{user_id}:"))
        {
            let _ = kv_delete(&store_name, &key).await;
        }
    }

    // Remove all user consent grants (GDPR Art. 17)
    let u_store = users_store();
    let consent_prefix = format!("consent:{user_id}:");
    if let Ok(user_keys) = kv_list_keys(&u_store).await {
        for key in user_keys {
            if key.starts_with(&consent_prefix) {
                let _ = kv_delete(&u_store, &key).await;
            }
        }
    }

    Ok(())
}

pub async fn get_superadmin_flag() -> Result<Option<bool>, String> {
    kv_get(&sessions_store(), "meta:has_superadmin").await
}

/// Atomically set the superadmin flag — only the first writer wins.
pub async fn set_superadmin_flag(val: bool) -> Result<(), String> {
    match kv_cas_create(&sessions_store(), "meta:has_superadmin", &val).await {
        Ok(_) => Ok(()),
        Err(e) if e.contains("already exists") => Ok(()), // another replica set it first
        Err(e) => Err(e),
    }
}

pub async fn list_users() -> Result<Vec<User>, String> {
    let store_name = users_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut users = Vec::new();
    for key in keys {
        if key.starts_with("user:")
            && let Some(u) = kv_get::<User>(&store_name, &key).await?
        {
            users.push(u);
        }
    }
    Ok(users)
}

pub async fn get_user_by_email(email: &str) -> Result<Option<User>, String> {
    let email_lower = email.to_lowercase();

    // Check with region-authority where this user lives.
    // If authority says user is remote, return None so the caller can
    // attempt a cross-region redirect.  Otherwise (local or unknown),
    // fall through to the local KV lookup.
    let lookup = crate::region_authority::lookup(&email_lower)
        .await
        .map_err(|e| format!("authority lookup failed: {}", e))?;

    match lookup.region.as_deref() {
        Some(r) if r != "local" && lookup.found => {
            // User is known to be in a remote region
            Ok(None)
        }
        _ => {
            // User is local, or authority doesn't know — check local KV
            let email_key = format!("email:{}", hmac_email(&email_lower));
            match kv_get_raw(&user_idx_store(), &email_key).await? {
                Some(bytes) => {
                    let user_id = String::from_utf8_lossy(&bytes);
                    get_user(&user_id).await
                }
                None => Ok(None),
            }
        }
    }
}

// ── Auth session operations ─────────────────────────────────

pub async fn save_auth_session(session_id: &str, session: &AuthSession) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("session:{session_id}"),
        session,
        TTL_AUTH_SESSION,
    )
    .await
}

pub async fn get_auth_session(session_id: &str) -> Result<Option<AuthSession>, String> {
    kv_get(&sessions_store(), &format!("session:{session_id}")).await
}

pub async fn delete_auth_session(session_id: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("session:{session_id}")).await
}

/// Atomically get and delete an auth session (CAS). Returns None if already consumed.
pub async fn consume_auth_session(session_id: &str) -> Result<Option<AuthSession>, String> {
    let key = format!("session:{session_id}");
    match kv_get_revision::<AuthSession>(&sessions_store(), &key).await? {
        Some((session, revision)) => {
            match kv_cas_delete(&sessions_store(), &key, revision).await {
                Ok(()) => Ok(Some(session)),
                Err(_) => Ok(None), // Already consumed by a concurrent request
            }
        }
        None => Ok(None),
    }
}

// ── Google OAuth CSRF state ─────────────────────────────────

pub async fn save_google_csrf(csrf_token: &str, session_id: &str) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("gcsrf:{csrf_token}"),
        &session_id.to_string(),
        600,
    )
    .await
}

pub async fn consume_google_csrf(csrf_token: &str) -> Result<Option<String>, String> {
    let key = format!("gcsrf:{csrf_token}");
    // Atomically read with revision and delete in one CAS operation
    match kv_get_revision::<String>(&sessions_store(), &key).await? {
        Some((session_id, revision)) => {
            match kv_cas_delete(&sessions_store(), &key, revision).await {
                Ok(()) => Ok(Some(session_id)),
                Err(e) if e.contains("revision mismatch") => {
                    // Another replica already consumed it
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
        None => Ok(None),
    }
}

// ── Auth code operations ────────────────────────────────────

pub async fn save_auth_code(code: &str, auth_code: &AuthCode) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("code:{code}"),
        auth_code,
        TTL_AUTH_CODE,
    )
    .await
}

#[allow(dead_code)]
pub async fn get_auth_code(code: &str) -> Result<Option<AuthCode>, String> {
    kv_get(&sessions_store(), &format!("code:{code}")).await
}

/// Get auth code with revision for CAS consumption.
pub async fn get_auth_code_cas(code: &str) -> Result<Option<(AuthCode, u64)>, String> {
    kv_get_revision(&sessions_store(), &format!("code:{code}")).await
}

/// Atomically consume an auth code (CAS swap to consumed marker).
pub async fn consume_auth_code(code: &str, revision: u64) -> Result<(), String> {
    let consumed = serde_json::json!({"consumed": true});
    kv_cas_swap_ttl(
        &sessions_store(),
        &format!("code:{code}"),
        &consumed,
        revision,
        TTL_AUTH_CODE,
    )
    .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn delete_auth_code(code: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("code:{code}")).await
}

// ── Refresh token operations ────────────────────────────────

#[allow(dead_code)]
pub async fn save_refresh_token(token_hash: &str, entry: &RefreshEntry) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("refresh:{token_hash}"),
        entry,
        TTL_REFRESH_TOKEN,
    )
    .await?;
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("refresh_idx:{}:{token_hash}", entry.user_id),
        &[1],
        TTL_REFRESH_TOKEN,
    )
    .await
}

pub async fn get_refresh_token(token_hash: &str) -> Result<Option<RefreshEntry>, String> {
    kv_get(&sessions_store(), &format!("refresh:{token_hash}")).await
}

/// Get refresh token with revision for CAS consumption.
pub async fn get_refresh_token_cas(
    token_hash: &str,
) -> Result<Option<(RefreshEntry, u64)>, String> {
    match kv_get_revision(&sessions_store(), &format!("refresh:{token_hash}")).await {
        Ok(v) => Ok(v),
        Err(e) if e.starts_with("deserialize:") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically consume a refresh token (CAS swap to consumed marker).
pub async fn consume_refresh_token(token_hash: &str, revision: u64) -> Result<(), String> {
    let consumed = serde_json::json!({"consumed": true});
    kv_cas_swap_ttl(
        &sessions_store(),
        &format!("refresh:{token_hash}"),
        &consumed,
        revision,
        TTL_CONSUMED_MARKER,
    )
    .await?;
    Ok(())
}

/// Mark a consumed refresh token hash so replay can be detected.
pub async fn mark_refresh_consumed(token_hash: &str, user_id: &str) -> Result<(), String> {
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("consumed:{token_hash}"),
        user_id.as_bytes(),
        TTL_CONSUMED_MARKER,
    )
    .await
}

/// Check if a refresh token hash was previously consumed (replay detection).
pub async fn get_consumed_refresh(token_hash: &str) -> Result<Option<String>, String> {
    match kv_get_raw(&sessions_store(), &format!("consumed:{token_hash}")).await? {
        Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
        None => Ok(None),
    }
}

pub async fn delete_refresh_token(token_hash: &str) -> Result<(), String> {
    if let Ok(Some(entry)) = get_refresh_token(token_hash).await {
        let _ = kv_delete(
            &sessions_store(),
            &format!("refresh_idx:{}:{token_hash}", entry.user_id),
        )
        .await;
    }
    kv_delete(&sessions_store(), &format!("refresh:{token_hash}")).await
}

/// Revoke all sessions for a user.
pub async fn revoke_user_sessions(user_id: &str) -> Result<(), String> {
    let key = format!("revoked:user:{user_id}");
    kv_set_raw_ttl(
        &sessions_store(),
        &key,
        &unix_now().to_be_bytes(),
        TTL_REVOCATION_MARKER,
    )
    .await
}

/// Check if a user's sessions have been revoked.
pub async fn is_user_revoked(user_id: &str, iat: u64) -> Result<bool, String> {
    let key = format!("revoked:user:{user_id}");
    match kv_get_raw(&sessions_store(), &key).await? {
        Some(bytes) if bytes.len() == 8 => {
            let revoked_at = u64::from_be_bytes(bytes.try_into().unwrap());
            Ok(iat < revoked_at)
        }
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

/// Delete all refresh tokens for a given user.
pub async fn delete_user_refresh_tokens(user_id: &str) -> Result<u32, String> {
    let store_name = sessions_store();
    let prefix = format!("refresh_idx:{user_id}:");
    let keys = kv_list_keys(&store_name).await?;
    let mut count = 0u32;
    for key in keys {
        if key.starts_with(&prefix) {
            let token_hash = key.strip_prefix(&prefix).unwrap_or("");
            if !token_hash.is_empty() {
                let _ = kv_delete(&store_name, &format!("refresh:{token_hash}")).await;
                let _ = kv_delete(&store_name, &key).await;
                count += 1;
            }
        }
    }
    revoke_user_sessions(user_id).await?;
    Ok(count)
}

// ── OIDC client operations ──────────────────────────────────

pub async fn get_client(client_id: &str) -> Result<Option<OidcClient>, String> {
    kv_get(&clients_store(), &format!("client:{client_id}")).await
}

pub async fn save_client(client: &OidcClient) -> Result<(), String> {
    kv_set(
        &clients_store(),
        &format!("client:{}", client.client_id),
        client,
    )
    .await
}

pub async fn list_clients() -> Result<Vec<OidcClient>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut clients = Vec::new();
    for key in keys {
        if key.starts_with("client:")
            && let Some(c) = kv_get::<OidcClient>(&store_name, &key).await?
        {
            clients.push(c);
        }
    }
    Ok(clients)
}

pub async fn delete_client(client_id: &str) -> Result<(), String> {
    let _ = kv_delete(&clients_store(), &format!("reg_token:{client_id}")).await;
    kv_delete(&clients_store(), &format!("client:{client_id}")).await
}

pub async fn save_registration_token(client_id: &str, token_hash: &str) -> Result<(), String> {
    kv_set(
        &clients_store(),
        &format!("reg_token:{client_id}"),
        &token_hash.to_string(),
    )
    .await
}

pub async fn get_registration_token(client_id: &str) -> Result<Option<String>, String> {
    kv_get(&clients_store(), &format!("reg_token:{client_id}")).await
}

pub async fn delete_registration_token(client_id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("reg_token:{client_id}")).await
}

// ── RFC 9126: Pushed Authorization Requests (PAR) ───────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PushedAuthRequest {
    pub client_id: String,
    pub parameters: std::collections::HashMap<String, String>,
    pub created_at: u64,
    pub expires_at: u64,
}

pub async fn save_pushed_auth_request(
    request_uri: &str,
    req: &PushedAuthRequest,
    ttl: u64,
) -> Result<(), String> {
    kv_set_ttl(&sessions_store(), &format!("par:{request_uri}"), req, ttl).await
}

pub async fn get_pushed_auth_request(
    request_uri: &str,
) -> Result<Option<PushedAuthRequest>, String> {
    kv_get(&sessions_store(), &format!("par:{request_uri}")).await
}

pub async fn delete_pushed_auth_request(request_uri: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("par:{request_uri}")).await
}

// ── JTI Replay Prevention (DPoP / Client Assertion) ─────────

pub async fn check_and_record_jti(jti: &str, ttl: u64) -> Result<(), String> {
    let key = format!("jti:{jti}");
    let store_name = sessions_store();
    if kv_get::<serde_json::Value>(&store_name, &key)
        .await?
        .is_some()
    {
        return Err("replay detected".into());
    }
    let marker = serde_json::json!({ "used_at": unix_now() });
    kv_set_ttl(&store_name, &key, &marker, ttl).await
}

// ── Tenant operations ───────────────────────────────────────

pub async fn create_tenant(tenant: &Tenant) -> Result<(), String> {
    let key = format!("tenant:{}", tenant.id);
    let store_name = tenants_store();
    if kv_get::<Tenant>(&store_name, &key).await?.is_some() {
        return Err("tenant already exists".into());
    }
    kv_set(&store_name, &key, tenant).await
}

pub async fn get_tenant(id: &str) -> Result<Option<Tenant>, String> {
    kv_get(&tenants_store(), &format!("tenant:{id}")).await
}

pub async fn delete_tenant(id: &str) -> Result<(), String> {
    kv_delete(&tenants_store(), &format!("tenant:{id}")).await
}

pub async fn list_tenants() -> Result<Vec<Tenant>, String> {
    let store_name = tenants_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut tenants = Vec::new();
    for key in keys {
        if key.starts_with("tenant:")
            && let Some(t) = kv_get::<Tenant>(&store_name, &key).await?
        {
            tenants.push(t);
        }
    }
    Ok(tenants)
}

// ── Membership operations ───────────────────────────────────

pub async fn add_membership(m: &Membership) -> Result<(), String> {
    let store_name = memberships_store();
    let fwd = format!("tenant:{}:user:{}", m.tenant_id, m.user_id);
    kv_set(&store_name, &fwd, m).await?;
    let rev = format!("user:{}:tenant:{}", m.user_id, m.tenant_id);
    kv_set_raw(&store_name, &rev, m.role.as_bytes()).await
}

pub async fn get_membership(tenant_id: &str, user_id: &str) -> Result<Option<Membership>, String> {
    kv_get(
        &memberships_store(),
        &format!("tenant:{tenant_id}:user:{user_id}"),
    )
    .await
}

pub async fn remove_membership(tenant_id: &str, user_id: &str) -> Result<(), String> {
    let store_name = memberships_store();
    kv_delete(&store_name, &format!("tenant:{tenant_id}:user:{user_id}")).await?;
    kv_delete(&store_name, &format!("user:{user_id}:tenant:{tenant_id}")).await
}

pub async fn list_tenant_members(tenant_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("tenant:{tenant_id}:user:");
    let store_name = memberships_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut members = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(m) = kv_get::<Membership>(&store_name, &key).await?
        {
            members.push(m);
        }
    }
    Ok(members)
}

pub async fn list_user_tenants(user_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("user:{user_id}:tenant:");
    let keys = kv_list_keys(&memberships_store()).await?;
    let mut memberships = Vec::new();
    for key in keys {
        if key.starts_with(&prefix) {
            let tenant_id = key.strip_prefix(&prefix).unwrap_or("");
            if let Some(m) = get_membership(tenant_id, user_id).await? {
                memberships.push(m);
            }
        }
    }
    Ok(memberships)
}

// ── Invitation operations ───────────────────────────────────

pub async fn save_invitation(inv: &Invitation) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("invite:{}", inv.token),
        inv,
        TTL_INVITATION,
    )
    .await
}

pub async fn get_invitation(token: &str) -> Result<Option<Invitation>, String> {
    kv_get(&sessions_store(), &format!("invite:{token}")).await
}

pub async fn delete_invitation(token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("invite:{token}")).await
}

// ── Account lockout operations ──────────────────────────────

pub async fn is_account_locked(user_id: &str) -> Result<bool, String> {
    match kv_get::<LoginAttempts>(&sessions_store(), &format!("lockout:{user_id}")).await? {
        Some(a) if a.locked_until > unix_now() => Ok(true),
        _ => Ok(false),
    }
}

/// Record a failed login. Returns true if the account is now locked.
pub async fn record_failed_login(user_id: &str) -> Result<bool, String> {
    let store_name = sessions_store();
    let key = format!("lockout:{user_id}");

    const MAX_RETRIES: usize = 5;
    for attempt in 0..MAX_RETRIES {
        let (mut attempts, revision) =
            match kv_get_revision::<LoginAttempts>(&store_name, &key).await? {
                Some((a, r)) => (a, r),
                None => (
                    LoginAttempts {
                        failures: 0,
                        locked_until: 0,
                    },
                    0,
                ),
            };

        if attempts.locked_until > 0 && attempts.locked_until <= unix_now() {
            attempts.failures = 0;
            attempts.locked_until = 0;
        }

        attempts.failures += 1;
        let locked = if attempts.failures >= max_login_failures() {
            attempts.locked_until = unix_now() + lockout_duration();
            true
        } else {
            false
        };

        let result = if revision == 0 {
            // First failure — atomic create
            let bytes = serde_json::to_vec(&attempts).map_err(|e| format!("serialize: {e}"))?;
            let value_b64 = B64.encode(&bytes);
            let payload = serde_json::json!({
                "table": store_name, "key": key, "value": value_b64,
                "ttl_seconds": TTL_LOCKOUT,
            });
            ldb_request("create", &payload).await
        } else {
            // Existing counter — CAS update
            kv_cas_swap_ttl(&store_name, &key, &attempts, revision, TTL_LOCKOUT)
                .await
                .map(|_| serde_json::Value::Null)
        };

        match result {
            Ok(_) => return Ok(locked),
            Err(e)
                if (e.contains("revision mismatch") || e.contains("already exists"))
                    && attempt < MAX_RETRIES - 1 =>
            {
                continue; // retry
            }
            Err(e) => return Err(format!("record_failed_login: {e}")),
        }
    }
    Err("record_failed_login: too many retries".into())
}

pub async fn clear_login_attempts(user_id: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("lockout:{user_id}")).await
}

// ── Audit log operations ────────────────────────────────────

pub async fn log_audit(
    event_type: &str,
    actor_id: &str,
    target_id: &str,
    details: &str,
) -> Result<(), String> {
    let now = unix_now();
    let rand = random_hex(4);
    let key = format!("audit:{now}:{rand}");
    let event = AuditEvent {
        event_type: event_type.to_string(),
        actor_id: actor_id.to_string(),
        target_id: target_id.to_string(),
        details: details.to_string(),
        timestamp: now,
    };
    kv_set_ttl(&audit_store(), &key, &event, TTL_AUDIT).await
}

pub async fn list_audit_events(
    actor_id: Option<&str>,
    target_id: Option<&str>,
    event_type: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    limit: usize,
) -> Result<Vec<AuditEvent>, String> {
    let store_name = audit_store();
    let keys = kv_list_keys(&store_name).await?;

    // Extract timestamps from key names: "audit:<timestamp>:<rand>"
    let mut parsed_keys: Vec<(u64, String)> = keys
        .into_iter()
        .filter_map(|k| {
            if !k.starts_with("audit:") {
                return None;
            }
            let mut parts = k.split(':');
            parts.next()?; // "audit"
            let ts = parts.next()?.parse::<u64>().ok()?;
            Some((ts, k))
        })
        .collect();

    // Pre-filter keys by timestamp before fetching payloads over TCP
    if let Some(lower) = since {
        parsed_keys.retain(|(ts, _)| *ts >= lower);
    }
    if let Some(upper) = until {
        parsed_keys.retain(|(ts, _)| *ts <= upper);
    }

    // Sort descending by timestamp (newest first)
    parsed_keys.sort_by(|(ts_a, _), (ts_b, _)| ts_b.cmp(ts_a));

    let mut events = Vec::new();
    let has_content_filter = actor_id.is_some() || target_id.is_some() || event_type.is_some();
    let max_scan = if has_content_filter {
        (limit * 5).max(200)
    } else {
        limit
    };

    for (_, key) in parsed_keys.into_iter().take(max_scan) {
        if let Some(event) = kv_get::<AuditEvent>(&store_name, &key).await? {
            if let Some(actor) = actor_id
                && event.actor_id != actor
            {
                continue;
            }
            if let Some(target) = target_id
                && event.target_id != target
            {
                continue;
            }
            if let Some(kind) = event_type
                && event.event_type != kind
            {
                continue;
            }
            events.push(event);
            if events.len() >= limit {
                break;
            }
        }
    }

    events.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| left.event_type.cmp(&right.event_type))
    });

    Ok(events)
}

/// Ensure a default OIDC client exists for development/testing.
pub async fn ensure_default_client() -> Result<(), String> {
    let default_id = "default";
    if get_client(default_id).await?.is_some() {
        return Ok(());
    }
    let client = OidcClient {
        client_id: default_id.to_string(),
        client_secret: None,
        redirect_uris: vec![
            "http://localhost:8090/callback".to_string(),
            "http://localhost:3000/callback".to_string(),
        ],
        post_logout_redirect_uris: vec![
            "http://localhost:8090/".to_string(),
            "http://localhost:8090/callback".to_string(),
            "http://localhost:3000/".to_string(),
        ],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        name: "Default Dev Client".to_string(),
        theme: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        id_token_signed_response_alg: None,
        first_party: true,
        token_endpoint_auth_method: Some("none".to_string()),
        jwks: None,
        require_pushed_authorization_requests: false,
    };
    kv_set(&clients_store(), &format!("client:{default_id}"), &client).await
}

/// Register the Lattice-ID Admin UI OIDC client.
pub async fn ensure_admin_client(issuer: &str, dev_mode: bool) -> Result<(), String> {
    let admin_id = "lid-admin";
    // Always rewrite the admin client so redirect URIs stay in sync with the
    // configured issuer (e.g. after switching from :8000 to port 80).
    let existing_secret = get_client(admin_id).await?.and_then(|c| c.client_secret);
    let mut redirect_uris = vec![
        format!("{issuer}"),
        format!("{issuer}/"),
        format!("{issuer}/callback"),
        format!("{issuer}/admin"),
        format!("{issuer}/admin/"),
        "/".to_string(),
        "/admin".to_string(),
        "/admin/".to_string(),
    ];

    if dev_mode {
        for port in &["8000", "8090", "8091"] {
            redirect_uris.push(format!("http://localhost:{port}/"));
            redirect_uris.push(format!("http://localhost:{port}/callback"));
        }
        // Also register portless localhost variants for port-80 local dev
        redirect_uris.push("http://localhost/admin".to_string());
        redirect_uris.push("http://localhost/admin/".to_string());
        redirect_uris.push("http://localhost/".to_string());
        redirect_uris.push("http://localhost/callback".to_string());
    }
    let client = OidcClient {
        client_id: admin_id.to_string(),
        client_secret: existing_secret,
        post_logout_redirect_uris: redirect_uris.clone(),
        redirect_uris,
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        name: "Lattice-ID Admin".to_string(),
        theme: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        id_token_signed_response_alg: None,
        first_party: true,
        token_endpoint_auth_method: Some("client_secret_basic".to_string()),
        jwks: None,
        require_pushed_authorization_requests: false,
    };
    kv_set(&clients_store(), &format!("client:{admin_id}"), &client).await
}

// ── Identity provider operations ────────────────────────────

pub async fn save_identity_provider(idp: &IdentityProvider) -> Result<(), String> {
    kv_set(&clients_store(), &format!("idp:{}", idp.id), idp).await
}

pub async fn get_identity_provider(id: &str) -> Result<Option<IdentityProvider>, String> {
    kv_get(&clients_store(), &format!("idp:{id}")).await
}

pub async fn get_identity_provider_by_type(
    provider_type: &str,
) -> Result<Option<IdentityProvider>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    for key in keys {
        if key.starts_with("idp:")
            && let Some(idp) = kv_get::<IdentityProvider>(&store_name, &key).await?
            && idp.provider_type == provider_type
            && idp.enabled
        {
            return Ok(Some(idp));
        }
    }
    Ok(None)
}

pub async fn list_identity_providers() -> Result<Vec<IdentityProvider>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut providers = Vec::new();
    for key in keys {
        if key.starts_with("idp:")
            && let Some(idp) = kv_get::<IdentityProvider>(&store_name, &key).await?
        {
            providers.push(idp);
        }
    }
    Ok(providers)
}

pub async fn delete_identity_provider(id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("idp:{id}")).await
}

// ── Social identity operations ──────────────────────────────

pub async fn save_social_identity(si: &SocialIdentity) -> Result<(), String> {
    let key = format!("social:{}:{}", si.provider, si.provider_sub);
    kv_set(&user_idx_store(), &key, si).await
}

pub async fn get_social_identity(
    provider: &str,
    provider_sub: &str,
) -> Result<Option<SocialIdentity>, String> {
    kv_get(
        &user_idx_store(),
        &format!("social:{provider}:{provider_sub}"),
    )
    .await
}

// ── MFA pending session ─────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct MfaPending {
    pub user_id: String,
    pub session_id: String,
    #[serde(default)]
    pub primary_amr: Vec<String>,
    pub expires_at: u64,
    #[serde(default)]
    pub remote_ip: String,
}

pub async fn save_mfa_pending(mfa_token: &str, pending: &MfaPending) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("mfa:{mfa_token}"),
        pending,
        TTL_MFA_PENDING,
    )
    .await
}

pub async fn get_mfa_pending(mfa_token: &str) -> Result<Option<MfaPending>, String> {
    kv_get(&sessions_store(), &format!("mfa:{mfa_token}")).await
}

pub async fn delete_mfa_pending(mfa_token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("mfa:{mfa_token}")).await
}

// ── Passkey challenges ──────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct PasskeyChallenge {
    pub challenge: String,
    pub purpose: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub session_id: String,
    pub expires_at: u64,
}

pub async fn save_passkey_challenge(
    token: &str,
    challenge: &PasskeyChallenge,
) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("passkey:{token}"),
        challenge,
        TTL_PASSKEY_CHALLENGE,
    )
    .await
}

/// Atomically consume a passkey challenge — returns None if already consumed
/// by another replica.
pub async fn consume_passkey_challenge(token: &str) -> Result<Option<PasskeyChallenge>, String> {
    let key = format!("passkey:{token}");
    match kv_get_revision::<PasskeyChallenge>(&sessions_store(), &key).await? {
        Some((challenge, revision)) => {
            match kv_cas_delete(&sessions_store(), &key, revision).await {
                Ok(()) => Ok(Some(challenge)),
                Err(e) if e.contains("revision mismatch") => Ok(None),
                Err(e) => Err(e),
            }
        }
        None => Ok(None),
    }
}

pub async fn get_passkey_challenge(token: &str) -> Result<Option<PasskeyChallenge>, String> {
    kv_get(&sessions_store(), &format!("passkey:{token}")).await
}

pub async fn delete_passkey_challenge(token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("passkey:{token}")).await
}

// ── Passkey credential index ────────────────────────────────

pub async fn index_passkey_credential(credential_id: &str, user_id: &str) -> Result<(), String> {
    kv_set_raw(
        &user_idx_store(),
        &format!("passkey:{credential_id}"),
        user_id.as_bytes(),
    )
    .await
}

pub async fn unindex_passkey_credential(credential_id: &str) -> Result<(), String> {
    kv_delete(&user_idx_store(), &format!("passkey:{credential_id}")).await
}

pub async fn get_user_by_passkey(credential_id: &str) -> Result<Option<User>, String> {
    match kv_get_raw(&user_idx_store(), &format!("passkey:{credential_id}")).await? {
        Some(bytes) => {
            let user_id = String::from_utf8_lossy(&bytes);
            get_user(&user_id).await
        }
        None => Ok(None),
    }
}

/// Record a consumed TOTP time-step atomically in sessions_store with a short TTL to prevent replay.
/// Returns Ok(true) if newly recorded, or Ok(false) if already used.
pub async fn record_totp_used(key: &str, ttl_seconds: u64) -> Result<bool, String> {
    match kv_create_raw(&sessions_store(), key, b"1", Some(ttl_seconds)).await {
        Ok(()) => Ok(true),
        Err(e) if e.contains("already exists") => Ok(false),
        Err(e) => Err(e),
    }
}

// ── Account sessions (cookie-based, for /account pages) ─────

#[derive(Serialize, Deserialize)]
pub struct AccountSession {
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// CSRF token embedded in every account management form.
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn save_account_session(token: &str, session: &AccountSession) -> Result<(), String> {
    let hashed = sha256_hex(token);
    let ttl = if session.expires_at > session.created_at {
        session.expires_at - session.created_at
    } else {
        TTL_ACCOUNT_SESSION
    };
    kv_set_ttl(&sessions_store(), &format!("acct:{hashed}"), session, ttl).await
}

pub async fn get_account_session(token: &str) -> Result<Option<AccountSession>, String> {
    let hashed = sha256_hex(token);
    if let Some(session) = kv_get(&sessions_store(), &format!("acct:{hashed}")).await? {
        return Ok(Some(session));
    }
    // Fallback to unhashed key for rolling deploys
    kv_get(&sessions_store(), &format!("acct:{token}")).await
}

pub async fn delete_account_session(token: &str) -> Result<(), String> {
    let hashed = sha256_hex(token);
    let _ = kv_delete(&sessions_store(), &format!("acct:{token}")).await;
    kv_delete(&sessions_store(), &format!("acct:{hashed}")).await
}

// ── IdP browser sessions (SSO, prompt=none) ─────────────────

/// A short-lived IdP browser session used for SSO and silent token renewal.
/// Created on login completion; enables `prompt=none` and skipping the login
/// page for SPAs doing access-token refresh.
#[derive(Serialize, Deserialize)]
pub struct IdpSession {
    pub user_id: String,
    /// Unix timestamp of the original authentication (used for max_age checking).
    pub auth_time: u64,
    /// Session expiry (Unix).
    pub expires_at: u64,
    /// AMR values from the original authentication (e.g. ["pwd"], ["passkey"]).
    #[serde(default)]
    pub amr: Vec<String>,
}

pub async fn save_idp_session(token: &str, session: &IdpSession) -> Result<(), String> {
    let hashed = sha256_hex(token);
    let ttl = get_idp_session_ttl().await;
    kv_set_ttl(&sessions_store(), &format!("idp:{hashed}"), session, ttl).await
}

pub async fn get_idp_session(token: &str) -> Result<Option<IdpSession>, String> {
    let hashed = sha256_hex(token);
    if let Some(session) = kv_get(&sessions_store(), &format!("idp:{hashed}")).await? {
        return Ok(Some(session));
    }
    // Fallback to unhashed key for rolling deploys
    kv_get(&sessions_store(), &format!("idp:{token}")).await
}

pub async fn delete_idp_session(token: &str) -> Result<(), String> {
    let hashed = sha256_hex(token);
    let _ = kv_delete(&sessions_store(), &format!("idp:{token}")).await;
    kv_delete(&sessions_store(), &format!("idp:{hashed}")).await
}

// ── Known IPs (suspicious login detection) ──────────────────

const MAX_KNOWN_IPS: usize = 20;

#[derive(Serialize, Deserialize)]
struct KnownIps {
    ips: Vec<String>,
}

pub async fn check_and_record_ip(user_id: &str, ip: &str) -> bool {
    if ip.is_empty() || ip == "unknown" {
        return false;
    }
    let key = format!("known_ips:{user_id}");
    let store = sessions_store();
    let mut entry: KnownIps = kv_get(&store, &key)
        .await
        .ok()
        .flatten()
        .unwrap_or(KnownIps { ips: Vec::new() });

    if entry.ips.iter().any(|existing| existing == ip) {
        return false;
    }

    entry.ips.push(ip.to_string());
    if entry.ips.len() > MAX_KNOWN_IPS {
        entry.ips.remove(0);
    }
    let _ = kv_set(&store, &key, &entry).await;
    true
}

// ── Hook operations ─────────────────────────────────────────

pub async fn save_hook(hook: &Hook) -> Result<(), String> {
    kv_set(&clients_store(), &format!("hook:{}", hook.id), hook).await
}

pub async fn get_hook(id: &str) -> Result<Option<Hook>, String> {
    kv_get(&clients_store(), &format!("hook:{id}")).await
}

pub async fn list_hooks() -> Result<Vec<Hook>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut hooks = Vec::new();
    for key in keys {
        if key.starts_with("hook:")
            && let Some(hook) = kv_get::<Hook>(&store_name, &key).await?
        {
            hooks.push(hook);
        }
    }
    Ok(hooks)
}

pub async fn delete_hook(id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("hook:{id}")).await
}

pub async fn save_hook_version(ver: &HookVersion) -> Result<(), String> {
    let key = format!("hookver:{}:{:06}", ver.hook_id, ver.version);
    kv_set(&audit_store(), &key, ver).await
}

pub async fn list_hook_versions(hook_id: &str) -> Result<Vec<HookVersion>, String> {
    let store_name = audit_store();
    let prefix = format!("hookver:{hook_id}:");
    let keys = kv_list_keys(&store_name).await?;
    let mut versions = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(ver) = kv_get::<HookVersion>(&store_name, &key).await?
        {
            versions.push(ver);
        }
    }
    versions.sort_by_key(|v| v.version);
    Ok(versions)
}

// ── Runtime settings ────────────────────────────────────────

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct RuntimeSettings {
    #[serde(default)]
    pub allow_registration: bool,
    #[serde(default)]
    pub default_theme: Option<ClientTheme>,
    #[serde(default)]
    pub idp_session_ttl_seconds: Option<u64>,
}

const SETTINGS_KEY: &str = "settings:global";

pub async fn get_runtime_settings() -> RuntimeSettings {
    kv_get::<RuntimeSettings>(&clients_store(), SETTINGS_KEY)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

pub async fn save_runtime_settings(settings: &RuntimeSettings) -> Result<(), String> {
    kv_set(&clients_store(), SETTINGS_KEY, settings).await
}

pub async fn get_idp_session_ttl() -> u64 {
    get_runtime_settings()
        .await
        .idp_session_ttl_seconds
        .unwrap_or(DEFAULT_IDP_SESSION_TTL)
}

// ── Persistent User Consent Grants ───────────────────────────

pub async fn save_user_consent(
    user_id: &str,
    client_id: &str,
    new_scopes: &[String],
) -> Result<(), String> {
    let key = format!("consent:{user_id}:{client_id}");
    let mut scopes = match get_user_consent(user_id, client_id).await? {
        Some(existing) => existing.scopes,
        None => Vec::new(),
    };
    for s in new_scopes {
        let trimmed = s.trim();
        if !trimmed.is_empty() && !scopes.iter().any(|existing| existing == trimmed) {
            scopes.push(trimmed.to_string());
        }
    }
    let now = unix_now();
    let record = UserConsent {
        user_id: user_id.to_string(),
        client_id: client_id.to_string(),
        scopes,
        granted_at: now,
        updated_at: now,
    };
    kv_set(&users_store(), &key, &record).await
}

pub async fn get_user_consent(
    user_id: &str,
    client_id: &str,
) -> Result<Option<UserConsent>, String> {
    let key = format!("consent:{user_id}:{client_id}");
    kv_get(&users_store(), &key).await
}

pub async fn has_user_consented(
    user_id: &str,
    client_id: &str,
    requested_scope_str: &str,
) -> Result<bool, String> {
    let consent = match get_user_consent(user_id, client_id).await? {
        Some(c) => c,
        None => return Ok(false),
    };
    let requested: Vec<&str> = requested_scope_str.split_whitespace().collect();
    if requested.is_empty() {
        return Ok(true);
    }
    let all_granted = requested
        .iter()
        .all(|req| consent.scopes.iter().any(|s| s == req));
    Ok(all_granted)
}

pub async fn delete_user_consent(user_id: &str, client_id: &str) -> Result<(), String> {
    let key = format!("consent:{user_id}:{client_id}");
    kv_delete(&users_store(), &key).await
}

pub async fn list_user_consents(user_id: &str) -> Result<Vec<UserConsent>, String> {
    let store_name = users_store();
    let keys = kv_list_keys(&store_name).await?;
    let prefix = format!("consent:{user_id}:");
    let mut consents = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(c) = kv_get::<UserConsent>(&store_name, &key).await?
        {
            consents.push(c);
        }
    }
    Ok(consents)
}

// ── Device Authorization Grant (RFC 8628) ───────────────────

const TTL_DEVICE_CODE: u64 = 300; // 5 minutes

pub async fn save_device_code(dc: &DeviceCode) -> Result<(), String> {
    // Indexed by both device_code (for polling) and user_code (for user entry).
    kv_set_ttl(
        &sessions_store(),
        &format!("device:{}", dc.device_code),
        dc,
        TTL_DEVICE_CODE,
    )
    .await?;
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("device_user_code:{}", dc.user_code.to_uppercase()),
        dc.device_code.as_bytes(),
        TTL_DEVICE_CODE,
    )
    .await
}

pub async fn get_device_code(device_code: &str) -> Result<Option<DeviceCode>, String> {
    kv_get(&sessions_store(), &format!("device:{device_code}")).await
}

/// Look up a device code by its short user_code.  Returns the DeviceCode if found.
pub async fn get_device_code_by_user_code(user_code: &str) -> Result<Option<DeviceCode>, String> {
    let key = format!("device_user_code:{}", user_code.to_uppercase());
    let Some(device_code_bytes) = kv_get_raw(&sessions_store(), &key).await? else {
        return Ok(None);
    };
    let device_code = String::from_utf8(device_code_bytes)
        .map_err(|_| "invalid device code bytes".to_string())?;
    kv_get(&sessions_store(), &format!("device:{device_code}")).await
}

pub async fn update_device_code_status(
    device_code: &str,
    status: &str,
    user_id: Option<&str>,
) -> Result<(), String> {
    if let Some(mut dc) = get_device_code(device_code).await? {
        dc.status = status.to_string();
        dc.user_id = user_id.map(String::from);
        let remaining_ttl = dc.expires_at.saturating_sub(unix_now());
        kv_set_ttl(
            &sessions_store(),
            &format!("device:{device_code}"),
            &dc,
            remaining_ttl.max(1),
        )
        .await?;
    }
    Ok(())
}

pub async fn delete_device_code(device_code: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("device:{device_code}")).await
}

// ── Generic OIDC social login CSRF ──────────────────────────

/// Save a CSRF token → session_id mapping for generic social login flows.
pub async fn save_social_csrf(csrf_token: &str, session_id: &str) -> Result<(), String> {
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("social_csrf:{csrf_token}"),
        session_id.as_bytes(),
        600,
    )
    .await
}

/// Consume and return the session_id for a generic social login CSRF token.
pub async fn consume_social_csrf(csrf_token: &str) -> Result<Option<String>, String> {
    let key = format!("social_csrf:{csrf_token}");
    match kv_get_raw(&sessions_store(), &key).await? {
        Some(bytes) => {
            let _ = kv_delete(&sessions_store(), &key).await;
            Ok(Some(
                String::from_utf8(bytes).map_err(|_| "invalid csrf bytes".to_string())?,
            ))
        }
        None => Ok(None),
    }
}

/// Return the unique client_ids that have active refresh tokens for a user.
/// Used to determine which clients to notify for backchannel logout.
pub async fn list_user_client_ids(user_id: &str) -> Result<Vec<String>, String> {
    let store_name = sessions_store();
    let prefix = format!("refresh_idx:{user_id}:");
    let keys = kv_list_keys(&store_name).await?;
    let mut client_ids = Vec::new();
    for key in keys {
        if key.starts_with(&prefix) {
            let token_hash = key.strip_prefix(&prefix).unwrap_or("");
            if !token_hash.is_empty()
                && let Ok(Some(entry)) =
                    kv_get::<RefreshEntry>(&store_name, &format!("refresh:{token_hash}")).await
                && !client_ids.contains(&entry.client_id)
            {
                client_ids.push(entry.client_id);
            }
        }
    }
    Ok(client_ids)
}
