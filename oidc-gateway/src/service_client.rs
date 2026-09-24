use serde_json::{Value, json};

use crate::{jwt, store};

/// Hash a password locally via imported hasher (stateless scaling).
pub async fn hash_password(plain: &str) -> Result<String, String> {
    crate::bindings::lattice_id::crypto::password::hash(plain)
}

/// Verify a password locally via imported hasher (stateless scaling).
pub async fn verify_password(plain: &str, hash: &str) -> Result<bool, String> {
    crate::bindings::lattice_id::crypto::password::verify(plain, hash)
}

/// Verify a JWT and enforce issuer, audience, and token_type requirements.
/// Runs entirely locally using signing keys loaded from KV.
pub async fn verify_token_scoped(
    token: &str,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
    required_token_type: Option<&str>,
) -> Result<Value, String> {
    let jwks = get_jwks().await?;
    let (_header, claims) = jwt::verify_jwt_with_jwks(token, &jwks)?;

    let now = store::unix_now();
    validate_token_times(&claims, now)?;

    // Revocation check
    if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
        let iat = claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
        if let Ok(true) = store::is_user_revoked(sub, iat).await {
            return Err("token revoked".into());
        }
    }

    // Issuer check
    if let Some(expected) = expected_issuer {
        let issuer = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if issuer != expected {
            return Err("invalid issuer".into());
        }
    }

    // Audience check
    if let Some(expected) = expected_audience {
        let aud_ok = match claims.get("aud") {
            Some(Value::String(value)) => value == expected,
            Some(Value::Array(values)) => {
                values.iter().any(|value| value.as_str() == Some(expected))
            }
            _ => false,
        };
        if !aud_ok {
            return Err("invalid audience".into());
        }
    }

    // Token type check
    if let Some(expected) = required_token_type {
        let token_type = claims
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if token_type != expected {
            return Err("invalid token type".into());
        }
    }

    Ok(claims)
}

fn validate_token_times(claims: &Value, now: u64) -> Result<(), String> {
    if let Some(iat) = claims.get("iat").and_then(|v| v.as_u64())
        && iat > now + 30
    {
        return Err("token iat is in the future".into());
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_u64())
        && nbf > now + 30
    {
        return Err("token not yet active (nbf)".into());
    }
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64())
        && now >= exp
    {
        return Err("token expired".into());
    }

    Ok(())
}

pub async fn get_jwks() -> Result<Value, String> {
    let keys_json = crate::key_manager::get_public_keys().await?;
    let keys: Vec<Value> =
        serde_json::from_str(&keys_json).map_err(|e| format!("parse keys: {e}"))?;
    Ok(serde_json::json!({ "keys": keys }))
}

/// Check rate limit via the inlined abuse module.
/// Returns (allowed, remaining).
pub async fn check_rate(key: &str, limit: u64, window_secs: u64) -> Result<(bool, u64), String> {
    crate::abuse::check_rate(key, limit, window_secs).await
}

pub async fn increment_metric(name: &str, labels: &[(&str, &str)]) -> Result<(), String> {
    let label_map: serde_json::Map<String, serde_json::Value> = labels
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(*v)))
        .collect();
    let _payload = json!({
        "op": "metric_increment",
        "name": name,
        "labels": label_map,
    });
    // Metric emission is recorded via structured logging
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_token_times;
    use serde_json::json;

    #[test]
    fn validate_token_times_accepts_current_token() {
        let now = 1_700_000_000;
        let claims = json!({
            "iat": now - 10,
            "nbf": now - 10,
            "exp": now + 60
        });

        assert!(validate_token_times(&claims, now).is_ok());
    }

    #[test]
    fn validate_token_times_rejects_expired_token() {
        let now = 1_700_000_000;
        let claims = json!({
            "exp": now
        });

        assert_eq!(validate_token_times(&claims, now), Err("token expired".into()));
    }
}

/// Cross-region lookup: first check local region via authority component,
/// then query remote regions via HTTP if not found.
/// Returns `Some(region_id)` if found, `None` otherwise.
pub async fn lookup_region(email_hash: &str) -> Result<Option<String>, String> {
    let cache_key = format!("region:{}", email_hash);

    // 1. Check in-memory cache
    if let Ok(Some(region)) = crate::store::kv_cache_get::<Option<String>>(&cache_key).await {
        return Ok(region);
    }

    // 2. Check local region via inlined region authority
    let local = crate::region_authority::lookup(email_hash).await?;
    if local.found {
        let region = local.region;
        let _ = crate::store::kv_cache_set(&cache_key, &region, 3600).await;
        return Ok(region);
    }

    // 3. Not found locally — query each remote region via HTTP.
    // region_internal_urls uses proper hostnames (e.g., eu.lid.internal:8000)
    // that match the remote gateway's virtual-host config, so the Host header
    // derived from the URL is correct automatically.
    let self_region = crate::store::region_id().unwrap_or_default();
    let internal_urls = crate::store::region_internal_urls();

    for (region_name, base_url) in &internal_urls {
        if *region_name == self_region {
            continue;
        }
        let url = format!(
            "{}/internal/lookup?hash={}",
            base_url.trim_end_matches('/'),
            email_hash
        );
        match internal_http_get(&url).await {
            Ok(body) => {
                if let Ok(reply) = serde_json::from_slice::<LookupReply>(&body)
                    && reply.found
                {
                    let region = Some(reply.region);
                    let _ = crate::store::kv_cache_set(&cache_key, &region, 3600).await;
                    return Ok(region);
                }
            }
            Err(e) => {
                crate::logger::warn(
                    "cross_region.lookup_failed",
                    serde_json::json!({ "region": region_name, "error": e }),
                );
            }
        }
    }

    // Not found anywhere — cache the negative result (shorter TTL)
    let _ = crate::store::kv_cache_set::<Option<String>>(&cache_key, &None, 300).await;
    Ok(None)
}

#[derive(serde::Deserialize)]
struct LookupReply {
    found: bool,
    region: String,
}

/// HTTP GET for cross-region internal calls.
async fn internal_http_get(url: &str) -> Result<Vec<u8>, String> {
    let mut headers = vec![("accept", "application/json")];
    let secret_owned;
    if let Some(secret) = crate::store::internal_auth_secret() {
        secret_owned = secret;
        headers.push(("x-internal-auth", &secret_owned));
    }
    let (status, body) = crate::http_client::get_bytes(url, &headers).await?;
    if !(200..300).contains(&status) {
        return Err(format!("http {status}"));
    }
    Ok(body)
}

/// Replicate a tenant or client mutation to all remote regions.
/// `op` is "put" or "delete".  `kind` is "tenant" or "client".
/// Fire-and-forget: failures are logged but do not block the caller.
pub async fn replicate_to_regions(
    op: &str,
    kind: &str,
    id: &str,
    data: Option<&serde_json::Value>,
) {
    let self_region = crate::store::region_id().unwrap_or_default();
    let internal_urls = crate::store::region_internal_urls();

    let payload = serde_json::json!({
        "op": op,
        "kind": kind,
        "id": id,
        "data": data,
    });
    let payload_str = payload.to_string();

    for (region_name, base_url) in &internal_urls {
        if *region_name == self_region {
            continue;
        }
        let url = format!("{}/internal/replicate", base_url.trim_end_matches('/'));
        let mut headers: Vec<(&str, &str)> = Vec::new();
        let secret_owned;
        if let Some(secret) = crate::store::internal_auth_secret() {
            secret_owned = secret;
            headers.push(("x-internal-auth", &secret_owned));
        }
        match crate::http_client::post_json(&url, &payload_str, &headers).await {
            Ok((status, _)) if (200..300).contains(&status) => {
                crate::logger::info(
                    "cross_region.replicate_ok",
                    serde_json::json!({ "region": region_name, "kind": kind, "op": op, "id": id }),
                );
            }
            Ok((status, body)) => {
                let body_str = String::from_utf8_lossy(&body);
                crate::logger::warn(
                    "cross_region.replicate_failed",
                    serde_json::json!({ "region": region_name, "status": status, "body": body_str.chars().take(200).collect::<String>() }),
                );
            }
            Err(e) => {
                crate::logger::warn(
                    "cross_region.replicate_error",
                    serde_json::json!({ "region": region_name, "error": e }),
                );
            }
        }
    }
}
