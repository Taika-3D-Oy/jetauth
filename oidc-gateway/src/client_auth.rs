use crate::jwt;
use crate::store::{self, OidcClient};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub struct AuthenticatedClient {
    pub client: OidcClient,
    pub auth_method: String,
}

/// Authenticate an OAuth 2.0 / OIDC client across endpoints (RFC 6749, RFC 7523).
/// Supports `client_secret_basic`, `client_secret_post`, `private_key_jwt`, and `none`.
pub async fn authenticate_client(
    form: &[(String, String)],
    auth_header: Option<&str>,
    issuer: &str,
    expected_endpoint: &str,
) -> Result<AuthenticatedClient, String> {
    let get_form = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let basic_auth = parse_basic_auth(auth_header);
    let form_client_id = get_form("client_id");
    let form_client_secret = get_form("client_secret");
    let client_assertion_type = get_form("client_assertion_type");
    let client_assertion = get_form("client_assertion");

    let has_basic = basic_auth.is_some();
    let has_form_secret = form_client_secret.is_some();
    let has_assertion = client_assertion.is_some() || client_assertion_type.is_some();

    // RFC 6749 §2.3: client MUST NOT use more than one authentication method
    let method_count = (has_basic as u8) + (has_form_secret as u8) + (has_assertion as u8);
    if method_count > 1 {
        return Err(
            "client authentication failed: multiple client authentication methods presented".into(),
        );
    }

    let auth_client = if let Some((basic_id, basic_secret)) = basic_auth {
        if let Some(fid) = form_client_id
            && fid != basic_id
        {
            return Err("client_id mismatch between Authorization header and request body".into());
        }
        let client = store::get_client(&basic_id)
            .await?
            .ok_or_else(|| format!("unknown client_id: {basic_id}"))?;
        verify_secret(&client, Some(&basic_secret))?;
        AuthenticatedClient {
            client,
            auth_method: "client_secret_basic".into(),
        }
    } else if let Some(assertion) = client_assertion {
        let assertion_type = client_assertion_type.ok_or("missing client_assertion_type")?;
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(format!(
                "unsupported client_assertion_type: {assertion_type}"
            ));
        }

        // Decode unverified header/payload to find client_id (sub)
        let parts: Vec<&str> = assertion.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("invalid client_assertion JWT format".into());
        }
        let p_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .map_err(|e| format!("decode client_assertion payload: {e}"))?;
        let unverified_payload: serde_json::Value = serde_json::from_slice(&p_bytes)
            .map_err(|e| format!("parse client_assertion payload: {e}"))?;

        let sub = unverified_payload
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or("missing sub claim in client_assertion")?;

        if let Some(fid) = form_client_id
            && fid != sub
        {
            return Err(
                "client_id in request body does not match sub claim in client_assertion".into(),
            );
        }

        let client = store::get_client(sub)
            .await?
            .ok_or_else(|| format!("unknown client_id: {sub}"))?;

        let jwks = client.jwks.as_ref().ok_or_else(|| {
            format!("client {sub} does not have registered jwks for private_key_jwt")
        })?;

        let (_header, payload) = jwt::verify_jwt_with_jwks(assertion, jwks)
            .map_err(|e| format!("client_assertion signature verification failed: {e}"))?;

        // Validate claims per RFC 7523 §3
        let iss = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or("missing iss claim")?;
        if iss != sub {
            return Err(format!("invalid iss claim: expected {sub}, got {iss}"));
        }

        let expected_endpoint_clean = if expected_endpoint.starts_with('/') {
            expected_endpoint
        } else {
            &format!("/{expected_endpoint}")
        };
        let valid_audiences = [
            issuer.to_string(),
            format!("{issuer}{expected_endpoint_clean}"),
            format!("{issuer}/token"),
        ];
        let aud_ok = match payload.get("aud") {
            Some(serde_json::Value::String(s)) => valid_audiences.iter().any(|a| s == a),
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| {
                v.as_str()
                    .map(|s| valid_audiences.iter().any(|a| s == a))
                    .unwrap_or(false)
            }),
            _ => false,
        };
        if !aud_ok {
            return Err("invalid aud claim in client_assertion".into());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let exp = payload
            .get("exp")
            .and_then(|v| v.as_u64())
            .ok_or("missing exp claim")?;
        if now > exp {
            return Err("client_assertion has expired".into());
        }
        if exp > now + 600 {
            return Err("client_assertion validity period is too long (max 10 minutes)".into());
        }

        if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_u64())
            && nbf > now + 60
        {
            return Err("client_assertion not yet valid (nbf in future)".into());
        }

        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or("missing jti claim")?;
        store::check_and_record_jti(jti, store::TTL_JTI)
            .await
            .map_err(|e| format!("client_assertion jti replay: {e}"))?;

        AuthenticatedClient {
            client,
            auth_method: "private_key_jwt".into(),
        }
    } else if let Some(cid) = form_client_id {
        let client = store::get_client(cid)
            .await?
            .ok_or_else(|| format!("unknown client_id: {cid}"))?;

        if let Some(secret) = form_client_secret {
            verify_secret(&client, Some(secret))?;
            AuthenticatedClient {
                client,
                auth_method: "client_secret_post".into(),
            }
        } else {
            verify_secret(&client, None)?;
            AuthenticatedClient {
                client,
                auth_method: "none".into(),
            }
        }
    } else {
        return Err("client authentication failed: missing client credentials".into());
    };

    if let Some(expected) = auth_client.client.token_endpoint_auth_method.as_deref()
        && auth_client.auth_method != expected
    {
        return Err(format!(
            "client '{}' must use registered token_endpoint_auth_method '{}', but used '{}'",
            auth_client.client.client_id, expected, auth_client.auth_method
        ));
    }

    Ok(auth_client)
}

fn verify_secret(client: &OidcClient, client_secret: Option<&str>) -> Result<(), String> {
    if let Some(stored_hash) = &client.client_secret {
        match client_secret {
            Some(provided) => {
                let provided_hash = store::hmac_client_secret(provided);
                if provided_hash
                    .as_bytes()
                    .ct_eq(stored_hash.as_bytes())
                    .into()
                    || provided.as_bytes().ct_eq(stored_hash.as_bytes()).into()
                {
                    Ok(())
                } else {
                    Err("invalid client_secret".into())
                }
            }
            None => Err("client_secret required for confidential clients".into()),
        }
    } else {
        if client_secret.is_some() {
            if let Some(expected) = client.token_endpoint_auth_method.as_deref() {
                return Err(format!(
                    "client '{}' must use registered token_endpoint_auth_method '{expected}'",
                    client.client_id
                ));
            }
            return Err("public client cannot provide client_secret".into());
        }
        Ok(())
    }
}

pub fn parse_basic_auth(auth_header: Option<&str>) -> Option<(String, String)> {
    let header = auth_header?;
    let encoded = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = text.split_once(':')?;
    Some((
        crate::util::url_decode(client_id),
        crate::util::url_decode(client_secret),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_auth() {
        assert_eq!(parse_basic_auth(None), None);
        assert_eq!(parse_basic_auth(Some("Bearer xyz")), None);

        // Basic client:secret
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"my-client:my-secret",
        );
        let header = format!("Basic {encoded}");
        let (id, secret) = parse_basic_auth(Some(&header)).unwrap();
        assert_eq!(id, "my-client");
        assert_eq!(secret, "my-secret");
    }

    #[test]
    fn test_verify_secret_confidential_and_public() {
        store::init_config_for_test(true, Some("test_pepper_123456789012345678901234567890"));
        let mut client = OidcClient {
            client_id: "test-client".into(),
            ..Default::default()
        };

        // Public client
        assert!(verify_secret(&client, None).is_ok());
        assert!(verify_secret(&client, Some("not-allowed")).is_err());

        // Confidential client
        let raw_secret = "super-secret-password-123";
        client.client_secret = Some(store::hmac_client_secret(raw_secret));

        assert!(verify_secret(&client, Some(raw_secret)).is_ok());
        assert!(verify_secret(&client, Some("wrong-secret")).is_err());
        assert!(verify_secret(&client, None).is_err());
    }

    #[test]
    fn test_private_key_jwt_authentication() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use p256::ecdsa::{SigningKey, signature::Signer};
        use p256::elliptic_curve::rand_core::OsRng;

        futures::executor::block_on(async {
            store::init_config_for_test(false, Some("test_pepper_123456789012345678901234567890"));

            // 1. Generate ES256 key
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let encoded_pt = verifying_key.to_encoded_point(false);
            let x = URL_SAFE_NO_PAD.encode(encoded_pt.x().unwrap());
            let y = URL_SAFE_NO_PAD.encode(encoded_pt.y().unwrap());

            let jwk = serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
                "kid": "client-key-1"
            });
            let jwks = serde_json::json!({
                "keys": [jwk]
            });

            let client = store::OidcClient {
                client_id: "private-key-client".to_string(),
                client_secret: None,
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                post_logout_redirect_uris: vec![],
                grant_types: vec!["client_credentials".to_string()],
                name: "Private Key Client".to_string(),
                theme: None,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                id_token_signed_response_alg: None,
                first_party: false,
                token_endpoint_auth_method: Some("private_key_jwt".to_string()),
                jwks: Some(jwks),
                require_pushed_authorization_requests: false,
            };
            store::save_client(&client).await.unwrap();

            // 2. Build client assertion JWT
            let now = store::unix_now();
            let header = serde_json::json!({
                "alg": "ES256",
                "typ": "JWT",
                "kid": "client-key-1"
            });
            let payload = serde_json::json!({
                "iss": "private-key-client",
                "sub": "private-key-client",
                "aud": "https://auth.example.com/token",
                "jti": "random-jti-1234567890",
                "exp": now + 300,
                "iat": now
            });

            let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
            let signing_input = format!("{h_b64}.{p_b64}");
            let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
            let assertion = format!("{signing_input}.{sig_b64}");

            // 3. Authenticate client
            let form = vec![
                ("client_id".to_string(), "private-key-client".to_string()),
                (
                    "client_assertion_type".to_string(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
                ),
                ("client_assertion".to_string(), assertion.clone()),
            ];

            let res = authenticate_client(&form, None, "https://auth.example.com", "/token").await;
            assert!(res.is_ok(), "Client auth failed: {:?}", res.err());
            let auth_res = res.unwrap();
            assert_eq!(auth_res.client.client_id, "private-key-client");
            assert_eq!(auth_res.auth_method, "private_key_jwt");

            // 4. Test JTI replay prevention: second call with same assertion must fail
            let res_replay =
                authenticate_client(&form, None, "https://auth.example.com", "/token").await;
            assert!(res_replay.is_err());
            assert!(res_replay.unwrap_err().contains("replay"));

            // 5. Mismatched auth method should fail: trying client_secret_post or basic when registered for private_key_jwt
            let form_wrong_method =
                vec![("client_id".to_string(), "private-key-client".to_string())];
            let res_wrong = authenticate_client(
                &form_wrong_method,
                None,
                "https://auth.example.com",
                "/token",
            )
            .await;
            assert!(res_wrong.is_err());
            assert!(
                res_wrong
                    .unwrap_err()
                    .contains("must use registered token_endpoint_auth_method")
            );
        });
    }
}
