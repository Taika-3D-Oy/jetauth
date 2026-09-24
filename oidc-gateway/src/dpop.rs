use crate::jwt;
use crate::store;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Compute the access token hash (ath) per RFC 9449 §4.2:
/// base64url(SHA-256(ASCII(access_token)))
pub fn compute_ath(access_token: &str) -> String {
    let hash = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Validate a DPoP proof JWT per RFC 9449 §4.3.
/// Returns the computed RFC 7638 JWK thumbprint (`jkt`) on success.
pub async fn validate_dpop_proof(
    dpop_proof: &str,
    expected_method: &str,
    expected_uri: &str,
    access_token_for_ath: Option<&str>,
) -> Result<String, String> {
    let parts: Vec<&str> = dpop_proof.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid DPoP proof format".into());
    }

    let h_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("decode DPoP header: {e}"))?;
    let header: serde_json::Value =
        serde_json::from_slice(&h_bytes).map_err(|e| format!("parse DPoP header: {e}"))?;

    // typ must be "dpop+jwt" (RFC 9449 §4.3 item 1)
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if !typ.eq_ignore_ascii_case("dpop+jwt") {
        return Err(format!(
            "invalid DPoP typ: expected 'dpop+jwt', got '{typ}'"
        ));
    }

    // alg must be an asymmetric signing algorithm (RFC 9449 §4.3 item 2)
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" && alg != "ES256" {
        return Err(format!("unsupported DPoP algorithm: {alg}"));
    }

    // jwk must be present and MUST NOT contain private key material (RFC 9449 §4.3 item 3)
    let jwk = header.get("jwk").ok_or("missing jwk in DPoP header")?;
    if jwk.get("d").is_some() || jwk.get("p").is_some() || jwk.get("q").is_some() {
        return Err("DPoP jwk must not contain private key parameters".into());
    }

    // Verify signature with embedded JWK
    let (_h, payload) = jwt::verify_jwt_with_jwk(dpop_proof, jwk)
        .map_err(|e| format!("DPoP proof signature verification failed: {e}"))?;

    // Validate htm (RFC 9449 §4.3 item 4)
    let htm = payload
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or("missing htm claim in DPoP proof")?;
    if !htm.eq_ignore_ascii_case(expected_method) {
        return Err(format!(
            "DPoP htm mismatch: expected {expected_method}, got {htm}"
        ));
    }

    // Validate htu (RFC 9449 §4.3 item 5)
    let htu = payload
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or("missing htu claim in DPoP proof")?;
    if !uri_matches(htu, expected_uri) {
        return Err(format!(
            "DPoP htu mismatch: expected {expected_uri}, got {htu}"
        ));
    }

    // Validate iat (RFC 9449 §4.3 item 6)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or("missing iat claim in DPoP proof")?;
    if iat > now + 300 || now > iat + 300 {
        return Err("DPoP proof iat is outside the acceptable ±300s time window".into());
    }

    // If exp is present, verify not expired
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64())
        && now > exp
    {
        return Err("DPoP proof has expired".into());
    }

    // Validate ath if access_token_for_ath is provided (RFC 9449 §4.3 item 7)
    if let Some(token) = access_token_for_ath {
        let expected_ath = compute_ath(token);
        let ath = payload
            .get("ath")
            .and_then(|v| v.as_str())
            .ok_or("missing ath claim in DPoP proof")?;
        if ath != expected_ath {
            return Err("DPoP ath hash does not match presented access token".into());
        }
    }

    // Validate and record jti replay (RFC 9449 §4.3 item 8)
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or("missing jti claim in DPoP proof")?;
    if jti.is_empty() {
        return Err("empty jti claim in DPoP proof".into());
    }
    store::check_and_record_jti(jti, store::TTL_JTI)
        .await
        .map_err(|e| format!("DPoP jti replay: {e}"))?;

    // Compute RFC 7638 thumbprint of the JWK
    jwt::compute_jwk_thumbprint(jwk)
}

fn clean_uri(u: &str) -> &str {
    let without_query = u.split('?').next().unwrap_or(u);
    let without_frag = without_query.split('#').next().unwrap_or(without_query);
    without_frag.trim_end_matches('/')
}

fn uri_matches(proof_uri: &str, expected_uri: &str) -> bool {
    let p = clean_uri(proof_uri);
    let e = clean_uri(expected_uri);
    p.eq_ignore_ascii_case(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn test_dpop_proof_validation() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let x_b64 = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
        let y_b64 = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());

        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
        });

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let payload = serde_json::json!({
            "jti": format!("test_jti_{}", now),
            "htm": "POST",
            "htu": "https://auth.example.com/token",
            "iat": now
        });

        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let msg = format!("{h_b64}.{p_b64}");

        let sig: p256::ecdsa::Signature = signing_key.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let proof = format!("{msg}.{sig_b64}");

        let expected_jkt = jwt::compute_jwk_thumbprint(&jwk).unwrap();
        let ath = compute_ath("test_token_123");
        assert!(!ath.is_empty());
        assert!(!expected_jkt.is_empty());

        // 1. Valid DPoP proof
        let jkt = futures::executor::block_on(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/token",
            None,
        ))
        .expect("DPoP proof should be valid");
        assert_eq!(jkt, expected_jkt);

        // 2. Replay prevention: second call with same proof must fail (same jti)
        let replay_err = futures::executor::block_on(validate_dpop_proof(
            &proof,
            "POST",
            "https://auth.example.com/token",
            None,
        ));
        assert!(replay_err.is_err());
        assert!(replay_err.unwrap_err().contains("replay"));

        // 3. Test HTTP method mismatch
        let payload_get = serde_json::json!({
            "jti": format!("test_jti_get_{}", now),
            "htm": "GET",
            "htu": "https://auth.example.com/userinfo",
            "iat": now,
            "ath": ath
        });
        let p_get_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload_get).unwrap());
        let msg_get = format!("{h_b64}.{p_get_b64}");
        let sig_get: p256::ecdsa::Signature = signing_key.sign(msg_get.as_bytes());
        let proof_get = format!("{msg_get}.{}", URL_SAFE_NO_PAD.encode(sig_get.to_bytes()));

        // Mismatched method (passed POST instead of GET)
        let method_err = futures::executor::block_on(validate_dpop_proof(
            &proof_get,
            "POST",
            "https://auth.example.com/userinfo",
            Some("test_token_123"),
        ));
        assert!(method_err.is_err());
        assert!(method_err.unwrap_err().contains("htm"));

        // Mismatched URI
        let uri_err = futures::executor::block_on(validate_dpop_proof(
            &proof_get,
            "GET",
            "https://auth.example.com/wrong",
            Some("test_token_123"),
        ));
        assert!(uri_err.is_err());
        assert!(uri_err.unwrap_err().contains("htu"));

        // Cross-origin proof reuse attempt (same path, different host)
        let cross_origin_err = futures::executor::block_on(validate_dpop_proof(
            &proof_get,
            "GET",
            "https://attacker.example.com/userinfo",
            Some("test_token_123"),
        ));
        assert!(cross_origin_err.is_err());
        assert!(cross_origin_err.unwrap_err().contains("htu"));

        // Mismatched access token hash (ath)
        let ath_err = futures::executor::block_on(validate_dpop_proof(
            &proof_get,
            "GET",
            "https://auth.example.com/userinfo",
            Some("wrong_token"),
        ));
        assert!(ath_err.is_err());
        assert!(ath_err.unwrap_err().contains("ath"));

        // Valid with ath and matching parameters
        let valid_get = futures::executor::block_on(validate_dpop_proof(
            &proof_get,
            "GET",
            "https://auth.example.com/userinfo",
            Some("test_token_123"),
        ))
        .expect("DPoP proof with ath should be valid");
        assert_eq!(valid_get, expected_jkt);
    }
}
