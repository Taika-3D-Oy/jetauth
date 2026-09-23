use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint_dig::BigUint;
use p256::ecdsa::{
    Signature as EcSig, VerifyingKey as EcVerifyingKey, signature::Verifier as EcVerifier,
};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Sign a set of claims as an RS256 JWT using the imported key-manager.
pub async fn sign(claims: &serde_json::Value) -> Result<String, String> {
    let kid = crate::key_manager::get_kid().await?;

    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    });

    let h = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| format!("header encode: {e}"))?);
    let p = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|e| format!("claims encode: {e}"))?);

    let s = crate::key_manager::sign_jwt(h.clone(), p.clone()).await?;

    Ok(format!("{h}.{p}.{s}"))
}

/// Sign a set of claims as an ES256 JWT using the imported key-manager.
pub async fn sign_es256(claims: &serde_json::Value) -> Result<String, String> {
    // Fetch the EC kid from the JWKS (second key in the array)
    let keys_json = crate::key_manager::get_public_keys().await?;
    let keys: Vec<serde_json::Value> =
        serde_json::from_str(&keys_json).map_err(|e| format!("parse keys: {e}"))?;
    let ec_kid = keys
        .iter()
        .find(|k| k.get("kty").and_then(|v| v.as_str()) == Some("EC"))
        .and_then(|k| k.get("kid"))
        .and_then(|v| v.as_str())
        .ok_or("no EC key found")?
        .to_string();

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": ec_kid,
    });

    let h = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| format!("header encode: {e}"))?);
    let p = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|e| format!("claims encode: {e}"))?);

    let s = crate::key_manager::sign_jwt(h.clone(), p.clone()).await?;

    Ok(format!("{h}.{p}.{s}"))
}

/// Sign id_token claims using the algorithm the client configured
/// (`id_token_signed_response_alg`). Defaults to RS256.
pub async fn sign_id_token_for_client(
    claims: &serde_json::Value,
    client: &crate::store::OidcClient,
) -> Result<String, String> {
    match client.id_token_signed_response_alg.as_deref() {
        Some("ES256") => sign_es256(claims).await,
        _ => sign(claims).await,
    }
}

/// Verify an RS256 JWT and return the decoded claims.
pub fn verify(
    token: &str,
    verifiers: &[(&str, &VerifyingKey<Sha256>)],
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }
    let (h_b64, p_b64, s_b64) = (parts[0], parts[1], parts[2]);

    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h_b64)
            .map_err(|e| format!("header decode: {e}"))?,
    )
    .map_err(|e| format!("header parse: {e}"))?;

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(format!("unsupported algorithm: {alg}"));
    }

    let message = format!("{h_b64}.{p_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s_b64)
        .map_err(|e| format!("signature decode: {e}"))?;
    let sig =
        Signature::try_from(sig_bytes.as_slice()).map_err(|e| format!("bad signature: {e}"))?;

    let token_kid = header.get("kid").and_then(|v| v.as_str());
    let candidates: Vec<&&VerifyingKey<Sha256>> = if let Some(kid) = token_kid {
        verifiers
            .iter()
            .filter(|(k, _)| *k == kid)
            .map(|(_, v)| v)
            .collect()
    } else {
        verifiers.iter().map(|(_, v)| v).collect()
    };

    if candidates.is_empty() {
        return Err("no matching signing key found".into());
    }

    let mut last_err = String::new();
    for vk in &candidates {
        match vk.verify(message.as_bytes(), &sig) {
            Ok(()) => {
                let claims: serde_json::Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(p_b64)
                        .map_err(|e| format!("payload decode: {e}"))?,
                )
                .map_err(|e| format!("payload parse: {e}"))?;

                if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now > exp {
                        return Err("token expired".into());
                    }
                }
                return Ok(claims);
            }
            Err(e) => {
                last_err = format!("verification failed: {e}");
            }
        }
    }

    Err(last_err)
}

/// Compute RFC 7638 JWK Thumbprint (SHA-256 base64url-encoded).
pub fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("missing kty")?;

    let canonical = match kty {
        "RSA" => {
            let e = jwk.get("e").and_then(|v| v.as_str()).ok_or("missing e")?;
            let n = jwk.get("n").and_then(|v| v.as_str()).ok_or("missing n")?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or("missing crv")?;
            let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("missing x")?;
            let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("missing y")?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        other => return Err(format!("unsupported kty for thumbprint: {other}")),
    };

    let hash = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Verify a JWT signature using a specific JWK public key.
/// Returns (header, payload) on success.
pub fn verify_jwt_with_jwk(
    token: &str,
    jwk: &serde_json::Value,
) -> Result<(serde_json::Value, serde_json::Value), String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }
    let (h_b64, p_b64, s_b64) = (parts[0], parts[1], parts[2]);

    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h_b64)
            .map_err(|e| format!("header decode: {e}"))?,
    )
    .map_err(|e| format!("header parse: {e}"))?;

    let payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(p_b64)
            .map_err(|e| format!("payload decode: {e}"))?,
    )
    .map_err(|e| format!("payload parse: {e}"))?;

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let message = format!("{h_b64}.{p_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s_b64)
        .map_err(|e| format!("signature decode: {e}"))?;

    match alg {
        "RS256" => {
            let n_str = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or("missing n in RSA JWK")?;
            let e_str = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or("missing e in RSA JWK")?;
            let n_bytes = URL_SAFE_NO_PAD
                .decode(n_str)
                .map_err(|e| format!("decode n: {e}"))?;
            let e_bytes = URL_SAFE_NO_PAD
                .decode(e_str)
                .map_err(|e| format!("decode e: {e}"))?;
            let n = BigUint::from_bytes_be(&n_bytes);
            let e = BigUint::from_bytes_be(&e_bytes);
            let pub_key = RsaPublicKey::new(n, e).map_err(|e| format!("invalid RSA key: {e}"))?;
            let verifier = VerifyingKey::<Sha256>::new(pub_key);
            let sig = Signature::try_from(sig_bytes.as_slice())
                .map_err(|e| format!("bad RS256 signature: {e}"))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| format!("RS256 verification failed: {e}"))?;
        }
        "ES256" => {
            let x_str = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or("missing x in EC JWK")?;
            let y_str = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or("missing y in EC JWK")?;
            let x = URL_SAFE_NO_PAD
                .decode(x_str)
                .map_err(|e| format!("decode x: {e}"))?;
            let y = URL_SAFE_NO_PAD
                .decode(y_str)
                .map_err(|e| format!("decode y: {e}"))?;
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let vk = EcVerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| format!("invalid EC key: {e}"))?;
            let sig = EcSig::from_bytes(sig_bytes.as_slice().into())
                .or_else(|_| EcSig::from_der(&sig_bytes))
                .map_err(|e| format!("bad ES256 signature: {e}"))?;
            EcVerifier::verify(&vk, message.as_bytes(), &sig)
                .map_err(|e| format!("ES256 verification failed: {e}"))?;
        }
        other => return Err(format!("unsupported signature algorithm: {other}")),
    }

    Ok((header, payload))
}

/// Verify a JWT signature using a JWKS (set of keys).
/// If `jwks` contains a `"keys"` array, inspects matching keys (by `kid` if present, and `kty`/`alg`).
/// Returns (header, payload) on success.
pub fn verify_jwt_with_jwks(
    token: &str,
    jwks: &serde_json::Value,
) -> Result<(serde_json::Value, serde_json::Value), String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }
    let h_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("header decode: {e}"))?;
    let header: serde_json::Value =
        serde_json::from_slice(&h_bytes).map_err(|e| format!("header parse: {e}"))?;

    let kid = header.get("kid").and_then(|v| v.as_str());
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    let empty_vec = Vec::new();
    let keys: Vec<&serde_json::Value> =
        if let Some(arr) = jwks.get("keys").and_then(|v| v.as_array()) {
            arr.iter().collect()
        } else if jwks.get("kty").is_some() {
            vec![jwks]
        } else {
            empty_vec
        };

    let expected_kty = match alg {
        "RS256" => Some("RSA"),
        "ES256" => Some("EC"),
        _ => None,
    };

    let candidates: Vec<&&serde_json::Value> = keys
        .iter()
        .filter(|k| expected_kty.is_none() || k.get("kty").and_then(|v| v.as_str()) == expected_kty)
        .filter(|k| kid.is_none() || k.get("kid").and_then(|v| v.as_str()) == kid)
        .collect();

    if candidates.is_empty() {
        return Err("no matching public key found in JWKS".into());
    }

    let mut last_err = String::from("signature verification failed");
    for key in candidates {
        match verify_jwt_with_jwk(token, key) {
            Ok(result) => return Ok(result),
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_header_payload_encoding_roundtrip() {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "test-kid"});
        let claims = serde_json::json!({"sub": "user1", "iss": "test"});
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

        // Decode and verify roundtrip
        let h_decoded: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&h).unwrap()).unwrap();
        let p_decoded: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&p).unwrap()).unwrap();
        assert_eq!(h_decoded["alg"], "RS256");
        assert_eq!(p_decoded["sub"], "user1");
    }

    #[test]
    fn test_rfc7638_rsa_thumbprint() {
        // RFC 7638 Section 3.1 example
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        let jkt = compute_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(jkt, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn test_rfc7638_ec_thumbprint() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xFMTbKEgahAcx3nvZZLtGs8maIjMmNSTtKE",
            "y": "x_daQauqm0EwQSkKLZ0REv05-UHCYV307jfCXdK-FWQV"
        });
        let jkt = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!jkt.is_empty());
    }

    #[test]
    fn test_verify_jwt_with_jwk_es256() {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use p256::elliptic_curve::rand_core::OsRng;

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

        let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
        let payload = serde_json::json!({"sub": "test_user", "iss": "https://id.example.com"});
        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let msg = format!("{h_b64}.{p_b64}");

        let sig: EcSig = signing_key.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{msg}.{sig_b64}");

        let (verified_header, verified_payload) = verify_jwt_with_jwk(&token, &jwk).unwrap();
        assert_eq!(verified_header["alg"], "ES256");
        assert_eq!(verified_payload["sub"], "test_user");

        // Verify with JWKS container
        let jwks = serde_json::json!({ "keys": [jwk] });
        let (_, verified_from_jwks) = verify_jwt_with_jwks(&token, &jwks).unwrap();
        assert_eq!(verified_from_jwks["sub"], "test_user");
    }
}
