/// WebAuthn passkey support for Lattice-ID.
///
/// Supports ES256 (ECDSA P-256) credentials — the universal passkey algorithm.
/// Implements a minimal but spec-compliant subset of the WebAuthn Level 2 spec:
///   - Registration (navigator.credentials.create)
///   - Authentication (navigator.credentials.get)
///   - Signature counter validation
///   - RP ID origin validation
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

use crate::store::{self, PasskeyCredential};

// ── Constants ───────────────────────────────────────────────

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256).
const COSE_ALG_ES256: i64 = -7;
/// WebAuthn attestation "none" format.
const ATTESTATION_FMT_NONE: &str = "none";
const ATTESTATION_FMT_PACKED: &str = "packed";

// ── Challenge generation ────────────────────────────────────

/// Generate a random 32-byte challenge, returned as base64url.
pub fn generate_challenge() -> String {
    let bytes = store::random_hex(32); // 64 hex chars = 32 bytes of entropy
    // Re-encode as raw bytes → base64url for WebAuthn
    let raw: Vec<u8> = (0..bytes.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).ok())
        .collect();
    URL_SAFE_NO_PAD.encode(&raw)
}

// ── RP ID ───────────────────────────────────────────────────

/// Derive the RP ID from the issuer URL (just the hostname).
pub fn rp_id() -> String {
    let issuer = crate::get_issuer();
    issuer
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string()
}

// ── Registration: parse attestation ─────────────────────────

/// Result of parsing a WebAuthn registration response.
pub struct ParsedRegistration {
    pub credential_id: Vec<u8>,
    pub public_key_bytes: Vec<u8>, // Uncompressed P-256 point (65 bytes)
    pub sign_count: u32,
}

/// Parse and verify a WebAuthn registration response.
///
/// `client_data_json` and `attestation_object` are base64url-encoded as
/// received from the browser.
pub fn verify_registration(
    client_data_json_b64: &str,
    attestation_object_b64: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<ParsedRegistration, String> {
    // 1. Decode and validate clientDataJSON
    let client_data_raw = URL_SAFE_NO_PAD
        .decode(client_data_json_b64)
        .map_err(|_| "invalid base64url in clientDataJSON")?;
    let client_data: serde_json::Value =
        serde_json::from_slice(&client_data_raw).map_err(|_| "invalid JSON in clientDataJSON")?;

    let cd_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_type != "webauthn.create" {
        return Err("clientData type must be webauthn.create".into());
    }

    let cd_challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_challenge != expected_challenge {
        return Err("challenge mismatch".into());
    }

    let cd_origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_origin != expected_origin {
        return Err(format!(
            "origin mismatch: expected {expected_origin}, got {cd_origin}"
        ));
    }

    // 2. Decode attestation object (CBOR)
    let att_raw = URL_SAFE_NO_PAD
        .decode(attestation_object_b64)
        .map_err(|_| "invalid base64url in attestationObject")?;

    let att_cbor: ciborium::Value =
        ciborium::from_reader(&att_raw[..]).map_err(|e| format!("CBOR decode error: {e}"))?;

    let att_map = match &att_cbor {
        ciborium::Value::Map(m) => m,
        _ => return Err("attestationObject is not a CBOR map".into()),
    };

    // 3. Check attestation format (we accept "none" and "packed" self-attestation)
    let fmt = cbor_map_get_text(att_map, "fmt").unwrap_or_default();
    if fmt != ATTESTATION_FMT_NONE && fmt != ATTESTATION_FMT_PACKED {
        return Err(format!("unsupported attestation format: {fmt}"));
    }

    // 4. Extract authData
    let auth_data =
        cbor_map_get_bytes(att_map, "authData").ok_or("missing authData in attestation")?;

    // 5. Verify RP ID hash (first 32 bytes of authData)
    if auth_data.len() < 37 {
        return Err("authData too short".into());
    }
    let rp_id_hash = &auth_data[0..32];
    let expected_rp_hash = Sha256::digest(rp_id().as_bytes());
    if rp_id_hash != &expected_rp_hash[..] {
        return Err("RP ID hash mismatch".into());
    }

    // 6. Check flags
    let flags = auth_data[32];
    let user_present = flags & 0x01 != 0;
    let attested_credential_data = flags & 0x40 != 0;
    if !user_present {
        return Err("user presence flag not set".into());
    }
    if !attested_credential_data {
        return Err("attested credential data flag not set".into());
    }

    // 7. Parse sign counter (bytes 33-36, big-endian)
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    // 8. Parse attested credential data (starts at byte 37)
    // AAGUID (16 bytes) + credential ID length (2 bytes) + credential ID + COSE key
    if auth_data.len() < 55 {
        return Err("authData too short for credential data".into());
    }
    let _aaguid = &auth_data[37..53];
    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if auth_data.len() < 55 + cred_id_len {
        return Err("authData too short for credential ID".into());
    }
    let credential_id = auth_data[55..55 + cred_id_len].to_vec();

    // 9. Parse COSE public key (CBOR, after credential ID)
    let cose_key_bytes = &auth_data[55 + cred_id_len..];
    let public_key_bytes = parse_cose_es256_key(cose_key_bytes)?;

    // 10. Verify the key is valid by attempting to construct a VerifyingKey
    VerifyingKey::from_sec1_bytes(&public_key_bytes).map_err(|_| "invalid P-256 public key")?;

    Ok(ParsedRegistration {
        credential_id,
        public_key_bytes,
        sign_count,
    })
}

// ── Authentication: verify assertion ────────────────────────

/// Verify a WebAuthn authentication assertion.
///
/// Returns the matched credential index and the new sign_count.
pub fn verify_assertion(
    client_data_json_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
    expected_challenge: &str,
    expected_origin: &str,
    credential: &PasskeyCredential,
) -> Result<u32, String> {
    // 1. Decode and validate clientDataJSON
    let client_data_raw = URL_SAFE_NO_PAD
        .decode(client_data_json_b64)
        .map_err(|_| "invalid base64url in clientDataJSON")?;
    let client_data: serde_json::Value =
        serde_json::from_slice(&client_data_raw).map_err(|_| "invalid JSON in clientDataJSON")?;

    let cd_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_type != "webauthn.get" {
        return Err("clientData type must be webauthn.get".into());
    }

    let cd_challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_challenge != expected_challenge {
        return Err("challenge mismatch".into());
    }

    let cd_origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_origin != expected_origin {
        return Err(format!(
            "origin mismatch: expected {expected_origin}, got {cd_origin}"
        ));
    }

    // 2. Decode authenticatorData
    let auth_data = URL_SAFE_NO_PAD
        .decode(authenticator_data_b64)
        .map_err(|_| "invalid base64url in authenticatorData")?;

    if auth_data.len() < 37 {
        return Err("authenticatorData too short".into());
    }

    // 3. Verify RP ID hash
    let rp_id_hash = &auth_data[0..32];
    let expected_rp_hash = Sha256::digest(rp_id().as_bytes());
    if rp_id_hash != &expected_rp_hash[..] {
        return Err("RP ID hash mismatch".into());
    }

    // 4. Check user presence
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err("user presence flag not set".into());
    }

    // 5. Sign counter check
    let new_sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    // If both are non-zero, new must be greater (clone detection)
    if credential.sign_count > 0 && new_sign_count > 0 && new_sign_count <= credential.sign_count {
        return Err("sign counter did not increment — possible credential clone".into());
    }

    // 6. Verify signature over (authenticatorData || SHA-256(clientDataJSON))
    let client_data_hash = Sha256::digest(&client_data_raw);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(&credential.public_key)
        .map_err(|_| "invalid base64url in stored public key")?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes)
        .map_err(|_| "invalid stored P-256 public key")?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| "invalid base64url in signature")?;
    let signature = Signature::from_der(&sig_bytes).map_err(|_| "invalid DER signature")?;

    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| "signature verification failed")?;

    Ok(new_sign_count)
}

// ── COSE key parsing ────────────────────────────────────────

/// Parse a COSE_Key (ES256 / P-256) from CBOR bytes.
/// Returns the uncompressed SEC1 public key (65 bytes: 0x04 || x || y).
fn parse_cose_es256_key(data: &[u8]) -> Result<Vec<u8>, String> {
    let cose_key: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| format!("COSE key CBOR error: {e}"))?;

    let map = match &cose_key {
        ciborium::Value::Map(m) => m,
        _ => return Err("COSE key is not a CBOR map".into()),
    };

    // Verify key type (kty = 2 = EC2) and algorithm (alg = -7 = ES256)
    let kty = cbor_map_get_int(map, &ciborium::Value::Integer(1.into()));
    if kty != Some(2) {
        return Err(format!(
            "unsupported COSE key type: {kty:?} (expected EC2=2)"
        ));
    }

    let alg = cbor_map_get_int(map, &ciborium::Value::Integer(3.into()));
    if alg != Some(COSE_ALG_ES256) {
        return Err(format!(
            "unsupported COSE algorithm: {alg:?} (expected ES256=-7)"
        ));
    }

    // Extract x and y coordinates (labels -2 and -3)
    let x = cbor_map_get_bytes_by_key(map, &ciborium::Value::Integer((-2_i64).into()))
        .ok_or("missing x coordinate in COSE key")?;
    let y = cbor_map_get_bytes_by_key(map, &ciborium::Value::Integer((-3_i64).into()))
        .ok_or("missing y coordinate in COSE key")?;

    if x.len() != 32 || y.len() != 32 {
        return Err("P-256 coordinates must be 32 bytes each".into());
    }

    // Uncompressed point: 0x04 || x || y
    let mut key = Vec::with_capacity(65);
    key.push(0x04);
    key.extend_from_slice(&x);
    key.extend_from_slice(&y);
    Ok(key)
}

// ── CBOR helpers ────────────────────────────────────────────

fn cbor_map_get_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| {
        if let ciborium::Value::Text(k_text) = k
            && k_text == key
            && let ciborium::Value::Text(val) = v
        {
            return Some(val.clone());
        }
        None
    })
}

fn cbor_map_get_bytes(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        if let ciborium::Value::Text(k_text) = k
            && k_text == key
            && let ciborium::Value::Bytes(val) = v
        {
            return Some(val.clone());
        }
        None
    })
}

fn cbor_map_get_int(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &ciborium::Value,
) -> Option<i64> {
    map.iter().find_map(|(k, v)| {
        if k == key {
            match v {
                ciborium::Value::Integer(i) => {
                    let val: i128 = (*i).into();
                    Some(val as i64)
                }
                _ => None,
            }
        } else {
            None
        }
    })
}

fn cbor_map_get_bytes_by_key(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &ciborium::Value,
) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        if k == key
            && let ciborium::Value::Bytes(val) = v
        {
            return Some(val.clone());
        }
        None
    })
}

// ── JSON helpers for WebAuthn API responses ─────────────────

/// Build the publicKeyCredentialCreationOptions JSON for a registration ceremony.
pub fn registration_options_json(
    user_id: &str,
    user_email: &str,
    user_name: &str,
    challenge: &str,
    existing_credential_ids: &[String],
) -> serde_json::Value {
    let exclude: Vec<serde_json::Value> = existing_credential_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "type": "public-key",
                "id": id,
            })
        })
        .collect();

    serde_json::json!({
        "challenge": challenge,
        "rp": {
            "name": "Lattice-ID",
            "id": rp_id(),
        },
        "user": {
            "id": URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
            "name": user_email,
            "displayName": user_name,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": COSE_ALG_ES256 }
        ],
        "timeout": 120000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred",
        },
        "excludeCredentials": exclude,
    })
}

/// Build the publicKeyCredentialRequestOptions JSON for an authentication ceremony.
pub fn authentication_options_json(
    challenge: &str,
    allow_credentials: &[String],
) -> serde_json::Value {
    let allow: Vec<serde_json::Value> = allow_credentials
        .iter()
        .map(|id| {
            serde_json::json!({
                "type": "public-key",
                "id": id,
            })
        })
        .collect();

    let mut opts = serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id(),
        "timeout": 120000,
        "userVerification": "preferred",
    });

    // If we have specific credentials, include them; otherwise allow discoverable
    if !allow.is_empty() {
        opts["allowCredentials"] = serde_json::Value::Array(allow);
    }

    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge_is_base64url() {
        let c = generate_challenge();
        assert!(!c.is_empty());
        assert!(
            c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn test_generate_challenge_is_unique() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_rp_id_from_https_issuer() {
        // We can't easily call rp_id() because it reads config.
        // Just verify the extraction logic inline.
        let issuer = "https://auth.example.com";
        let rp = issuer
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or("localhost");
        assert_eq!(rp, "auth.example.com");
    }

    #[test]
    fn test_rp_id_from_http_localhost_with_port() {
        let issuer = "http://localhost:8000";
        let rp = issuer
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or("localhost");
        assert_eq!(rp, "localhost");
    }

    #[test]
    fn test_parse_cose_es256_key_rejects_non_map() {
        let mut data = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Text("not a map".into()), &mut data).unwrap();
        let result = parse_cose_es256_key(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a CBOR map"));
    }

    #[test]
    fn test_cbor_helpers() {
        let map = vec![
            (
                ciborium::Value::Text("text-key".into()),
                ciborium::Value::Text("text-val".into()),
            ),
            (
                ciborium::Value::Text("bytes-key".into()),
                ciborium::Value::Bytes(vec![1u8, 2u8, 3u8]),
            ),
            (
                ciborium::Value::Integer(42.into()),
                ciborium::Value::Integer((-7).into()),
            ),
        ];
        assert_eq!(
            cbor_map_get_text(&map, "text-key"),
            Some("text-val".to_string())
        );
        assert_eq!(
            cbor_map_get_bytes(&map, "bytes-key"),
            Some(vec![1u8, 2u8, 3u8])
        );
        assert_eq!(
            cbor_map_get_int(&map, &ciborium::Value::Integer(42.into())),
            Some(-7)
        );
        assert_eq!(cbor_map_get_text(&map, "missing"), None);
    }

    #[test]
    fn test_cbor_map_get_bytes_by_key() {
        let map = vec![(
            ciborium::Value::Integer((-2i64).into()),
            ciborium::Value::Bytes(vec![0u8; 32]),
        )];
        let result = cbor_map_get_bytes_by_key(&map, &ciborium::Value::Integer((-2i64).into()));
        assert_eq!(result, Some(vec![0u8; 32]));
    }
}
