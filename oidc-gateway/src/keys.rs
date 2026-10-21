#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint_dig::BigUint;
use rsa::pkcs1v15::VerifyingKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub struct SigningKeyPair {
    pub kid: String,
    pub verifying_key: VerifyingKey<Sha256>,
    pub jwk: serde_json::Value,
    #[allow(dead_code)]
    pub created_at: u64,
}

pub struct RetiredKey {
    pub kid: String,
    pub verifying_key: VerifyingKey<Sha256>,
    pub jwk: serde_json::Value,
    /// Unix timestamp the key was retired; it leaves JWKS and stops verifying
    /// at `retired_at + key_manager::RETIRED_GRACE_SECS`.
    #[allow(dead_code)]
    pub retired_at: u64,
}

pub struct KeyStore {
    pub current: SigningKeyPair,
    pub previous: Vec<RetiredKey>,
}

impl KeyStore {
    /// Load signing keys from the key-manager component (JWK string cached).
    /// `previous` is populated with retired keys still within the verification
    /// grace period, so `jwks()` / `all_verifiers()` cover current + retired.
    pub async fn load() -> Result<Self, String> {
        let jwk_str = crate::key_manager::get_public_key().await?;
        let jwk: serde_json::Value = serde_json::from_str(&jwk_str).map_err(|e| e.to_string())?;

        let kid = jwk
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or("JWK missing kid")?
            .to_string();
        let verifying_key = verifying_key_from_jwk(&jwk)?;

        let current = SigningKeyPair {
            kid,
            verifying_key,
            jwk,
            created_at: 0,
        };

        let mut previous = Vec::new();
        let retired = crate::key_manager::get_retired_public_keys()
            .await
            .unwrap_or_default();
        for (kid, retired_at, jwk_str) in retired {
            let jwk: serde_json::Value = match serde_json::from_str(&jwk_str) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match verifying_key_from_jwk(&jwk) {
                Ok(verifying_key) => previous.push(RetiredKey {
                    kid,
                    verifying_key,
                    jwk,
                    retired_at,
                }),
                Err(_) => continue,
            }
        }

        Ok(Self { current, previous })
    }

    /// Combined JWKS including current key and all active retired keys.
    pub fn jwks(&self) -> serde_json::Value {
        let mut keys = vec![self.current.jwk.clone()];
        for prev in &self.previous {
            keys.push(prev.jwk.clone());
        }
        serde_json::json!({ "keys": keys })
    }

    /// All verifying keys (current + retired) as (kid, key) pairs.
    pub fn all_verifiers(&self) -> Vec<(&str, &VerifyingKey<Sha256>)> {
        let mut result = vec![(self.current.kid.as_str(), &self.current.verifying_key)];
        for prev in &self.previous {
            result.push((prev.kid.as_str(), &prev.verifying_key));
        }
        result
    }

    /// Restore a key store from previously exported data.
    fn import(data: &serde_json::Value) -> Result<Self, String> {
        let exported: ExportedKeyStore =
            serde_json::from_value(data.clone()).map_err(|e| format!("deserialize keys: {e}"))?;

        let n = decode_biguint(&exported.current.n, "n")?;
        let e = decode_biguint(&exported.current.e, "e")?;
        let d = decode_biguint(&exported.current.d, "d")?;
        let primes: Vec<BigUint> = exported
            .current
            .primes
            .iter()
            .enumerate()
            .map(|(i, p)| decode_biguint(p, &format!("prime[{i}]")))
            .collect::<Result<Vec<_>, _>>()?;

        let private_key = RsaPrivateKey::from_components(n, e, d, primes)
            .map_err(|e| format!("reconstruct private key: {e}"))?;
        let public_key = RsaPublicKey::from(&private_key);

        let jwk = build_jwk(&public_key, &exported.current.kid);

        let current = SigningKeyPair {
            kid: exported.current.kid,
            verifying_key: VerifyingKey::<Sha256>::new(public_key),
            jwk,
            created_at: exported.current.created_at,
        };

        let mut previous = Vec::new();
        for rk in exported.previous {
            let n_b64 = rk
                .jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or("retired JWK missing n")?;
            let e_b64 = rk
                .jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or("retired JWK missing e")?;
            let n = decode_biguint(n_b64, "retired n")?;
            let e = decode_biguint(e_b64, "retired e")?;
            let public_key = RsaPublicKey::new(n, e)
                .map_err(|e| format!("reconstruct retired public key: {e}"))?;
            previous.push(RetiredKey {
                kid: rk.kid,
                verifying_key: VerifyingKey::<Sha256>::new(public_key),
                jwk: rk.jwk,
                retired_at: rk.retired_at,
            });
        }

        Ok(Self { current, previous })
    }
}

// ── Serialization types (must match key-manager's export format) ──

#[derive(Serialize, Deserialize)]
struct ExportedKeyStore {
    current: ExportedSigningKey,
    previous: Vec<ExportedRetiredKey>,
}

#[derive(Serialize, Deserialize)]
struct ExportedSigningKey {
    kid: String,
    created_at: u64,
    n: String,
    e: String,
    d: String,
    primes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ExportedRetiredKey {
    kid: String,
    retired_at: u64,
    jwk: serde_json::Value,
}

fn verifying_key_from_jwk(jwk: &serde_json::Value) -> Result<VerifyingKey<Sha256>, String> {
    let n_b64 = jwk
        .get("n")
        .and_then(|v| v.as_str())
        .ok_or("JWK missing n")?;
    let e_b64 = jwk
        .get("e")
        .and_then(|v| v.as_str())
        .ok_or("JWK missing e")?;
    let n = decode_biguint(n_b64, "n")?;
    let e = decode_biguint(e_b64, "e")?;
    let public_key = RsaPublicKey::new(n, e).map_err(|e| e.to_string())?;
    Ok(VerifyingKey::<Sha256>::new(public_key))
}

fn decode_biguint(b64: &str, label: &str) -> Result<BigUint, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("decode {label}: {e}"))?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn build_jwk(public_key: &RsaPublicKey, kid: &str) -> serde_json::Value {
    serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
    })
}
