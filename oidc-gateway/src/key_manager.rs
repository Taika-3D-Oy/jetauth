use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey as EcSigningKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

const KEY_NAME: &str = "signing-key-v1";
const EC_KEY_NAME: &str = "signing-key-ec-v1";

fn keys_table() -> String {
    "keys".to_string()
}

// ── Persistence types ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKey {
    kid: String,
    n: String,
    e: String,
    d: String,
    primes: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEcKey {
    kid: String,
    d: String,
}

#[allow(dead_code)]
struct LoadedKeys {
    kid: String,
    rsa_jwk: String,
    ec_kid: String,
    ec_jwk: String,
    signing_key: SigningKey<Sha256>,
    ec_signing_key: EcSigningKey,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn decode_biguint(b64: &str, label: &str) -> Result<num_bigint_dig::BigUint, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("decode {label}: {e}"))?;
    Ok(num_bigint_dig::BigUint::from_bytes_be(&bytes))
}

fn generate_kid_rsa(pub_key: &RsaPublicKey) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(pub_key.n().to_bytes_be());
    hasher.update(pub_key.e().to_bytes_be());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&hash[..12])
}

fn build_jwk_string(pub_key: &RsaPublicKey, kid: &str) -> String {
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    })
    .to_string()
}

// ── RSA key loading / generation ──────────────────────────────────────────────

async fn load_from_db() -> Result<Option<StoredKey>, String> {
    match crate::store::kv_get_raw(&keys_table(), KEY_NAME).await? {
        Some(bytes) => {
            let stored: StoredKey =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialize key: {e}"))?;
            Ok(Some(stored))
        }
        None => Ok(None),
    }
}

async fn generate_and_store() -> Result<StoredKey, String> {
    let mut rng = p256::elliptic_curve::rand_core::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("RSA gen failed: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);
    let kid = generate_kid_rsa(&public_key);

    let stored = StoredKey {
        kid: kid.clone(),
        n: URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be()),
        d: URL_SAFE_NO_PAD.encode(private_key.d().to_bytes_be()),
        primes: private_key
            .primes()
            .iter()
            .map(|p| URL_SAFE_NO_PAD.encode(p.to_bytes_be()))
            .collect(),
    };

    let stored_bytes = serde_json::to_vec(&stored).map_err(|e| format!("serialize: {e}"))?;
    match crate::store::kv_create_raw(&keys_table(), KEY_NAME, &stored_bytes, None).await {
        Ok(()) => {
            eprintln!("KEY-MANAGER: generated and stored new signing key kid={kid}");
            Ok(stored)
        }
        Err(e) if e.contains("already exists") => {
            eprintln!("KEY-MANAGER: key race lost, loading existing key");
            load_from_db()
                .await?
                .ok_or_else(|| "key disappeared after race".to_string())
        }
        Err(e) => Err(format!("store key: {e}")),
    }
}

fn stored_key_to_parts(
    stored: &StoredKey,
) -> Result<(SigningKey<Sha256>, RsaPublicKey, String), String> {
    let n = decode_biguint(&stored.n, "n")?;
    let e = decode_biguint(&stored.e, "e")?;
    let d = decode_biguint(&stored.d, "d")?;
    let primes: Vec<num_bigint_dig::BigUint> = stored
        .primes
        .iter()
        .enumerate()
        .map(|(i, p)| decode_biguint(p, &format!("prime[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;

    let private_key = RsaPrivateKey::from_components(n, e, d, primes)
        .map_err(|e| format!("reconstruct key: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);
    let jwk = build_jwk_string(&public_key, &stored.kid);
    Ok((SigningKey::<Sha256>::new(private_key), public_key, jwk))
}

// ── EC key loading / generation ───────────────────────────────────────────────

async fn load_ec_from_db() -> Result<Option<StoredEcKey>, String> {
    match crate::store::kv_get_raw(&keys_table(), EC_KEY_NAME).await? {
        Some(bytes) => {
            let stored: StoredEcKey =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialize EC key: {e}"))?;
            Ok(Some(stored))
        }
        None => Ok(None),
    }
}

async fn generate_and_store_ec() -> Result<StoredEcKey, String> {
    let sk = EcSigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let scalar_bytes: Vec<u8> = sk.to_bytes().to_vec();
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let kid = {
        use sha2::Digest;
        let hash = Sha256::digest(point.as_bytes());
        URL_SAFE_NO_PAD.encode(&hash[..12])
    };

    let stored = StoredEcKey {
        kid: kid.clone(),
        d: URL_SAFE_NO_PAD.encode(&scalar_bytes),
    };

    let stored_bytes = serde_json::to_vec(&stored).map_err(|e| format!("serialize EC key: {e}"))?;
    match crate::store::kv_set_raw(&keys_table(), EC_KEY_NAME, &stored_bytes).await {
        Ok(()) => {
            eprintln!("KEY-MANAGER: generated and stored new EC signing key kid={kid}");
            Ok(stored)
        }
        Err(e) => {
            eprintln!("KEY-MANAGER: EC key store returned {e}, trying to load existing EC key");
            if let Ok(Some(existing)) = load_ec_from_db().await {
                return Ok(existing);
            }
            Err(format!("store EC key: {e}"))
        }
    }
}

fn stored_ec_to_parts(stored: &StoredEcKey) -> Result<(EcSigningKey, String), String> {
    let scalar_bytes = URL_SAFE_NO_PAD
        .decode(&stored.d)
        .map_err(|e| format!("decode EC key: {e}"))?;
    let sk = EcSigningKey::from_bytes(scalar_bytes.as_slice().into())
        .map_err(|e| format!("parse EC key: {e}"))?;
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let coords = point.coordinates();
    let (x_bytes, y_bytes) = match coords {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => return Err("expected uncompressed EC point".into()),
    };
    let jwk = serde_json::json!({
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "kid": stored.kid,
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x_bytes),
        "y": URL_SAFE_NO_PAD.encode(y_bytes),
    })
    .to_string();
    Ok((sk, jwk))
}

// ── Combined load ─────────────────────────────────────────────────────────────

async fn load_keys() -> Result<LoadedKeys, String> {
    let rsa_stored = match load_from_db().await? {
        Some(s) => s,
        None => generate_and_store().await?,
    };
    let ec_stored = match load_ec_from_db().await? {
        Some(s) => s,
        None => generate_and_store_ec().await?,
    };

    let (signing_key, _pub_key, rsa_jwk) = stored_key_to_parts(&rsa_stored)?;
    let (ec_signing_key, ec_jwk) = stored_ec_to_parts(&ec_stored)?;

    Ok(LoadedKeys {
        kid: rsa_stored.kid,
        rsa_jwk,
        ec_kid: ec_stored.kid,
        ec_jwk,
        signing_key,
        ec_signing_key,
    })
}

pub async fn get_public_key() -> Result<String, String> {
    let rsa_stored = match load_from_db().await? {
        Some(s) => s,
        None => generate_and_store().await?,
    };
    Ok(serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": rsa_stored.kid,
        "n": rsa_stored.n,
        "e": rsa_stored.e,
    })
    .to_string())
}

pub async fn get_public_keys() -> Result<String, String> {
    let t0 = crate::bindings::wasi::clocks::monotonic_clock::now();
    let rsa_stored = match load_from_db().await? {
        Some(s) => s,
        None => {
            eprintln!("KEY-MANAGER: RSA key not found in db, generating new RSA key");
            generate_and_store().await?
        }
    };
    let t_rsa = crate::bindings::wasi::clocks::monotonic_clock::now();
    let ec_stored = match load_ec_from_db().await {
        Ok(Some(s)) => Some(s),
        _ => generate_and_store_ec().await.ok(),
    };
    let t_ec = crate::bindings::wasi::clocks::monotonic_clock::now();
    let rsa_val = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": rsa_stored.kid,
        "n": rsa_stored.n,
        "e": rsa_stored.e,
    });
    let mut keys = vec![rsa_val];
    if let Some(ec_stored) = ec_stored
        && let Ok((_, ec_jwk)) = stored_ec_to_parts(&ec_stored)
        && let Ok(ec_val) = serde_json::from_str::<serde_json::Value>(&ec_jwk)
    {
        keys.push(ec_val);
    }
    let t_done = crate::bindings::wasi::clocks::monotonic_clock::now();
    eprintln!(
        "KEY-MANAGER TIMING: RSA load: {} ms, EC load: {} ms, total: {} ms",
        (t_rsa - t0) / 1_000_000,
        (t_ec - t_rsa) / 1_000_000,
        (t_done - t0) / 1_000_000,
    );
    serde_json::to_string(&keys).map_err(|e| format!("{e}"))
}

pub async fn get_kid() -> Result<String, String> {
    let rsa_stored = match load_from_db().await? {
        Some(s) => s,
        None => generate_and_store().await?,
    };
    Ok(rsa_stored.kid)
}

pub async fn sign_jwt(header: String, payload: String) -> Result<String, String> {
    let keys = load_keys().await?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&header)
        .map_err(|e| format!("decode header: {e}"))?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("parse header: {e}"))?;
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("RS256");

    let message = format!("{}.{}", header, payload);
    match alg {
        "RS256" => {
            let sig = keys.signing_key.sign(message.as_bytes());
            Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        }
        "ES256" => {
            use p256::ecdsa::signature::Signer as _;
            let sig: p256::ecdsa::Signature = keys.ec_signing_key.sign(message.as_bytes());
            Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        }
        _ => Err(format!("unsupported algorithm: {alg}")),
    }
}
