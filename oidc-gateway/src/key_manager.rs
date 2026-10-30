use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey as EcSigningKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Key records are stored under versioned names; the current generation number
/// lives in the ring metadata (`META_KEY`), CAS-guarded.
const RSA_KEY_PREFIX: &str = "signing-key-v";
const EC_KEY_PREFIX: &str = "signing-key-ec-v";
/// Ring metadata pointer: current generation + retired keys.
const META_KEY: &str = "meta:current";

/// How long a retired key stays in JWKS and remains valid for verification.
/// Derived from the maximum JWT lifetime in use: access, ID and backchannel
/// logout tokens are all issued with `exp = now + 3600` (see token.rs), plus a
/// 10-minute margin for clock skew and the 30s leeway applied at verification.
pub const RETIRED_GRACE_SECS: u64 = 3600 + 600;

fn keys_table() -> String {
    "keys".to_string()
}

fn rsa_key_name(version: u32) -> String {
    format!("{RSA_KEY_PREFIX}{version}")
}

fn ec_key_name(version: u32) -> String {
    format!("{EC_KEY_PREFIX}{version}")
}

// ── Persistence types ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    n: String,
    e: String,
    d: String,
    primes: Vec<String>,
    #[serde(default)]
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredEcKey {
    kid: String,
    d: String,
    #[serde(default)]
    created_at: u64,
}

/// A retired signing key: still published in JWKS (and accepted at
/// verification) until `retired_at + RETIRED_GRACE_SECS`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RetiredKeyMeta {
    pub kid: String,
    pub alg: String, // "RS256" | "ES256"
    /// KV key holding the stored private material.
    pub key_name: String,
    pub retired_at: u64,
}

/// The signing-key ring pointer. `signing-key-v{version}` /
/// `signing-key-ec-v{version}` are the current generation; everything in
/// `retired` is verifiable-only and dropped after the grace period.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyRingMeta {
    pub version: u32,
    pub rsa_kid: String,
    pub ec_kid: String,
    pub created_at: u64,
    #[serde(default)]
    pub retired: Vec<RetiredKeyMeta>,
}

/// Result of a successful rotation.
pub struct RotationOutcome {
    pub version: u32,
    pub rsa_kid: String,
    pub ec_kid: String,
    pub rsa_key_name: String,
    pub ec_key_name: String,
    pub retired: Vec<RetiredKeyMeta>,
    /// When the just-retired keys leave JWKS and stop verifying.
    pub grace_expires_at: u64,
}

/// Public description of one signing key for the management API.
pub struct KeyInfo {
    pub kid: String,
    pub alg: String,
    /// "current" | "retired" | "expired"
    pub status: String,
    pub version: u32,
    pub created_at: Option<u64>,
    pub retired_at: Option<u64>,
    pub grace_expires_at: Option<u64>,
}

struct LoadedKeys {
    signing_key: SigningKey<Sha256>,
    ec_signing_key: EcSigningKey,
}

// ── Time (injectable in tests) ────────────────────────────────────────────────

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::RefCell<Option<u64>> = const { std::cell::RefCell::new(None) };
}

fn now_secs() -> u64 {
    #[cfg(test)]
    if let Some(t) = TEST_NOW.with(|c| *c.borrow()) {
        return t;
    }
    crate::store::unix_now()
}

#[cfg(test)]
fn set_test_now(t: Option<u64>) {
    TEST_NOW.with(|c| *c.borrow_mut() = t);
}

/// A retired key is still valid for verification while within the grace window.
fn retired_active(r: &RetiredKeyMeta, now: u64) -> bool {
    r.retired_at.saturating_add(RETIRED_GRACE_SECS) > now
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

fn rsa_public_jwk(stored: &StoredKey) -> serde_json::Value {
    serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": stored.kid,
        "n": stored.n,
        "e": stored.e,
    })
}

// ── RSA key loading / generation ──────────────────────────────────────────────

async fn load_rsa_from_db(name: &str) -> Result<Option<StoredKey>, String> {
    match crate::store::kv_get_raw(&keys_table(), name).await? {
        Some(bytes) => {
            let stored: StoredKey =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialize key: {e}"))?;
            Ok(Some(stored))
        }
        None => Ok(None),
    }
}

/// Create a fresh RSA key under `name`, or adopt the record already stored
/// there if a concurrent writer won the create race.
async fn create_or_load_rsa_key(name: &str) -> Result<StoredKey, String> {
    let mut rng = rand_core::OsRng;
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
        created_at: now_secs(),
    };

    let stored_bytes = serde_json::to_vec(&stored).map_err(|e| format!("serialize: {e}"))?;
    match crate::store::kv_create_raw(&keys_table(), name, &stored_bytes, None).await {
        Ok(()) => {
            eprintln!("KEY-MANAGER: generated and stored new signing key {name} kid={kid}");
            Ok(stored)
        }
        Err(e) if e.contains("already exists") => {
            eprintln!("KEY-MANAGER: key race lost for {name}, loading existing key");
            load_rsa_from_db(name)
                .await?
                .ok_or_else(|| format!("key {name} disappeared after race"))
        }
        Err(e) => Err(format!("store key {name}: {e}")),
    }
}

fn stored_key_to_signing_key(stored: &StoredKey) -> Result<SigningKey<Sha256>, String> {
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
    Ok(SigningKey::<Sha256>::new(private_key))
}

// ── EC key loading / generation ───────────────────────────────────────────────

async fn load_ec_from_db(name: &str) -> Result<Option<StoredEcKey>, String> {
    match crate::store::kv_get_raw(&keys_table(), name).await? {
        Some(bytes) => {
            let stored: StoredEcKey =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialize EC key: {e}"))?;
            Ok(Some(stored))
        }
        None => Ok(None),
    }
}

async fn create_or_load_ec_key(name: &str) -> Result<StoredEcKey, String> {
    use p256::elliptic_curve::Generate;

    let sk = EcSigningKey::generate();
    let scalar_bytes: Vec<u8> = sk.to_bytes().to_vec();
    let vk = sk.verifying_key();
    let point = vk.to_sec1_point(false);
    let kid = {
        use sha2::Digest;
        let hash = Sha256::digest(point.as_bytes());
        URL_SAFE_NO_PAD.encode(&hash[..12])
    };

    let stored = StoredEcKey {
        kid: kid.clone(),
        d: URL_SAFE_NO_PAD.encode(&scalar_bytes),
        created_at: now_secs(),
    };

    let stored_bytes = serde_json::to_vec(&stored).map_err(|e| format!("serialize EC key: {e}"))?;
    match crate::store::kv_create_raw(&keys_table(), name, &stored_bytes, None).await {
        Ok(()) => {
            eprintln!("KEY-MANAGER: generated and stored new EC signing key {name} kid={kid}");
            Ok(stored)
        }
        Err(e) if e.contains("already exists") => {
            eprintln!("KEY-MANAGER: EC key race lost for {name}, loading existing EC key");
            load_ec_from_db(name)
                .await?
                .ok_or_else(|| format!("EC key {name} disappeared after race"))
        }
        Err(e) => Err(format!("store EC key {name}: {e}")),
    }
}

fn stored_ec_to_signing_key(stored: &StoredEcKey) -> Result<EcSigningKey, String> {
    let scalar_bytes = URL_SAFE_NO_PAD
        .decode(&stored.d)
        .map_err(|e| format!("decode EC key: {e}"))?;
    EcSigningKey::from_slice(&scalar_bytes).map_err(|e| format!("parse EC key: {e}"))
}

fn ec_public_jwk(stored: &StoredEcKey) -> Result<serde_json::Value, String> {
    let sk = stored_ec_to_signing_key(stored)?;
    let vk = sk.verifying_key();
    let point = vk.to_sec1_point(false);
    let coords = point.coordinates();
    let (x_bytes, y_bytes) = match coords {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => return Err("expected uncompressed EC point".into()),
    };
    Ok(serde_json::json!({
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "kid": stored.kid,
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x_bytes),
        "y": URL_SAFE_NO_PAD.encode(y_bytes),
    }))
}

// ── Ring metadata (CAS-guarded current pointer) ───────────────────────────────

/// Load the ring metadata with its KV revision for CAS updates.
/// Bootstraps (and persists) the metadata on first run.
async fn load_meta_with_revision() -> Result<(KeyRingMeta, u64), String> {
    match crate::store::kv_get_raw_with_revision(&keys_table(), META_KEY).await? {
        Some((bytes, revision)) => {
            let meta: KeyRingMeta = serde_json::from_slice(&bytes)
                .map_err(|e| format!("deserialize key ring metadata: {e}"))?;
            Ok((meta, revision))
        }
        None => bootstrap_meta().await,
    }
}

async fn load_meta() -> Result<KeyRingMeta, String> {
    Ok(load_meta_with_revision().await?.0)
}

/// First-run migration: adopt the legacy fixed-name v1 keys (generating them
/// if absent) as the current generation — no forced rotation — and persist the
/// ring pointer. The atomic create makes this safe under concurrent
/// first-touch; a lost race reloads the winner's metadata.
async fn bootstrap_meta() -> Result<(KeyRingMeta, u64), String> {
    let rsa = create_or_load_rsa_key(&rsa_key_name(1)).await?;
    let ec = create_or_load_ec_key(&ec_key_name(1)).await?;
    let meta = KeyRingMeta {
        version: 1,
        rsa_kid: rsa.kid,
        ec_kid: ec.kid,
        created_at: now_secs(),
        retired: Vec::new(),
    };
    let bytes = serde_json::to_vec(&meta).map_err(|e| format!("serialize metadata: {e}"))?;
    match crate::store::kv_create_raw(&keys_table(), META_KEY, &bytes, None).await {
        Ok(()) => Ok((meta, 1)),
        Err(e) if e.contains("already exists") => {
            match crate::store::kv_get_raw_with_revision(&keys_table(), META_KEY).await? {
                Some((bytes, revision)) => {
                    let meta: KeyRingMeta = serde_json::from_slice(&bytes)
                        .map_err(|e| format!("deserialize key ring metadata: {e}"))?;
                    Ok((meta, revision))
                }
                None => Err("key ring metadata disappeared after race".to_string()),
            }
        }
        Err(e) => Err(format!("store key ring metadata: {e}")),
    }
}

// ── Rotation ──────────────────────────────────────────────────────────────────

/// Rotate signing keys: generate a fresh RSA+EC pair as the next generation,
/// make it current, and retire the previous generation (both algs together —
/// the ring versions them as a unit). The metadata pointer is swapped with a
/// CAS, so a concurrent rotation loses cleanly and retries against the new
/// state; it can never corrupt the key set.
///
/// Orphan note: a rotation attempt that loses the CAS race may leave its
/// freshly generated key records behind, unreferenced by the metadata. They
/// are never signed with or published, and are overwritten by name on a later
/// rotation reaching the same version.
///
/// Multi-region note: signing keys are per-region (each region is its own OIDC
/// issuer — see MULTI_REGION.md), so rotation is a per-region operation and is
/// deliberately NOT replicated via `service_client::replicate_to_regions`.
pub async fn rotate_keys() -> Result<RotationOutcome, String> {
    const MAX_ATTEMPTS: usize = 5;
    for attempt in 0..MAX_ATTEMPTS {
        let now = now_secs();
        let (meta, revision) = load_meta_with_revision().await?;
        let new_version = meta.version + 1;
        let rsa_name = rsa_key_name(new_version);
        let ec_name = ec_key_name(new_version);

        // Persist the new pair first. If a concurrent rotation already stored
        // keys under these names we adopt them, so the metadata CAS'd below
        // always matches the stored material.
        let new_rsa = create_or_load_rsa_key(&rsa_name).await?;
        let new_ec = create_or_load_ec_key(&ec_name).await?;

        // Drop retired entries past their grace period, then retire the
        // outgoing generation.
        let mut retired: Vec<RetiredKeyMeta> = meta
            .retired
            .iter()
            .filter(|r| retired_active(r, now))
            .cloned()
            .collect();
        retired.push(RetiredKeyMeta {
            kid: meta.rsa_kid.clone(),
            alg: "RS256".to_string(),
            key_name: rsa_key_name(meta.version),
            retired_at: now,
        });
        retired.push(RetiredKeyMeta {
            kid: meta.ec_kid.clone(),
            alg: "ES256".to_string(),
            key_name: ec_key_name(meta.version),
            retired_at: now,
        });

        let new_meta = KeyRingMeta {
            version: new_version,
            rsa_kid: new_rsa.kid.clone(),
            ec_kid: new_ec.kid.clone(),
            created_at: now,
            retired,
        };
        let bytes =
            serde_json::to_vec(&new_meta).map_err(|e| format!("serialize metadata: {e}"))?;
        match crate::store::kv_cas_raw(&keys_table(), META_KEY, &bytes, revision, None).await {
            Ok(()) => {
                // Purge private material whose grace period has fully elapsed.
                for r in &meta.retired {
                    if !retired_active(r, now) {
                        let _ = crate::store::kv_delete(&keys_table(), &r.key_name).await;
                    }
                }
                eprintln!(
                    "KEY-MANAGER: rotated signing keys v{} -> v{} (rsa kid={}, ec kid={})",
                    meta.version, new_version, new_meta.rsa_kid, new_meta.ec_kid
                );
                return Ok(RotationOutcome {
                    version: new_version,
                    rsa_kid: new_meta.rsa_kid,
                    ec_kid: new_meta.ec_kid,
                    rsa_key_name: rsa_name,
                    ec_key_name: ec_name,
                    retired: new_meta.retired,
                    grace_expires_at: now + RETIRED_GRACE_SECS,
                });
            }
            Err(e) if e.contains("revision mismatch") && attempt + 1 < MAX_ATTEMPTS => {
                eprintln!("KEY-MANAGER: rotation CAS conflict, retrying ({attempt})");
                continue;
            }
            Err(e) => return Err(format!("rotate keys: {e}")),
        }
    }
    Err("rotate keys: too many concurrent rotations".to_string())
}

/// List all signing keys referenced by the ring metadata (current + retired).
/// Never exposes private material.
pub async fn list_keys() -> Result<Vec<KeyInfo>, String> {
    let meta = load_meta().await?;
    let now = now_secs();
    let mut out = Vec::new();

    let rsa_created = load_rsa_from_db(&rsa_key_name(meta.version))
        .await?
        .map(|s| s.created_at)
        .filter(|t| *t > 0)
        .or(Some(meta.created_at));
    out.push(KeyInfo {
        kid: meta.rsa_kid.clone(),
        alg: "RS256".to_string(),
        status: "current".to_string(),
        version: meta.version,
        created_at: rsa_created,
        retired_at: None,
        grace_expires_at: None,
    });
    let ec_created = load_ec_from_db(&ec_key_name(meta.version))
        .await?
        .map(|s| s.created_at)
        .filter(|t| *t > 0)
        .or(Some(meta.created_at));
    out.push(KeyInfo {
        kid: meta.ec_kid.clone(),
        alg: "ES256".to_string(),
        status: "current".to_string(),
        version: meta.version,
        created_at: ec_created,
        retired_at: None,
        grace_expires_at: None,
    });

    for r in &meta.retired {
        let status = if retired_active(r, now) {
            "retired"
        } else {
            "expired"
        };
        let created_at = match r.alg.as_str() {
            "RS256" => load_rsa_from_db(&r.key_name).await?.map(|s| s.created_at),
            "ES256" => load_ec_from_db(&r.key_name).await?.map(|s| s.created_at),
            _ => None,
        }
        .filter(|t| *t > 0);
        // key names are "<prefix>v{n}" — the version is the trailing number
        let version = r
            .key_name
            .rsplit('v')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        out.push(KeyInfo {
            kid: r.kid.clone(),
            alg: r.alg.clone(),
            status: status.to_string(),
            version,
            created_at,
            retired_at: Some(r.retired_at),
            grace_expires_at: Some(r.retired_at.saturating_add(RETIRED_GRACE_SECS)),
        });
    }

    Ok(out)
}

// ── Combined load ─────────────────────────────────────────────────────────────

async fn load_keys() -> Result<LoadedKeys, String> {
    let meta = load_meta().await?;
    let rsa_stored = load_rsa_from_db(&rsa_key_name(meta.version))
        .await?
        .ok_or_else(|| format!("current RSA signing key v{} missing", meta.version))?;
    let ec_stored = load_ec_from_db(&ec_key_name(meta.version))
        .await?
        .ok_or_else(|| format!("current EC signing key v{} missing", meta.version))?;

    Ok(LoadedKeys {
        signing_key: stored_key_to_signing_key(&rsa_stored)?,
        ec_signing_key: stored_ec_to_signing_key(&ec_stored)?,
    })
}

pub async fn get_public_key() -> Result<String, String> {
    let meta = load_meta().await?;
    let rsa_stored = load_rsa_from_db(&rsa_key_name(meta.version))
        .await?
        .ok_or_else(|| format!("current RSA signing key v{} missing", meta.version))?;
    Ok(rsa_public_jwk(&rsa_stored).to_string())
}

/// (kid, retired_at, public JWK JSON string) for retired RSA keys still within
/// the verification grace period.
pub async fn get_retired_public_keys() -> Result<Vec<(String, u64, String)>, String> {
    let meta = load_meta().await?;
    let now = now_secs();
    let mut out = Vec::new();
    for r in &meta.retired {
        if r.alg != "RS256" || !retired_active(r, now) {
            continue;
        }
        if let Some(stored) = load_rsa_from_db(&r.key_name).await? {
            out.push((
                stored.kid.clone(),
                r.retired_at,
                rsa_public_jwk(&stored).to_string(),
            ));
        }
    }
    Ok(out)
}

/// JWKS key array: current RSA + current EC first (signing keys), then retired
/// keys still within the grace window. Ordering matters: `jwt::sign_es256`
/// historically picked the first EC entry, and retired keys must never be
/// selected for signing.
pub async fn get_public_keys() -> Result<String, String> {
    let meta = load_meta().await?;
    let now = now_secs();
    let mut keys = Vec::new();

    let rsa_stored = load_rsa_from_db(&rsa_key_name(meta.version))
        .await?
        .ok_or_else(|| format!("current RSA signing key v{} missing", meta.version))?;
    keys.push(rsa_public_jwk(&rsa_stored));
    if let Some(ec_stored) = load_ec_from_db(&ec_key_name(meta.version)).await?
        && let Ok(ec_jwk) = ec_public_jwk(&ec_stored)
    {
        keys.push(ec_jwk);
    }

    for r in &meta.retired {
        if !retired_active(r, now) {
            // Grace fully elapsed — drop from JWKS and purge the stored
            // private material so nothing can ever sign or verify with it.
            let _ = crate::store::kv_delete(&keys_table(), &r.key_name).await;
            continue;
        }
        match r.alg.as_str() {
            "RS256" => {
                if let Some(stored) = load_rsa_from_db(&r.key_name).await? {
                    keys.push(rsa_public_jwk(&stored));
                }
            }
            "ES256" => {
                if let Some(stored) = load_ec_from_db(&r.key_name).await?
                    && let Ok(ec_jwk) = ec_public_jwk(&stored)
                {
                    keys.push(ec_jwk);
                }
            }
            _ => {}
        }
    }

    serde_json::to_string(&keys).map_err(|e| format!("{e}"))
}

/// kid of the current RSA (RS256) signing key.
pub async fn get_kid() -> Result<String, String> {
    Ok(load_meta().await?.rsa_kid)
}

/// kid of the current EC (ES256) signing key.
pub async fn get_ec_kid() -> Result<String, String> {
    Ok(load_meta().await?.ec_kid)
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

#[cfg(test)]
mod tests {
    use super::*;

    // The in-memory test KV is shared process-wide; key tests must not run
    // concurrently with each other (they all mutate the `keys` table).
    static KEY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    async fn wipe_keys() {
        crate::store::kv_delete(&keys_table(), META_KEY)
            .await
            .unwrap();
        for v in 1..=64 {
            let _ = crate::store::kv_delete(&keys_table(), &rsa_key_name(v)).await;
            let _ = crate::store::kv_delete(&keys_table(), &ec_key_name(v)).await;
        }
    }

    fn jwks_kids(jwks: &serde_json::Value) -> Vec<String> {
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn test_first_run_adopts_v1_and_rotation_increments_version() {
        let _guard = KEY_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            set_test_now(Some(1_000_000));
            wipe_keys().await;

            // First run: bootstrap adopts/generates v1 as current — no rotation.
            let kid1 = get_kid().await.unwrap();
            let meta1 = load_meta().await.unwrap();
            assert_eq!(meta1.version, 1);
            assert!(meta1.retired.is_empty());
            // Legacy fixed names are the v1 generation.
            assert!(
                crate::store::kv_get_raw(&keys_table(), "signing-key-v1")
                    .await
                    .unwrap()
                    .is_some()
            );

            // Rotation: v1 retired, v2 current, kids change.
            let out = rotate_keys().await.unwrap();
            assert_eq!(out.version, 2);
            assert_ne!(out.rsa_kid, kid1);
            assert_eq!(get_kid().await.unwrap(), out.rsa_kid);
            assert_eq!(out.retired.len(), 2); // RSA + EC of v1
            assert!(out.retired.iter().any(|r| r.kid == kid1));
            assert_eq!(out.grace_expires_at, 1_000_000 + RETIRED_GRACE_SECS);

            set_test_now(None);
        });
    }

    #[test]
    fn test_old_key_verifies_during_grace() {
        let _guard = KEY_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            set_test_now(Some(2_000_000));
            wipe_keys().await;

            // Sign with the pre-rotation key.
            let claims = serde_json::json!({
                "sub": "user1", "iss": "https://id.example.com", "exp": 2_000_000 + 3600
            });
            let token = crate::jwt::sign(&claims).await.unwrap();
            let old_kid = get_kid().await.unwrap();

            rotate_keys().await.unwrap();

            // Token signed by the retired key still verifies during grace.
            let jwks = crate::service_client::get_jwks().await.unwrap();
            let (header, payload) = crate::jwt::verify_jwt_with_jwks(&token, &jwks).unwrap();
            assert_eq!(header["kid"].as_str().unwrap(), old_kid);
            assert_eq!(payload["sub"], "user1");

            set_test_now(None);
        });
    }

    #[test]
    fn test_jwks_contains_current_and_retired_during_grace() {
        let _guard = KEY_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            set_test_now(Some(3_000_000));
            wipe_keys().await;

            let old_rsa_kid = get_kid().await.unwrap();
            let old_ec_kid = get_ec_kid().await.unwrap();
            let out = rotate_keys().await.unwrap();

            let jwks = crate::service_client::get_jwks().await.unwrap();
            let kids = jwks_kids(&jwks);
            assert_eq!(kids.len(), 4, "current + retired, both algs: {kids:?}");
            assert!(kids.contains(&old_rsa_kid));
            assert!(kids.contains(&old_ec_kid));
            assert!(kids.contains(&out.rsa_kid));
            assert!(kids.contains(&out.ec_kid));

            // New signatures use the new kids (both algs).
            let claims = serde_json::json!({"sub": "u", "exp": 3_000_000 + 3600});
            let tok_rsa = crate::jwt::sign(&claims).await.unwrap();
            let (h, _) = crate::jwt::verify_jwt_with_jwks(&tok_rsa, &jwks).unwrap();
            assert_eq!(h["kid"].as_str().unwrap(), out.rsa_kid);
            let tok_ec = crate::jwt::sign_es256(&claims).await.unwrap();
            let (h, _) = crate::jwt::verify_jwt_with_jwks(&tok_ec, &jwks).unwrap();
            assert_eq!(h["kid"].as_str().unwrap(), out.ec_kid);

            set_test_now(None);
        });
    }

    #[test]
    fn test_retired_key_dropped_after_grace() {
        let _guard = KEY_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            set_test_now(Some(4_000_000));
            wipe_keys().await;

            let claims = serde_json::json!({"sub": "u", "exp": 4_000_000 + 3600});
            let token = crate::jwt::sign(&claims).await.unwrap();
            let old_kid = get_kid().await.unwrap();
            rotate_keys().await.unwrap();

            // Advance past the grace period.
            set_test_now(Some(4_000_000 + RETIRED_GRACE_SECS + 1));

            let jwks = crate::service_client::get_jwks().await.unwrap();
            let kids = jwks_kids(&jwks);
            assert_eq!(kids.len(), 2, "only current RSA+EC remain: {kids:?}");
            assert!(!kids.contains(&old_kid));

            // The retired private material was purged from the store.
            assert!(
                crate::store::kv_get_raw(&keys_table(), "signing-key-v1")
                    .await
                    .unwrap()
                    .is_none()
            );

            // Tokens signed by the expired retired key are rejected.
            let err = crate::jwt::verify_jwt_with_jwks(&token, &jwks).unwrap_err();
            assert!(
                err.contains("no matching public key"),
                "unexpected error: {err}"
            );

            set_test_now(None);
        });
    }

    #[test]
    fn test_concurrent_rotation_cas_safety() {
        let _guard = KEY_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            set_test_now(Some(5_000_000));
            wipe_keys().await;

            // Read the ring, then have a "concurrent" rotation modify it: a CAS
            // with the stale revision must fail rather than corrupt the ring.
            let (_meta, stale_rev) = load_meta_with_revision().await.unwrap();
            rotate_keys().await.unwrap();
            let res =
                crate::store::kv_cas_raw(&keys_table(), META_KEY, b"{}", stale_rev, None).await;
            let err = res.unwrap_err();
            assert!(
                err.contains("revision mismatch"),
                "stale CAS must fail, got: {err}"
            );

            // Sequential double rotation works: both old gens stay retired,
            // version increments by one each time, all kids unique.
            let v2_kid = get_kid().await.unwrap();
            let out = rotate_keys().await.unwrap();
            assert_eq!(out.version, 3);
            let meta = load_meta().await.unwrap();
            assert_eq!(meta.version, 3);
            assert_eq!(meta.retired.len(), 4); // v1 + v2, both algs
            assert!(meta.retired.iter().any(|r| r.kid == v2_kid));

            set_test_now(None);
        });
    }

    /// Sign a management-API access token with the given role.
    async fn admin_token(role: &str) -> String {
        let claims = serde_json::json!({
            "sub": "admin-user",
            "iss": "http://localhost:8000",
            "aud": "lid-admin",
            "token_type": "access",
            "role": role,
            "exp": crate::store::unix_now() + 3600,
        });
        crate::jwt::sign(&claims).await.unwrap()
    }

    #[test]
    fn test_management_endpoints_require_superadmin() {
        let _guard = KEY_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            crate::store::init_config_for_test(true, None);
            wipe_keys().await;

            let member = format!("Bearer {}", admin_token("member").await);
            let superadmin = format!("Bearer {}", admin_token("superadmin").await);

            // Non-superadmin is rejected with 403 before any rotation happens.
            let err = crate::management::rotate_keys(Some(&member))
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::FORBIDDEN);
            let err = crate::management::list_keys(Some(&member))
                .await
                .unwrap_err();
            assert_eq!(err.status, http::StatusCode::FORBIDDEN);

            // Superadmin: rotation succeeds and reports new + retired kids.
            let old_kid = get_kid().await.unwrap();
            let resp = crate::management::rotate_keys(Some(&superadmin))
                .await
                .unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
            let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            assert_eq!(body["rotated"], true);
            assert_eq!(body["version"], 2);
            let retired = body["retired"].as_array().unwrap();
            assert!(
                retired
                    .iter()
                    .any(|r| r["kid"].as_str() == Some(old_kid.as_str()))
            );
            assert!(body["grace_expires_at"].as_u64().unwrap() > 0);

            // GET /api/keys shows current + retired, no private material.
            let resp = crate::management::list_keys(Some(&superadmin))
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_str(resp.body()).unwrap();
            let keys = body["keys"].as_array().unwrap();
            assert_eq!(keys.len(), 4); // current RSA+EC + retired RSA+EC
            assert!(
                keys.iter()
                    .any(|k| k["kid"] == old_kid && k["status"] == "retired")
            );
            assert!(keys.iter().all(|k| k.get("d").is_none()));
            // Audit events are emitted to stderr (GKE Cloud Logging) rather than stored in KV.
            let audit =
                crate::store::list_audit_events(None, None, Some("keys_rotated"), None, None, 10)
                    .await
                    .unwrap();
            assert!(audit.is_empty());
        });
    }
}
