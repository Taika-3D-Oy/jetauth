use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use x509_cert::builder::{Builder as _, CertificateBuilder, Profile};
use x509_cert::der::Encode as _;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

use crate::store::{self, SamlKeyRing, SamlSigningKey};

const KEY_GRACE_SECS: u64 = 30 * 86400;

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn generate_key(version: u32) -> Result<SamlSigningKey, String> {
    let mut rng = rand_core::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("SAML RSA generation: {e}"))?;
    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|e| format!("SAML private-key encoding: {e}"))?;
    let public_der = RsaPublicKey::from(&private_key)
        .to_public_key_der()
        .map_err(|e| format!("SAML public-key encoding: {e}"))?;
    let public_info = SubjectPublicKeyInfoOwned::try_from(public_der.as_bytes())
        .map_err(|e| format!("SAML public-key parsing: {e}"))?;

    let signing_key = SigningKey::<Sha256>::new(private_key);
    let subject = Name::from_str("CN=JetAuth SAML,O=JetAuth").map_err(|e| e.to_string())?;
    let serial_bytes = store::random_hex(8);
    let serial = u64::from_str_radix(&serial_bytes, 16).map_err(|e| e.to_string())?;
    let validity = Validity::from_now(Duration::from_secs(365 * 86400))
        .map_err(|e| format!("SAML certificate validity: {e}"))?;
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(serial),
        validity,
        subject,
        public_info,
        &signing_key,
    )
    .map_err(|e| format!("SAML certificate builder: {e}"))?;
    let certificate = builder
        .build::<rsa::pkcs1v15::Signature>()
        .map_err(|e| format!("SAML certificate signing: {e}"))?;
    let certificate_der = certificate.to_der().map_err(|e| e.to_string())?;

    Ok(SamlSigningKey {
        version,
        private_key_pem: pem("PRIVATE KEY", private_der.as_bytes()),
        certificate_pem: pem("CERTIFICATE", &certificate_der),
        created_at: store::unix_now(),
    })
}

pub async fn ensure_key_ring() -> Result<SamlKeyRing, String> {
    if let Some(mut ring) = store::get_saml_key_ring().await? {
        let expired = ring
            .previous_grace_expires
            .is_some_and(|expiry| store::unix_now() >= expiry);
        if expired {
            ring.previous = None;
            ring.previous_grace_expires = None;
        }
        return Ok(ring);
    }
    let ring = SamlKeyRing {
        current: generate_key(1)?,
        previous: None,
        previous_grace_expires: None,
    };
    match store::create_saml_key_ring(&ring).await {
        Ok(()) => Ok(ring),
        Err(error) if error.contains("already exists") => store::get_saml_key_ring()
            .await?
            .ok_or_else(|| "SAML key ring disappeared during initialization".into()),
        Err(error) => Err(error),
    }
}

pub async fn rotate_key_ring() -> Result<SamlKeyRing, String> {
    crate::logger::info(
        "saml.key_rotation",
        serde_json::json!({"step": "acquire_lock"}),
    );
    store::acquire_saml_rotation_lock().await?;
    let result = async {
        crate::logger::info(
            "saml.key_rotation",
            serde_json::json!({"step": "load_ring"}),
        );
        let ring = ensure_key_ring().await?;
        crate::logger::info(
            "saml.key_rotation",
            serde_json::json!({"step": "generate_key"}),
        );
        let rotated = SamlKeyRing {
            current: generate_key(ring.current.version.saturating_add(1))?,
            previous: Some(ring.current),
            previous_grace_expires: Some(store::unix_now() + KEY_GRACE_SECS),
        };
        crate::logger::info(
            "saml.key_rotation",
            serde_json::json!({"step": "save_ring"}),
        );
        store::save_saml_key_ring(&rotated).await?;
        Ok(rotated)
    }
    .await;
    store::release_saml_rotation_lock().await;
    result
}
