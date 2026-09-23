use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const TOTP_PERIOD: u64 = 30;
const TOTP_DIGITS: u32 = 6;

/// Generate a random 20-byte TOTP secret and return it as base32-encoded string.
pub fn generate_secret() -> String {
    let mut secret = [0u8; 20];
    getrandom::getrandom(&mut secret).expect("getrandom failed");
    base32_encode(&secret)
}

/// Generate recovery codes (10 codes, 10 lowercase alphanumeric chars each, ≥50 bits entropy).
pub fn generate_recovery_codes() -> Vec<String> {
    // Task 2.11: Increase recovery code entropy — 10 alphanumeric characters (≥50 bits)
    (0..10)
        .map(|_| crate::store::random_alphanumeric(10))
        .collect()
}

/// Build the otpauth:// URI for QR code scanning.
pub fn otpauth_uri(secret_b32: &str, email: &str, issuer: &str) -> String {
    let encoded_email = percent_encode(email);
    let encoded_issuer = percent_encode(issuer);
    format!(
        "otpauth://totp/{encoded_issuer}:{encoded_email}?secret={secret_b32}&issuer={encoded_issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )
}

/// Verify a TOTP code and return the matching time step if valid. Allows ±1 time step for clock skew.
pub fn verify_totp_step(secret_b32: &str, code: &str) -> Option<u64> {
    let secret = base32_decode(secret_b32)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let current_step = now / TOTP_PERIOD;

    // Check current, previous, and next time steps (±1 for clock skew)
    for step in [current_step.wrapping_sub(1), current_step, current_step + 1] {
        let expected = compute_totp(&secret, step);
        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return Some(step);
        }
    }
    None
}

/// Verify a TOTP code. Allows ±1 time step for clock skew.
pub fn verify_totp(secret_b32: &str, code: &str) -> bool {
    verify_totp_step(secret_b32, code).is_some()
}

/// Compute TOTP for a given time step (RFC 6238 / RFC 4226).
fn compute_totp(secret: &[u8], time_step: u64) -> String {
    // HOTP(K, C) = Truncate(HMAC-SHA1(K, C))
    let message = time_step.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&message);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 section 5.4)
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let otp = code % 10u32.pow(TOTP_DIGITS);
    format!("{otp:0>width$}", width = TOTP_DIGITS as usize)
}

/// Constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Base32 encode/decode (RFC 4648, no padding) ─────────────

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        result.push(BASE32_ALPHABET[idx] as char);
    }
    result
}

fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for c in encoded.chars() {
        let val = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            'a'..='z' => c as u64 - 'a' as u64, // case-insensitive
            '=' | ' ' => continue,              // skip padding/spaces
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Some(result)
}

fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_totp_generation() {
        // RFC 6238 test vector: secret = "12345678901234567890" (ASCII), time = 59
        // Expected TOTP for step 1 (time 30-59) = 287082
        let secret = b"12345678901234567890";
        let code = compute_totp(secret, 1);
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
