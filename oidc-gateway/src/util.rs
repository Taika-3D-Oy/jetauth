/// URL-decode a percent-encoded string (handles %XX and + as space).
pub fn url_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let mut bytes = s.as_bytes().iter();
    while let Some(&b) = bytes.next() {
        if b == b'%' {
            if let (Some(&h), Some(&l)) = (bytes.next(), bytes.next())
                && let (Some(hv), Some(lv)) = (hex_val(h), hex_val(l))
            {
                result.push(hv << 4 | lv);
                continue;
            }
            result.push(b);
        } else if b == b'+' {
            result.push(b' ');
        } else {
            result.push(b);
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a URL query string into key-value pairs with URL decoding.
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = url_decode(parts.next()?);
            let value = url_decode(parts.next().unwrap_or(""));
            Some((key, value))
        })
        .collect()
}

/// Parse a URL-encoded form body into key-value pairs with URL decoding.
pub fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let s = std::str::from_utf8(body).unwrap_or("");
    parse_query(s)
}

/// Look up a value in a parsed form/query.
pub fn form_value<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Look up all values for a given key in a parsed form/query (useful for checkboxes/multi-selects).
pub fn form_values<'a>(form: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    form.iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .collect()
}

/// Escape HTML special characters to prevent XSS.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Percent-encode a string for use in URLs (RFC 3986 unreserved characters pass through).
pub fn percent_encode(s: &str) -> String {
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

/// Validate a hex color string (e.g., "#2563eb"). Returns true if valid.
pub fn is_valid_hex_color(s: &str) -> bool {
    let s = s.trim();
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Sanitize a color value: return it if it's a valid hex color, otherwise return the fallback.
pub fn sanitize_color(color: Option<&str>, fallback: &str) -> String {
    match color {
        Some(c) if is_valid_hex_color(c) => c.to_string(),
        _ => fallback.to_string(),
    }
}

/// Validate that a URL uses http:// or https:// scheme only.
pub fn is_safe_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Validate that a URL is a safe external destination (prevents SSRF to internal networks/cloud metadata).
pub fn is_safe_external_url(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("invalid scheme (must be http or https)".into());
    }

    let without_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Err("invalid scheme".into());
    };

    // Extract authority (host[:port]) before '/', '?', or '#'
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();

    if authority.is_empty() {
        return Err("missing host in URL".into());
    }

    // Strip userinfo (user:pass@) if present
    let host_port = if let Some((_, hp)) = authority.split_once('@') {
        hp
    } else {
        authority
    };

    // Extract host without port or ipv6 brackets
    let host = if host_port.starts_with('[') {
        let end = host_port.find(']').ok_or("unclosed IPv6 bracket in URL")?;
        &host_port[1..end]
    } else if let Some((h, _)) = host_port.split_once(':') {
        h
    } else {
        host_port
    };

    let host_lower = host.to_lowercase();

    // Check prohibited hostnames
    if host_lower == "localhost"
        || host_lower.ends_with(".localhost")
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower == "metadata.google.internal"
        || host_lower == "metadata"
        || host_lower == "instance-data"
    {
        return Err(format!("forbidden target host: {host}"));
    }

    // If host is an IP address, check against private/reserved ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_or_reserved_ip(&ip) {
            return Err(format!("forbidden target IP: {ip}"));
        }
    }

    Ok(())
}

fn is_private_or_reserved_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 0.0.0.0/8 (Current network)
            if octets[0] == 0 {
                return true;
            }
            // 10.0.0.0/8 (Private Class A)
            if octets[0] == 10 {
                return true;
            }
            // 127.0.0.0/8 (Loopback)
            if octets[0] == 127 {
                return true;
            }
            // 169.254.0.0/16 (Link-local / Cloud Metadata)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 172.16.0.0/12 (Private Class B)
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16 (Private Class C)
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 100.64.0.0/10 (Carrier-grade NAT)
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return true;
            }
            // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                return true;
            }
            // 224.0.0.0/4 (Multicast), 240.0.0.0/4 (Reserved), 255.255.255.255 (Broadcast)
            if octets[0] >= 224 {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_unspecified() {
                return true;
            }
            let segments = ipv6.segments();
            // fe80::/10 (Link-local)
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // fc00::/7 (Unique local)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // ff00::/8 (Multicast)
            if (segments[0] & 0xff00) == 0xff00 {
                return true;
            }
            // IPv4-mapped IPv6: ::ffff:x.x.x.x
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff
            {
                let ipv4 = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                return is_private_or_reserved_ip(&std::net::IpAddr::V4(ipv4));
            }
            false
        }
    }
}

/// RFC 9207 compliant authorization code redirection URL builder.
/// Always includes the authorization code and the issuer identifier (`iss`).
/// Preserves any existing query parameters in `redirect_uri` and appends `state` if present.
pub fn build_auth_code_redirect(
    redirect_uri: &str,
    code: &str,
    state: &str,
    issuer: &str,
) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut redirect = format!(
        "{redirect_uri}{sep}code={}&iss={}",
        percent_encode(code),
        percent_encode(issuer)
    );
    if !state.is_empty() {
        redirect.push_str(&format!("&state={}", percent_encode(state)));
    }
    redirect
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_code_redirect() {
        let url = build_auth_code_redirect(
            "https://app.example.com/callback",
            "xyz123",
            "state_abc",
            "https://id.example.com",
        );
        assert_eq!(
            url,
            "https://app.example.com/callback?code=xyz123&iss=https%3A%2F%2Fid.example.com&state=state_abc"
        );

        // Without state
        let url_no_state = build_auth_code_redirect(
            "https://app.example.com/callback",
            "xyz123",
            "",
            "https://id.example.com",
        );
        assert_eq!(
            url_no_state,
            "https://app.example.com/callback?code=xyz123&iss=https%3A%2F%2Fid.example.com"
        );

        // With existing query parameter in redirect_uri
        let url_with_query = build_auth_code_redirect(
            "https://app.example.com/callback?foo=bar",
            "xyz123",
            "st",
            "https://id.example.com",
        );
        assert_eq!(
            url_with_query,
            "https://app.example.com/callback?foo=bar&code=xyz123&iss=https%3A%2F%2Fid.example.com&state=st"
        );
    }

    #[test]
    fn test_is_safe_external_url() {
        assert!(is_safe_external_url("https://example.com/oauth/callback").is_ok());
        assert!(is_safe_external_url("https://auth.company.com:8443/logout").is_ok());

        // Prohibited schemes
        assert!(is_safe_external_url("file:///etc/passwd").is_err());
        assert!(is_safe_external_url("ftp://ftp.example.com").is_err());
        assert!(is_safe_external_url("javascript:alert(1)").is_err());

        // Prohibited hostnames
        assert!(is_safe_external_url("http://localhost/api").is_err());
        assert!(is_safe_external_url("http://sub.localhost/api").is_err());
        assert!(is_safe_external_url("http://internal.taika3d.local/api").is_err());
        assert!(is_safe_external_url("http://service.default.internal:8080").is_err());
        assert!(
            is_safe_external_url("http://metadata.google.internal/computeMetadata/v1/").is_err()
        );

        // Private/loopback IPv4
        assert!(is_safe_external_url("http://127.0.0.1:8080/hook").is_err());
        assert!(is_safe_external_url("http://127.0.0.2/hook").is_err());
        assert!(is_safe_external_url("http://10.0.0.5/logout").is_err());
        assert!(is_safe_external_url("http://172.16.10.20/logout").is_err());
        assert!(is_safe_external_url("http://192.168.1.1/admin").is_err());
        assert!(is_safe_external_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(is_safe_external_url("http://0.0.0.0:80/").is_err());

        // Private/loopback IPv6
        assert!(is_safe_external_url("http://[::1]/logout").is_err());
        assert!(is_safe_external_url("http://[fe80::1]/logout").is_err());
        assert!(is_safe_external_url("http://[fc00::1]/logout").is_err());
        assert!(is_safe_external_url("http://[::ffff:127.0.0.1]/logout").is_err());
        assert!(is_safe_external_url("http://[::ffff:169.254.169.254]/logout").is_err());
    }
}
