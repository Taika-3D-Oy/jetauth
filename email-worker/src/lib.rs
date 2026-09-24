wit_bindgen::generate!({
    path: "wit",
    world: "worker",
    generate_all,
});

struct Component;
export!(Component);

/// Email event — reconstructed from the WIT parameters.
struct EmailEvent {
    event_type: String,
    to: String,
    name: String,
    action_url: String,
    metadata: serde_json::Value,
}

/// Read a config value from wasi:config/store, returning empty string on miss.
fn cfg(key: &str) -> String {
    wasi::config::store::get(key)
        .ok()
        .flatten()
        .unwrap_or_default()
}

impl exports::lattice_id::notify::email::Guest for Component {
    fn send(
        event_type: String,
        to: String,
        name: String,
        action_url: String,
        metadata: String,
    ) -> Result<(), String> {
        eprintln!(
            "email-worker: received event={} to={} url={}",
            event_type, to, action_url
        );

        let metadata_val: serde_json::Value = serde_json::from_str(&metadata)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let event = EmailEvent {
            event_type,
            to,
            name,
            action_url,
            metadata: metadata_val,
        };

        let provider = cfg("email_provider");

        match provider.as_str() {
            "ses" => futures::executor::block_on(ses::deliver(&event)),
            "log" | "" => deliver_log(&event),
            other => Err(format!("unknown email provider: '{other}'")),
        }
    }
}

// ── Log provider (default / dev) ────────────────────────────────────────

fn deliver_log(event: &EmailEvent) -> Result<(), String> {
    eprintln!(
        "email-worker [LOG]: type={} to={} name={} url={}",
        event.event_type, event.to, event.name, event.action_url
    );
    Ok(())
}

// ── HTML email templates ────────────────────────────────────────────────

mod templates {
    use super::EmailEvent;

    pub fn subject(event: &EmailEvent) -> String {
        match event.event_type.as_str() {
            "verify_email" => "Verify your email address".into(),
            "password_reset" => "Reset your password".into(),
            "invitation" => {
                let tenant = event
                    .metadata
                    .get("tenant_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("the platform");
                format!("You've been invited to {tenant}")
            }
            other => format!("Notification: {other}"),
        }
    }

    pub fn html_body(event: &EmailEvent) -> String {
        let raw_name = if event.name.is_empty() {
            "there"
        } else {
            &event.name
        };
        let name = html_escape(raw_name);
        let button_text = match event.event_type.as_str() {
            "verify_email" => "Verify Email",
            "password_reset" => "Reset Password",
            "invitation" => "Accept Invitation",
            _ => "Take Action",
        };
        let message = match event.event_type.as_str() {
            "verify_email" => "Please verify your email address by clicking the button below.",
            "password_reset" => {
                "You requested a password reset. Click below to set a new password."
            }
            "invitation" => "You've been invited to join. Click below to accept.",
            _ => "An action is required.",
        };
        let action_url = html_escape(&event.action_url);

        format!(
            r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
.card {{ max-width: 480px; margin: 40px auto; background: #fff; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
h1 {{ font-size: 20px; color: #333; margin: 0 0 16px; }}
p {{ font-size: 15px; color: #555; line-height: 1.6; }}
.btn {{ display: inline-block; padding: 12px 32px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 24px 0; }}
.footer {{ font-size: 12px; color: #999; margin-top: 32px; }}
</style></head><body>
<div class="card">
  <h1>Hi {name},</h1>
  <p>{message}</p>
  <a class="btn" href="{action_url}">{button_text}</a>
  <p class="footer">If you didn't request this, you can safely ignore this email.<br>
  This link expires in 24 hours.</p>
</div></body></html>"#
        )
    }

    pub fn text_body(event: &EmailEvent) -> String {
        let name = if event.name.is_empty() {
            "there"
        } else {
            &event.name
        };
        format!(
            "Hi {},\n\n{}\n\n{}\n\nIf you didn't request this, you can safely ignore this email.\n",
            name,
            match event.event_type.as_str() {
                "verify_email" => "Please verify your email address by visiting the link below.",
                "password_reset" =>
                    "You requested a password reset. Visit the link below to set a new password.",
                "invitation" => "You've been invited. Visit the link below to accept.",
                _ => "An action is required.",
            },
            event.action_url
        )
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

// ── AWS SES v2 provider ─────────────────────────────────────────────────

mod ses {
    use super::{EmailEvent, cfg, templates};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Deliver an email via SES v2 SendEmail API.
    pub async fn deliver(event: &EmailEvent) -> Result<(), String> {
        let region = cfg("ses_region");
        let access_key = cfg("ses_access_key_id");
        let secret_key = cfg("ses_secret_access_key");
        let from_addr = cfg("ses_from_address");

        if access_key.is_empty() || secret_key.is_empty() || from_addr.is_empty() {
            return Err("SES not configured: set ses_access_key_id, ses_secret_access_key, ses_from_address".into());
        }
        let region = if region.is_empty() {
            "eu-west-1".to_string()
        } else {
            region
        };

        let subject = templates::subject(event);
        let html = templates::html_body(event);
        let text = templates::text_body(event);

        let body = serde_json::json!({
            "Content": {
                "Simple": {
                    "Subject": { "Data": subject, "Charset": "UTF-8" },
                    "Body": {
                        "Html": { "Data": html, "Charset": "UTF-8" },
                        "Text": { "Data": text, "Charset": "UTF-8" }
                    }
                }
            },
            "Destination": {
                "ToAddresses": [event.to]
            },
            "FromEmailAddress": from_addr
        });
        let payload = serde_json::to_string(&body).map_err(|e| format!("json: {e}"))?;

        let host = format!("email.{region}.amazonaws.com");

        let now = chrono::DateTime::from_timestamp(
            crate::wasi::clocks::wall_clock::now().seconds as i64,
            0,
        )
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
        let datestamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // AWS SigV4 signing
        let payload_hash = hex_sha256(payload.as_bytes());
        let canonical_headers = format!(
            "content-type:application/json\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        );
        let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
        let canonical_request = format!(
            "POST\n/v2/email/outbound-emails\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let credential_scope = format!("{datestamp}/{region}/ses/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );

        let signing_key = derive_signing_key(&secret_key, &datestamp, &region, "ses");
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );

        use crate::wasi::http::outgoing_handler;
        use crate::wasi::http::types::{
            Fields, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
        };

        let headers_vec: Vec<(String, Vec<u8>)> = vec![
            ("content-type".to_string(), b"application/json".to_vec()),
            ("x-amz-date".to_string(), amz_date.as_bytes().to_vec()),
            (
                "x-amz-content-sha256".to_string(),
                payload_hash.as_bytes().to_vec(),
            ),
            (
                "authorization".to_string(),
                authorization.as_bytes().to_vec(),
            ),
        ];

        let fields = Fields::from_list(&headers_vec).map_err(|e| format!("headers: {e:?}"))?;
        let outgoing = OutgoingRequest::new(fields);
        let _ = outgoing.set_method(&Method::Post);
        let _ = outgoing.set_path_with_query(Some("/v2/email/outbound-emails"));
        let _ = outgoing.set_authority(Some(&host));
        let _ = outgoing.set_scheme(Some(&Scheme::Https));

        if let Ok(out_body) = outgoing.body() {
            if let Ok(stream) = out_body.write() {
                let _ = stream.blocking_write_and_flush(payload.as_bytes());
                drop(stream);
            }
            let _ = OutgoingBody::finish(out_body, None);
        }

        let opts = RequestOptions::new();
        let fut = outgoing_handler::handle(outgoing, Some(opts))
            .map_err(|e| format!("outgoing_handler: {e:?}"))?;
        let pollable = fut.subscribe();
        pollable.block();
        drop(pollable);

        let incoming = fut
            .get()
            .ok_or_else(|| "no response".to_string())?
            .map_err(|e| format!("http error: {e:?}"))?
            .map_err(|e| format!("response error: {e:?}"))?;

        let status = incoming.status();
        let mut body_bytes = Vec::new();
        if let Ok(inc_body) = incoming.consume()
            && let Ok(in_stream) = inc_body.stream()
        {
            loop {
                match in_stream.blocking_read(65536) {
                    Ok(chunk) if !chunk.is_empty() => body_bytes.extend_from_slice(&chunk),
                    _ => break,
                }
            }
        }

        if (200..300).contains(&status) {
            eprintln!(
                "email-worker [SES]: sent {} to {}",
                event.event_type, event.to
            );
            Ok(())
        } else {
            let detail = String::from_utf8_lossy(&body_bytes);
            Err(format!("SES returned HTTP {status}: {detail}"))
        }
    }

    pub fn hex_sha256(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn derive_signing_key(
        secret: &str,
        datestamp: &str,
        region: &str,
        service: &str,
    ) -> Vec<u8> {
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

#[cfg(test)]
mod tests {
    use super::ses;

    #[test]
    fn test_sigv4_derivation() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let datestamp = "20130524";
        let region = "us-east-1";
        let service = "ses";

        let key = ses::derive_signing_key(secret, datestamp, region, service);
        assert!(!key.is_empty());
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"{}";
        let hash = ses::hex_sha256(data);
        assert_eq!(
            hash,
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
