use http::{Response, StatusCode};

fn has_scope(scope: &str, value: &str) -> bool {
    scope.split(' ').any(|candidate| candidate == value)
}

fn push_unique(values: &mut Vec<String>, candidate: &str) {
    if !candidate.is_empty() && !values.iter().any(|existing| existing == candidate) {
        values.push(candidate.to_string());
    }
}

fn requested_userinfo_claims(claims: &serde_json::Value) -> Vec<String> {
    let mut requested = vec!["sub".to_string()];
    let scope = claims
        .get("scope")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if has_scope(scope, "profile") {
        for claim_name in ["name", "given_name", "family_name", "preferred_username"] {
            push_unique(&mut requested, claim_name);
        }
    }
    if has_scope(scope, "email") {
        push_unique(&mut requested, "email");
        push_unique(&mut requested, "email_verified");
    }
    if let Some(extra) = claims
        .get("lid_userinfo_claims")
        .and_then(|value| value.as_array())
    {
        for claim_name in extra {
            if let Some(claim_name) = claim_name.as_str() {
                push_unique(&mut requested, claim_name);
            }
        }
    }
    requested
}

fn populate_userinfo_claim(
    userinfo: &mut serde_json::Map<String, serde_json::Value>,
    requested: &str,
    user: &crate::store::User,
    claims: &serde_json::Value,
) {
    match requested {
        "sub" => {
            if let Some(value) = claims.get("sub") {
                userinfo.insert("sub".to_string(), value.clone());
            }
        }
        "name" => {
            userinfo.insert("name".to_string(), serde_json::json!(user.name));
        }
        "given_name" => {
            if let Some(value) = user.name.split_whitespace().next()
                && !value.is_empty()
            {
                userinfo.insert("given_name".to_string(), serde_json::json!(value));
            }
        }
        "family_name" => {
            let mut parts = user.name.split_whitespace();
            let _ = parts.next();
            let remainder = parts.collect::<Vec<_>>().join(" ");
            if !remainder.is_empty() {
                userinfo.insert("family_name".to_string(), serde_json::json!(remainder));
            }
        }
        "preferred_username" => {
            let preferred = user.email.split('@').next().unwrap_or("");
            if !preferred.is_empty() {
                userinfo.insert(
                    "preferred_username".to_string(),
                    serde_json::json!(preferred),
                );
            }
        }
        "email" => {
            userinfo.insert("email".to_string(), serde_json::json!(user.email));
        }
        "email_verified" => {
            userinfo.insert(
                "email_verified".to_string(),
                serde_json::json!(user.status == "active"),
            );
        }
        "auth_time" | "amr" | "acr" | "tenant_id" | "role" | "tenants" => {
            if let Some(value) = claims.get(requested) {
                userinfo.insert(requested.to_string(), value.clone());
            }
        }
        _ => {}
    }
}

/// RFC 6750 §3.1 / RFC 9449 §7.1 compliant error response for protected resources.
fn unauthorized_response(
    scheme: &str,
    status: StatusCode,
    error: Option<(&str, &str)>,
) -> Response<String> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store");

    match error {
        Some((code, desc)) => {
            builder = builder.header(
                "www-authenticate",
                format!("{scheme} error=\"{code}\", error_description=\"{desc}\""),
            );
            let body = serde_json::json!({
                "error": code,
                "error_description": desc,
            });
            builder.body(body.to_string()).unwrap()
        }
        None => {
            builder = builder.header("www-authenticate", scheme);
            let body = serde_json::json!({
                "error": "unauthorized",
                "error_description": "missing authorization header",
            });
            builder.body(body.to_string()).unwrap()
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthScheme {
    Bearer,
    DPoP,
}

pub fn extract_token(
    header: Option<&str>,
) -> Result<(String, AuthScheme), (StatusCode, Option<&'static str>, &'static str)> {
    let header = header.ok_or((
        StatusCode::UNAUTHORIZED,
        None,
        "missing authorization header",
    ))?;
    if let Some(t) = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
    {
        Ok((t.trim().to_string(), AuthScheme::Bearer))
    } else if let Some(t) = header
        .strip_prefix("DPoP ")
        .or_else(|| header.strip_prefix("dpop "))
    {
        Ok((t.trim().to_string(), AuthScheme::DPoP))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Some("invalid_request"),
            "invalid Authorization header (expected Bearer or DPoP)",
        ))
    }
}

#[allow(dead_code)]
pub fn extract_bearer(
    header: Option<&str>,
) -> Result<String, (StatusCode, Option<&'static str>, &'static str)> {
    extract_token(header).map(|(t, _)| t)
}

/// Handle GET/POST /userinfo — validate Bearer or DPoP token, return user claims.
/// Per OIDC Core §5.3.3: The access token MUST be validated (issuer, audience, type).
/// Per RFC 6750 §3.1 / RFC 9449 §7: Failed authentication MUST return 401 with WWW-Authenticate header.
pub async fn handle(
    auth_header: Option<&str>,
    dpop_header: Option<&str>,
    issuer: &str,
    method: &str,
) -> Result<Response<String>, String> {
    let (token, scheme) = match extract_token(auth_header) {
        Ok(t) => t,
        Err((status, code, desc)) => {
            return Ok(unauthorized_response(
                "Bearer",
                status,
                code.map(|c| (c, desc)),
            ));
        }
    };

    // Verify JWT and extract claims.
    let claims = match crate::service_client::verify_token_scoped(
        &token,
        Some(issuer),
        None,
        Some("access"),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let auth_scheme = if scheme == AuthScheme::DPoP {
                "DPoP"
            } else {
                "Bearer"
            };
            return Ok(unauthorized_response(
                auth_scheme,
                StatusCode::UNAUTHORIZED,
                Some(("invalid_token", &e)),
            ));
        }
    };

    // RFC 9449 §7: Check sender-constraining
    if let Some(cnf) = claims.get("cnf") {
        let expected_jkt = match cnf.get("jkt").and_then(|v| v.as_str()) {
            Some(jkt) => jkt,
            None => {
                return Ok(unauthorized_response(
                    "DPoP",
                    StatusCode::UNAUTHORIZED,
                    Some(("invalid_token", "malformed cnf claim in access token")),
                ));
            }
        };

        let proof = match dpop_header {
            Some(p) => p,
            None => {
                return Ok(unauthorized_response(
                    "DPoP",
                    StatusCode::UNAUTHORIZED,
                    Some((
                        "invalid_token",
                        "DPoP proof required for DPoP bound access token",
                    )),
                ));
            }
        };

        let proof_jkt = match crate::dpop::validate_dpop_proof(
            proof,
            method,
            &format!("{issuer}/userinfo"),
            Some(&token),
        )
        .await
        {
            Ok(jkt) => jkt,
            Err(e) => {
                return Ok(unauthorized_response(
                    "DPoP",
                    StatusCode::UNAUTHORIZED,
                    Some(("invalid_dpop_proof", &e)),
                ));
            }
        };

        if proof_jkt != expected_jkt {
            return Ok(unauthorized_response(
                "DPoP",
                StatusCode::UNAUTHORIZED,
                Some(("invalid_token", "DPoP key thumbprint mismatch")),
            ));
        }
    } else if scheme == AuthScheme::DPoP {
        return Ok(unauthorized_response(
            "Bearer",
            StatusCode::UNAUTHORIZED,
            Some(("invalid_token", "access token is not DPoP bound")),
        ));
    }

    let user_id = match claims.get("sub").and_then(|value| value.as_str()) {
        Some(id) => id,
        None => {
            let auth_scheme = if scheme == AuthScheme::DPoP {
                "DPoP"
            } else {
                "Bearer"
            };
            return Ok(unauthorized_response(
                auth_scheme,
                StatusCode::UNAUTHORIZED,
                Some(("invalid_token", "missing subject claim")),
            ));
        }
    };

    let user = match crate::store::get_user(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            let auth_scheme = if scheme == AuthScheme::DPoP {
                "DPoP"
            } else {
                "Bearer"
            };
            return Ok(unauthorized_response(
                auth_scheme,
                StatusCode::UNAUTHORIZED,
                Some(("invalid_token", "user not found")),
            ));
        }
        Err(e) => return Err(format!("store error: {e}")),
    };

    let requested_claims = requested_userinfo_claims(&claims);
    let mut userinfo = serde_json::Map::new();
    for requested in requested_claims {
        populate_userinfo_claim(&mut userinfo, &requested, &user, &claims);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&serde_json::Value::Object(userinfo)).unwrap_or_default())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_missing() {
        let err = extract_bearer(None).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, None);
    }

    #[test]
    fn test_extract_bearer_wrong_scheme() {
        let err = extract_bearer(Some("Basic dXNlcjpwYXNz")).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, Some("invalid_request"));
    }

    #[test]
    fn test_extract_bearer_valid() {
        let token = extract_bearer(Some("Bearer my.secret.token")).unwrap();
        assert_eq!(token, "my.secret.token");
        let token_lower = extract_bearer(Some("bearer my.other.token")).unwrap();
        assert_eq!(token_lower, "my.other.token");
    }

    #[test]
    fn test_extract_dpop_valid() {
        let (token, scheme) = extract_token(Some("DPoP my.dpop.token")).unwrap();
        assert_eq!(token, "my.dpop.token");
        assert_eq!(scheme, AuthScheme::DPoP);

        let (token2, scheme2) = extract_token(Some("dpop my.other.dpop.token")).unwrap();
        assert_eq!(token2, "my.other.dpop.token");
        assert_eq!(scheme2, AuthScheme::DPoP);
    }

    #[test]
    fn test_unauthorized_response_missing_header() {
        let resp = unauthorized_response("Bearer", StatusCode::UNAUTHORIZED, None);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers().get("www-authenticate").unwrap(), "Bearer");
    }

    #[test]
    fn test_unauthorized_response_invalid_token() {
        let resp = unauthorized_response(
            "Bearer",
            StatusCode::UNAUTHORIZED,
            Some(("invalid_token", "token expired")),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get("www-authenticate").unwrap(),
            "Bearer error=\"invalid_token\", error_description=\"token expired\""
        );

        let dpop_resp = unauthorized_response(
            "DPoP",
            StatusCode::UNAUTHORIZED,
            Some(("invalid_dpop_proof", "proof expired")),
        );
        assert_eq!(dpop_resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            dpop_resp.headers().get("www-authenticate").unwrap(),
            "DPoP error=\"invalid_dpop_proof\", error_description=\"proof expired\""
        );
    }
}
