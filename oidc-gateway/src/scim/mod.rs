use http::{Method, Response, StatusCode};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store::{self, Membership, ScimConnection, ScimIdentity, User};

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

struct Failure {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

impl Failure {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some("invalidValue"), detail)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, None, "resource not found")
    }

    fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, Some("uniqueness"), detail)
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, None, "internal error")
    }

    fn render(self) -> Response<String> {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        response(self.status, &body, None)
    }
}

fn response(status: StatusCode, body: &Value, version: Option<u64>) -> Response<String> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/scim+json; charset=utf-8")
        .header("cache-control", "no-store");
    if let Some(version) = version {
        builder = builder.header("etag", format!("W/\"{version}\""));
    }
    builder.body(body.to_string()).unwrap()
}

pub fn enabled() -> bool {
    store::config_value("scim_enabled").is_some_and(|value| value == "true" || value == "1")
}

async fn authenticate(headers: &http::HeaderMap) -> Result<ScimConnection, Failure> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .ok_or_else(|| Failure::new(StatusCode::UNAUTHORIZED, None, "missing bearer token"))?;
    let hash = store::sha256_hex(token);
    let connections = store::list_scim_connections()
        .await
        .map_err(|_| Failure::internal())?;
    connections
        .into_iter()
        .filter(|connection| connection.enabled)
        .find(|connection| bool::from(connection.token_hash.as_bytes().ct_eq(hash.as_bytes())))
        .ok_or_else(|| Failure::new(StatusCode::UNAUTHORIZED, None, "invalid bearer token"))
}

fn timestamp(seconds: u64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds as i64)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

fn user_resource(
    connection: &ScimConnection,
    identity: &ScimIdentity,
    user: &User,
    issuer: &str,
) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "id": user.id,
        "externalId": identity.external_id,
        "userName": user.email,
        "name": { "formatted": user.name },
        "active": user.status == "active",
        "emails": [{ "value": user.email, "primary": true }],
        "meta": {
            "resourceType": "User",
            "created": timestamp(identity.created_at),
            "lastModified": timestamp(identity.updated_at),
            "location": format!("{issuer}/scim/v2/Users/{}", user.id),
            "version": format!("W/\"{}\"", identity.version),
        },
        "tenant": connection.tenant_id,
    })
}

struct UserInput {
    user_name: String,
    name: String,
    active: bool,
    external_id: String,
}

fn valid_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 256 || email.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    email.rsplit_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && !domain.is_empty() && domain.contains('.')
    })
}

fn parse_input(value: &Value) -> Result<UserInput, Failure> {
    if let Some(schemas) = value.get("schemas").and_then(Value::as_array)
        && !schemas
            .iter()
            .any(|schema| schema.as_str() == Some(USER_SCHEMA))
    {
        return Err(Failure::bad_request("missing SCIM User schema"));
    }
    let user_name = value
        .get("userName")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_lowercase();
    if !valid_email(&user_name) {
        return Err(Failure::bad_request(
            "userName must be a valid email address",
        ));
    }
    let name_value = value.get("name");
    let formatted = name_value
        .and_then(|name| name.get("formatted"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            let given = name_value
                .and_then(|name| name.get("givenName"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let family = name_value
                .and_then(|name| name.get("familyName"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let combined = format!("{given} {family}").trim().to_string();
            (!combined.is_empty()).then_some(combined)
        })
        .unwrap_or_else(|| user_name.clone());
    if formatted.len() > 256 {
        return Err(Failure::bad_request("name is too long"));
    }
    let external_id = value
        .get("externalId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if external_id.is_empty() || external_id.len() > 256 {
        return Err(Failure::bad_request(
            "externalId is required and must be at most 256 characters",
        ));
    }
    Ok(UserInput {
        user_name,
        name: formatted,
        active: value.get("active").and_then(Value::as_bool).unwrap_or(true),
        external_id,
    })
}

async fn identity_and_user(
    connection: &ScimConnection,
    user_id: &str,
) -> Result<(ScimIdentity, User), Failure> {
    let identity = store::get_scim_identity_by_user(&connection.id, user_id)
        .await
        .map_err(|_| Failure::internal())?
        .ok_or_else(Failure::not_found)?;
    let user = store::get_user(user_id)
        .await
        .map_err(|_| Failure::internal())?
        .ok_or_else(Failure::not_found)?;
    Ok((identity, user))
}

fn check_if_match(headers: &http::HeaderMap, version: u64) -> Result<(), Failure> {
    let Some(value) = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    let weak = format!("W/\"{version}\"");
    let strong = format!("\"{version}\"");
    if value == "*" || value == weak || value == strong {
        Ok(())
    } else {
        Err(Failure::new(
            StatusCode::PRECONDITION_FAILED,
            None,
            "resource version does not match",
        ))
    }
}

async fn create_user(
    connection: &ScimConnection,
    body: &[u8],
    issuer: &str,
) -> Result<Response<String>, Failure> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Failure::bad_request("invalid JSON"))?;
    let input = parse_input(&value)?;
    if store::get_user_by_email(&input.user_name)
        .await
        .map_err(|_| Failure::internal())?
        .is_some()
    {
        return Err(Failure::conflict("userName is already registered"));
    }
    if store::get_scim_identity(&connection.id, &input.external_id)
        .await
        .map_err(|_| Failure::internal())?
        .is_some()
    {
        return Err(Failure::conflict("externalId is already provisioned"));
    }
    let now = store::unix_now();
    let user = User {
        id: store::random_hex(16),
        email: input.user_name.clone(),
        name: input.name.clone(),
        password_hash: format!("scim:{}:{}", connection.id, store::random_hex(16)),
        status: if input.active { "active" } else { "disabled" }.into(),
        created_at: now,
        superadmin: false,
        totp_secret: None,
        totp_enabled: false,
        recovery_codes: Vec::new(),
        passkey_credentials: Vec::new(),
    };
    store::create_user(&user).await.map_err(|error| {
        if error.contains("already registered") {
            Failure::conflict("userName is already registered")
        } else {
            Failure::internal()
        }
    })?;
    if store::update_user_rmw(&user.id, |current| {
        current.status = user.status.clone();
        Ok(true)
    })
    .await
    .is_err()
    {
        let _ = store::delete_user(&user.id).await;
        return Err(Failure::internal());
    }
    let membership = Membership {
        tenant_id: connection.tenant_id.clone(),
        user_id: user.id.clone(),
        role: connection.default_role.clone(),
        joined_at: now,
    };
    if store::add_membership(&membership).await.is_err() {
        let _ = store::delete_user(&user.id).await;
        return Err(Failure::internal());
    }
    let identity = ScimIdentity {
        connection_id: connection.id.clone(),
        external_id: input.external_id,
        user_id: user.id.clone(),
        version: 1,
        created_at: now,
        updated_at: now,
    };
    if let Err(error) = store::create_scim_identity(&identity).await {
        let _ = store::remove_membership(&connection.tenant_id, &user.id).await;
        let _ = store::delete_user(&user.id).await;
        return Err(if error.contains("already provisioned") {
            Failure::conflict("externalId is already provisioned")
        } else {
            Failure::internal()
        });
    }
    let _ = store::log_audit(
        "scim_user_created",
        &format!("scim:{}", connection.id),
        &user.id,
        &connection.tenant_id,
    )
    .await;
    let resource = user_resource(connection, &identity, &user, issuer);
    Ok(response(
        StatusCode::CREATED,
        &resource,
        Some(identity.version),
    ))
}

async fn update_user(
    connection: &ScimConnection,
    user_id: &str,
    mut identity: ScimIdentity,
    current: User,
    input: UserInput,
    issuer: &str,
) -> Result<Response<String>, Failure> {
    if current.superadmin {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            None,
            "superadmin cannot be provisioned",
        ));
    }
    if input.external_id != identity.external_id {
        return Err(Failure::bad_request("externalId cannot be changed"));
    }
    if !current.email.eq_ignore_ascii_case(&input.user_name)
        && store::get_user_by_email(&input.user_name)
            .await
            .map_err(|_| Failure::internal())?
            .is_some()
    {
        return Err(Failure::conflict("userName is already registered"));
    }
    let status = if input.active { "active" } else { "disabled" };
    store::update_user_provisioned(user_id, &input.user_name, &input.name, status)
        .await
        .map_err(|error| {
            if error.contains("already registered") {
                Failure::conflict("userName is already registered")
            } else {
                Failure::internal()
            }
        })?;
    if !input.active {
        let _ = store::delete_user_refresh_tokens(user_id).await;
        let _ = store::revoke_user_sessions(user_id).await;
    }
    identity.version = identity.version.saturating_add(1);
    identity.updated_at = store::unix_now();
    store::save_scim_identity(&identity)
        .await
        .map_err(|_| Failure::internal())?;
    let user = store::get_user(user_id)
        .await
        .map_err(|_| Failure::internal())?
        .ok_or_else(Failure::not_found)?;
    let _ = store::log_audit(
        "scim_user_updated",
        &format!("scim:{}", connection.id),
        user_id,
        if input.active { "active" } else { "disabled" },
    )
    .await;
    Ok(response(
        StatusCode::OK,
        &user_resource(connection, &identity, &user, issuer),
        Some(identity.version),
    ))
}

fn patch_field(input: &mut UserInput, path: &str, value: &Value) -> Result<(), Failure> {
    match path {
        "userName" => {
            let email = value.as_str().map(str::trim).unwrap_or("").to_lowercase();
            if !valid_email(&email) {
                return Err(Failure::bad_request(
                    "userName must be a valid email address",
                ));
            }
            input.user_name = email;
        }
        "active" => {
            input.active = value
                .as_bool()
                .ok_or_else(|| Failure::bad_request("active must be boolean"))?;
        }
        "name" | "name.formatted" => {
            let name = if path == "name" {
                value.get("formatted").and_then(Value::as_str)
            } else {
                value.as_str()
            }
            .ok_or_else(|| Failure::bad_request("name.formatted must be a string"))?;
            if name.len() > 256 {
                return Err(Failure::bad_request("name is too long"));
            }
            input.name = name.to_string();
        }
        "externalId" => {
            if value.as_str() != Some(&input.external_id) {
                return Err(Failure::new(
                    StatusCode::BAD_REQUEST,
                    Some("mutability"),
                    "externalId is immutable",
                ));
            }
        }
        _ => {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                Some("invalidPath"),
                format!("unsupported PATCH path: {path}"),
            ));
        }
    }
    Ok(())
}

async fn patch_user(
    connection: &ScimConnection,
    user_id: &str,
    identity: ScimIdentity,
    current: User,
    body: &[u8],
    issuer: &str,
) -> Result<Response<String>, Failure> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Failure::bad_request("invalid JSON"))?;
    let operations = value
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| Failure::bad_request("Operations array is required"))?;
    if operations.is_empty() || operations.len() > 100 {
        return Err(Failure::bad_request(
            "between 1 and 100 PATCH operations are required",
        ));
    }
    let mut input = UserInput {
        user_name: current.email.clone(),
        name: current.name.clone(),
        active: current.status == "active",
        external_id: identity.external_id.clone(),
    };
    for operation in operations {
        let op = operation.get("op").and_then(Value::as_str).unwrap_or("");
        if !["add", "replace"].contains(&op) {
            return Err(Failure::bad_request(
                "only add and replace PATCH operations are supported",
            ));
        }
        let operation_value = operation.get("value").unwrap_or(&Value::Null);
        if let Some(path) = operation.get("path").and_then(Value::as_str) {
            patch_field(&mut input, path, operation_value)?;
        } else if let Some(fields) = operation_value.as_object() {
            for (path, value) in fields {
                patch_field(&mut input, path, value)?;
            }
        } else {
            return Err(Failure::bad_request(
                "PATCH path or object value is required",
            ));
        }
    }
    update_user(connection, user_id, identity, current, input, issuer).await
}

fn parse_filter(filter: &str) -> Result<(String, String), Failure> {
    for attribute in ["userName", "externalId", "id"] {
        if let Some(rest) = filter.strip_prefix(attribute) {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix("eq") {
                let value = rest.trim();
                if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
                    return Ok((attribute.to_string(), value[1..value.len() - 1].to_string()));
                }
            }
        }
    }
    Err(Failure::new(
        StatusCode::BAD_REQUEST,
        Some("invalidFilter"),
        "supported filters: userName, externalId, or id eq \"value\"",
    ))
}

async fn list_users(
    connection: &ScimConnection,
    query: &str,
    issuer: &str,
) -> Result<Response<String>, Failure> {
    let params = crate::util::parse_query(query);
    let get = |key: &str| {
        params
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    };
    let start_index = get("startIndex")
        .unwrap_or("1")
        .parse::<usize>()
        .map_err(|_| Failure::bad_request("invalid startIndex"))?;
    if start_index == 0 {
        return Err(Failure::bad_request("startIndex must be at least 1"));
    }
    let count = get("count")
        .unwrap_or("100")
        .parse::<usize>()
        .map_err(|_| Failure::bad_request("invalid count"))?
        .min(500);
    let filter = get("filter").map(parse_filter).transpose()?;
    let mut identities = store::list_scim_identities(&connection.id)
        .await
        .map_err(|_| Failure::internal())?;
    identities.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    let mut resources = Vec::new();
    for identity in identities {
        if let Some(user) = store::get_user(&identity.user_id)
            .await
            .map_err(|_| Failure::internal())?
        {
            if let Some((attribute, expected)) = &filter {
                let actual = match attribute.as_str() {
                    "userName" => &user.email,
                    "externalId" => &identity.external_id,
                    "id" => &user.id,
                    _ => continue,
                };
                if actual != expected {
                    continue;
                }
            }
            resources.push(user_resource(connection, &identity, &user, issuer));
        }
    }
    let total = resources.len();
    let resources: Vec<Value> = resources
        .into_iter()
        .skip(start_index - 1)
        .take(count)
        .collect();
    Ok(response(
        StatusCode::OK,
        &json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "itemsPerPage": resources.len(),
            "startIndex": start_index,
            "Resources": resources,
        }),
        None,
    ))
}

fn user_schema_attributes() -> Value {
    json!([
        { "name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "always", "uniqueness": "server" },
        { "name": "externalId", "type": "string", "multiValued": false, "required": true, "caseExact": true, "mutability": "immutable", "returned": "always", "uniqueness": "server" },
        { "name": "name", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": [
            { "name": "formatted", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" }
        ] },
        { "name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" },
        { "name": "emails", "type": "complex", "multiValued": true, "required": false, "mutability": "readOnly", "returned": "default" },
        { "name": "id", "type": "string", "multiValued": false, "required": false, "mutability": "readOnly", "returned": "always", "uniqueness": "global" },
        { "name": "meta", "type": "complex", "multiValued": false, "required": false, "mutability": "readOnly", "returned": "default" }
    ])
}

fn discovery(path: &str, issuer: &str) -> Option<Response<String>> {
    let body = match path {
        "ServiceProviderConfig" => json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": format!("{issuer}/"),
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": 500 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": true },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "SCIM connection bearer token",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": true
            }]
        }),
        "ResourceTypes" => json!([{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": USER_SCHEMA,
            "meta": { "location": format!("{issuer}/scim/v2/ResourceTypes/User"), "resourceType": "ResourceType" }
        }]),
        "ResourceTypes/User" => json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User", "name": "User", "endpoint": "/Users", "schema": USER_SCHEMA,
            "meta": { "location": format!("{issuer}/scim/v2/ResourceTypes/User"), "resourceType": "ResourceType" }
        }),
        "Schemas" => json!([{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": USER_SCHEMA,
            "name": "User",
            "description": "JetAuth SCIM User",
            "attributes": user_schema_attributes()
        }]),
        "Schemas/urn:ietf:params:scim:schemas:core:2.0:User" => json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": USER_SCHEMA,
            "name": "User",
            "description": "JetAuth SCIM User",
            "attributes": user_schema_attributes()
        }),
        _ => return None,
    };
    Some(response(StatusCode::OK, &body, None))
}

async fn handle_authenticated(
    method: &Method,
    path: &str,
    query: &str,
    body: &[u8],
    headers: &http::HeaderMap,
    issuer: &str,
    connection: &ScimConnection,
) -> Result<Response<String>, Failure> {
    if method != Method::GET
        && matches!(
            crate::service_client::check_rate(&format!("scim:{}", connection.id), 600, 60).await,
            Ok((false, _))
        )
    {
        return Err(Failure::new(
            StatusCode::TOO_MANY_REQUESTS,
            None,
            "SCIM write rate limit exceeded",
        ));
    }
    if method == Method::GET
        && let Some(response) = discovery(path, issuer)
    {
        return Ok(response);
    }
    if path == "Users" {
        return match *method {
            Method::GET => list_users(connection, query, issuer).await,
            Method::POST => create_user(connection, body, issuer).await,
            _ => Err(Failure::new(
                StatusCode::METHOD_NOT_ALLOWED,
                None,
                "method not allowed",
            )),
        };
    }
    if let Some(user_id) = path.strip_prefix("Users/") {
        if user_id.is_empty() || user_id.contains('/') {
            return Err(Failure::not_found());
        }
        let (identity, user) = identity_and_user(connection, user_id).await?;
        match *method {
            Method::GET => Ok(response(
                StatusCode::OK,
                &user_resource(connection, &identity, &user, issuer),
                Some(identity.version),
            )),
            Method::PUT => {
                check_if_match(headers, identity.version)?;
                let value: Value = serde_json::from_slice(body)
                    .map_err(|_| Failure::bad_request("invalid JSON"))?;
                let input = parse_input(&value)?;
                update_user(connection, user_id, identity, user, input, issuer).await
            }
            Method::PATCH => {
                check_if_match(headers, identity.version)?;
                patch_user(connection, user_id, identity, user, body, issuer).await
            }
            Method::DELETE => {
                check_if_match(headers, identity.version)?;
                if user.superadmin {
                    return Err(Failure::new(
                        StatusCode::FORBIDDEN,
                        None,
                        "superadmin cannot be deleted through SCIM",
                    ));
                }
                let _ = store::delete_user_refresh_tokens(user_id).await;
                let _ = store::revoke_user_sessions(user_id).await;
                store::delete_user(user_id)
                    .await
                    .map_err(|_| Failure::internal())?;
                store::delete_scim_identity(&identity)
                    .await
                    .map_err(|_| Failure::internal())?;
                let _ = store::log_audit(
                    "scim_user_deleted",
                    &format!("scim:{}", connection.id),
                    user_id,
                    &connection.tenant_id,
                )
                .await;
                Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("cache-control", "no-store")
                    .body(String::new())
                    .unwrap())
            }
            _ => Err(Failure::new(
                StatusCode::METHOD_NOT_ALLOWED,
                None,
                "method not allowed",
            )),
        }
    } else {
        Err(Failure::not_found())
    }
}

pub async fn handle(
    method: &Method,
    path: &str,
    query: &str,
    body: &[u8],
    headers: &http::HeaderMap,
    issuer: &str,
) -> Response<String> {
    if !enabled() {
        return Failure::not_found().render();
    }
    let connection = match authenticate(headers).await {
        Ok(connection) => connection,
        Err(error) => return error.render(),
    };
    match handle_authenticated(method, path, query, body, headers, issuer, &connection).await {
        Ok(response) => response,
        Err(error) => error.render(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Tenant;

    static SCIM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn token_headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }

    fn connection(id: &str, tenant_id: &str, token: &str) -> ScimConnection {
        ScimConnection {
            id: id.into(),
            name: id.into(),
            tenant_id: tenant_id.into(),
            token_hash: store::sha256_hex(token),
            enabled: true,
            default_role: "member".into(),
            created_at: store::unix_now(),
        }
    }

    #[test]
    fn user_lifecycle_and_connection_isolation() {
        let _guard = SCIM_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            store::init_protocol_features_for_test(false, true);
            for id in ["scim-tenant-a", "scim-tenant-b"] {
                store::create_tenant(&Tenant {
                    id: id.into(),
                    name: id.into(),
                    display_name: id.into(),
                    status: "active".into(),
                    created_at: store::unix_now(),
                })
                .await
                .unwrap();
            }
            store::save_scim_connection(&connection("scim-a", "scim-tenant-a", "token-a"))
                .await
                .unwrap();
            store::save_scim_connection(&connection("scim-b", "scim-tenant-b", "token-b"))
                .await
                .unwrap();

            let create = json!({
                "schemas": [USER_SCHEMA],
                "userName": "scim.person@example.com",
                "externalId": "directory-123",
                "name": { "formatted": "SCIM Person" },
                "active": true
            });
            let response = handle(
                &Method::POST,
                "Users",
                "",
                create.to_string().as_bytes(),
                &token_headers("token-a"),
                "http://localhost:8000",
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            let resource: Value = serde_json::from_str(&response.into_body()).unwrap();
            let user_id = resource["id"].as_str().unwrap().to_string();
            assert_eq!(resource["meta"]["version"], "W/\"1\"");

            let other = handle(
                &Method::GET,
                &format!("Users/{user_id}"),
                "",
                &[],
                &token_headers("token-b"),
                "http://localhost:8000",
            )
            .await;
            assert_eq!(other.status(), StatusCode::NOT_FOUND);

            let patch = json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "replace", "path": "active", "value": false }]
            });
            let response = handle(
                &Method::PATCH,
                &format!("Users/{user_id}"),
                "",
                patch.to_string().as_bytes(),
                &token_headers("token-a"),
                "http://localhost:8000",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                store::get_user(&user_id).await.unwrap().unwrap().status,
                "disabled"
            );
            assert!(
                store::get_membership("scim-tenant-a", &user_id)
                    .await
                    .unwrap()
                    .is_some()
            );

            let mut stale_headers = token_headers("token-a");
            stale_headers.insert("if-match", "W/\"99\"".parse().unwrap());
            let stale = handle(
                &Method::PUT,
                &format!("Users/{user_id}"),
                "",
                create.to_string().as_bytes(),
                &stale_headers,
                "http://localhost:8000",
            )
            .await;
            assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

            let filtered = handle(
                &Method::GET,
                "Users",
                "filter=userName%20eq%20%22scim.person%40example.com%22",
                &[],
                &token_headers("token-b"),
                "http://localhost:8000",
            )
            .await;
            let list: Value = serde_json::from_str(&filtered.into_body()).unwrap();
            assert_eq!(list["totalResults"], 0);

            let deleted = handle(
                &Method::DELETE,
                &format!("Users/{user_id}"),
                "",
                &[],
                &token_headers("token-a"),
                "http://localhost:8000",
            )
            .await;
            assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
            assert!(deleted.into_body().is_empty());
            assert!(store::get_user(&user_id).await.unwrap().is_none());
        });
    }
}
