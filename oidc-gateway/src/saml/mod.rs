pub mod keys;

use std::time::{Duration, UNIX_EPOCH};

use http::{Method, Response, StatusCode};
use saml_rs::raw::LoginResponseOptions;
use saml_rs::template::{LoginResponseAttribute, LoginResponseTemplate};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AuthnRequest, AuthnRequestAgePolicy,
    AuthnRequestSigningPolicy, BrowserInput, CertificatePem, Credentials, EntityId, ForceAuthn,
    FormField, Idp, IdpConfig, IdpValidationPolicy, IsPassive, MetadataTrustPolicy, NameIdFormat,
    PrivateKeyPem, Received, ReplayPolicy, Saml, SamlValidationContext, SpConfig, SpDescriptor,
    SpValidationPolicy, SsoEndpoint, SsoResponseBinding, TemplatePolicy,
};

use crate::store::{self, AuthSession, SamlFlow, SamlServiceProvider, User};
use crate::util;

pub fn enabled() -> bool {
    store::config_value("saml_enabled").is_some_and(|value| value == "true" || value == "1")
}

fn saml_error(error: impl std::fmt::Display) -> String {
    format!("SAML request could not be processed: {error}")
}

fn idp_entity_id(issuer: &str) -> String {
    format!("{issuer}/saml/metadata")
}

fn sso_url(issuer: &str) -> String {
    format!("{issuer}/saml/sso")
}

fn validation() -> SamlValidationContext<'static> {
    let now = UNIX_EPOCH + Duration::from_secs(store::unix_now());
    SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility).with_authn_request_age(
        AuthnRequestAgePolicy::Bounded {
            max_age: Duration::from_secs(600),
        },
    )
}

fn name_id_format(sp: &SamlServiceProvider) -> NameIdFormat {
    if sp.name_id_format == "persistent" {
        NameIdFormat::Persistent
    } else {
        NameIdFormat::EmailAddress
    }
}

async fn build_idp(issuer: &str, sp: Option<&SamlServiceProvider>) -> Result<Saml<Idp>, String> {
    saml_rs::initialize_crypto_provider().map_err(saml_error)?;
    let key_ring = keys::ensure_key_ring().await?;
    let entity_id = idp_entity_id(issuer);
    let endpoint = sso_url(issuer);
    let mut builder = IdpConfig::builder(EntityId::try_new(entity_id).map_err(saml_error)?)
        .sso_endpoint(SsoEndpoint::redirect(&endpoint).map_err(saml_error)?)
        .sso_endpoint(SsoEndpoint::post(&endpoint).map_err(saml_error)?)
        .credentials(Credentials {
            signing_key: Some(PrivateKeyPem::new(key_ring.current.private_key_pem)),
            signing_certificate: Some(CertificatePem::new(key_ring.current.certificate_pem)),
            ..Credentials::default()
        })
        .issuance_lifetime(Duration::from_secs(300))
        .validation(IdpValidationPolicy::recommended());

    if let Some(sp) = sp {
        let attributes = sp
            .attribute_mappings
            .iter()
            .enumerate()
            .map(|(index, (name, _))| LoginResponseAttribute {
                name: name.clone(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: format!("a{index}"),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            })
            .collect();
        builder = builder
            .name_id_format(name_id_format(sp))
            .templates(TemplatePolicy {
                login_response_template: Some(LoginResponseTemplate {
                    context: None,
                    attributes,
                }),
                ..TemplatePolicy::default()
            });
    } else {
        builder = builder
            .name_id_format(NameIdFormat::EmailAddress)
            .name_id_format(NameIdFormat::Persistent);
    }

    Saml::idp(builder.build().map_err(saml_error)?).map_err(saml_error)
}

fn build_sp(sp: &SamlServiceProvider, acs_urls: &[String]) -> Result<SpDescriptor, String> {
    let mut builder = SpConfig::builder(EntityId::try_new(&sp.entity_id).map_err(saml_error)?)
        .name_id_format(name_id_format(sp))
        .validation(SpValidationPolicy {
            assertions: AssertionSignaturePolicy::RequireSigned,
            authn_requests: AuthnRequestSigningPolicy::DoNotSignForCompatibility,
            ..SpValidationPolicy::recommended()
        });
    for url in acs_urls {
        builder = builder.acs_endpoint(AcsEndpoint::post(url).map_err(saml_error)?);
    }
    if let Some(certificate) = &sp.request_signing_certificate {
        builder = builder.credentials(Credentials {
            signing_certificate: Some(CertificatePem::new(certificate)),
            ..Credentials::default()
        });
    }
    let local = Saml::sp(builder.build().map_err(saml_error)?).map_err(saml_error)?;
    SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(&sp.entity_id).map_err(saml_error)?,
        local.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .map_err(saml_error)
}

fn request_input(flow: &SamlFlow, query: &str) -> Result<BrowserInput<AuthnRequest>, String> {
    match flow.binding.as_str() {
        "redirect" => Ok(BrowserInput::<AuthnRequest>::redirect(query)),
        "post" => Ok(BrowserInput::<AuthnRequest>::post(
            flow.request_fields
                .iter()
                .map(|(name, value)| FormField::new(name, value))
                .collect(),
        )),
        _ => Err("unsupported SAML request binding".into()),
    }
}

async fn receive_request(
    sp: &SamlServiceProvider,
    issuer: &str,
    input: BrowserInput<AuthnRequest>,
) -> Result<Received<AuthnRequest>, String> {
    let descriptor = build_sp(sp, &sp.acs_urls)?;
    let idp = build_idp(issuer, Some(sp)).await?;
    idp.receive_sso(&descriptor, input, validation())
        .map_err(saml_error)
}

fn selected_acs(sp: &SamlServiceProvider, request: &AuthnRequest) -> Result<String, String> {
    if request
        .protocol_binding()
        .is_some_and(|binding| binding != SsoResponseBinding::Post)
    {
        return Err("only HTTP-POST SAML responses are supported".into());
    }
    if let Some(url) = request.acs_url() {
        if !sp
            .acs_urls
            .iter()
            .any(|registered| registered == url.as_str())
        {
            return Err("unregistered assertion consumer service URL".into());
        }
        return Ok(url.as_str().to_string());
    }
    if let Some(index) = request.acs_index() {
        return sp
            .acs_urls
            .get(index as usize)
            .cloned()
            .ok_or_else(|| "unknown assertion consumer service index".into());
    }
    sp.acs_urls
        .first()
        .cloned()
        .ok_or_else(|| "SAML service provider has no assertion consumer service".into())
}

async fn attribute_values(sp: &SamlServiceProvider, user: &User) -> Vec<(String, String)> {
    let memberships = store::list_user_tenants(&user.id).await.unwrap_or_default();
    let tenant_id = memberships
        .first()
        .map(|m| m.tenant_id.as_str())
        .unwrap_or("");
    let role = memberships.first().map(|m| m.role.as_str()).unwrap_or("");
    let roles = memberships
        .iter()
        .map(|membership| format!("{}:{}", membership.tenant_id, membership.role))
        .collect::<Vec<_>>()
        .join(",");
    sp.attribute_mappings
        .iter()
        .enumerate()
        .map(|(index, (_, source))| {
            let value = match source.as_str() {
                "email" => user.email.clone(),
                "name" => user.name.clone(),
                "user_id" => user.id.clone(),
                "tenant_id" => tenant_id.to_string(),
                "role" => role.to_string(),
                "roles" => roles.clone(),
                _ => String::new(),
            };
            (format!("a{index}"), value)
        })
        .collect()
}

async fn issue_response(
    sp: &SamlServiceProvider,
    request: &Received<AuthnRequest>,
    user: &User,
    issuer: &str,
) -> Result<Response<String>, String> {
    if user.status != "active" {
        return Err("account is not active".into());
    }
    let acs = selected_acs(sp, request.message())?;
    let descriptor = build_sp(sp, &[acs])?;
    let idp = build_idp(issuer, Some(sp)).await?;
    let name_id = if sp.name_id_format == "persistent" {
        user.id.clone()
    } else {
        user.email.clone()
    };
    let raw_user = saml_rs::entity::User {
        name_id,
        attributes: attribute_values(sp, user).await,
        ..saml_rs::entity::User::default()
    };
    let raw_sp = saml_rs::raw::ServiceProvider::from_metadata(
        descriptor.metadata_xml(),
        saml_rs::raw::EntitySetting::default(),
    )
    .map_err(saml_error)?;
    let response = idp
        .raw_identity_provider()
        .create_login_response(
            &raw_sp,
            saml_rs::constants::Binding::Post,
            &raw_user,
            &LoginResponseOptions {
                in_response_to: Some(request.message().id().as_str()),
                relay_state: request.relay_state().as_deref(),
                ..LoginResponseOptions::default()
            },
        )
        .map_err(saml_error)?;
    let html = response.try_post_form().map_err(saml_error)?;
    let _ = store::log_audit("saml_sso_success", &user.id, &sp.id, &sp.entity_id).await;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .map_err(|e| e.to_string())
}

pub async fn metadata(issuer: &str) -> Result<Response<String>, String> {
    if !enabled() {
        return Err("SAML is not enabled".into());
    }
    let ring = keys::ensure_key_ring().await?;
    let mut certificates = vec![ring.current.certificate_pem.clone()];
    if let Some(previous) = ring.previous {
        certificates.push(previous.certificate_pem);
    }
    let endpoint = sso_url(issuer);
    let idp = saml_rs::raw::IdentityProvider::from_config(
        &saml_rs::raw::metadata::IdpMetadataConfig {
            entity_id: idp_entity_id(issuer),
            signing_certs: certificates,
            name_id_format: vec![
                NameIdFormat::EmailAddress.as_uri().to_string(),
                NameIdFormat::Persistent.as_uri().to_string(),
            ],
            single_sign_on_service: vec![
                saml_rs::raw::metadata::Endpoint::new(saml_rs::raw::Binding::Redirect, &endpoint),
                saml_rs::raw::metadata::Endpoint::new(saml_rs::raw::Binding::Post, &endpoint),
            ],
            ..Default::default()
        },
        saml_rs::raw::EntitySetting::default(),
    )
    .map_err(saml_error)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(
            "content-type",
            "application/samlmetadata+xml; charset=utf-8",
        )
        .header("cache-control", "public, max-age=300")
        .body(idp.metadata_xml().to_string())
        .map_err(|e| e.to_string())
}

pub async fn start(
    method: &Method,
    query: &str,
    body: &[u8],
    issuer: &str,
    headers: &http::HeaderMap,
) -> Result<Response<String>, String> {
    if !enabled() {
        return Err("SAML is not enabled".into());
    }
    let flow = if method == Method::GET {
        SamlFlow {
            sp_id: String::new(),
            request_fields: vec![("__raw_query".into(), query.to_string())],
            binding: "redirect".into(),
            created_at: store::unix_now(),
        }
    } else if method == Method::POST {
        SamlFlow {
            sp_id: String::new(),
            request_fields: util::parse_form(body),
            binding: "post".into(),
            created_at: store::unix_now(),
        }
    } else {
        return Err("unsupported SAML SSO method".into());
    };

    let mut matched = None;
    for sp in store::list_saml_service_providers()
        .await?
        .into_iter()
        .filter(|sp| sp.enabled)
    {
        if let Ok(request) = receive_request(&sp, issuer, request_input(&flow, query)?).await {
            matched = Some((sp, request));
            break;
        }
    }
    let (sp, request) =
        matched.ok_or_else(|| "unknown or invalid SAML service provider request".to_string())?;
    let acs = selected_acs(&sp, request.message())?;
    if !sp.acs_urls.contains(&acs) {
        return Err("unregistered assertion consumer service URL".into());
    }

    let force_authn = matches!(request.message().force_authn(), Some(ForceAuthn::Required));
    let is_passive = matches!(request.message().is_passive(), Some(IsPassive::Required));
    if !force_authn
        && let Some(idp_session) = crate::account::get_idp_session_from_headers(headers).await
        && let Some(user) = store::get_user(&idp_session.user_id).await?
    {
        store::reserve_saml_request(&sp.id, request.message().id().as_str()).await?;
        let outcome = crate::hooks::execute_hooks("post-login", &user).await;
        if let Some(reason) = outcome.deny_reason {
            return Err(reason);
        }
        let mut user = user;
        crate::hooks::apply_outcome(&mut user, &outcome).await?;
        let response = issue_response(&sp, &request, &user, issuer).await?;
        let (mut parts, body) = response.into_parts();
        if let Some(cookie) = crate::account::refresh_idp_session_cookie_header(headers).await
            && let Ok(value) = cookie.parse()
        {
            parts.headers.append("set-cookie", value);
        }
        return Ok(Response::from_parts(parts, body));
    }
    if is_passive {
        return Err("SAML passive authentication could not be satisfied".into());
    }

    store::reserve_saml_request(&sp.id, request.message().id().as_str()).await?;
    let session_id = store::random_hex(32);
    let session = AuthSession {
        client_id: format!("saml:{}", sp.id),
        redirect_uri: String::new(),
        code_challenge: String::new(),
        code_challenge_method: "saml".into(),
        state: String::new(),
        scope: String::new(),
        nonce: String::new(),
        max_age: None,
        acr_values: Vec::new(),
        requested_id_token_claims: Vec::new(),
        requested_userinfo_claims: Vec::new(),
        hinted_user_id: None,
        hinted_email: None,
        created_at: store::unix_now(),
        needs_consent: false,
        prompt: None,
        sid: None,
    };
    store::save_auth_session(&session_id, &session).await?;
    let flow = SamlFlow {
        sp_id: sp.id,
        ..flow
    };
    store::save_saml_flow(&session_id, &flow).await?;
    let response = crate::login::login_page(&session_id, None).await;
    let (mut parts, body) = response.into_parts();
    if let Ok(cookie) = crate::account::create_flow_cookie(&session_id).parse() {
        parts.headers.append("set-cookie", cookie);
    }
    Ok(Response::from_parts(parts, body))
}

pub async fn complete_after_login(
    session_id: &str,
    user: &User,
    issuer: &str,
) -> Result<Response<String>, String> {
    let flow = store::consume_saml_flow(session_id)
        .await?
        .ok_or("SAML login flow has already been used or expired")?;
    if store::unix_now() > flow.created_at + 600 {
        return Err("SAML login flow expired".into());
    }
    let sp = store::get_saml_service_provider(&flow.sp_id)
        .await?
        .filter(|sp| sp.enabled)
        .ok_or("SAML service provider is not available")?;
    let raw_query = flow
        .request_fields
        .iter()
        .find(|(name, _)| name == "__raw_query")
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    let request = receive_request(&sp, issuer, request_input(&flow, raw_query)?).await?;
    issue_response(&sp, &request, user, issuer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use saml_rs::{IdpDescriptor, SsoResponse, StartSso};

    static SAML_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn sp_request_to_signed_jetauth_response_round_trip() {
        let _guard = SAML_TEST_LOCK.lock().unwrap();
        futures::executor::block_on(async {
            store::init_protocol_features_for_test(true, false);
            let issuer = "http://localhost:8000";
            let sp = SamlServiceProvider {
                id: "saml_test".into(),
                name: "Test SP".into(),
                entity_id: "https://sp.example.com/metadata".into(),
                acs_urls: vec!["https://sp.example.com/acs".into()],
                enabled: true,
                name_id_format: "email".into(),
                attribute_mappings: vec![
                    ("email".into(), "email".into()),
                    ("displayName".into(), "name".into()),
                ],
                request_signing_certificate: None,
                theme: None,
                created_at: store::unix_now(),
            };
            let user = User {
                id: "saml-user".into(),
                email: "person@example.com".into(),
                name: "Example Person".into(),
                password_hash: String::new(),
                status: "active".into(),
                created_at: store::unix_now(),
                superadmin: false,
                totp_secret: None,
                totp_enabled: false,
                recovery_codes: Vec::new(),
                passkey_credentials: Vec::new(),
            };

            let relying_party = Saml::sp(
                SpConfig::builder(EntityId::try_new(&sp.entity_id).unwrap())
                    .acs_endpoint(AcsEndpoint::post(&sp.acs_urls[0]).unwrap())
                    .validation(SpValidationPolicy {
                        assertions: AssertionSignaturePolicy::RequireSigned,
                        ..SpValidationPolicy::recommended()
                    })
                    .build()
                    .unwrap(),
            )
            .unwrap();
            let idp = build_idp(issuer, Some(&sp)).await.unwrap();
            let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
                EntityId::try_new(idp_entity_id(issuer)).unwrap(),
                idp.metadata_xml(),
                MetadataTrustPolicy::UnsignedForCompatibility,
            )
            .unwrap();
            let started = relying_party
                .start_sso(&idp_descriptor, StartSso::post())
                .unwrap();
            let fields = started.outbound.post_form().unwrap().fields().to_vec();
            let request = receive_request(&sp, issuer, BrowserInput::<AuthnRequest>::post(fields))
                .await
                .unwrap();
            let response = issue_response(&sp, &request, &user, issuer).await.unwrap();
            let html = response.into_body();
            let encoded = html
                .split("name=\"SAMLResponse\" value=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .expect("SAMLResponse form field");
            let session = relying_party.finish_sso(
                &idp_descriptor,
                &started.pending,
                BrowserInput::<SsoResponse>::post(vec![FormField::new("SAMLResponse", encoded)]),
                validation(),
            );
            let session = session.unwrap();
            assert_eq!(session.name_id().value(), "person@example.com");
        });
    }
}
