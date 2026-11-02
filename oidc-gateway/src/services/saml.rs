use crate::error::ApiError;
use crate::store::{self, ClientTheme, SamlServiceProvider};

use super::authz::Caller;

pub struct CreateSamlSpParams {
    pub name: String,
    pub entity_id: String,
    pub acs_urls: Vec<String>,
    pub name_id_format: Option<String>,
    pub attribute_mappings: Vec<(String, String)>,
    pub request_signing_certificate: Option<String>,
    pub theme: Option<ClientTheme>,
}

#[derive(Default)]
pub struct UpdateSamlSpParams {
    pub name: Option<String>,
    pub acs_urls: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub name_id_format: Option<String>,
    pub attribute_mappings: Option<Vec<(String, String)>>,
    pub request_signing_certificate: Option<Option<String>>,
    pub theme: Option<Option<ClientTheme>>,
}

fn validate_acs(url: &str) -> Result<(), ApiError> {
    let uri = url
        .parse::<http::Uri>()
        .map_err(|_| "invalid assertion consumer service URL")?;
    let scheme = uri.scheme_str().unwrap_or("");
    if scheme != "https" && !(scheme == "http" && crate::is_dev_mode()) {
        return Err("assertion consumer service URLs must use https".into());
    }
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("invalid assertion consumer service URL authority".into());
    }
    Ok(())
}

fn validate_params(
    name: &str,
    acs_urls: &[String],
    name_id_format: &str,
    mappings: &[(String, String)],
) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 128 {
        return Err("name is required and must be at most 128 characters".into());
    }
    if acs_urls.is_empty() || acs_urls.len() > 20 {
        return Err("between 1 and 20 assertion consumer service URLs are required".into());
    }
    for url in acs_urls {
        validate_acs(url)?;
    }
    if !["email", "persistent"].contains(&name_id_format) {
        return Err("name_id_format must be email or persistent".into());
    }
    if mappings.len() > 50 {
        return Err("too many SAML attribute mappings".into());
    }
    for (attribute, source) in mappings {
        if attribute.trim().is_empty() || attribute.len() > 256 {
            return Err("SAML attribute names must be non-empty and at most 256 characters".into());
        }
        if !["email", "name", "user_id", "tenant_id", "role", "roles"].contains(&source.as_str()) {
            return Err(format!("unsupported SAML attribute source: {source}").into());
        }
    }
    Ok(())
}

pub async fn create_service_provider(
    caller: &Caller,
    params: CreateSamlSpParams,
) -> Result<SamlServiceProvider, ApiError> {
    caller.require_superadmin()?;
    let name_id_format = params.name_id_format.unwrap_or_else(|| "email".into());
    validate_params(
        &params.name,
        &params.acs_urls,
        &name_id_format,
        &params.attribute_mappings,
    )?;
    if params.entity_id.trim().is_empty() || params.entity_id.len() > 2048 {
        return Err("entity_id is required and must be at most 2048 characters".into());
    }
    if store::list_saml_service_providers()
        .await
        .map_err(ApiError::internal)?
        .iter()
        .any(|sp| sp.entity_id == params.entity_id)
    {
        return Err(ApiError::conflict("SAML entity_id is already registered"));
    }
    let sp = SamlServiceProvider {
        id: format!("saml_{}", store::random_alphanumeric(12)),
        name: params.name,
        entity_id: params.entity_id,
        acs_urls: params.acs_urls,
        enabled: true,
        name_id_format,
        attribute_mappings: params.attribute_mappings,
        request_signing_certificate: params.request_signing_certificate,
        theme: params.theme,
        created_at: store::unix_now(),
    };
    store::save_saml_service_provider(&sp)
        .await
        .map_err(ApiError::internal)?;
    let json = serde_json::to_value(&sp).unwrap_or_default();
    crate::service_client::replicate_to_regions("put", "saml_sp", &sp.id, Some(&json)).await;
    let _ = store::log_audit("saml_sp_created", &caller.user_id, &sp.id, &sp.entity_id).await;
    Ok(sp)
}

pub async fn update_service_provider(
    caller: &Caller,
    id: &str,
    params: UpdateSamlSpParams,
) -> Result<SamlServiceProvider, ApiError> {
    caller.require_superadmin()?;
    let mut sp = store::get_saml_service_provider(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("SAML service provider not found"))?;
    let name = params.name.unwrap_or_else(|| sp.name.clone());
    let acs_urls = params.acs_urls.unwrap_or_else(|| sp.acs_urls.clone());
    let name_id_format = params
        .name_id_format
        .unwrap_or_else(|| sp.name_id_format.clone());
    let mappings = params
        .attribute_mappings
        .unwrap_or_else(|| sp.attribute_mappings.clone());
    validate_params(&name, &acs_urls, &name_id_format, &mappings)?;
    sp.name = name;
    sp.acs_urls = acs_urls;
    sp.name_id_format = name_id_format;
    sp.attribute_mappings = mappings;
    if let Some(enabled) = params.enabled {
        sp.enabled = enabled;
    }
    if let Some(certificate) = params.request_signing_certificate {
        sp.request_signing_certificate = certificate.filter(|value| !value.is_empty());
    }
    if let Some(theme) = params.theme {
        sp.theme = theme;
    }
    store::save_saml_service_provider(&sp)
        .await
        .map_err(ApiError::internal)?;
    let json = serde_json::to_value(&sp).unwrap_or_default();
    crate::service_client::replicate_to_regions("put", "saml_sp", &sp.id, Some(&json)).await;
    let _ = store::log_audit("saml_sp_updated", &caller.user_id, id, "").await;
    Ok(sp)
}

pub async fn delete_service_provider(caller: &Caller, id: &str) -> Result<(), ApiError> {
    caller.require_superadmin()?;
    store::get_saml_service_provider(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("SAML service provider not found"))?;
    store::delete_saml_service_provider(id)
        .await
        .map_err(ApiError::internal)?;
    crate::service_client::replicate_to_regions("delete", "saml_sp", id, None).await;
    let _ = store::log_audit("saml_sp_deleted", &caller.user_id, id, "").await;
    Ok(())
}
