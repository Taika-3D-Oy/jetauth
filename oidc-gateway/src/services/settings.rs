//! Runtime settings read/write shared by the management API and the admin panel.

use crate::error::ApiError;
use crate::store::{self, ClientTheme, RuntimeSettings};

use super::authz::Caller;

/// Partial runtime-settings update; `None` leaves the field unchanged.
#[derive(Default)]
pub struct SettingsPatch {
    pub allow_registration: Option<bool>,
    pub default_theme: Option<ClientTheme>,
    pub idp_session_ttl_seconds: Option<u64>,
}

/// Read the current runtime settings. Superadmin only.
pub async fn get_settings(caller: &Caller) -> Result<RuntimeSettings, ApiError> {
    caller.require_superadmin()?;
    Ok(store::get_runtime_settings().await)
}

/// Bounds for the IdP session TTL: 5 minutes to 90 days (the admin UI offers
/// 1–90 days; the lower bound keeps sessions from expiring mid-flow).
const MIN_IDP_SESSION_TTL_SECONDS: u64 = 300;
const MAX_IDP_SESSION_TTL_SECONDS: u64 = 90 * 86400;

/// Apply a partial runtime-settings update. Superadmin only.
pub async fn update_settings(
    caller: &Caller,
    patch: SettingsPatch,
) -> Result<RuntimeSettings, ApiError> {
    caller.require_superadmin()?;

    if let Some(ttl) = patch.idp_session_ttl_seconds
        && !(MIN_IDP_SESSION_TTL_SECONDS..=MAX_IDP_SESSION_TTL_SECONDS).contains(&ttl)
    {
        return Err(format!(
            "idp_session_ttl_seconds must be between {MIN_IDP_SESSION_TTL_SECONDS} and {MAX_IDP_SESSION_TTL_SECONDS}"
        )
        .into());
    }
    if let Some(theme) = &patch.default_theme {
        crate::theme::validate_theme(theme)?;
    }

    let mut settings = store::get_runtime_settings().await;

    if let Some(v) = patch.allow_registration {
        settings.allow_registration = v;
    }
    if let Some(theme) = patch.default_theme {
        settings.default_theme = Some(theme);
    }
    if let Some(ttl) = patch.idp_session_ttl_seconds {
        settings.idp_session_ttl_seconds = Some(ttl);
    }

    store::save_runtime_settings(&settings)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "settings_updated",
        &caller.user_id,
        "settings:global",
        &serde_json::to_string(&serde_json::json!({
            "allow_registration": settings.allow_registration,
            "default_theme": settings.default_theme.clone(),
            "idp_session_ttl_seconds": settings.idp_session_ttl_seconds,
        }))
        .unwrap_or_default(),
    )
    .await;

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superadmin() -> Caller {
        Caller {
            user_id: "admin-1".to_string(),
            is_superadmin: true,
            tenant_roles: Vec::new(),
        }
    }

    #[test]
    fn test_update_settings_ttl_bounds() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let caller = superadmin();

            for bad in [0, 299, 90 * 86400 + 1] {
                let err = update_settings(
                    &caller,
                    SettingsPatch {
                        idp_session_ttl_seconds: Some(bad),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
                assert_eq!(err.status, http::StatusCode::BAD_REQUEST, "ttl={bad}");
            }

            let ok = update_settings(
                &caller,
                SettingsPatch {
                    idp_session_ttl_seconds: Some(3600),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(ok.idp_session_ttl_seconds, Some(3600));
        });
    }

    #[test]
    fn test_update_settings_theme_preset_validation() {
        futures::executor::block_on(async {
            store::init_config_for_test(true, None);
            let caller = superadmin();

            let err = update_settings(
                &caller,
                SettingsPatch {
                    default_theme: Some(ClientTheme {
                        theme_preset: Some("not-a-preset".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
            assert_eq!(err.status, http::StatusCode::BAD_REQUEST);

            let ok = update_settings(
                &caller,
                SettingsPatch {
                    default_theme: Some(ClientTheme {
                        theme_preset: Some("cyberpunk".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(
                ok.default_theme.and_then(|t| t.theme_preset).as_deref(),
                Some("cyberpunk")
            );
        });
    }
}
