//! Hook (Rhai script) mutations shared by the management API and the admin
//! panel. Scripts are compile-tested before they are stored; every stored
//! state is snapshotted as an immutable version.

use crate::error::ApiError;
use crate::store::{self, Hook, HookVersion};

use super::authz::Caller;

pub const VALID_TRIGGERS: &[&str] = &["post-login", "post-registration"];

/// Fields for creating a hook.
pub struct CreateHookParams {
    pub name: String,
    pub trigger: String,
    pub script: String,
    pub enabled: bool,
    pub priority: i32,
}

/// Partial hook update; `None` leaves the field unchanged.
#[derive(Default)]
pub struct UpdateHookParams {
    pub name: Option<String>,
    pub trigger: Option<String>,
    pub script: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
}

fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 128 {
        return Err("name must be 1-128 characters".into());
    }
    Ok(())
}

fn validate_trigger(trigger: &str) -> Result<(), ApiError> {
    if !VALID_TRIGGERS.contains(&trigger) {
        return Err(format!("invalid trigger (valid: {})", VALID_TRIGGERS.join(", ")).into());
    }
    Ok(())
}

fn validate_script(script: &str, trigger: &str) -> Result<(), ApiError> {
    if script.is_empty() || script.len() > 65536 {
        return Err("script must be 1-65536 characters".into());
    }
    // Validate script compiles
    if let Err(e) = crate::hooks::test_hook(script, trigger) {
        return Err(format!("script validation failed: {e}").into());
    }
    Ok(())
}

/// Create a hook (version 1). Superadmin only.
pub async fn create_hook(caller: &Caller, params: CreateHookParams) -> Result<Hook, ApiError> {
    caller.require_superadmin()?;

    validate_name(&params.name)?;
    validate_trigger(&params.trigger)?;
    validate_script(&params.script, &params.trigger)?;

    let script_hash = store::sha256_hex(&params.script);
    let now = store::unix_now();

    let hook = Hook {
        id: format!("hook_{}", store::random_alphanumeric(12)),
        name: params.name,
        trigger: params.trigger,
        script: params.script,
        enabled: params.enabled,
        priority: params.priority,
        created_at: now,
        version: 1,
        script_hash: script_hash.clone(),
        updated_by: caller.user_id.clone(),
        updated_at: now,
    };
    store::save_hook(&hook).await.map_err(ApiError::internal)?;

    // Save immutable version snapshot
    let ver = HookVersion {
        hook_id: hook.id.clone(),
        version: 1,
        name: hook.name.clone(),
        trigger: hook.trigger.clone(),
        script: hook.script.clone(),
        script_hash: script_hash.clone(),
        enabled: hook.enabled,
        priority: hook.priority,
        changed_by: caller.user_id.clone(),
        changed_at: now,
    };
    let _ = store::save_hook_version(&ver).await;

    let _ = store::log_audit(
        "hook_created",
        &caller.user_id,
        &hook.id,
        &format!("name={} hash={} v={}", hook.name, script_hash, 1),
    )
    .await;

    Ok(hook)
}

/// Update a hook, bumping its version and snapshotting the new state.
/// Superadmin only.
pub async fn update_hook(
    caller: &Caller,
    hook_id: &str,
    params: UpdateHookParams,
) -> Result<Hook, ApiError> {
    caller.require_superadmin()?;

    let mut hook = store::get_hook(hook_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("hook not found"))?;

    if let Some(name) = params.name {
        validate_name(&name)?;
        hook.name = name;
    }
    if let Some(trigger) = params.trigger {
        validate_trigger(&trigger)?;
        hook.trigger = trigger;
    }
    if let Some(script) = params.script {
        validate_script(&script, &hook.trigger)?;
        hook.script = script;
    }
    if let Some(enabled) = params.enabled {
        hook.enabled = enabled;
    }
    if let Some(priority) = params.priority {
        hook.priority = priority;
    }

    // Bump version, recompute hash, record who changed it
    hook.version += 1;
    hook.script_hash = store::sha256_hex(&hook.script);
    hook.updated_by = caller.user_id.clone();
    hook.updated_at = store::unix_now();

    store::save_hook(&hook).await.map_err(ApiError::internal)?;

    // Save immutable version snapshot of the new state
    let ver = HookVersion {
        hook_id: hook.id.clone(),
        version: hook.version,
        name: hook.name.clone(),
        trigger: hook.trigger.clone(),
        script: hook.script.clone(),
        script_hash: hook.script_hash.clone(),
        enabled: hook.enabled,
        priority: hook.priority,
        changed_by: caller.user_id.clone(),
        changed_at: hook.updated_at,
    };
    let _ = store::save_hook_version(&ver).await;

    let _ = store::log_audit(
        "hook_updated",
        &caller.user_id,
        hook_id,
        &format!(
            "name={} hash={} v={}",
            hook.name, hook.script_hash, hook.version
        ),
    )
    .await;

    Ok(hook)
}

/// Delete a hook. Superadmin only.
pub async fn delete_hook(caller: &Caller, hook_id: &str) -> Result<Hook, ApiError> {
    caller.require_superadmin()?;

    let hook = store::get_hook(hook_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("hook not found"))?;
    store::delete_hook(hook_id)
        .await
        .map_err(ApiError::internal)?;

    let _ = store::log_audit(
        "hook_deleted",
        &caller.user_id,
        hook_id,
        &format!(
            "name={} hash={} v={}",
            hook.name, hook.script_hash, hook.version
        ),
    )
    .await;

    Ok(hook)
}
