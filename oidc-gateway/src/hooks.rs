//! Rhai-based scripting hooks — Auth0-style "Actions" for Lattice-ID.
//!
//! Hooks are Rhai scripts stored in KV that execute at specific points in
//! the authentication lifecycle. Each script receives a read-only context
//! and can call mutation functions to affect the outcome.
//!
//! Hook triggers:
//!   - `post-login`       — after successful auth, before issuing the auth code
//!   - `post-registration` — after a new user is created
//!
//! Available in scripts:
//!   Variables:  user (map), event (string), tenants (array of maps)
//!   Functions:  set_superadmin(bool), add_to_tenant(id, role), create_tenant(id, name, display),
//!               deny(msg), set_claim(key, value), log(msg)

use crate::store::{self, Hook, User};
use rhai::{AST, Dynamic, Engine, Map, Scope};
use std::cell::RefCell;
use std::rc::Rc;

/// Outcome after executing all hooks for a trigger point.
#[derive(Default, Debug)]
pub struct HookOutcome {
    /// If set, the login/registration should be denied with this message.
    pub deny_reason: Option<String>,
    /// Whether to set the user as superadmin.
    pub set_superadmin: Option<bool>,
    /// Whether to explicitly set user account active/suspended status.
    pub set_active: Option<bool>,
    /// Tenants to create from the hook: (id, name, display_name).
    pub create_tenants: Vec<(String, String, String)>,
    /// Tenant memberships to add: (tenant_id, role).
    pub add_to_tenants: Vec<(String, String)>,
    /// Custom claims to inject into tokens.
    pub extra_claims: Vec<(String, String)>,
    /// Messages logged by scripts (for audit trail).
    pub log_messages: Vec<String>,
}

/// Accumulator for hook side-effects, shared with the Rhai engine.
#[derive(Default, Clone)]
struct HookAccumulator {
    deny_reason: Rc<RefCell<Option<String>>>,
    set_superadmin: Rc<RefCell<Option<bool>>>,
    set_active: Rc<RefCell<Option<bool>>>,
    create_tenants: Rc<RefCell<Vec<(String, String, String)>>>,
    add_to_tenants: Rc<RefCell<Vec<(String, String)>>>,
    extra_claims: Rc<RefCell<Vec<(String, String)>>>,
    log_messages: Rc<RefCell<Vec<String>>>,
}

impl HookAccumulator {
    fn into_outcome(self) -> HookOutcome {
        HookOutcome {
            deny_reason: self.deny_reason.take(),
            set_superadmin: self.set_superadmin.take(),
            set_active: self.set_active.take(),
            create_tenants: self.create_tenants.take(),
            add_to_tenants: self.add_to_tenants.take(),
            extra_claims: self.extra_claims.take(),
            log_messages: self.log_messages.take(),
        }
    }
}

/// Build a Rhai `Map` representing the user for script consumption.
fn user_to_map(user: &User) -> Map {
    let mut m = Map::new();
    m.insert("id".into(), Dynamic::from(user.id.clone()));
    m.insert("email".into(), Dynamic::from(user.email.clone()));
    m.insert("name".into(), Dynamic::from(user.name.clone()));
    m.insert("superadmin".into(), Dynamic::from(user.superadmin));
    m.insert("created_at".into(), Dynamic::from(user.created_at as i64));
    m.insert("status".into(), Dynamic::from(user.status.clone()));
    m.insert("totp_enabled".into(), Dynamic::from(user.totp_enabled));
    m
}

/// Build the tenants array for script consumption.
async fn tenants_to_array(user_id: &str) -> rhai::Array {
    let memberships = store::list_user_tenants(user_id).await.unwrap_or_default();
    memberships
        .iter()
        .map(|m| {
            let mut tm = Map::new();
            tm.insert("tenant_id".into(), Dynamic::from(m.tenant_id.clone()));
            tm.insert("role".into(), Dynamic::from(m.role.clone()));
            Dynamic::from(tm)
        })
        .collect()
}

/// Create a new Rhai engine with sandboxing limits and hook API functions.
fn create_engine(acc: &HookAccumulator) -> Engine {
    let mut engine = Engine::new();

    // Sandboxing: limit execution to prevent runaway scripts
    engine.set_max_operations(10_000);
    engine.set_max_string_size(4_096);
    engine.set_max_array_size(256);
    engine.set_max_map_size(128);

    // Register hook API functions

    let deny_ref = acc.deny_reason.clone();
    engine.register_fn("deny", move |msg: &str| {
        *deny_ref.borrow_mut() = Some(msg.to_string());
    });

    let sa_ref = acc.set_superadmin.clone();
    engine.register_fn("set_superadmin", move |val: bool| {
        *sa_ref.borrow_mut() = Some(val);
    });

    let active_ref = acc.set_active.clone();
    engine.register_fn("set_active", move |val: bool| {
        *active_ref.borrow_mut() = Some(val);
    });

    let tenant_ref = acc.add_to_tenants.clone();
    engine.register_fn("add_to_tenant", move |tenant_id: &str, role: &str| {
        let valid_roles = ["owner", "admin", "manager", "member"];
        if valid_roles.contains(&role) {
            tenant_ref
                .borrow_mut()
                .push((tenant_id.to_string(), role.to_string()));
        }
    });

    let claims_ref = acc.extra_claims.clone();
    engine.register_fn("set_claim", move |key: &str, value: &str| {
        // Prevent overwriting standard OIDC and identity claims
        let reserved = [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nbf",
            "nonce",
            "auth_time",
            "token_type",
            "role",
            "tenant_id",
            "tenants",
            "email",
            "name",
            "email_verified",
            "amr",
            "acr",
            "scope",
            "at_hash",
            "c_hash",
            "azp",
        ];
        if !reserved.contains(&key) {
            claims_ref
                .borrow_mut()
                .push((key.to_string(), value.to_string()));
        }
    });

    let log_ref = acc.log_messages.clone();
    engine.register_fn("log", move |msg: &str| {
        log_ref.borrow_mut().push(msg.to_string());
    });

    let ct_ref = acc.create_tenants.clone();
    engine.register_fn(
        "create_tenant",
        move |id: &str, name: &str, display_name: &str| {
            // Validate id: lowercase alphanumeric + internal hyphens, 2-63 chars.
            let id_valid = id.len() >= 2
                && id.len() <= 63
                && id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !id.starts_with('-')
                && !id.ends_with('-');
            if id_valid && !name.is_empty() && !display_name.is_empty() {
                ct_ref.borrow_mut().push((
                    id.to_string(),
                    name.to_string(),
                    display_name.to_string(),
                ));
            }
        },
    );

    engine
}

/// Execute all enabled hooks for the given trigger, returning the combined outcome.
pub async fn execute_hooks(trigger: &str, user: &User) -> HookOutcome {
    let hooks = match load_hooks_for_trigger(trigger).await {
        Ok(h) => h,
        Err(e) => {
            crate::logger::error_message("hooks.load_failed", e);
            return HookOutcome::default();
        }
    };

    if hooks.is_empty() {
        return HookOutcome::default();
    }

    let acc = HookAccumulator::default();
    let engine = create_engine(&acc);

    let user_map = user_to_map(user);
    let tenants_arr = tenants_to_array(&user.id).await;

    for hook in &hooks {
        // Log execution with content hash for audit traceability
        let _ = store::log_audit(
            "hook_executed",
            &hook.id,
            &user.id,
            &format!(
                "trigger={} name={} v={} hash={}",
                trigger, hook.name, hook.version, hook.script_hash
            ),
        )
        .await;

        // Compile the script
        let ast: AST = match engine.compile(&hook.script) {
            Ok(ast) => ast,
            Err(e) => {
                crate::logger::error_message(
                    "hooks.compile_failed",
                    format!("hook '{}': {}", hook.name, e),
                );
                let _ =
                    store::log_audit("hook_error", &hook.id, "", &format!("compile error: {e}"))
                        .await;
                continue;
            }
        };

        // Build scope with read-only context variables
        let mut scope = Scope::new();
        scope.push_constant("user", Dynamic::from(user_map.clone()));
        scope.push_constant("event", Dynamic::from(trigger.to_string()));
        scope.push_constant("tenants", Dynamic::from(tenants_arr.clone()));

        // Execute
        if let Err(e) = engine.run_ast_with_scope(&mut scope, &ast) {
            crate::logger::error_message(
                "hooks.runtime_error",
                format!("hook '{}': {}", hook.name, e),
            );
            let _ = store::log_audit(
                "hook_error",
                &hook.id,
                &user.id,
                &format!("runtime error: {e}"),
            )
            .await;
        }

        // If a hook denied, stop processing further hooks
        if acc.deny_reason.borrow().is_some() {
            break;
        }
    }

    acc.into_outcome()
}

/// Apply the side-effects from hook execution to the actual user record and memberships.
pub async fn apply_outcome(user: &mut User, outcome: &HookOutcome) -> Result<(), String> {
    let mut changed = false;

    if let Some(sa) = outcome.set_superadmin {
        if user.superadmin != sa {
            changed = true;
            let _ = store::log_audit(
                "hook_set_superadmin",
                "system",
                &user.id,
                &format!("superadmin={sa}"),
            )
            .await;
        }
        // If email verification is NOT required, activate superadmin automatically
        if sa && !crate::require_email_verification() && user.status != "active" {
            changed = true;
        }
    }

    let mut target_status = None;
    if let Some(active) = outcome.set_active {
        let new_status = if active { "active" } else { "suspended" };
        if user.status != new_status {
            changed = true;
            target_status = Some(new_status.to_string());
            let _ = store::log_audit(
                "hook_set_status",
                "system",
                &user.id,
                &format!("status={new_status}"),
            )
            .await;
        }
    }

    if changed {
        let set_sa = outcome.set_superadmin;
        let require_verification = crate::require_email_verification();
        let status_override = target_status;
        store::update_user_rmw(&user.id, |u| {
            if let Some(sa) = set_sa {
                u.superadmin = sa;
                if sa && !require_verification && u.status != "active" {
                    u.status = "active".to_string();
                }
            }
            if let Some(ref st) = status_override {
                u.status = st.clone();
            }
            Ok(true)
        })
        .await?;
        // Re-read the updated user so the caller has the latest state
        if let Some(updated) = store::get_user(&user.id).await? {
            *user = updated;
        }
    }

    for (id, name, display_name) in &outcome.create_tenants {
        // Idempotent: skip silently if the tenant already exists so that
        // retries and non-first-registrant invocations don't error out.
        if store::get_tenant(id).await?.is_none() {
            let tenant = store::Tenant {
                id: id.clone(),
                name: name.clone(),
                display_name: display_name.clone(),
                status: "active".to_string(),
                created_at: store::unix_now(),
            };
            store::create_tenant(&tenant).await?;
            let _ = store::log_audit(
                "hook_create_tenant",
                "system",
                &user.id,
                &format!("tenant={id} name={name}"),
            )
            .await;
        }
    }

    for (tenant_id, role) in &outcome.add_to_tenants {
        // Only add if not already a member
        let existing = store::list_user_tenants(&user.id).await.unwrap_or_default();
        if !existing.iter().any(|m| m.tenant_id == *tenant_id) {
            // Verify or ensure the tenant exists
            if store::get_tenant(tenant_id).await?.is_none() {
                let tenant = store::Tenant {
                    id: tenant_id.clone(),
                    name: tenant_id.clone(),
                    display_name: tenant_id.clone(),
                    status: "active".to_string(),
                    created_at: store::unix_now(),
                };
                let _ = store::create_tenant(&tenant).await;
            }
            let membership = store::Membership {
                tenant_id: tenant_id.clone(),
                user_id: user.id.clone(),
                role: role.clone(),
                joined_at: store::unix_now(),
            };
            store::add_membership(&membership).await?;
            let _ = store::log_audit(
                "hook_add_to_tenant",
                "system",
                &user.id,
                &format!("tenant={tenant_id} role={role}"),
            )
            .await;
        }
    }

    // Log any script log messages to audit
    for msg in &outcome.log_messages {
        let _ = store::log_audit("hook_log", "system", &user.id, msg).await;
    }

    Ok(())
}

/// Load hooks for a trigger, sorted by priority (ascending).
async fn load_hooks_for_trigger(trigger: &str) -> Result<Vec<Hook>, String> {
    let mut hooks = store::list_hooks().await?;
    hooks.retain(|h| h.enabled && h.trigger == trigger);
    hooks.sort_by_key(|h| h.priority);
    Ok(hooks)
}

/// Check whether any superadmin user already exists.
/// Uses a cached flag in KV to avoid scanning all users on every call.
pub async fn has_superadmin() -> bool {
    // Fast path: check the cached flag
    if let Ok(Some(true)) = store::get_superadmin_flag().await {
        return true;
    }
    // Slow path: scan users and update the flag
    let found = store::list_users()
        .await
        .unwrap_or_default()
        .iter()
        .any(|u| u.superadmin);
    if found {
        let _ = store::set_superadmin_flag(true).await;
    }
    found
}

/// Execute the deployment-config bootstrap hook (if present) for a newly
/// registered user.  This only fires when:
///   1. A `bootstrap_hook` config value is set
///   2. No superadmin user exists yet
///
/// This enables zero-credential bootstrapping: the deployer specifies a
/// Rhai script (e.g. via `.wash/config.yaml` or env) that promotes a
/// matching email to superadmin on first registration.  Once a superadmin
/// exists the hook never fires again.
pub async fn execute_bootstrap_hook(user: &User) -> HookOutcome {
    // Fast-path: once any superadmin exists, skip entirely.
    if has_superadmin().await {
        return HookOutcome::default();
    }

    let script = match crate::get_bootstrap_hook() {
        Some(s) => s,
        None => return HookOutcome::default(),
    };

    crate::logger::info(
        "bootstrap_hook.executing",
        serde_json::json!({ "email": &user.email }),
    );

    let acc = HookAccumulator::default();
    let engine = create_engine(&acc);

    let ast: AST = match engine.compile(&script) {
        Ok(ast) => ast,
        Err(e) => {
            crate::logger::error_message("bootstrap_hook.compile_failed", format!("{e}"));
            return HookOutcome::default();
        }
    };

    let user_map = user_to_map(user);
    let tenants_arr = tenants_to_array(&user.id).await;

    let mut scope = Scope::new();
    scope.push_constant("user", Dynamic::from(user_map));
    scope.push_constant("event", Dynamic::from("post-registration".to_string()));
    scope.push_constant("tenants", Dynamic::from(tenants_arr));

    if let Err(e) = engine.run_ast_with_scope(&mut scope, &ast) {
        crate::logger::error_message("bootstrap_hook.runtime_error", format!("{e}"));
    }

    let outcome = acc.into_outcome();

    // Audit the bootstrap hook execution.
    let hash = store::sha256_hex(&script);
    let _ = store::log_audit(
        "bootstrap_hook_executed",
        "config",
        &user.id,
        &format!(
            "hash={} set_superadmin={:?} deny={:?}",
            hash, outcome.set_superadmin, outcome.deny_reason
        ),
    )
    .await;

    outcome
}

/// Dry-run a hook script with sample data, returning the outcome or error.
pub fn test_hook(script: &str, trigger: &str) -> Result<HookOutcome, String> {
    let sample_user = User {
        id: "test-user-id".to_string(),
        email: "test@example.com".to_string(),
        name: "Test User".to_string(),
        password_hash: String::new(),
        status: "active".to_string(),
        created_at: store::unix_now(),
        superadmin: false,
        totp_secret: None,
        totp_enabled: false,
        recovery_codes: Vec::new(),
        passkey_credentials: Vec::new(),
    };

    let acc = HookAccumulator::default();
    let engine = create_engine(&acc);

    let ast = engine
        .compile(script)
        .map_err(|e| format!("compile error: {e}"))?;

    let mut scope = Scope::new();
    scope.push_constant("user", Dynamic::from(user_to_map(&sample_user)));
    scope.push_constant("event", Dynamic::from(trigger.to_string()));
    scope.push_constant("tenants", Dynamic::from(rhai::Array::new()));

    engine
        .run_ast_with_scope(&mut scope, &ast)
        .map_err(|e| format!("runtime error: {e}"))?;

    Ok(acc.into_outcome())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_superadmin() {
        let outcome = test_hook(r#"set_superadmin(true);"#, "post-login").unwrap();
        assert_eq!(outcome.set_superadmin, Some(true));
        assert!(outcome.deny_reason.is_none());
    }

    #[test]
    fn test_deny() {
        let outcome = test_hook(r#"deny("blocked by policy");"#, "post-login").unwrap();
        assert_eq!(outcome.deny_reason.as_deref(), Some("blocked by policy"));
    }

    #[test]
    fn test_log_message() {
        let outcome = test_hook(r#"log("hello from hook");"#, "post-login").unwrap();
        assert_eq!(outcome.log_messages, vec!["hello from hook"]);
    }

    #[test]
    fn test_add_to_tenant() {
        let outcome = test_hook(
            r#"add_to_tenant("tenant-1", "member");"#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(
            outcome.add_to_tenants,
            vec![("tenant-1".to_string(), "member".to_string())]
        );
    }

    #[test]
    fn test_add_to_tenant_rejects_invalid_role() {
        let outcome = test_hook(r#"add_to_tenant("t1", "superadmin");"#, "post-login").unwrap();
        // "superadmin" is not a valid tenant role, should be ignored
        assert!(outcome.add_to_tenants.is_empty());
    }

    #[test]
    fn test_set_claim() {
        let outcome = test_hook(r#"set_claim("org_name", "Acme Corp");"#, "post-login").unwrap();
        assert_eq!(
            outcome.extra_claims,
            vec![("org_name".to_string(), "Acme Corp".to_string())]
        );
    }

    #[test]
    fn test_set_claim_reserved_rejected() {
        let outcome = test_hook(
            r#"set_claim("sub", "evil"); set_claim("custom", "ok");"#,
            "post-login",
        )
        .unwrap();
        // "sub" is reserved and should be dropped, "custom" should pass
        assert_eq!(outcome.extra_claims.len(), 1);
        assert_eq!(outcome.extra_claims[0].0, "custom");
    }

    #[test]
    fn test_user_context_accessible() {
        let outcome = test_hook(
            r#"if user.email == "test@example.com" { log("found"); }"#,
            "post-login",
        )
        .unwrap();
        assert_eq!(outcome.log_messages, vec!["found"]);
    }

    #[test]
    fn test_event_context() {
        let outcome = test_hook(r#"log(event);"#, "post-registration").unwrap();
        assert_eq!(outcome.log_messages, vec!["post-registration"]);
    }

    #[test]
    fn test_conditional_superadmin_promotion() {
        // Simulate: promote admin@example.com to superadmin
        let outcome = test_hook(
            r#"
            if user.email == "test@example.com" {
                set_superadmin(true);
                log("promoted");
            }
            "#,
            "post-login",
        )
        .unwrap();
        assert_eq!(outcome.set_superadmin, Some(true));
        assert_eq!(outcome.log_messages, vec!["promoted"]);
    }

    #[test]
    fn test_conditional_no_match() {
        let outcome = test_hook(
            r#"
            if user.email == "other@example.com" {
                set_superadmin(true);
            }
            "#,
            "post-login",
        )
        .unwrap();
        // Condition didn't match, so no superadmin change
        assert!(outcome.set_superadmin.is_none());
    }

    #[test]
    fn test_compile_error_reported() {
        let result = test_hook(r#"this is not valid rhai }{{"#, "post-login");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("compile error"));
    }

    #[test]
    fn test_multiple_actions() {
        let outcome = test_hook(
            r#"
            set_superadmin(true);
            add_to_tenant("t1", "admin");
            set_claim("department", "engineering");
            log("all set");
            "#,
            "post-login",
        )
        .unwrap();
        assert_eq!(outcome.set_superadmin, Some(true));
        assert_eq!(outcome.add_to_tenants.len(), 1);
        assert_eq!(outcome.extra_claims.len(), 1);
        assert_eq!(outcome.log_messages, vec!["all set"]);
    }

    #[test]
    fn test_domain_based_auto_join() {
        // Common demo pattern: auto-join users by email domain
        let outcome = test_hook(
            r#"
            if user.email.ends_with("@example.com") {
                add_to_tenant("default-org", "member");
                log("auto-joined default-org");
            }
            "#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.add_to_tenants.len(), 1);
        assert_eq!(outcome.add_to_tenants[0].0, "default-org");
        assert_eq!(outcome.add_to_tenants[0].1, "member");
    }

    #[test]
    fn test_sandbox_max_operations() {
        // An infinite loop should hit the operations limit
        let result = test_hook(r#"loop { }"#, "post-login");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("runtime error"));
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let script = r#"set_superadmin(true);"#;
        let hash1 = store::sha256_hex(script);
        let hash2 = store::sha256_hex(script);
        assert_eq!(hash1, hash2, "same script should produce same hash");
        assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[test]
    fn test_sha256_hex_different_scripts() {
        let hash1 = store::sha256_hex("log(1);");
        let hash2 = store::sha256_hex("log(2);");
        assert_ne!(
            hash1, hash2,
            "different scripts should produce different hashes"
        );
    }

    #[test]
    fn test_bootstrap_style_script_promotes_matching_email() {
        // Simulates the bootstrap_hook config: promote a specific email
        let outcome = test_hook(
            r#"
            if user.email == "test@example.com" {
                set_superadmin(true);
                log("bootstrap: promoted " + user.email);
            }
            "#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.set_superadmin, Some(true));
        assert_eq!(outcome.log_messages.len(), 1);
        assert!(outcome.log_messages[0].contains("bootstrap: promoted"));
    }

    #[test]
    fn test_bootstrap_style_script_ignores_non_matching_email() {
        // test_hook uses "test@example.com" as the sample user
        let outcome = test_hook(
            r#"
            if user.email == "admin@corp.org" {
                set_superadmin(true);
            }
            "#,
            "post-registration",
        )
        .unwrap();
        assert!(outcome.set_superadmin.is_none());
    }

    #[test]
    fn test_bootstrap_style_domain_wildcard() {
        // Bootstrap via domain match instead of exact email
        let outcome = test_hook(
            r#"
            if user.email.ends_with("@example.com") {
                set_superadmin(true);
                log("domain bootstrap");
            }
            "#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.set_superadmin, Some(true));
    }

    #[test]
    fn test_create_tenant_basic() {
        let outcome = test_hook(
            r#"create_tenant("acme", "acme", "Acme Inc.");"#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.create_tenants.len(), 1);
        assert_eq!(outcome.create_tenants[0].0, "acme");
        assert_eq!(outcome.create_tenants[0].1, "acme");
        assert_eq!(outcome.create_tenants[0].2, "Acme Inc.");
    }

    #[test]
    fn test_create_tenant_and_join_in_one_hook() {
        // The canonical bootstrap pattern: create org + make founder owner
        let outcome = test_hook(
            r#"
            if user.email == "test@example.com" {
                set_superadmin(true);
                create_tenant("acme", "acme", "Acme Inc.");
                add_to_tenant("acme", "owner");
                log("bootstrap complete");
            }
            "#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.set_superadmin, Some(true));
        assert_eq!(outcome.create_tenants.len(), 1);
        assert_eq!(outcome.create_tenants[0].0, "acme");
        assert_eq!(outcome.add_to_tenants.len(), 1);
        assert_eq!(outcome.add_to_tenants[0], ("acme".into(), "owner".into()));
        assert_eq!(outcome.log_messages, vec!["bootstrap complete"]);
    }

    #[test]
    fn test_create_tenant_rejects_id_with_leading_hyphen() {
        let outcome = test_hook(
            r#"create_tenant("-bad", "bad", "Bad");"#,
            "post-registration",
        )
        .unwrap();
        assert!(outcome.create_tenants.is_empty());
    }

    #[test]
    fn test_create_tenant_rejects_id_with_trailing_hyphen() {
        let outcome = test_hook(
            r#"create_tenant("bad-", "bad", "Bad");"#,
            "post-registration",
        )
        .unwrap();
        assert!(outcome.create_tenants.is_empty());
    }

    #[test]
    fn test_create_tenant_rejects_id_too_short() {
        let outcome = test_hook(
            r#"create_tenant("x", "short", "Short");"#,
            "post-registration",
        )
        .unwrap();
        assert!(outcome.create_tenants.is_empty());
    }

    #[test]
    fn test_create_tenant_rejects_uppercase_in_id() {
        let outcome = test_hook(
            r#"create_tenant("MyOrg", "MyOrg", "My Org");"#,
            "post-registration",
        )
        .unwrap();
        assert!(outcome.create_tenants.is_empty());
    }

    #[test]
    fn test_create_tenant_rejects_empty_name() {
        let outcome = test_hook(
            r#"create_tenant("acme", "", "Acme Inc.");"#,
            "post-registration",
        )
        .unwrap();
        assert!(outcome.create_tenants.is_empty());
    }

    #[test]
    fn test_create_tenant_allows_hyphens_in_id() {
        let outcome = test_hook(
            r#"create_tenant("my-org-2", "my-org", "My Org 2");"#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.create_tenants.len(), 1);
        assert_eq!(outcome.create_tenants[0].0, "my-org-2");
    }

    #[test]
    fn test_set_active_hook() {
        let outcome = test_hook(
            r#"
            if user.email == "test@example.com" {
                set_active(true);
            }
            "#,
            "post-registration",
        )
        .unwrap();
        assert_eq!(outcome.set_active, Some(true));
    }
}
