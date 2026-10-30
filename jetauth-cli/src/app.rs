use crate::auth;
use crate::cli::*;
use crate::client;
use crate::config::{
    Config, ConfigStore, CredentialStoreKind, Profile, normalize_issuer, validate_profile_name,
};
use crate::credentials::{CredentialBackend, CredentialStore, Credentials};
use crate::error::{CliError, Result};
use crate::output::{self, OutputFormat};
use clap::Parser;
use reqwest::Method;
use serde_json::{Value, json};
use std::io::{IsTerminal, Write};

pub async fn run() -> Result<()> {
    App::new(Cli::parse())?.run().await
}

struct App {
    cli: Cli,
    config_store: ConfigStore,
    http: reqwest::Client,
    format: OutputFormat,
}

impl App {
    fn new(cli: Cli) -> Result<Self> {
        let config_store = ConfigStore::new()?;
        let http = auth::http_client()?;
        let format = output::effective_format(cli.output);
        Ok(Self {
            cli,
            config_store,
            http,
            format,
        })
    }

    async fn run(self) -> Result<()> {
        match self.cli.command.clone() {
            Command::Login {
                no_browser,
                no_refresh,
                credential_store,
            } => {
                self.login(no_browser, no_refresh, credential_store.into())
                    .await
            }
            Command::Logout => self.logout(),
            Command::Status => self.status().await,
            Command::Token => self.token().await,
            Command::Config { command } => self.config(command),
            Command::Api {
                method,
                path,
                input,
            } => {
                let method = parse_method(&method)?;
                let body = input
                    .as_deref()
                    .map(|input| self.read_json(input))
                    .transpose()?;
                self.call_and_render(method, &path, body.as_ref()).await
            }
            Command::Clients { command } => self.clients(command).await,
            Command::Tenants { command } => self.tenants(command).await,
            Command::Users { command } => self.users(command).await,
            Command::Idps { command } => self.idps(command).await,
            Command::Hooks { command } => self.hooks(command).await,
            Command::Keys { command } => self.keys(command).await,
            Command::Settings { command } => self.settings(command).await,
            Command::Audit { command } => self.audit(command).await,
            Command::Stats => self.call_and_render(Method::GET, "/api/stats", None).await,
        }
    }

    fn profile_name(&self, config: &Config) -> String {
        self.cli
            .profile
            .clone()
            .or_else(|| std::env::var("JETAUTH_PROFILE").ok())
            .unwrap_or_else(|| config.current_profile.clone())
    }

    fn issuer_override(&self) -> Option<String> {
        self.cli
            .issuer
            .clone()
            .or_else(|| std::env::var("JETAUTH_ISSUER").ok())
    }

    fn context(&self) -> Result<(String, Profile)> {
        let config = self.config_store.load()?;
        let name = self.profile_name(&config);
        validate_profile_name(&name)?;
        let override_issuer = self
            .issuer_override()
            .map(|value| normalize_issuer(&value))
            .transpose()?;
        match config.profiles.get(&name) {
            Some(profile) => {
                if let Some(issuer) = &override_issuer
                    && issuer != &profile.issuer
                {
                    return Err(CliError::Input(format!(
                        "issuer '{issuer}' does not match profile '{name}'; use a different profile"
                    )));
                }
                Ok((name, profile.clone()))
            }
            None if std::env::var_os("JETAUTH_ACCESS_TOKEN").is_some() => {
                let issuer = override_issuer.ok_or_else(|| {
                    CliError::Config(
                        "JETAUTH_ISSUER or --issuer is required with JETAUTH_ACCESS_TOKEN".into(),
                    )
                })?;
                Ok((
                    name,
                    Profile {
                        issuer,
                        credential_store: CredentialStoreKind::File,
                    },
                ))
            }
            None => Err(CliError::Config(format!(
                "profile '{name}' is not configured; run `jetauth login --issuer <URL> --profile {name}`"
            ))),
        }
    }

    async fn login(
        &self,
        no_browser: bool,
        no_refresh: bool,
        credential_store: CredentialStoreKind,
    ) -> Result<()> {
        let mut config = self.config_store.load()?;
        let name = self.profile_name(&config);
        validate_profile_name(&name)?;
        let issuer = match self.issuer_override() {
            Some(issuer) => normalize_issuer(&issuer)?,
            None => config
                .profiles
                .get(&name)
                .map(|profile| profile.issuer.clone())
                .ok_or_else(|| CliError::Input("--issuer is required for a new profile".into()))?,
        };
        let store = CredentialStore::new(&self.config_store, &name, credential_store);
        let (credentials, backend) =
            auth::login(&self.http, &issuer, &store, no_browser, no_refresh).await?;
        config.current_profile = name.clone();
        config.profiles.insert(
            name.clone(),
            Profile {
                issuer: issuer.clone(),
                credential_store,
            },
        );
        self.config_store.save(&config)?;
        let mut result = json!({
            "profile": name,
            "issuer": issuer,
            "credential_store": backend.as_str(),
            "access_token_expires_at": credentials.expires_at,
            "refresh_token_stored": credentials.refresh_token.is_some(),
        });
        add_identity(&mut result, &credentials);
        output::render(&result, self.format)
    }

    fn logout(&self) -> Result<()> {
        let (name, profile) = self.context()?;
        CredentialStore::new(&self.config_store, &name, profile.credential_store).delete()?;
        output::render(&json!({ "profile": name, "logged_out": true }), self.format)
    }

    async fn token(&self) -> Result<()> {
        if let Ok(token) = std::env::var("JETAUTH_ACCESS_TOKEN") {
            if token.is_empty() {
                return Err(CliError::Auth("JETAUTH_ACCESS_TOKEN is empty".into()));
            }
            println!("{token}");
            return Ok(());
        }
        let (_, _, credentials, _) = self.valid_credentials(false).await?;
        println!("{}", credentials.access_token);
        Ok(())
    }

    async fn status(&self) -> Result<()> {
        let (name, profile) = self.context()?;
        if let Ok(token) = std::env::var("JETAUTH_ACCESS_TOKEN") {
            let claims = auth::claims(&token)?;
            let result = json!({
                "profile": name,
                "issuer": profile.issuer,
                "credential_store": "environment",
                "email": claims.get("email"),
                "name": claims.get("name"),
                "role": claims.get("role"),
                "subject": claims.get("sub"),
                "access_token_expires_at": claims.get("exp"),
                "refresh_token_stored": false,
            });
            return output::render(&result, self.format);
        }
        let (_, _, credentials, backend) = self.valid_credentials(false).await?;
        let mut result = json!({
            "profile": name,
            "issuer": profile.issuer,
            "credential_store": backend.as_str(),
            "access_token_expires_at": credentials.expires_at,
            "refresh_token_stored": credentials.refresh_token.is_some(),
        });
        add_identity(&mut result, &credentials);
        output::render(&result, self.format)
    }

    async fn valid_credentials(
        &self,
        force_refresh: bool,
    ) -> Result<(String, Profile, Credentials, CredentialBackend)> {
        let (name, profile) = self.context()?;
        let store = CredentialStore::new(&self.config_store, &name, profile.credential_store);
        let (mut credentials, mut backend) = store.load()?;
        if force_refresh || auth::needs_refresh(&credentials) {
            credentials = auth::refresh(&self.http, &profile.issuer, &credentials).await?;
            let save_kind = match backend {
                CredentialBackend::Keyring => CredentialStoreKind::Keyring,
                CredentialBackend::File => CredentialStoreKind::File,
            };
            backend =
                CredentialStore::new(&self.config_store, &name, save_kind).save(&credentials)?;
        }
        Ok((name, profile, credentials, backend))
    }

    async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        if let Ok(token) = std::env::var("JETAUTH_ACCESS_TOKEN") {
            let (_, profile) = self.context()?;
            return client::request(
                &self.http,
                &profile.issuer,
                &token,
                method,
                path,
                body,
                self.cli.verbose,
            )
            .await
            .map(|response| response.value);
        }
        let (_, profile, credentials, _) = self.valid_credentials(false).await?;
        let result = client::request(
            &self.http,
            &profile.issuer,
            &credentials.access_token,
            method.clone(),
            path,
            body,
            self.cli.verbose,
        )
        .await;
        match result {
            Err(CliError::Auth(_)) if credentials.refresh_token.is_some() => {
                let (_, _, refreshed, _) = self.valid_credentials(true).await?;
                client::request(
                    &self.http,
                    &profile.issuer,
                    &refreshed.access_token,
                    method,
                    path,
                    body,
                    self.cli.verbose,
                )
                .await
                .map(|response| response.value)
            }
            result => result.map(|response| response.value),
        }
        .map_err(|error| match error {
            CliError::Auth(message) if message.contains("Management API returned") => {
                CliError::Auth(format!("{message}; run `jetauth login` again"))
            }
            other => other,
        })
    }

    async fn call_and_render(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<()> {
        let value = self.call(method, path, body).await?;
        output::render(&value, self.format)
    }

    fn read_json(&self, source: &str) -> Result<Value> {
        let contents = if source == "-" {
            if self.cli.no_input {
                return Err(CliError::Input(
                    "--input - cannot be used with --no-input".into(),
                ));
            }
            let mut contents = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut contents).map_err(
                |error| CliError::Input(format!("cannot read JSON from stdin: {error}")),
            )?;
            contents
        } else {
            std::fs::read_to_string(source).map_err(|error| {
                CliError::Input(format!("cannot read JSON input {source}: {error}"))
            })?
        };
        serde_json::from_str(&contents)
            .map_err(|error| CliError::Input(format!("invalid JSON input: {error}")))
    }

    fn confirm(&self, action: &str) -> Result<()> {
        if self.cli.yes {
            return Ok(());
        }
        if self.cli.no_input || !std::io::stdin().is_terminal() {
            return Err(CliError::Input(format!(
                "{action} requires confirmation; pass --yes"
            )));
        }
        eprint!("{action}? [y/N] ");
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| CliError::Input(format!("cannot read confirmation: {error}")))?;
        if matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            Ok(())
        } else {
            Err(CliError::Input("operation cancelled".into()))
        }
    }

    fn config(&self, command: ConfigCommand) -> Result<()> {
        let mut config = self.config_store.load()?;
        match command {
            ConfigCommand::Use { profile } => {
                if !config.profiles.contains_key(&profile) {
                    return Err(CliError::NotFound(format!(
                        "profile '{profile}' does not exist"
                    )));
                }
                config.current_profile = profile.clone();
                self.config_store.save(&config)?;
                output::render(&json!({ "current_profile": profile }), self.format)
            }
            ConfigCommand::List => {
                if self.format == OutputFormat::Json {
                    let profiles = config
                        .profiles
                        .keys()
                        .map(|name| json!({ "name": name, "current": name == &config.current_profile }))
                        .collect::<Vec<_>>();
                    output::render(&Value::Array(profiles), self.format)
                } else {
                    for (name, profile) in &config.profiles {
                        let marker = if name == &config.current_profile {
                            "*"
                        } else {
                            " "
                        };
                        println!("{marker} {name}\t{}", profile.issuer);
                    }
                    Ok(())
                }
            }
            ConfigCommand::Show => {
                let value = serde_json::to_value(config)
                    .map_err(|error| CliError::Config(format!("cannot encode config: {error}")))?;
                output::render(&value, self.format)
            }
        }
    }

    async fn clients(&self, command: ClientsCommand) -> Result<()> {
        use ClientsCommand::*;
        match command {
            List => {
                self.call_and_render(Method::GET, "/api/clients", None)
                    .await
            }
            Get { client_id } => {
                self.call_and_render(
                    Method::GET,
                    &format!("/api/clients/{}", client::segment(&client_id)),
                    None,
                )
                .await
            }
            Create { input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::POST, "/api/clients", Some(&body))
                    .await
            }
            Update { client_id, input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(
                    Method::PUT,
                    &format!("/api/clients/{}", client::segment(&client_id)),
                    Some(&body),
                )
                .await
            }
            Delete { client_id } => {
                self.confirm(&format!("Delete client {client_id}"))?;
                self.call_and_render(
                    Method::DELETE,
                    &format!("/api/clients/{}", client::segment(&client_id)),
                    None,
                )
                .await
            }
            RotateSecret { client_id } => {
                self.confirm(&format!("Rotate the secret for client {client_id}"))?;
                self.call_and_render(
                    Method::POST,
                    &format!("/api/clients/{}/rotate-secret", client::segment(&client_id)),
                    None,
                )
                .await
            }
        }
    }

    async fn tenants(&self, command: TenantsCommand) -> Result<()> {
        use TenantsCommand::*;
        match command {
            List => {
                self.call_and_render(Method::GET, "/api/tenants", None)
                    .await
            }
            Get { tenant_id } => {
                self.call_and_render(Method::GET, &tenant_path(&tenant_id), None)
                    .await
            }
            Create { input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::POST, "/api/tenants", Some(&body))
                    .await
            }
            Update { tenant_id, input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::PATCH, &tenant_path(&tenant_id), Some(&body))
                    .await
            }
            Delete { tenant_id } => {
                self.confirm(&format!("Delete tenant {tenant_id}"))?;
                self.call_and_render(Method::DELETE, &tenant_path(&tenant_id), None)
                    .await
            }
            Members { tenant_id } => {
                self.call_and_render(
                    Method::GET,
                    &format!("{}/users", tenant_path(&tenant_id)),
                    None,
                )
                .await
            }
            AddMember {
                tenant_id,
                user_id,
                role,
            } => {
                let body = json!({ "user_id": user_id, "role": role });
                self.call_and_render(
                    Method::POST,
                    &format!("{}/users", tenant_path(&tenant_id)),
                    Some(&body),
                )
                .await
            }
            RemoveMember { tenant_id, user_id } => {
                self.confirm(&format!("Remove user {user_id} from tenant {tenant_id}"))?;
                self.call_and_render(
                    Method::DELETE,
                    &format!(
                        "{}/users/{}",
                        tenant_path(&tenant_id),
                        client::segment(&user_id)
                    ),
                    None,
                )
                .await
            }
            Invite {
                tenant_id,
                email,
                role,
            } => {
                let body = json!({ "email": email, "role": role });
                self.call_and_render(
                    Method::POST,
                    &format!("{}/users/invite", tenant_path(&tenant_id)),
                    Some(&body),
                )
                .await
            }
        }
    }

    async fn users(&self, command: UsersCommand) -> Result<()> {
        use UsersCommand::*;
        match command {
            List { query, limit } => {
                if limit > 500 {
                    return Err(CliError::Input("--limit must be at most 500".into()));
                }
                let mut parameters = vec![("limit", limit.to_string())];
                if let Some(query) = query {
                    parameters.push(("q", query));
                }
                let path = client::query_path("/api/users", &parameters)?;
                self.call_and_render(Method::GET, &path, None).await
            }
            Activate { user_id } => {
                self.user_action(&user_id, "activate", Method::POST, None)
                    .await
            }
            ResetPassword { user_id } => {
                self.user_action(&user_id, "password-reset", Method::POST, None)
                    .await
            }
            Export { user_id } => {
                self.user_action(&user_id, "export", Method::GET, None)
                    .await
            }
            Delete { user_id } => {
                self.confirm(&format!("Permanently delete user {user_id}"))?;
                self.call_and_render(Method::DELETE, &user_path(&user_id), None)
                    .await
            }
            MfaSetup { user_id } => {
                self.user_action(&user_id, "mfa/setup", Method::POST, None)
                    .await
            }
            MfaConfirm { user_id, code } => {
                let body = json!({ "code": code });
                self.user_action(&user_id, "mfa/confirm", Method::POST, Some(&body))
                    .await
            }
            MfaDisable { user_id } => {
                self.confirm(&format!("Disable MFA for user {user_id}"))?;
                self.user_action(&user_id, "mfa", Method::DELETE, None)
                    .await
            }
            Passkeys { user_id } => {
                self.user_action(&user_id, "passkeys", Method::GET, None)
                    .await
            }
            PasskeyRegisterOptions { user_id } => {
                self.user_action(&user_id, "passkeys/register-options", Method::POST, None)
                    .await
            }
            PasskeyRegisterComplete { user_id, input } => {
                let body = self.read_json(&input)?;
                self.user_action(
                    &user_id,
                    "passkeys/register-complete",
                    Method::POST,
                    Some(&body),
                )
                .await
            }
            PasskeyDelete {
                user_id,
                credential_id,
            } => {
                self.confirm(&format!("Delete passkey {credential_id}"))?;
                self.call_and_render(
                    Method::DELETE,
                    &format!(
                        "{}/passkeys/{}",
                        user_path(&user_id),
                        client::segment(&credential_id)
                    ),
                    None,
                )
                .await
            }
        }
    }

    async fn user_action(
        &self,
        user_id: &str,
        action: &str,
        method: Method,
        body: Option<&Value>,
    ) -> Result<()> {
        self.call_and_render(method, &format!("{}/{action}", user_path(user_id)), body)
            .await
    }

    async fn idps(&self, command: IdpsCommand) -> Result<()> {
        use IdpsCommand::*;
        match command {
            List => {
                self.call_and_render(Method::GET, "/api/identity-providers", None)
                    .await
            }
            Create { input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::POST, "/api/identity-providers", Some(&body))
                    .await
            }
            Update { idp_id, input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(
                    Method::PUT,
                    &format!("/api/identity-providers/{}", client::segment(&idp_id)),
                    Some(&body),
                )
                .await
            }
            Delete { idp_id } => {
                self.confirm(&format!("Delete identity provider {idp_id}"))?;
                self.call_and_render(
                    Method::DELETE,
                    &format!("/api/identity-providers/{}", client::segment(&idp_id)),
                    None,
                )
                .await
            }
        }
    }

    async fn hooks(&self, command: HooksCommand) -> Result<()> {
        use HooksCommand::*;
        match command {
            List => self.call_and_render(Method::GET, "/api/hooks", None).await,
            Create { input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::POST, "/api/hooks", Some(&body))
                    .await
            }
            Update { hook_id, input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::PUT, &hook_path(&hook_id), Some(&body))
                    .await
            }
            Test { hook_id } => {
                self.call_and_render(Method::POST, &format!("{}/test", hook_path(&hook_id)), None)
                    .await
            }
            Versions { hook_id } => {
                self.call_and_render(
                    Method::GET,
                    &format!("{}/versions", hook_path(&hook_id)),
                    None,
                )
                .await
            }
            Delete { hook_id } => {
                self.confirm(&format!("Delete hook {hook_id}"))?;
                self.call_and_render(Method::DELETE, &hook_path(&hook_id), None)
                    .await
            }
        }
    }

    async fn keys(&self, command: KeysCommand) -> Result<()> {
        match command {
            KeysCommand::List => self.call_and_render(Method::GET, "/api/keys", None).await,
            KeysCommand::Rotate => {
                self.confirm("Rotate signing keys")?;
                self.call_and_render(Method::POST, "/api/keys/rotate", None)
                    .await
            }
        }
    }

    async fn settings(&self, command: SettingsCommand) -> Result<()> {
        match command {
            SettingsCommand::Get => {
                self.call_and_render(Method::GET, "/api/settings", None)
                    .await
            }
            SettingsCommand::Update { input } => {
                let body = self.read_json(&input)?;
                self.call_and_render(Method::PUT, "/api/settings", Some(&body))
                    .await
            }
        }
    }

    async fn audit(&self, command: AuditCommand) -> Result<()> {
        match command {
            AuditCommand::List {
                actor_id,
                target_id,
                event_type,
                since,
                until,
                limit,
            } => {
                if limit > 500 {
                    return Err(CliError::Input("--limit must be at most 500".into()));
                }
                let mut parameters = vec![("limit", limit.to_string())];
                for (key, value) in [
                    ("actor_id", actor_id),
                    ("target_id", target_id),
                    ("event_type", event_type),
                    ("since", since.map(|value| value.to_string())),
                    ("until", until.map(|value| value.to_string())),
                ] {
                    if let Some(value) = value {
                        parameters.push((key, value));
                    }
                }
                let path = client::query_path("/api/audit", &parameters)?;
                self.call_and_render(Method::GET, &path, None).await
            }
        }
    }
}

fn add_identity(result: &mut Value, credentials: &Credentials) {
    if let (Some(result), Value::Object(identity)) =
        (result.as_object_mut(), auth::identity(credentials))
    {
        result.extend(identity);
    }
}

fn parse_method(method: &str) -> Result<Method> {
    Method::from_bytes(method.to_ascii_uppercase().as_bytes())
        .map_err(|_| CliError::Input(format!("invalid HTTP method '{method}'")))
}

fn tenant_path(tenant_id: &str) -> String {
    format!("/api/tenants/{}", client::segment(tenant_id))
}

fn user_path(user_id: &str) -> String {
    format!("/api/users/{}", client::segment(user_id))
}

fn hook_path(hook_id: &str) -> String {
    format!("/api/hooks/{}", client::segment(hook_id))
}
