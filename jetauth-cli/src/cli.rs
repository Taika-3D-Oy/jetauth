use crate::config::CredentialStoreKind;
use crate::output::OutputFormat;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "jetauth", version, about = "JetAuth management CLI")]
pub struct Cli {
    #[arg(long, global = true)]
    pub profile: Option<String>,
    #[arg(long, global = true)]
    pub issuer: Option<String>,
    #[arg(long, global = true, value_enum)]
    pub output: Option<OutputFormat>,
    #[arg(long, global = true)]
    pub yes: bool,
    #[arg(long, global = true)]
    pub no_input: bool,
    #[arg(long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Login {
        #[arg(long)]
        no_browser: bool,
        #[arg(long)]
        no_refresh: bool,
        #[arg(long, value_enum, default_value = "auto")]
        credential_store: CredentialStoreKindArg,
    },
    Logout,
    Status,
    Token,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Api {
        method: String,
        path: String,
        #[arg(long, allow_hyphen_values = true)]
        input: Option<String>,
    },
    Clients {
        #[command(subcommand)]
        command: ClientsCommand,
    },
    Tenants {
        #[command(subcommand)]
        command: TenantsCommand,
    },
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },
    Idps {
        #[command(subcommand)]
        command: IdpsCommand,
    },
    Hooks {
        #[command(subcommand)]
        command: HooksCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Stats,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CredentialStoreKindArg {
    Auto,
    Keyring,
    File,
}

impl From<CredentialStoreKindArg> for CredentialStoreKind {
    fn from(value: CredentialStoreKindArg) -> Self {
        match value {
            CredentialStoreKindArg::Auto => Self::Auto,
            CredentialStoreKindArg::Keyring => Self::Keyring,
            CredentialStoreKindArg::File => Self::File,
        }
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConfigCommand {
    Use { profile: String },
    List,
    Show,
}

#[derive(Clone, Debug, Subcommand)]
pub enum ClientsCommand {
    List,
    Get {
        client_id: String,
    },
    Create {
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Update {
        client_id: String,
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Delete {
        client_id: String,
    },
    RotateSecret {
        client_id: String,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum TenantsCommand {
    List,
    Get {
        tenant_id: String,
    },
    Create {
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Update {
        tenant_id: String,
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Delete {
        tenant_id: String,
    },
    Members {
        tenant_id: String,
    },
    AddMember {
        tenant_id: String,
        user_id: String,
        #[arg(long)]
        role: String,
    },
    RemoveMember {
        tenant_id: String,
        user_id: String,
    },
    Invite {
        tenant_id: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        role: String,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum UsersCommand {
    List {
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u16,
    },
    Activate {
        user_id: String,
    },
    ResetPassword {
        user_id: String,
    },
    Export {
        user_id: String,
    },
    Delete {
        user_id: String,
    },
    MfaSetup {
        user_id: String,
    },
    MfaConfirm {
        user_id: String,
        #[arg(long)]
        code: String,
    },
    MfaDisable {
        user_id: String,
    },
    Passkeys {
        user_id: String,
    },
    PasskeyRegisterOptions {
        user_id: String,
    },
    PasskeyRegisterComplete {
        user_id: String,
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    PasskeyDelete {
        user_id: String,
        credential_id: String,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum IdpsCommand {
    List,
    Create {
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Update {
        idp_id: String,
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Delete {
        idp_id: String,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum HooksCommand {
    List,
    Create {
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Update {
        hook_id: String,
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
    Test {
        hook_id: String,
    },
    Versions {
        hook_id: String,
    },
    Delete {
        hook_id: String,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum KeysCommand {
    List,
    Rotate,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SettingsCommand {
    Get,
    Update {
        #[arg(long, allow_hyphen_values = true)]
        input: String,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuditCommand {
    List {
        #[arg(long)]
        actor_id: Option<String>,
        #[arg(long)]
        target_id: Option<String>,
        #[arg(long)]
        event_type: Option<String>,
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        until: Option<u64>,
        #[arg(long, default_value_t = 100)]
        limit: u16,
    },
}
