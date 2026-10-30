use crate::config::{ConfigStore, CredentialStoreKind, write_private};
use crate::error::{CliError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "dev.jetauth.cli";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_at: u64,
    pub scope: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialBackend {
    Keyring,
    File,
}

impl CredentialBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::File => "file",
        }
    }
}

pub struct CredentialStore {
    kind: CredentialStoreKind,
    profile: String,
    file: PathBuf,
}

impl CredentialStore {
    pub fn new(config: &ConfigStore, profile: &str, kind: CredentialStoreKind) -> Self {
        Self {
            kind,
            profile: profile.to_string(),
            file: config
                .root()
                .join("credentials")
                .join(format!("{profile}.json")),
        }
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, &self.profile)
            .map_err(|error| CliError::Auth(format!("cannot access the OS keyring: {error}")))
    }

    fn save_keyring(&self, json: &str) -> Result<()> {
        self.entry()?.set_password(json).map_err(|error| {
            CliError::Auth(format!(
                "cannot save credentials to the OS keyring: {error}"
            ))
        })
    }

    fn save_file(&self, json: &str) -> Result<()> {
        let parent = self
            .file
            .parent()
            .ok_or_else(|| CliError::Config("cannot determine the credentials directory".into()))?;
        fs::create_dir_all(parent).map_err(|error| {
            CliError::Config(format!("cannot create {}: {error}", parent.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
                CliError::Config(format!("cannot secure {}: {error}", parent.display()))
            })?;
        }
        write_private(&self.file, json.as_bytes())
    }

    pub fn save(&self, credentials: &Credentials) -> Result<CredentialBackend> {
        let json = serde_json::to_string(credentials)
            .map_err(|error| CliError::Auth(format!("cannot encode credentials: {error}")))?;
        match self.kind {
            CredentialStoreKind::Keyring => {
                self.save_keyring(&json)?;
                Ok(CredentialBackend::Keyring)
            }
            CredentialStoreKind::File => {
                self.save_file(&json)?;
                Ok(CredentialBackend::File)
            }
            CredentialStoreKind::Auto => match self.save_keyring(&json) {
                Ok(()) => Ok(CredentialBackend::Keyring),
                Err(error) => {
                    eprintln!("warning: {error}; falling back to a private credentials file");
                    self.save_file(&json)?;
                    Ok(CredentialBackend::File)
                }
            },
        }
    }

    fn load_file(&self) -> Result<Credentials> {
        let json = fs::read_to_string(&self.file).map_err(|error| {
            CliError::Auth(format!("cannot read {}: {error}", self.file.display()))
        })?;
        serde_json::from_str(&json)
            .map_err(|error| CliError::Auth(format!("invalid stored credentials: {error}")))
    }

    fn load_keyring(&self) -> Result<Credentials> {
        let json = self.entry()?.get_password().map_err(|error| {
            CliError::Auth(format!(
                "cannot load credentials from the OS keyring: {error}"
            ))
        })?;
        serde_json::from_str(&json)
            .map_err(|error| CliError::Auth(format!("invalid stored credentials: {error}")))
    }

    pub fn load(&self) -> Result<(Credentials, CredentialBackend)> {
        match self.kind {
            CredentialStoreKind::Keyring => Ok((self.load_keyring()?, CredentialBackend::Keyring)),
            CredentialStoreKind::File => Ok((self.load_file()?, CredentialBackend::File)),
            CredentialStoreKind::Auto if self.file.exists() => {
                Ok((self.load_file()?, CredentialBackend::File))
            }
            CredentialStoreKind::Auto => Ok((self.load_keyring()?, CredentialBackend::Keyring)),
        }
    }

    pub fn delete(&self) -> Result<()> {
        if self.file.exists() {
            fs::remove_file(&self.file).map_err(|error| {
                CliError::Auth(format!("cannot remove {}: {error}", self.file.display()))
            })?;
        }
        if matches!(
            self.kind,
            CredentialStoreKind::Auto | CredentialStoreKind::Keyring
        ) {
            match self.entry()?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) if self.kind == CredentialStoreKind::Auto => {
                    eprintln!("warning: could not remove keyring credentials: {error}");
                }
                Err(error) => {
                    return Err(CliError::Auth(format!(
                        "cannot remove credentials from the OS keyring: {error}"
                    )));
                }
            }
        }
        Ok(())
    }
}
