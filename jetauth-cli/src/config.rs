use crate::error::{CliError, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use url::Url;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStoreKind {
    #[default]
    Auto,
    Keyring,
    File,
}

impl CredentialStoreKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Keyring => "keyring",
            Self::File => "file",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Profile {
    pub issuer: String,
    #[serde(default)]
    pub credential_store: CredentialStoreKind,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_profile")]
    pub current_profile: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            current_profile: default_profile(),
            profiles: BTreeMap::new(),
        }
    }
}

fn default_profile() -> String {
    "default".to_string()
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    root: PathBuf,
}

impl ConfigStore {
    pub fn new() -> Result<Self> {
        let root = match std::env::var_os("JETAUTH_CONFIG_DIR") {
            Some(path) => PathBuf::from(path),
            None => ProjectDirs::from("dev", "JetAuth", "JetAuth")
                .ok_or_else(|| CliError::Config("cannot determine the config directory".into()))?
                .config_dir()
                .to_path_buf(),
        };
        Ok(Self { root })
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    fn path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    pub fn load(&self) -> Result<Config> {
        let path = self.path();
        if !path.exists() {
            return Ok(Config::default());
        }
        let contents = fs::read_to_string(&path).map_err(|error| {
            CliError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        toml::from_str(&contents)
            .map_err(|error| CliError::Config(format!("invalid {}: {error}", path.display())))
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|error| {
            CliError::Config(format!("cannot create {}: {error}", self.root.display()))
        })?;
        let contents = toml::to_string_pretty(config)
            .map_err(|error| CliError::Config(format!("cannot encode config: {error}")))?;
        write_private(&self.path(), contents.as_bytes())
    }

    pub fn select_profile<'a>(
        &self,
        config: &'a Config,
        requested: Option<&str>,
    ) -> Result<(String, &'a Profile)> {
        let name = requested.unwrap_or(&config.current_profile);
        let profile = config.profiles.get(name).ok_or_else(|| {
            CliError::Config(format!(
                "profile '{name}' is not configured; run `jetauth login --issuer <URL> --profile {name}`"
            ))
        })?;
        Ok((name.to_string(), profile))
    }
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err(CliError::Input(
            "profile names may contain only letters, numbers, '.', '_' and '-'".into(),
        ));
    }
    Ok(())
}

pub fn normalize_issuer(value: &str) -> Result<String> {
    let mut url = Url::parse(value)
        .map_err(|error| CliError::Input(format!("invalid issuer URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CliError::Input("issuer must use HTTP or HTTPS".into()));
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(CliError::Input(
            "issuer must use HTTPS except for loopback development addresses".into(),
        ));
    }
    if url.host_str().is_none() {
        return Err(CliError::Input("issuer must include a host".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CliError::Input(
            "issuer must not contain user information".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(CliError::Input(
            "issuer must not contain a query string or fragment".into(),
        ));
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

pub fn write_private(path: &PathBuf, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        CliError::Config(format!(
            "cannot determine the parent directory for {}",
            path.display()
        ))
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Config(format!(
            "cannot create a temporary file in {}: {error}",
            parent.display()
        ))
    })?;
    std::io::Write::write_all(temporary.as_file_mut(), contents).map_err(|error| {
        CliError::Config(format!(
            "cannot write {}: {error}",
            temporary.path().display()
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        CliError::Config(format!(
            "cannot sync {}: {error}",
            temporary.path().display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                CliError::Config(format!(
                    "cannot secure {}: {error}",
                    temporary.path().display()
                ))
            },
        )?;
    }
    temporary
        .persist(path)
        .map_err(|error| CliError::Config(format!("cannot replace {}: {error}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_requires_tls_outside_loopback() {
        assert!(normalize_issuer("http://auth.example.com").is_err());
        assert_eq!(
            normalize_issuer("http://localhost:8000/").unwrap(),
            "http://localhost:8000"
        );
        assert_eq!(
            normalize_issuer("https://auth.example.com/").unwrap(),
            "https://auth.example.com"
        );
    }

    #[test]
    fn profile_names_cannot_escape_the_credentials_directory() {
        assert!(validate_profile_name("prod-eu").is_ok());
        assert!(validate_profile_name("../prod").is_err());
    }
}
