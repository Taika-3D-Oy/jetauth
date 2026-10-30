use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum CliError {
    Input(String),
    Config(String),
    Auth(String),
    Permission(String),
    NotFound(String),
    Conflict(String),
    Api(String),
    Network(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Input(_) | Self::Config(_) => 2,
            Self::Auth(_) => 3,
            Self::Permission(_) => 4,
            Self::NotFound(_) => 5,
            Self::Conflict(_) => 6,
            Self::Api(_) => 1,
            Self::Network(_) => 7,
        }
    }
}

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(message)
            | Self::Config(message)
            | Self::Auth(message)
            | Self::Permission(message)
            | Self::NotFound(message)
            | Self::Conflict(message)
            | Self::Api(message)
            | Self::Network(message) => f.write_str(message),
        }
    }
}

impl From<reqwest::Error> for CliError {
    fn from(error: reqwest::Error) -> Self {
        Self::Network(format!("request failed: {error}"))
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
