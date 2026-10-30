use crate::error::{CliError, Result};
use std::process::Command;

pub fn open(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    #[cfg(not(any(unix, target_os = "windows")))]
    return Err(CliError::Input(
        "automatic browser opening is not supported on this platform".into(),
    ));

    #[cfg(any(unix, target_os = "windows"))]
    command
        .spawn()
        .map(|_| ())
        .map_err(|error| CliError::Input(format!("cannot launch the browser: {error}")))
}
