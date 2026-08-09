use std::fs;
use std::path::Path;

use super::file::ConfigFile;

/// Failure modes when loading `.pedant.toml`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Disk I/O failure reading the config file.
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    /// TOML syntax or schema error in the config file.
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Read and deserialize a `.pedant.toml` from the given path.
pub fn load_config_file(path: &Path) -> Result<ConfigFile, ConfigError> {
    let content = fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}

/// Search `.pedant.toml` in the project root, then `$XDG_CONFIG_HOME/pedant/config.toml`.
pub fn find_config_file() -> Result<Option<std::path::PathBuf>, ConfigError> {
    let project_config = find_project_config_file()?;
    Ok(project_config.or_else(find_global_config_file))
}

fn find_project_config_file() -> Result<Option<std::path::PathBuf>, ConfigError> {
    let config_path = std::env::current_dir()?.join(".pedant.toml");
    Ok(config_path.exists().then_some(config_path))
}

fn find_global_config_file() -> Option<std::path::PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    let config_path = config_dir.join("pedant").join("config.toml");
    config_path.exists().then_some(config_path)
}
