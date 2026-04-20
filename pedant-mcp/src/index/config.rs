use std::path::Path;

use pedant_core::GateConfig;
use pedant_core::check_config::load_config_file;

use super::IndexError;

/// Load `GateConfig` from the workspace `.pedant.toml`, falling back to defaults.
///
/// Returns the default config when the file does not exist.
/// Returns an error when the file exists but contains invalid TOML.
pub(super) fn load_gate_config(workspace_root: &Path) -> Result<GateConfig, IndexError> {
    let config_path = workspace_root.join(".pedant.toml");
    match load_config_file(&config_path) {
        Ok(cfg) => Ok(cfg.gate),
        Err(pedant_core::check_config::ConfigError::Read(ref io_err))
            if io_err.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(GateConfig::default())
        }
        Err(pedant_core::check_config::ConfigError::Read(io_err)) => Err(IndexError::Io {
            path: config_path.to_string_lossy().into(),
            source: io_err,
        }),
        Err(pedant_core::check_config::ConfigError::Parse(toml_err)) => {
            Err(IndexError::TomlParse {
                path: config_path.to_string_lossy().into(),
                source: toml_err,
            })
        }
    }
}
