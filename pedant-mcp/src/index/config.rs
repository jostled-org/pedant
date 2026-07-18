use std::borrow::Cow;
use std::io::Write;
use std::path::Path;

use pedant_core::check_config::{ConfigError, load_config_file};
use pedant_core::{Config, ConfigFile, GateConfig};

/// The workspace's resolved check configuration, loaded once from `.pedant.toml`.
///
/// Holds the base [`Config`] that per-file analysis runs with, plus the raw
/// [`ConfigFile`] so path overrides (`[overrides."tests/**"]`) resolve per file,
/// exactly as the CLI does. Gate rules come from the same file.
pub(super) struct WorkspaceConfig {
    base: Config,
    file: Option<ConfigFile>,
    default_gate: GateConfig,
}

impl WorkspaceConfig {
    /// The base check config for files with no matching path override.
    ///
    /// Project-level checks run against this, matching the CLI, which passes its
    /// `base_config` (not a per-file resolution) to `check_project`.
    pub(super) fn base(&self) -> &Config {
        &self.base
    }

    /// Gate rules from the `[gate]` section, or defaults when no file loaded.
    pub(super) fn gate(&self) -> &GateConfig {
        self.file
            .as_ref()
            .map_or(&self.default_gate, |file| &file.gate)
    }

    /// Effective config for a file path, applying any matching path override.
    ///
    /// Returns `None` when an override disables analysis for the path, so the
    /// caller skips the file entirely — the same contract the CLI honors.
    pub(super) fn resolve_for_path(&self, file_path: &str) -> Option<Cow<'_, Config>> {
        self.base.resolve_for_path(file_path, self.file.as_ref())
    }
}

/// Load the workspace check configuration from `<workspace_root>/.pedant.toml`.
///
/// A missing config falls back to defaults. A malformed config warns on stderr
/// and falls back to defaults, mirroring the CLI's handling of a *discovered*
/// (non-explicit) config path in `load_file_config`.
pub(super) fn load_workspace_config(workspace_root: &Path) -> WorkspaceConfig {
    let config_path = workspace_root.join(".pedant.toml");
    let file = match load_config_file(&config_path) {
        Ok(loaded) => Some(loaded),
        Err(ConfigError::Read(ref io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            report_config_warning(&config_path, &error);
            None
        }
    };
    let base = file
        .as_ref()
        .map_or_else(Config::default, Config::from_config_file);
    WorkspaceConfig {
        base,
        file,
        default_gate: GateConfig::default(),
    }
}

/// Emit a warning that a discovered config was unreadable and defaults apply.
///
/// The MCP server speaks the protocol on stdout, so diagnostics go to stderr.
fn report_config_warning(config_path: &Path, error: &ConfigError) {
    drop(writeln!(
        std::io::stderr(),
        "warning: ignoring {}: {error}; using default check config",
        config_path.display()
    ));
}
