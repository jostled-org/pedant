use std::io::Write;
use std::path::{Path, PathBuf};

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::discover_workspace_root;
use pedant_core::project::{CargoMetadata, ProjectContext, check_project};

use super::AnalysisAccumulator;

#[derive(Debug, thiserror::Error)]
#[error("failed to discover workspace root for {file}: {source}")]
pub(super) struct WorkspaceDiscoveryError {
    file: Box<Path>,
    #[source]
    source: Box<pedant_core::lint::LintError>,
}

pub(super) fn discover_requested_workspace_root(
    files: &[String],
) -> Result<Option<PathBuf>, WorkspaceDiscoveryError> {
    files.iter().try_fold(None, |root, file| {
        discover_workspace_root(Path::new(file.as_str()))
            .map(|candidate| root.or(candidate))
            .map_err(|source| WorkspaceDiscoveryError {
                file: PathBuf::from(file).into_boxed_path(),
                source: Box::new(source),
            })
    })
}

/// Run whole-workspace structural checks and merge their violations into `acc`.
/// The workspace root is discovered from the analyzed files, falling back to the
/// current directory.
pub(crate) fn run_project_checks(
    files: &[String],
    config: &CheckConfig,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let workspace_root = match discover_requested_workspace_root(files) {
        Ok(Some(root)) => root,
        Ok(None) => PathBuf::from("."),
        Err(error) => {
            crate::report_error(stderr, format_args!("error: {error}"));
            acc.had_error = true;
            return;
        }
    };
    let metadata = load_cargo_metadata_if_needed(config, &workspace_root, stderr);
    let ctx = ProjectContext {
        rust_files: files,
        workspace_root: &workspace_root,
        metadata: metadata.as_ref(),
        file_shapes: &acc.file_shapes,
    };
    check_project(&ctx, config, &mut acc.violations);
}

/// Run `cargo metadata` for the feature-boundary check, but only when it is
/// enabled and has rules. Failures fall back to skipping the check with a warning.
fn load_cargo_metadata_if_needed(
    config: &CheckConfig,
    workspace_root: &Path,
    stderr: &mut impl Write,
) -> Option<CargoMetadata> {
    if !config.check_feature_boundary || config.feature_boundaries.is_empty() {
        return None;
    }
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(workspace_root)
        .output();
    match output {
        Ok(out) if out.status.success() => serde_json::from_slice(&out.stdout).ok(),
        _ => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: feature-boundary: `cargo metadata` unavailable; skipping the check"
                ),
            );
            None
        }
    }
}
