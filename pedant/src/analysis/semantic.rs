use std::io::Write;
#[cfg(feature = "semantic")]
use std::path::Path;

use pedant_core::SemanticContext;

/// Load `SemanticContext` when `--semantic` is requested.
///
/// Returns `None` (with a stderr warning) if loading fails or the flag is absent.
#[cfg(feature = "semantic")]
pub(crate) fn load_semantic_if_requested(
    enabled: bool,
    files: &[String],
    stderr: &mut impl Write,
) -> Option<SemanticContext> {
    use std::time::Instant;

    if !enabled {
        return None;
    }

    let root = match discover_semantic_workspace_root(files) {
        Ok(Some(root)) => root,
        Ok(None) => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: --semantic: no Cargo.toml found, falling back to syntactic analysis"
                ),
            );
            return None;
        }
        Err(error) => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: --semantic: failed to discover workspace root: {error}; falling back to syntactic analysis"
                ),
            );
            return None;
        }
    };

    let start = Instant::now();
    let ctx = SemanticContext::load(&root);
    let elapsed = start.elapsed();

    match ctx {
        Some(c) => {
            crate::report_error(
                stderr,
                format_args!(
                    "semantic: loaded workspace in {:.1}s",
                    elapsed.as_secs_f64()
                ),
            );
            Some(c)
        }
        None => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: --semantic: failed to load workspace at {}, falling back to syntactic analysis",
                    root.display()
                ),
            );
            None
        }
    }
}

#[cfg(feature = "semantic")]
fn discover_semantic_workspace_root(
    files: &[String],
) -> Result<Option<Box<Path>>, pedant_core::lint::LintError> {
    use pedant_core::lint::discover_workspace_root;

    let mut last_error = None;

    for file in files {
        match discover_workspace_root(Path::new(file.as_str())) {
            Ok(Some(root)) => return Ok(Some(root.into_boxed_path())),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// Stub when the `semantic` feature is disabled — always returns `None`.
#[cfg(not(feature = "semantic"))]
pub(crate) fn load_semantic_if_requested(
    _enabled: bool,
    _files: &[String],
    _stderr: &mut impl Write,
) -> Option<SemanticContext> {
    None
}
