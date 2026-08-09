use std::io::Write;

use pedant_core::SemanticContext;

#[cfg(feature = "semantic")]
use super::project::discover_requested_workspace_root;

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

    let root = match discover_requested_workspace_root(files) {
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
                format_args!("warning: --semantic: {error}; falling back to syntactic analysis"),
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

/// Stub when the `semantic` feature is disabled — always returns `None`.
#[cfg(not(feature = "semantic"))]
pub(crate) fn load_semantic_if_requested(
    _enabled: bool,
    _files: &[String],
    _stderr: &mut impl Write,
) -> Option<SemanticContext> {
    None
}
