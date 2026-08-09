//! Rust source analyzer signature used by crate indexing.

use std::path::Path;

use pedant_core::project::FileShape;
use pedant_core::{AnalysisResult, Config, SemanticContext};

use super::IndexError;

/// Analyze a Rust file and return its result beside its project-check shape.
pub(super) type AnalyzeAt = fn(
    &Path,
    &str,
    &Config,
    Option<&SemanticContext>,
) -> Result<(AnalysisResult, FileShape), IndexError>;
