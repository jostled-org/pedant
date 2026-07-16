use std::path::Path;

use crate::check_config::CheckConfig;
use crate::violation::Violation;

use super::cargo_meta::CargoMetadata;
use super::{feature_boundary, module_layout};

/// Inputs for whole-workspace structural checks. Unlike per-file style checks,
/// these examine the source tree and Cargo metadata rather than a single AST.
pub struct ProjectContext<'a> {
    /// Paths of the Rust source files under analysis, as passed on the CLI.
    pub rust_files: &'a [String],
    /// Workspace root directory, for resolving path-relative config rules.
    pub workspace_root: &'a Path,
    /// Parsed `cargo metadata`, when the feature-boundary check needs it.
    pub metadata: Option<&'a CargoMetadata>,
}

/// Run every enabled project-level check and collect their violations.
pub fn check_project(ctx: &ProjectContext<'_>, config: &CheckConfig) -> Vec<Violation> {
    let mut violations = Vec::new();
    module_layout::check_conflicting_module_root(ctx, config, &mut violations);
    module_layout::check_flat_module_family(ctx, config, &mut violations);
    feature_boundary::check_feature_boundary(ctx, config, &mut violations);
    violations
}
