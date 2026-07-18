use std::path::Path;

use crate::check_config::CheckConfig;
use crate::violation::Violation;

use super::cargo_meta::CargoMetadata;
use super::shape::FileShape;
use super::{feature_boundary, module_layout, type_footprint};

/// Inputs for whole-workspace structural checks. Unlike per-file style checks,
/// these examine the source tree, Cargo metadata, and the per-file shape
/// projections rather than a single AST.
pub struct ProjectContext<'a> {
    /// Paths of the Rust source files under analysis, as passed on the CLI.
    pub rust_files: &'a [String],
    /// Workspace root directory, for resolving path-relative config rules.
    pub workspace_root: &'a Path,
    /// Parsed `cargo metadata`, when the feature-boundary check needs it.
    pub metadata: Option<&'a CargoMetadata>,
    /// One [`FileShape`] per analyzed Rust file, in analysis order.
    pub file_shapes: &'a [FileShape],
}

/// Run every enabled project-level check, appending to `violations`.
///
/// `violations` carries the per-file findings collected so far, because a check
/// with a whole-crate view may supersede a per-file finding that saw only a
/// slice of the same problem.
pub fn check_project(
    ctx: &ProjectContext<'_>,
    config: &CheckConfig,
    violations: &mut Vec<Violation>,
) {
    module_layout::check_conflicting_module_root(ctx, config, violations);
    module_layout::check_flat_module_family(ctx, config, violations);
    feature_boundary::check_feature_boundary(ctx, config, violations);
    type_footprint::check_type_footprint(ctx, config, violations);
}
