//! Real semantic database and resolution-snapshot pairings used by Tier 2
//! component cases.

use std::path::Path;

use pedant_core::SemanticContext;
use pedant_core::resolution::rust::{RustResolutionSnapshot, RustResolver, RustTargetResolution};

use crate::resolution::fixture;
use crate::resolution::views::app_library;

/// One snapshot and the database Tier 2 must verify before promotion.
pub struct Pairing {
    pub snapshot: RustResolutionSnapshot,
    pub context: SemanticContext,
}

/// Load a semantic database at `root`, or say which root refused to load.
pub fn load_context(root: &Path) -> SemanticContext {
    SemanticContext::load(root)
        .unwrap_or_else(|| panic!("{} should load a semantic database", root.display()))
}

/// The resolution snapshot of one fixture's library target.
pub fn library_snapshot(tmp: &tempfile::TempDir) -> RustResolutionSnapshot {
    let project = fixture::load_default(tmp);
    project
        .snapshot_resolution(app_library(&project))
        .expect("the fixture resolves under the documented defaults")
}

/// The snapshot and database of one fixture, both taken from its own root.
pub fn matched_pairing(tmp: &tempfile::TempDir) -> Pairing {
    Pairing {
        snapshot: library_snapshot(tmp),
        context: load_context(&fixture::repository_root(tmp)),
    }
}

/// Resolve one fixture's library target through a verified database.
pub fn resolve_semantic(tmp: &tempfile::TempDir) -> RustTargetResolution {
    let pairing = matched_pairing(tmp);
    RustResolver::resolve_semantic(&pairing.snapshot, &pairing.context)
        .expect("Tier 2 resolves the fixture against its own database")
}

/// Resolve one fixture's library target from its stored IR alone.
pub fn resolve_syntactic(tmp: &tempfile::TempDir) -> RustTargetResolution {
    let snapshot = library_snapshot(tmp);
    RustResolver::resolve_syntactic(&snapshot).expect("Tier 1 resolves the fixture")
}
