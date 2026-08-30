//! The bounded snapshot one loaded Go project states.
//!
//! One walk per admitted module, one read per source, one package unit per
//! compilation context, and one fingerprint over everything a resolution or a
//! graph can restate. The snapshot restates its modules rather than borrowing
//! them, so it outlives the project it came from.

use std::path::Path;
use std::sync::Arc;

use crate::resolution::line_index;
use crate::resolution::supply::SourceSupply;

use super::discovery::{EntryBudget, package_directories};
use super::fault::GoSourceFault;
use super::fingerprint::{self, GoSnapshotFingerprint};
use super::identity::{index_of, position};
use super::inventory::GoFileInventory;
use super::limits::GoResolutionLimits;
use super::packages::{PackageSite, UnitDraft};
use super::project::GoProject;
use super::requirement::GoRequirementResolution;
use super::snapshot_error::GoSnapshotError;
use super::snapshot_module::{GoSnapshotEdge, GoSnapshotModule, GoSnapshotModuleId};
use super::source::GoSource;
use super::store::GoSourceStore;
use super::unit::{GoResolutionUnit, GoSnapshotUnitId};
use super::unit_table::UnitTable;

/// One Go project's modules, package units, local dependency edges, and the
/// shared source store all of them read from.
#[derive(Debug)]
pub struct GoResolutionSnapshot {
    root: Box<Path>,
    limits: GoResolutionLimits,
    modules: Box<[GoSnapshotModule]>,
    units: Box<[GoResolutionUnit]>,
    edges: Box<[GoSnapshotEdge]>,
    sources: Box<[GoSource]>,
    fingerprint: GoSnapshotFingerprint,
}

impl GoResolutionSnapshot {
    /// The canonical repository root this snapshot was taken beneath.
    ///
    /// Every path a snapshot or a report states is relative to it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The ceilings the project this snapshot came from was loaded under.
    pub fn limits(&self) -> GoResolutionLimits {
        self.limits
    }

    /// The main module, which is always the snapshot's first.
    pub fn root_module(&self) -> GoSnapshotModuleId {
        GoSnapshotModuleId::new(position(0))
    }

    /// Every admitted module, the main module first.
    pub fn modules(&self) -> &[GoSnapshotModule] {
        &self.modules
    }

    /// The module one snapshot-local identity selects.
    pub fn module(&self, id: GoSnapshotModuleId) -> Option<&GoSnapshotModule> {
        self.modules.get(index_of(id.index()))
    }

    /// Every package unit, ordered by module, import path, then context.
    pub fn units(&self) -> &[GoResolutionUnit] {
        &self.units
    }

    /// The unit one snapshot-local identity selects.
    pub fn unit(&self, id: GoSnapshotUnitId) -> Option<&GoResolutionUnit> {
        self.units.get(index_of(id.index()))
    }

    /// Every local dependency edge, in the order the manifests declared them.
    pub fn edges(&self) -> &[GoSnapshotEdge] {
        &self.edges
    }

    /// Every distinct source across all units, sorted by path.
    pub fn sources(&self) -> &[GoSource] {
        &self.sources
    }

    /// The source at one repository-relative path.
    pub fn source(&self, path: &str) -> Option<&GoSource> {
        line_index::find(&self.sources, path)
    }

    /// The opaque identity computed when this snapshot was completed.
    ///
    /// Two snapshots taken over the same repository state share it; a
    /// source-only edit that leaves every manifest unchanged does not.
    pub fn fingerprint(&self) -> GoSnapshotFingerprint {
        self.fingerprint
    }
}

/// Walk every admitted module, then seal what the walk found.
///
/// The sole snapshot constructor: every ceiling this stage owns is checked
/// here or in the store it drives, and no other body grows the unit table.
pub(super) fn build<P: SourceSupply<GoFileInventory, GoSourceFault>>(
    project: &GoProject,
    provider: &mut P,
) -> Result<GoResolutionSnapshot, GoSnapshotError> {
    let limits = project.limits();
    let root = project.root();
    let mut store = GoSourceStore::new(root, limits);
    let mut budget = EntryBudget::new(limits);
    let mut table = UnitTable::new(limits);
    for (index, module) in project.modules().enumerate() {
        let site = PackageSite {
            root,
            module: position(index),
            module_path: &module.path,
        };
        let directories = package_directories(root, &root.join(module.directory()), &mut budget)?;
        table.retain_module(&mut store, provider, &site, &directories)?;
    }
    Ok(complete(
        project,
        sealed_units(table.finish()),
        store.finish(),
    ))
}

/// Mint identities and seal the snapshot.
///
/// Nothing else assembles this value. The identity covers the canonical root,
/// every module, every unit and its source membership, every local edge, and
/// every source's path, digest, and predicates.
///
/// `limits` stays out of it, and is derivable from the fields that are in it. A
/// breached ceiling refuses the snapshot rather than publishing it, so a
/// published snapshot states the same fields under every limit that admits it.
fn complete(
    project: &GoProject,
    units: Box<[GoResolutionUnit]>,
    sources: Box<[GoSource]>,
) -> GoResolutionSnapshot {
    let root = Box::from(project.root());
    let modules = snapshot_modules(project);
    let edges = snapshot_edges(project);
    let fingerprint = fingerprint::of_completed(&root, &modules, (&units, &edges), &sources);
    GoResolutionSnapshot {
        root,
        limits: project.limits(),
        modules,
        units,
        edges,
        sources,
        fingerprint,
    }
}

/// Order the drafts deterministically, then give each its identity.
fn sealed_units(drafts: Vec<UnitDraft>) -> Box<[GoResolutionUnit]> {
    let mut ordered = drafts;
    ordered.sort_by(|left, right| {
        (left.module, &left.import_path, left.context).cmp(&(
            right.module,
            &right.import_path,
            right.context,
        ))
    });
    ordered
        .into_iter()
        .enumerate()
        .map(|(index, draft)| GoResolutionUnit {
            id: GoSnapshotUnitId::new(position(index)),
            module: GoSnapshotModuleId::new(draft.module),
            context: draft.context,
            import_path: draft.import_path,
            package_name: draft.package_name,
            directory: draft.directory,
            sources: draft.sources,
        })
        .collect()
}

/// The snapshot's own restatement of every module the project admitted.
fn snapshot_modules(project: &GoProject) -> Box<[GoSnapshotModule]> {
    project
        .modules()
        .enumerate()
        .map(|(index, module)| GoSnapshotModule {
            id: GoSnapshotModuleId::new(position(index)),
            path: Arc::clone(&module.path),
            directory: Arc::clone(&module.directory),
            manifest: Arc::clone(&module.manifest),
            depth: module.depth,
        })
        .collect()
}

/// One edge per requirement an admitted local replacement satisfied.
fn snapshot_edges(project: &GoProject) -> Box<[GoSnapshotEdge]> {
    project
        .requirements()
        .iter()
        .filter_map(|requirement| {
            let GoRequirementResolution::LocalModule(target) = requirement.resolution() else {
                return None;
            };
            Some(GoSnapshotEdge {
                source: GoSnapshotModuleId::new(requirement.module().index()),
                target: GoSnapshotModuleId::new(target.index()),
                module_path: Box::from(requirement.path()),
                version: Box::from(requirement.version()),
            })
        })
        .collect()
}
