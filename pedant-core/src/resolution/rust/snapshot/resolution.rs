//! The multi-unit resolution snapshot: the root target, its Cargo-exposed
//! same-package library, and every in-repository dependency library its
//! namespace reaches.
//!
//! Cargo edges select units; Rust module edges select sources inside a unit.
//! One normalized path is read and parsed once and instantiated per unit.

use std::path::Path;
use std::sync::Arc;

use crate::resolution::line_index;
use crate::resolution::rust::fault::RustSourceFault;
use crate::resolution::rust::fingerprint::{self, RustSnapshotFingerprint};
use crate::resolution::rust::identity::{TargetId, index_of, position};
use crate::resolution::rust::inventory::RustFileInventory;
use crate::resolution::rust::limits::ResolutionLimits;
use crate::resolution::rust::project::RustProject;
use crate::resolution::rust::warning::{self, RustResolutionWarning};
use crate::resolution::supply::SourceSupply;

use super::authority;
use super::closure::{self, ClosureEntry, UnitClosure, UnitWalk};
use super::error::{RustSnapshotError, SourceClosureFailure};
use super::selection::{self, EdgeDraft, Selection, UnitDraft};
use super::source::RustSource;
use super::store::{SourceStore, refuse};
use super::unit::{RustResolutionUnit, RustSnapshotEdge, RustSnapshotUnitId};

/// One root target, the dependency library units it resolves against, and the
/// shared source store all of them read from.
#[derive(Debug)]
pub struct RustResolutionSnapshot {
    root: Box<Path>,
    root_target: TargetId,
    limits: ResolutionLimits,
    root_unit: RustSnapshotUnitId,
    units: Box<[RustResolutionUnit]>,
    edges: Box<[RustSnapshotEdge]>,
    sources: Box<[RustSource]>,
    warnings: Box<[RustResolutionWarning]>,
    fingerprint: RustSnapshotFingerprint,
}

impl RustResolutionSnapshot {
    /// The canonical repository root this snapshot was taken beneath.
    ///
    /// Every path a snapshot or a report states is relative to it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The target this snapshot was requested for.
    pub fn root_target(&self) -> TargetId {
        self.root_target
    }

    /// The unit that compiles the requested target.
    pub fn root_unit(&self) -> RustSnapshotUnitId {
        self.root_unit
    }

    /// The ceilings the project this snapshot came from was loaded under.
    pub fn limits(&self) -> ResolutionLimits {
        self.limits
    }

    /// Every selected unit, ordered by manifest path, target kind, then name.
    pub fn units(&self) -> &[RustResolutionUnit] {
        &self.units
    }

    /// The unit one snapshot-local identity selects.
    pub fn unit(&self, id: RustSnapshotUnitId) -> Option<&RustResolutionUnit> {
        self.units.get(index_of(id.index()))
    }

    /// Every selected Cargo edge, ordered by source unit, kind, then name.
    pub fn edges(&self) -> &[RustSnapshotEdge] {
        &self.edges
    }

    /// Every distinct source across all units, sorted by path.
    pub fn sources(&self) -> &[RustSource] {
        &self.sources
    }

    /// Non-fatal project-layout diagnostics discovered while walking this
    /// snapshot's complete source closures.
    pub fn warnings(&self) -> &[RustResolutionWarning] {
        &self.warnings
    }

    /// The source at one repository-relative path.
    pub fn source(&self, path: &str) -> Option<&RustSource> {
        line_index::find(&self.sources, path)
    }

    /// The opaque identity computed when this snapshot was completed.
    ///
    /// Two snapshots taken over the same repository state share it; a
    /// source-only edit that leaves every manifest and target identity
    /// unchanged does not.
    pub fn fingerprint(&self) -> RustSnapshotFingerprint {
        self.fingerprint
    }
}

/// Validate authority, select the units, then walk each unit's closure.
pub(in crate::resolution::rust) fn build<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    project: &RustProject,
    provider: &mut P,
    id: TargetId,
) -> Result<RustResolutionSnapshot, RustSnapshotError> {
    let root = authority::validated_target(project, id)?;
    let selection = selection::select(project, root)?;
    let mut store = SourceStore::new(project.root(), project.limits());
    let mut failures = Vec::new();
    let units = build_units(&selection, &mut store, provider, &mut failures);
    match failures.is_empty() {
        false => Err(refuse(&store, failures)),
        true => Ok(complete(
            project,
            (id, RustSnapshotUnitId::new(selection.root)),
            units,
            (build_edges(&selection.edges), store.finish()),
        )),
    }
}

/// Publish one snapshot, fingerprinting its completed fields first.
///
/// Nothing else assembles this value. The identity covers the canonical root,
/// the requested unit, every unit, every Cargo edge, and every source.
///
/// `limits` and `root_target` stay out of it, and both are derivable. A breached
/// ceiling refuses the snapshot rather than publishing it, so a published
/// snapshot states the same fields under every limit. The root target is the
/// target the hashed requested unit compiles, and the graph consumer checks that
/// pairing on its own.
fn complete(
    project: &RustProject,
    requested: (TargetId, RustSnapshotUnitId),
    units: Box<[RustResolutionUnit]>,
    reached: (Box<[RustSnapshotEdge]>, Box<[RustSource]>),
) -> RustResolutionSnapshot {
    let (root_target, root_unit) = requested;
    let (edges, sources) = reached;
    let root = Box::from(project.root());
    let fingerprint = fingerprint::of_completed(&root, root_unit.index(), &units, &edges, &sources);
    RustResolutionSnapshot {
        warnings: warning::shared_sources(&units),
        root,
        root_target,
        limits: project.limits(),
        root_unit,
        units,
        edges,
        sources,
        fingerprint,
    }
}

/// Walk each selected unit in turn, stopping where the walk says it stopped.
///
/// A crossed ceiling ends the whole selection: the walk that met it already
/// decided that, on the failure it collected, so this reads its answer rather
/// than rescanning the failures it added.
fn build_units<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    selection: &Selection,
    store: &mut SourceStore,
    provider: &mut P,
    failures: &mut Vec<SourceClosureFailure>,
) -> Box<[RustResolutionUnit]> {
    let mut units = Vec::new();
    for (index, draft) in selection.units.iter().enumerate() {
        match walk_draft(draft, store, provider, failures) {
            UnitWalk::Followed(closure) => units.push(build_unit((draft, index), closure)),
            UnitWalk::Halted(closure) => {
                units.push(build_unit((draft, index), closure));
                break;
            }
            UnitWalk::Unreached => (),
            UnitWalk::Exhausted => break,
        }
    }
    units.into_boxed_slice()
}

fn walk_draft<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    unit: &UnitDraft,
    store: &mut SourceStore,
    provider: &mut P,
    failures: &mut Vec<SourceClosureFailure>,
) -> UnitWalk {
    let entry = ClosureEntry {
        target_name: &unit.target_name,
        entry_path: &unit.entry,
        edition: unit.edition,
    };
    closure::walk_unit(store, provider, &entry, failures)
}

fn build_unit(draft: (&UnitDraft, usize), closure: UnitClosure) -> RustResolutionUnit {
    let (unit, index) = draft;
    RustResolutionUnit {
        id: RustSnapshotUnitId::new(position(index)),
        package: unit.package,
        target: unit.target,
        name: Arc::clone(&unit.target_name),
        manifest: Arc::clone(&unit.manifest),
        kind: unit.kind,
        activation: unit.predicate.activation(),
        crate_root: Arc::clone(&unit.entry),
        modules: closure.modules,
        sources: closure.sources,
    }
}

fn build_edges(drafts: &[EdgeDraft]) -> Box<[RustSnapshotEdge]> {
    drafts
        .iter()
        .map(|draft| RustSnapshotEdge {
            source: RustSnapshotUnitId::new(draft.source),
            target: RustSnapshotUnitId::new(draft.target),
            name: Arc::clone(&draft.name),
            kind: draft.kind,
            activation: draft.predicate.activation(),
        })
        .collect()
}
