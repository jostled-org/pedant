//! Which resolution units one root target exposes, and through which edges.
//!
//! A binary, example, test, or benchmark root sees its package library through
//! Cargo's implicit crate edge. A library or binary root sees its normal
//! dependencies as declared and its development dependencies under test
//! compilation; an example, test, or benchmark root sees both as declared; a
//! build-script root sees only build dependencies. A dependency library
//! propagates its normal dependencies only. No source is read here.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::resolution::rust::dependency::CargoDependencyKind;
use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::identity::{PackageId, TargetId, position};
use crate::resolution::rust::package::RustPackage;
use crate::resolution::rust::project::RustProject;
use crate::resolution::rust::target::{CargoTargetKind, RustTarget};

use super::activation::{Predicate, conjoin, disjoin};
use super::error::{
    ClosureSite, ResolutionLimit, RustSnapshotError, SourceClosureFailure, SourceClosureFailureKind,
};
use super::failure::{failure, limit_failure};
use super::selection_chain::Ancestry;
use super::selection_edge::{self, SelectedEdge};

/// Everything a queued unit needs after the project has been consulted once.
struct UnitIdentity {
    package: PackageId,
    package_name: Arc<str>,
    target: TargetId,
    target_name: Arc<str>,
    entry: Arc<str>,
    manifest: Arc<str>,
    kind: CargoTargetKind,
    edition: CargoEdition,
}

/// One selected unit, before snapshot identities are issued.
pub(super) struct UnitDraft {
    pub(super) package: PackageId,
    pub(super) target: TargetId,
    pub(super) target_name: Arc<str>,
    pub(super) manifest: Arc<str>,
    pub(super) kind: CargoTargetKind,
    pub(super) entry: Arc<str>,
    pub(super) predicate: Predicate,
    pub(super) edition: CargoEdition,
}

/// One selected edge, addressed by the positions of the units it joins.
pub(super) struct EdgeDraft {
    pub(super) source: u32,
    pub(super) target: u32,
    pub(super) name: Arc<str>,
    pub(super) kind: CargoDependencyKind,
    pub(super) predicate: Predicate,
}

/// The complete, deterministically ordered unit and edge selection.
pub(super) struct Selection {
    pub(super) units: Box<[UnitDraft]>,
    pub(super) edges: Box<[EdgeDraft]>,
    pub(super) root: u32,
}

/// Sort key that fixes unit order independent of traversal order.
type UnitSortKey = (Arc<str>, CargoTargetKind, Arc<str>);

/// Edge key that fixes edge order and collapses repeated traversals.
type EdgeKey = (TargetId, CargoDependencyKind, Arc<str>, TargetId);

/// One unit still owing its dependency expansion.
struct Pending {
    identity: UnitIdentity,
    predicate: Predicate,
    chain: Ancestry,
    depth: u32,
    origin: ClosureSite,
}

/// Units and edges under construction.
struct Selector<'a> {
    project: &'a RustProject,
    root_target: TargetId,
    root_kind: CargoTargetKind,
    units: BTreeMap<TargetId, (UnitSortKey, UnitDraft)>,
    edges: BTreeMap<EdgeKey, Predicate>,
}

/// Select every unit and edge the root target's namespace reaches.
pub(super) fn select(
    project: &RustProject,
    root: &RustTarget,
) -> Result<Selection, RustSnapshotError> {
    let package = project
        .package(root.package())
        .ok_or(RustSnapshotError::UnknownTarget {
            index: root.package().index(),
        })?;
    let identity = identity_of(package, root);
    let chain = Ancestry::root(identity.target, &identity.package_name);
    let mut selector = Selector {
        project,
        root_target: root.id(),
        root_kind: root.kind(),
        units: BTreeMap::new(),
        edges: BTreeMap::new(),
    };
    let mut pending = vec![Pending {
        origin: ClosureSite::Target {
            name: Box::from(root.name()),
            entry: Box::from(root.entry_path()),
        },
        identity,
        predicate: Predicate::Always,
        chain,
        depth: 0,
    }];
    while let Some(item) = pending.pop() {
        pending.extend(selector.visit(item)?);
    }
    selector.finish()
}

/// Every string here is already an `Arc<str>` the loaded project owns, so the
/// identity shares them rather than heap-copying four strings per traversed
/// edge.
fn identity_of(package: &RustPackage, target: &RustTarget) -> UnitIdentity {
    UnitIdentity {
        package: package.id(),
        package_name: Arc::clone(&package.name),
        target: target.id(),
        target_name: Arc::clone(&target.name),
        entry: Arc::clone(&target.entry_path),
        manifest: Arc::clone(&package.manifest_path),
        kind: target.kind(),
        edition: package.edition(),
    }
}

impl Selector<'_> {
    /// Record one unit and report the dependencies it still owes.
    fn visit(&mut self, item: Pending) -> Result<Vec<Pending>, RustSnapshotError> {
        self.check_chain(&item)?;
        self.check_depth(&item)?;
        match self.merge(&item)? {
            true => self.children(&item),
            false => Ok(Vec::new()),
        }
    }

    fn check_chain(&self, item: &Pending) -> Result<(), RustSnapshotError> {
        match item.chain.repeats_latest() {
            true => Err(refuse(cycle_failure(item))),
            false => Ok(()),
        }
    }

    fn check_depth(&self, item: &Pending) -> Result<(), RustSnapshotError> {
        let ceiling = self.project.limits().max_dependency_depth;
        match item.depth > ceiling {
            true => Err(refuse(limit_failure(
                ResolutionLimit::DependencyDepth,
                (&item.origin, None),
                ceiling.into(),
            ))),
            false => Ok(()),
        }
    }

    /// Widen the unit's predicate; report whether it changed.
    fn merge(&mut self, item: &Pending) -> Result<bool, RustSnapshotError> {
        let existing = self
            .units
            .get(&item.identity.target)
            .map(|(_, draft)| draft.predicate.clone());
        let merged = match &existing {
            Some(current) => disjoin(current, &item.predicate),
            None => item.predicate.clone(),
        };
        if existing.as_ref() == Some(&merged) {
            return Ok(false);
        }
        self.insert(&item.identity, merged);
        self.check_capacity(item)?;
        Ok(true)
    }

    fn insert(&mut self, identity: &UnitIdentity, predicate: Predicate) {
        let key = (
            Arc::clone(&identity.manifest),
            identity.kind,
            Arc::clone(&identity.target_name),
        );
        let draft = UnitDraft {
            package: identity.package,
            target: identity.target,
            target_name: Arc::clone(&identity.target_name),
            manifest: Arc::clone(&identity.manifest),
            kind: identity.kind,
            entry: Arc::clone(&identity.entry),
            predicate,
            edition: identity.edition,
        };
        self.units.insert(identity.target, (key, draft));
    }

    fn check_capacity(&self, item: &Pending) -> Result<(), RustSnapshotError> {
        let ceiling = self.project.limits().max_units;
        match u64::try_from(self.units.len()).unwrap_or(u64::MAX) > u64::from(ceiling) {
            true => Err(refuse(limit_failure(
                ResolutionLimit::Units,
                (&item.origin, None),
                ceiling.into(),
            ))),
            false => Ok(()),
        }
    }

    fn children(&mut self, item: &Pending) -> Result<Vec<Pending>, RustSnapshotError> {
        let root = (item.identity.target == self.root_target, self.root_kind);
        let selected =
            selection_edge::select(self.project, item.identity.package, root).map_err(refuse)?;
        let mut next = Vec::new();
        for edge in selected.iter() {
            next.push(self.follow(item, edge));
        }
        Ok(next)
    }

    /// Record the edge and queue the unit it selects.
    fn follow(&mut self, item: &Pending, edge: &SelectedEdge<'_>) -> Pending {
        let predicate = edge.predicate();
        let key = (
            item.identity.target,
            edge.kind(),
            Arc::clone(edge.shared_name()),
            edge.target().id(),
        );
        self.edges.insert(key, predicate.clone());
        let identity = identity_of(edge.package(), edge.target());
        let chain = item.chain.extend(identity.target, &identity.package_name);
        Pending {
            predicate: conjoin(&item.predicate, &predicate),
            chain,
            depth: item.depth.saturating_add(1),
            origin: edge.site(self.project),
            identity,
        }
    }

    fn finish(self) -> Result<Selection, RustSnapshotError> {
        let mut ordered: Vec<(UnitSortKey, UnitDraft)> = self.units.into_values().collect();
        ordered.sort_by(|left, right| left.0.cmp(&right.0));
        let positions: BTreeMap<TargetId, u32> = ordered
            .iter()
            .enumerate()
            .map(|(index, (_, draft))| (draft.target, position(index)))
            .collect();
        let root =
            positions
                .get(&self.root_target)
                .copied()
                .ok_or(RustSnapshotError::UnknownTarget {
                    index: self.root_target.index(),
                })?;
        Ok(Selection {
            edges: ordered_edges(&self.edges, &positions)?,
            units: ordered
                .into_iter()
                .map(|(_, draft)| draft)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            root,
        })
    }
}

fn ordered_edges(
    edges: &BTreeMap<EdgeKey, Predicate>,
    positions: &BTreeMap<TargetId, u32>,
) -> Result<Box<[EdgeDraft]>, RustSnapshotError> {
    let mut drafts: Vec<EdgeDraft> = edges
        .iter()
        .map(|(key, predicate)| edge_draft(key, predicate, positions))
        .collect::<Result<_, _>>()?;
    drafts.sort_by(|left, right| {
        (left.source, left.kind, left.name.as_ref(), left.target).cmp(&(
            right.source,
            right.kind,
            right.name.as_ref(),
            right.target,
        ))
    });
    Ok(drafts.into_boxed_slice())
}

/// One edge, addressed by the positions of the units it joins.
///
/// An endpoint with no position is a selection this pass never recorded, so it
/// is refused rather than dropped: a silently missing edge is a namespace the
/// resolver would read as empty.
fn edge_draft(
    key: &EdgeKey,
    predicate: &Predicate,
    positions: &BTreeMap<TargetId, u32>,
) -> Result<EdgeDraft, RustSnapshotError> {
    let (source, kind, name, target) = key;
    Ok(EdgeDraft {
        source: placed(source, positions)?,
        target: placed(target, positions)?,
        name: Arc::clone(name),
        kind: *kind,
        predicate: predicate.clone(),
    })
}

fn placed(
    target: &TargetId,
    positions: &BTreeMap<TargetId, u32>,
) -> Result<u32, RustSnapshotError> {
    positions
        .get(target)
        .copied()
        .ok_or(RustSnapshotError::UnknownTarget {
            index: target.index(),
        })
}

fn cycle_failure(item: &Pending) -> SourceClosureFailure {
    let names = item.chain.package_names();
    let message = format!(
        "the dependency chain {} repeats a package",
        names.join(" -> ")
    );
    failure(
        SourceClosureFailureKind::DependencyCycle,
        (&item.origin, None),
        message,
    )
}

/// Selection failures precede every source read, so their evidence names no
/// reached path.
fn refuse(failure: SourceClosureFailure) -> RustSnapshotError {
    RustSnapshotError::SourceClosure(super::error::SourceClosureError::new(
        Box::new([]),
        Box::new([failure]),
    ))
}
