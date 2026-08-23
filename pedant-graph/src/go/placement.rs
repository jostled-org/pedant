//! Where each admitted module and package context sits in one Go plan.
//!
//! A Go build has two container levels the graph keeps apart. A module is
//! declared by its own `go.mod`, so the plan states its container itself. A
//! package context is declared by the package clause its own sources write, so
//! the report definition that clause produced is its container and the plan
//! mints none beside it.
//!
//! Package contexts take the plan's leading positions, in report order, so the
//! report's own unit identifiers index the plan directly. Modules follow them,
//! because no report unit names one.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::resolution::go::{
    GoProjectResolution, GoResolutionSnapshot, GoSnapshotModuleId, GoSnapshotUnitId, GoUnitBinding,
};
use pedant_types::{Language, ResolutionReport, ResolutionUnit, SymbolDefinition, SymbolKind};

use crate::edge::{DependencyEvidence, GraphCertainty, GraphDependencyKind};
use crate::error::GraphBuildError;
use crate::id::{index_of, position};
use crate::projection::draft::{
    DependencyProjection, StatedContainer, StatedDependency, UnitDeclaration, UnitPlan,
};
use crate::projection::validation as neutral;

use super::mapping::Vocabulary;
use super::validation;

/// Every unit one Go plan states, and where the two kinds of them sit.
pub(crate) struct PlannedUnits {
    /// Every package context in report order, then every admitted module.
    pub(crate) units: Box<[UnitPlan]>,
    /// The package clause each package context is rooted at.
    pub(crate) declarations: Box<[UnitDeclaration]>,
    /// The plan position each snapshot module took, by module identity.
    pub(crate) modules: BTreeMap<GoSnapshotModuleId, u32>,
}

/// One unit per package context and one per admitted module.
///
/// Every plan position a package context takes is captured where that unit is
/// pushed, and the module positions are derived from how many were pushed. A
/// later filter over the report's units would therefore move the modules with
/// them rather than leave every package rooted at the wrong container.
pub(crate) fn plan_units(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
    vocabulary: &Vocabulary,
) -> Result<PlannedUnits, GraphBuildError> {
    let report = resolution.report();
    let declared = declared_packages(report)?;
    let mut planned = PlannedContexts::opening(report);
    for unit in report.units() {
        plan_context(&mut planned, (snapshot, resolution), (unit, &declared))?;
    }
    let modules = module_positions(snapshot, planned.units.len());
    planned.root(&modules)?;
    Ok(planned.finish((snapshot, vocabulary), modules))
}

/// One `DependsOn` projection per local dependency edge, in snapshot order.
///
/// An admitted local replacement is proved by the manifests the loader read, so
/// the edge is resolved and its evidence is the required module path under the
/// one Go dependency table. A version-only or unreplaced external requirement
/// states no snapshot edge, so nothing here fabricates a node to point at.
pub(crate) fn plan_dependencies(
    snapshot: &GoResolutionSnapshot,
    modules: &BTreeMap<GoSnapshotModuleId, u32>,
) -> Result<Box<[DependencyProjection]>, GraphBuildError> {
    DependencyProjection::stated(snapshot.edges(), |edge| StatedDependency {
        bound: (
            modules.get(&edge.source()).copied(),
            modules.get(&edge.target()).copied(),
        ),
        certainty: GraphCertainty::Resolved,
        evidence: DependencyEvidence::new(
            Arc::from(edge.module_path()),
            GraphDependencyKind::Normal,
            None,
        ),
    })
}

/// Every package context planned so far, and what each still owes.
///
/// The module a context is rooted under is resolved only once every context has
/// taken its plan position, because the modules sit after them. Both tables are
/// filled in one pass, in plan order, so a context's declaration and its
/// module are read back at exactly the position that context took.
struct PlannedContexts {
    units: Vec<UnitPlan>,
    declarations: Vec<UnitDeclaration>,
    rooted: Vec<(u32, GoSnapshotModuleId)>,
    bound: BTreeMap<GoSnapshotUnitId, u32>,
}

impl PlannedContexts {
    /// Empty tables sized for one report's units.
    fn opening(report: &ResolutionReport) -> Self {
        let stated = report.units().len();
        Self {
            units: Vec::with_capacity(stated),
            declarations: Vec::with_capacity(stated),
            rooted: Vec::with_capacity(stated),
            bound: BTreeMap::new(),
        }
    }

    /// Root every planned package context under the module whose tree declares
    /// it.
    ///
    /// The module table is filled from the snapshot's own modules, so a module
    /// identity outside it names nothing this graph holds a container for. That
    /// is the same dangling binding a missing package context is, and it is
    /// refused through the same neutral owner.
    fn root(&mut self, modules: &BTreeMap<GoSnapshotModuleId, u32>) -> Result<(), GraphBuildError> {
        for (plan, (reported, module)) in self.units.iter_mut().zip(&self.rooted) {
            plan.parent = Some(neutral::bound_instance(
                modules.get(module).copied(),
                *reported,
            )?);
        }
        Ok(())
    }

    /// Every unit this plan states: the contexts it planned, then one container
    /// per admitted module.
    fn finish(
        self,
        planned: (&GoResolutionSnapshot, &Vocabulary),
        modules: BTreeMap<GoSnapshotModuleId, u32>,
    ) -> PlannedUnits {
        let (snapshot, vocabulary) = planned;
        let mut units = self.units;
        units.extend(planned_modules(snapshot, vocabulary));
        PlannedUnits {
            units: units.into_boxed_slice(),
            declarations: self.declarations.into_boxed_slice(),
            modules,
        }
    }
}

/// Plan one package context, at the position this plan gives it.
///
/// One build unit is bound by one report unit here as it is in every other
/// adapter: a second report unit naming one package context would give every
/// source of that context two owners, and a graph that dropped one of the two
/// joins would be indistinguishable from a repository that states one.
fn plan_context(
    planned: &mut PlannedContexts,
    supplied: (&GoResolutionSnapshot, &GoProjectResolution),
    stated: (&ResolutionUnit, &[Option<u32>]),
) -> Result<(), GraphBuildError> {
    let (snapshot, resolution) = supplied;
    let (unit, declared) = stated;
    let reported = unit.id().index();
    let binding = validation::stated_binding(resolution, unit)?;
    let snapshot_unit = binding.snapshot_unit();
    let instance = neutral::bound_instance(snapshot.unit(snapshot_unit), reported)?;
    neutral::distinct_binding(planned.bound.get(&snapshot_unit).copied(), reported)?;
    planned.bound.insert(snapshot_unit, reported);
    let at = position(planned.units.len());
    planned.declarations.push(UnitDeclaration {
        unit: at,
        definition: validation::package_declaration(
            declared.get(index_of(reported)).copied().flatten(),
            reported,
        )?,
    });
    planned
        .rooted
        .push((reported, GoUnitBinding::module(binding)));
    planned.units.push(UnitPlan {
        key: Arc::from(unit.key()),
        language: unit.language(),
        container: None,
        parent: None,
        sources: instance.sources().into(),
    });
    Ok(())
}

/// The plan position every snapshot module takes, by module identity.
///
/// Modules sit after the package contexts, so the count is the plan's own count
/// of contexts rather than the report's count of units. The two agree today —
/// one context per report unit — and deriving the offset from the plan is what
/// keeps them agreeing if they ever stop.
fn module_positions(
    snapshot: &GoResolutionSnapshot,
    contexts: usize,
) -> BTreeMap<GoSnapshotModuleId, u32> {
    snapshot
        .modules()
        .iter()
        .enumerate()
        .map(|(index, module)| (module.id(), position(contexts.saturating_add(index))))
        .collect()
}

/// One container plan per admitted module, in snapshot order.
///
/// The module path is the unit's key and its container's name alike, so it is
/// allocated once and shared rather than copied out of the snapshot twice.
fn planned_modules<'a>(
    snapshot: &'a GoResolutionSnapshot,
    vocabulary: &'a Vocabulary,
) -> impl Iterator<Item = UnitPlan> + 'a {
    snapshot.modules().iter().map(|module| {
        let path: Arc<str> = Arc::from(module.path());
        UnitPlan {
            key: Arc::clone(&path),
            language: Language::Go,
            container: Some(StatedContainer {
                name: path,
                kind: vocabulary.module_root(),
            }),
            parent: None,
            sources: Box::default(),
        }
    })
}

/// The package definition each report unit declares, by report unit position.
///
/// One per unit, refused where a second is found: a package context with two
/// package clauses in its report would take two root containers, and the
/// containment check would then name a doubled node instead of the doubled
/// declaration.
///
/// The kind decides first and the slot is taken through a refusing accessor, so
/// skipping means only "this definition is not a package clause". A package
/// clause naming a unit this report holds no unit for is refused where it is
/// read, rather than dropped here and surfaced later as a missing source node
/// naming a subject that is not the one at fault.
fn declared_packages(report: &ResolutionReport) -> Result<Box<[Option<u32>]>, GraphBuildError> {
    let mut declared: Box<[Option<u32>]> = vec![None; report.units().len()].into_boxed_slice();
    for (index, definition) in report.definitions().iter().enumerate() {
        let reported = definition.unit().index();
        match definition.kind() {
            SymbolKind::Package => declare_package(&mut declared, reported, position(index))?,
            SymbolKind::Module
            | SymbolKind::Function
            | SymbolKind::Method
            | SymbolKind::Struct
            | SymbolKind::Enum
            | SymbolKind::Union
            | SymbolKind::Trait
            | SymbolKind::Interface
            | SymbolKind::DefinedType
            | SymbolKind::TypeAlias
            | SymbolKind::Constant
            | SymbolKind::Variable
            | SymbolKind::Static
            | SymbolKind::Field => continue,
        }
    }
    Ok(declared)
}

/// Record the one package clause one report unit is rooted at.
fn declare_package(
    declared: &mut [Option<u32>],
    unit: u32,
    definition: u32,
) -> Result<(), GraphBuildError> {
    let slot = neutral::unit_slot(declared.get_mut(index_of(unit)), unit)?;
    validation::distinct_declaration(*slot, unit)?;
    *slot = Some(definition);
    Ok(())
}

/// The kind of the definition one report definition names as its holder.
///
/// A method takes a different callable token depending on whether an interface
/// or a receiver's named type declares it, so the holder is read from the
/// report rather than inferred from the method itself.
pub(crate) fn holder_kind(
    report: &ResolutionReport,
    definition: &SymbolDefinition,
) -> Result<Option<SymbolKind>, GraphBuildError> {
    match definition.parent() {
        None => Ok(None),
        Some(holder) => validation::holder_kind(report, holder.index()).map(Some),
    }
}
