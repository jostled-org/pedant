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
    GoProjectResolution, GoResolutionSnapshot, GoSnapshotModuleId, GoUnitBinding,
};
use pedant_types::{Language, ResolutionReport, SymbolDefinition, SymbolKind};

use crate::edge::{DependencyEvidence, GraphCertainty, GraphDependencyKind};
use crate::error::GraphBuildError;
use crate::id::{index_of, position};
use crate::projection::draft::{DependencyProjection, StatedContainer, UnitDeclaration, UnitPlan};
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
pub(crate) fn plan_units(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
    vocabulary: &Vocabulary,
) -> Result<PlannedUnits, GraphBuildError> {
    let report = resolution.report();
    let modules = module_positions(snapshot, report.units().len());
    let declared = declared_packages(report)?;
    let mut units = Vec::with_capacity(report.units().len().saturating_add(modules.len()));
    let mut declarations = Vec::with_capacity(report.units().len());
    for unit in report.units() {
        let reported = unit.id().index();
        let binding = validation::stated_binding(resolution, unit)?;
        let instance = neutral::bound_instance(snapshot.unit(binding.snapshot_unit()), reported)?;
        declarations.push(UnitDeclaration {
            unit: reported,
            definition: validation::package_declaration(
                declared.get(index_of(reported)).copied().flatten(),
                reported,
            )?,
        });
        units.push(UnitPlan {
            key: Arc::from(unit.key()),
            language: unit.language(),
            container: None,
            parent: Some(validation::module_unit(
                &modules,
                GoUnitBinding::module(binding),
                reported,
            )?),
            sources: instance.sources().into(),
        });
    }
    units.extend(planned_modules(snapshot, vocabulary));
    Ok(PlannedUnits {
        units: units.into_boxed_slice(),
        declarations: declarations.into_boxed_slice(),
        modules,
    })
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
    snapshot
        .edges()
        .iter()
        .enumerate()
        .map(|(index, edge)| {
            let stated = (position(index), edge);
            let source = validation::dependency_unit(modules.get(&edge.source()).copied(), stated)?;
            let target = validation::dependency_unit(modules.get(&edge.target()).copied(), stated)?;
            Ok(DependencyProjection {
                source,
                target,
                certainty: GraphCertainty::Resolved,
                evidence: DependencyEvidence::new(
                    Arc::from(edge.module_path()),
                    GraphDependencyKind::Normal,
                    None,
                ),
            })
        })
        .collect()
}

/// The plan position every snapshot module takes, by module identity.
///
/// Modules sit after the package contexts, so the first `units` positions stay
/// the report's own unit order and every record the report places is found at
/// the position the report states.
fn module_positions(
    snapshot: &GoResolutionSnapshot,
    units: usize,
) -> BTreeMap<GoSnapshotModuleId, u32> {
    snapshot
        .modules()
        .iter()
        .enumerate()
        .map(|(index, module)| (module.id(), position(units.saturating_add(index))))
        .collect()
}

/// One container plan per admitted module, in snapshot order.
fn planned_modules<'a>(
    snapshot: &'a GoResolutionSnapshot,
    vocabulary: &'a Vocabulary,
) -> impl Iterator<Item = UnitPlan> + 'a {
    snapshot.modules().iter().map(|module| UnitPlan {
        key: Arc::from(module.path()),
        language: Language::Go,
        container: Some(StatedContainer {
            name: Arc::from(module.path()),
            kind: vocabulary.module_root(),
        }),
        parent: None,
        sources: Box::default(),
    })
}

/// The package definition each report unit declares, by report unit position.
///
/// One per unit, refused where a second is found: a package context with two
/// package clauses in its report would take two root containers, and the
/// containment check would then name a doubled node instead of the doubled
/// declaration.
fn declared_packages(report: &ResolutionReport) -> Result<Box<[Option<u32>]>, GraphBuildError> {
    let mut declared: Box<[Option<u32>]> = vec![None; report.units().len()].into_boxed_slice();
    for (index, definition) in report.definitions().iter().enumerate() {
        let reported = definition.unit().index();
        let held = match definition.kind() {
            SymbolKind::Package => declared.get_mut(index_of(reported)),
            _ => None,
        };
        let Some(slot) = held else {
            continue;
        };
        validation::distinct_declaration(*slot, reported)?;
        *slot = Some(position(index));
    }
    Ok(declared)
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
