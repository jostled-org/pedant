//! Graph-neutral structural inputs and the pure module-boundary evaluator.
//!
//! The composition owner projects its topology into validated facts; this
//! module judges them. Every decision is exact integer comparison over the
//! counts a fact carries, so the same facts always produce the same verdicts.

use std::collections::BTreeSet;
use std::sync::Arc;

use thiserror::Error;

use crate::check_config::{GateConfig, ModuleBoundaryConfig};

use super::catalog::{MODULE_BOUNDARY_RULES, ModuleBoundaryRule, resolve_severity};
use super::verdict::{
    GateAnchor, GateEvidence, GateLocation, GateSeverity, GateVerdict, ModuleBoundaryEntity,
    ModuleBoundaryEvidence, ModuleBoundaryMeasurement,
};

/// Why a graph-neutral module-boundary value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ModuleBoundaryInputError {
    /// A location was written without a source path.
    #[error("a gate location requires a non-empty path")]
    EmptyLocationPath,
    /// A location line was zero; lines are one-based.
    #[error("a gate location requires a one-based line")]
    ZeroLocationLine,
    /// A location column was zero; columns are one-based.
    #[error("a gate location requires a one-based column")]
    ZeroLocationColumn,
    /// An entity was written without a qualified label.
    #[error("entity {ordinal} requires a non-empty label")]
    EmptyEntityLabel {
        /// The ordinal of the rejected entity.
        ordinal: u32,
    },
    /// A component listed no member.
    #[error("a component requires at least one member")]
    EmptyComponentMembers,
    /// Two component members shared one ordinal.
    #[error("component member ordinal {ordinal} is repeated")]
    DuplicateComponentMember {
        /// The repeated member ordinal.
        ordinal: u32,
    },
    /// A component listed no declared partition.
    #[error("a component requires at least one declared partition")]
    EmptyComponentPartitions,
    /// Two component partitions shared one ordinal.
    #[error("component partition ordinal {ordinal} is repeated")]
    DuplicateComponentPartition {
        /// The repeated partition ordinal.
        ordinal: u32,
    },
    /// More partitions were listed than the component has members.
    #[error("a component with {members} members cannot occupy {partitions} partitions")]
    ComponentPartitionsExceedMembers {
        /// Members the component listed.
        members: usize,
        /// Partitions the component listed.
        partitions: usize,
    },
    /// A component with several members was reported acyclic.
    #[error("an acyclic component cannot hold {members} members")]
    AcyclicComponentHasMultipleMembers {
        /// Members the component listed.
        members: usize,
    },
    /// A misplacement named one partition as both declared and candidate.
    #[error("a misplaced symbol cannot prefer its declared partition {ordinal}")]
    MisplacedSymbolPartitionsAreEqual {
        /// The ordinal named twice.
        ordinal: u32,
    },
    /// A misplacement was reported for a symbol with no outgoing edge.
    #[error("symbol {ordinal} has no outgoing selected edge to attribute")]
    MisplacedSymbolHasNoOutgoingEdges {
        /// The ordinal of the rejected symbol.
        ordinal: u32,
    },
    /// More foreign edges were counted than the symbol has outgoing edges.
    #[error("{foreign_edges} foreign edges exceed {total_outgoing_edges} outgoing edges")]
    MisplacedSymbolForeignEdgesExceedTotal {
        /// Foreign edges counted.
        foreign_edges: u32,
        /// All outgoing edges counted.
        total_outgoing_edges: u32,
    },
    /// An input was written without a root target label.
    #[error("a module-boundary input requires a non-empty target")]
    EmptyInputTarget,
}

/// One validated structural observation about a single root target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleBoundaryFact {
    subject: ModuleBoundaryEntity,
    measurement: ModuleBoundaryMeasurement,
}

impl ModuleBoundaryFact {
    /// Build a component fact, deriving its subject from the first member.
    pub fn component(
        cyclic: bool,
        members: Arc<[ModuleBoundaryEntity]>,
        partitions: Arc<[ModuleBoundaryEntity]>,
    ) -> Result<Self, ModuleBoundaryInputError> {
        let first = validate_component(cyclic, &members, &partitions)?;
        let subject = component_subject(first, &members)?;
        Ok(Self {
            subject,
            measurement: ModuleBoundaryMeasurement::Component {
                cyclic,
                members,
                partitions,
            },
        })
    }

    /// Build a misplacement fact whose subject is the symbol itself.
    pub fn misplaced_symbol(
        symbol: ModuleBoundaryEntity,
        declared_partition: ModuleBoundaryEntity,
        candidate_partition: ModuleBoundaryEntity,
        foreign_edges: u32,
        total_outgoing_edges: u32,
    ) -> Result<Self, ModuleBoundaryInputError> {
        validate_misplacement(
            &symbol,
            &declared_partition,
            &candidate_partition,
            foreign_edges,
            total_outgoing_edges,
        )?;
        Ok(Self {
            subject: symbol,
            measurement: ModuleBoundaryMeasurement::MisplacedSymbol {
                declared_partition,
                candidate_partition,
                foreign_edges,
                total_outgoing_edges,
            },
        })
    }

    /// Build a cohesion fact whose subject is the module itself.
    ///
    /// Infallible, unlike its siblings: a module's two edge counts are
    /// independent, so no pair contradicts the other. Two zeros are accepted
    /// too, because an isolated module is a valid observation.
    pub fn low_module_cohesion(
        partition: ModuleBoundaryEntity,
        internal_edges: u32,
        boundary_edges: u32,
    ) -> Self {
        Self {
            subject: partition,
            measurement: ModuleBoundaryMeasurement::LowModuleCohesion {
                internal_edges,
                boundary_edges,
            },
        }
    }

    /// The entity a verdict built from this fact names.
    pub fn subject(&self) -> &ModuleBoundaryEntity {
        &self.subject
    }

    /// The counts a rule compares against its thresholds.
    pub fn measurement(&self) -> &ModuleBoundaryMeasurement {
        &self.measurement
    }
}

/// Every validated fact of one root target, with the label they are scoped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleBoundaryInput {
    target: Arc<str>,
    facts: Box<[ModuleBoundaryFact]>,
}

impl ModuleBoundaryInput {
    /// Scope already validated facts to one non-empty root target label.
    pub fn try_new(
        target: impl Into<Arc<str>>,
        facts: Box<[ModuleBoundaryFact]>,
    ) -> Result<Self, ModuleBoundaryInputError> {
        let target = target.into();
        match target.is_empty() {
            true => Err(ModuleBoundaryInputError::EmptyInputTarget),
            false => Ok(Self { target, facts }),
        }
    }

    /// The root target label every emitted verdict repeats.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The validated facts, in projection order.
    pub fn facts(&self) -> &[ModuleBoundaryFact] {
        &self.facts
    }
}

/// Check component self-consistency, returning the member the subject derives from.
fn validate_component<'m>(
    cyclic: bool,
    members: &'m [ModuleBoundaryEntity],
    partitions: &[ModuleBoundaryEntity],
) -> Result<&'m ModuleBoundaryEntity, ModuleBoundaryInputError> {
    let first = members
        .first()
        .ok_or(ModuleBoundaryInputError::EmptyComponentMembers)?;
    require_unique_ordinals(members, |ordinal| {
        ModuleBoundaryInputError::DuplicateComponentMember { ordinal }
    })?;
    if partitions.is_empty() {
        return Err(ModuleBoundaryInputError::EmptyComponentPartitions);
    }
    require_unique_ordinals(partitions, |ordinal| {
        ModuleBoundaryInputError::DuplicateComponentPartition { ordinal }
    })?;
    if partitions.len() > members.len() {
        return Err(ModuleBoundaryInputError::ComponentPartitionsExceedMembers {
            members: members.len(),
            partitions: partitions.len(),
        });
    }
    if !cyclic && members.len() > 1 {
        return Err(
            ModuleBoundaryInputError::AcyclicComponentHasMultipleMembers {
                members: members.len(),
            },
        );
    }
    Ok(first)
}

fn require_unique_ordinals(
    entities: &[ModuleBoundaryEntity],
    repeated: impl Fn(u32) -> ModuleBoundaryInputError,
) -> Result<(), ModuleBoundaryInputError> {
    // A one-element slice repeats nothing, and an acyclic project produces one
    // single-member component per node up to the node ceiling, so the set is
    // built only where duplication is possible.
    if entities.len() < 2 {
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    match entities
        .iter()
        .map(ModuleBoundaryEntity::ordinal)
        .find(|ordinal| !seen.insert(*ordinal))
    {
        Some(ordinal) => Err(repeated(ordinal)),
        None => Ok(()),
    }
}

/// Name the component after its first member and annotate it with the first
/// member in node order that carries a span, then the first that carries a
/// file, then no location.
///
/// The annotation never changes the subject's first-member ordinal or label.
fn component_subject(
    first: &ModuleBoundaryEntity,
    members: &[ModuleBoundaryEntity],
) -> Result<ModuleBoundaryEntity, ModuleBoundaryInputError> {
    let annotation = first_anchored(members, GateAnchor::Span)
        .or_else(|| first_anchored(members, GateAnchor::File));
    ModuleBoundaryEntity::try_new(
        first.ordinal(),
        format!("scc::{}", first.label()),
        annotation,
    )
}

/// The first member location in node order with the requested derivation.
fn first_anchored(members: &[ModuleBoundaryEntity], anchor: GateAnchor) -> Option<GateLocation> {
    members
        .iter()
        .filter_map(ModuleBoundaryEntity::location)
        .find(|location| location.anchor() == anchor)
        .cloned()
}

fn validate_misplacement(
    symbol: &ModuleBoundaryEntity,
    declared_partition: &ModuleBoundaryEntity,
    candidate_partition: &ModuleBoundaryEntity,
    foreign_edges: u32,
    total_outgoing_edges: u32,
) -> Result<(), ModuleBoundaryInputError> {
    if declared_partition.ordinal() == candidate_partition.ordinal() {
        return Err(
            ModuleBoundaryInputError::MisplacedSymbolPartitionsAreEqual {
                ordinal: declared_partition.ordinal(),
            },
        );
    }
    if total_outgoing_edges == 0 {
        return Err(
            ModuleBoundaryInputError::MisplacedSymbolHasNoOutgoingEdges {
                ordinal: symbol.ordinal(),
            },
        );
    }
    if foreign_edges > total_outgoing_edges {
        return Err(
            ModuleBoundaryInputError::MisplacedSymbolForeignEdgesExceedTotal {
                foreign_edges,
                total_outgoing_edges,
            },
        );
    }
    Ok(())
}

/// A cyclic component with more members than the configured limit.
pub(super) fn is_large_component(
    measurement: &ModuleBoundaryMeasurement,
    config: &ModuleBoundaryConfig,
) -> bool {
    match measurement {
        ModuleBoundaryMeasurement::Component {
            cyclic: true,
            members,
            ..
        } => members.len() as u64 > u64::from(config.max_scc_members()),
        _ => false,
    }
}

/// A cycle whose members occupy more than one declared partition.
///
/// Numeric policy cannot change this answer, so it reads no configuration.
pub(super) fn is_boundary_crossing_component(measurement: &ModuleBoundaryMeasurement) -> bool {
    match measurement {
        ModuleBoundaryMeasurement::Component {
            cyclic: true,
            partitions,
            ..
        } => partitions.len() > 1,
        _ => false,
    }
}

/// A symbol whose foreign-edge share meets both misplacement thresholds.
pub(super) fn is_misplaced_symbol(
    measurement: &ModuleBoundaryMeasurement,
    config: &ModuleBoundaryConfig,
) -> bool {
    match measurement {
        ModuleBoundaryMeasurement::MisplacedSymbol {
            foreign_edges,
            total_outgoing_edges,
            ..
        } => {
            *foreign_edges >= config.misplaced_symbol_min_foreign_edges()
                && at_least_percent(
                    u64::from(*foreign_edges),
                    u64::from(*total_outgoing_edges),
                    config.misplaced_symbol_min_affinity_percent(),
                )
        }
        _ => false,
    }
}

/// A module with enough selected traffic whose internal share is too small.
pub(super) fn is_low_cohesion_module(
    measurement: &ModuleBoundaryMeasurement,
    config: &ModuleBoundaryConfig,
) -> bool {
    match measurement {
        ModuleBoundaryMeasurement::LowModuleCohesion {
            internal_edges,
            boundary_edges,
        } => {
            let total = u64::from(*internal_edges) + u64::from(*boundary_edges);
            total >= u64::from(config.low_module_cohesion_min_outgoing_edges())
                && below_percent(
                    u64::from(*internal_edges),
                    total,
                    config.low_module_cohesion_min_percent(),
                )
        }
        _ => false,
    }
}

/// `part / total >= percent / 100`, by exact cross multiplication.
fn at_least_percent(part: u64, total: u64, percent: u8) -> bool {
    part * 100 >= total * u64::from(percent)
}

/// `part / total < percent / 100`, by exact cross multiplication.
fn below_percent(part: u64, total: u64, percent: u8) -> bool {
    part * 100 < total * u64::from(percent)
}

/// Judge one target's validated facts against local module-boundary policy.
///
/// Pure and infallible: rules run in catalog order, input order is retained
/// within one rule, and every emitted verdict carries the exact row that
/// triggered it.
pub fn evaluate_module_boundary_rules(
    input: &ModuleBoundaryInput,
    config: &GateConfig,
) -> Box<[GateVerdict]> {
    if !config.enabled || !config.module_boundary.enabled() {
        return Box::new([]);
    }

    MODULE_BOUNDARY_RULES
        .iter()
        .flat_map(|rule| rule_verdicts(rule, input, &config.module_boundary))
        .collect()
}

/// One rule's verdicts, streamed so the evaluation allocates once in total.
fn rule_verdicts<'i>(
    rule: &'static ModuleBoundaryRule,
    input: &'i ModuleBoundaryInput,
    config: &'i ModuleBoundaryConfig,
) -> impl Iterator<Item = GateVerdict> + 'i {
    resolve_severity(rule.name, rule.default_severity, config.rule_overrides())
        .into_iter()
        .flat_map(move |severity| {
            input
                .facts()
                .iter()
                .filter(move |fact| (rule.predicate)(fact.measurement(), config))
                .map(move |fact| verdict(rule, severity, &input.target, fact))
        })
}

fn verdict(
    rule: &'static ModuleBoundaryRule,
    severity: GateSeverity,
    target: &Arc<str>,
    fact: &ModuleBoundaryFact,
) -> GateVerdict {
    let evidence = ModuleBoundaryEvidence::new(
        Arc::clone(target),
        fact.subject().clone(),
        fact.measurement().clone(),
    );
    rule.verdict(severity, Some(GateEvidence::ModuleBoundary(evidence)))
}
