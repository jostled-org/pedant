//! The graph-neutral projection one plan is made of.
//!
//! A fragment is everything one unit's instantiation of one source contributes
//! to a graph, stated without a single dense identity. Cross-fragment joins —
//! logical parents, enclosing definitions, candidate targets — travel as the
//! stable identities of [`super::identity`], so a fragment stays true while the
//! graph around it is renumbered.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{Language, ResolutionGap, ResolutionTier, SourceSpan};

use crate::edge::{DependencyEvidence, EdgeDraft, GraphCertainty, GraphEdgeKind, GraphEdgeOrigin};
use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, GraphReferenceId, position};
use crate::node::{GraphNodeKind, GraphNodeLocation, NodeDraft};
use crate::reference::{GraphReferenceKind, ReferenceDraft};

use super::identity::{DefinitionIdentity, SourceIdentity};
use super::index::ProjectionCapacity;
use super::validation;

/// One report unit's container and the sources it instantiates.
pub(crate) struct UnitPlan {
    /// The stable key this unit is identified by across reports.
    pub(crate) key: Arc<str>,
    /// The language of every node this unit contributes.
    pub(crate) language: Language,
    /// The unit's declared name.
    pub(crate) name: Arc<str>,
    /// The container level the bound Cargo target takes.
    pub(crate) kind: GraphNodeKind,
    /// Every source this unit instantiates, in snapshot order.
    pub(crate) sources: Box<[Arc<str>]>,
}

impl UnitPlan {
    /// The node this unit's root container is minted from.
    pub(crate) fn container_draft(&self) -> NodeDraft {
        NodeDraft {
            language: self.language,
            name: Arc::clone(&self.name),
            kind: self.kind.clone(),
            location: None,
        }
    }

    /// The node one instantiated source is minted from.
    pub(crate) fn file_draft(&self, path: &Arc<str>) -> NodeDraft {
        NodeDraft {
            language: self.language,
            name: Arc::clone(path),
            kind: GraphNodeKind::File,
            location: Some(GraphNodeLocation::File {
                path: Arc::clone(path),
            }),
        }
    }
}

/// One definition, before any dense identity exists.
pub(crate) struct DefinitionProjection {
    /// The stable identity every join to this definition uses.
    pub(crate) identity: Arc<DefinitionIdentity>,
    /// The language of the unit declaring it.
    pub(crate) language: Language,
    /// The graph vocabulary its symbol kind maps to.
    pub(crate) kind: GraphNodeKind,
    /// The definition that logically owns it, when the report states one.
    pub(crate) parent: Option<Arc<DefinitionIdentity>>,
}

impl DefinitionProjection {
    /// The node this definition is minted from, in one file node's bytes.
    pub(crate) fn draft(&self, file: GraphNodeId) -> NodeDraft {
        NodeDraft {
            language: self.language,
            name: Arc::clone(self.identity.name()),
            kind: self.kind.clone(),
            location: Some(GraphNodeLocation::Span {
                file,
                span: self.identity.span().clone(),
            }),
        }
    }
}

/// One candidate edge, before any dense identity exists.
pub(crate) struct CandidateProjection {
    /// The definition this candidate names.
    pub(crate) target: Arc<DefinitionIdentity>,
    /// The edge kind the referring site produces.
    pub(crate) kind: GraphEdgeKind,
    /// How much the candidate is known.
    pub(crate) certainty: GraphCertainty,
}

impl CandidateProjection {
    /// The edge this candidate is minted from.
    pub(crate) fn draft(
        &self,
        site: (GraphNodeId, GraphReferenceId),
        target: GraphNodeId,
    ) -> EdgeDraft {
        let (source, reference) = site;
        EdgeDraft {
            source,
            target,
            kind: self.kind,
            certainty: self.certainty,
            origin: GraphEdgeOrigin::Reference { reference },
        }
    }
}

/// One reference record and the candidates it produced.
pub(crate) struct ReferenceProjection {
    /// The language of the unit stating the site.
    pub(crate) language: Language,
    /// What the site denotes at the graph layer.
    pub(crate) kind: GraphReferenceKind,
    /// The exact referring text.
    pub(crate) text: Arc<str>,
    /// The exact referring range.
    pub(crate) span: SourceSpan,
    /// Why the answer is incomplete, when it is.
    pub(crate) gaps: Box<[ResolutionGap]>,
    /// The definition the site sits inside, when the report states one.
    pub(crate) enclosing: Option<Arc<DefinitionIdentity>>,
    /// Every candidate the answer offered, in stated order.
    pub(crate) candidates: Box<[CandidateProjection]>,
}

impl ReferenceProjection {
    /// The record this reference is minted from, at one source node.
    pub(crate) fn draft(&self, source: GraphNodeId) -> ReferenceDraft {
        ReferenceDraft {
            source,
            language: self.language,
            kind: self.kind,
            text: Arc::clone(&self.text),
            span: self.span.clone(),
            gaps: self.gaps.iter().copied().collect(),
        }
    }
}

/// One `DependsOn` edge, stated between unit positions.
pub(crate) struct DependencyProjection {
    /// The depending unit's position in the plan.
    pub(crate) source: u32,
    /// The depended-on unit's position in the plan.
    pub(crate) target: u32,
    /// How much the declaration is known.
    pub(crate) certainty: GraphCertainty,
    /// The declaration that is its own evidence.
    pub(crate) evidence: DependencyEvidence,
}

impl DependencyProjection {
    /// The edge this declaration is minted from, between two containers.
    pub(crate) fn draft(&self, source: GraphNodeId, target: GraphNodeId) -> EdgeDraft {
        EdgeDraft {
            source,
            target,
            kind: GraphEdgeKind::DependsOn,
            certainty: self.certainty,
            origin: GraphEdgeOrigin::Dependency {
                evidence: self.evidence.clone(),
            },
        }
    }
}

/// One source unit's complete graph-neutral projection.
///
/// A fragment is the complete local graph claim: the source it answers for,
/// every definition it declares, every reference it states, and every candidate
/// those references offered. A later build reuses one only when its own report
/// states exactly this, so a change made in another source that reaches this one
/// is a change to this fragment.
///
/// Nothing here states an equality of its own. Whether a retained fragment still
/// holds is asked of the current report by [`super::source`], column for column,
/// and a derived equality beside it would be a second definition of the same
/// question that no compiler holds to the first.
pub(crate) struct SourceFragment {
    /// The unit and path this fragment answers for.
    pub(crate) source: SourceIdentity,
    /// Every definition declared in it, in report order.
    pub(crate) definitions: Box<[DefinitionProjection]>,
    /// Every reference stated in it, in report order.
    pub(crate) references: Box<[ReferenceProjection]>,
}

/// One fragment beside the unit the current report places it under.
///
/// The placement is derived per build; the fragment is the part a later build
/// may reuse, so no report-order value is stored inside it.
pub(crate) struct PlacedFragment {
    /// The unit's position in the current plan.
    pub(crate) unit: u32,
    /// The projection itself, shared with whatever retained it.
    pub(crate) fragment: Arc<SourceFragment>,
}

/// One source one unit instantiates, before anything is projected for it.
///
/// This is what a plan knows about a source before it derives anything: which
/// unit reads it, and the unit-qualified identity it is read under. Both are
/// stated by the snapshot and the report, so the key that selects a retained
/// projection is known here, before a single record of that source is projected.
pub(crate) struct PlacedSource {
    /// The unit's position in the current plan.
    pub(crate) unit: u32,
    /// The unit-qualified identity of the source itself.
    pub(crate) source: SourceIdentity,
}

/// Where one record sits: which fragment holds it, and where in that fragment.
#[derive(Clone, Copy)]
pub(crate) struct FragmentSlot {
    /// The fragment's position in the plan.
    pub(crate) fragment: u32,
    /// The record's position inside that fragment.
    pub(crate) slot: u32,
}

/// Every source one plan states, and the units that instantiate them.
///
/// One entry exists per unit-and-source pair before any record is placed, so a
/// source that contributes no definition and no reference is still a source this
/// plan knows the unit reads. The set holds no projection: what a source
/// contributes is decided per source, after its key has been stated.
pub(crate) struct SourceSet {
    units: Box<[UnitPlan]>,
    located: Box<[BTreeMap<Arc<str>, u32>]>,
    placed: Box<[PlacedSource]>,
}

impl SourceSet {
    /// One placement per source each planned unit instantiates.
    pub(crate) fn new(units: Box<[UnitPlan]>) -> Result<Self, GraphBuildError> {
        let mut placed: Vec<PlacedSource> = Vec::new();
        let located: Vec<BTreeMap<Arc<str>, u32>> = units
            .iter()
            .enumerate()
            .map(|(index, unit)| unit_sources(&mut placed, position(index), unit))
            .collect::<Result<_, GraphBuildError>>()?;
        Ok(Self {
            units,
            located: located.into_boxed_slice(),
            placed: placed.into_boxed_slice(),
        })
    }

    /// Every planned unit, in report order.
    pub(crate) fn units(&self) -> &[UnitPlan] {
        &self.units
    }

    /// Every source this plan states, grouped by unit in report order.
    pub(crate) fn placed(&self) -> &[PlacedSource] {
        &self.placed
    }

    /// The source one unit reads `path` through, beside the identity that
    /// placement was stated under.
    pub(crate) fn locate(&self, unit: u32, path: &str) -> Option<(u32, &SourceIdentity)> {
        let scope = self.located.get(crate::id::index_of(unit))?;
        let source = *scope.get(path)?;
        let placed = self.placed.get(crate::id::index_of(source))?;
        Some((source, &placed.source))
    }

    /// The planned units, once every source has been projected.
    pub(crate) fn finish(self) -> Box<[UnitPlan]> {
        self.units
    }
}

/// One unit's sources, and where each of them is placed.
///
/// One placement per path, so a unit that stated a path twice is refused here
/// rather than mint a second file node the placement then holds no records for.
fn unit_sources(
    placed: &mut Vec<PlacedSource>,
    unit: u32,
    plan: &UnitPlan,
) -> Result<BTreeMap<Arc<str>, u32>, GraphBuildError> {
    let mut located = BTreeMap::new();
    for path in &plan.sources {
        let at = position(placed.len());
        validation::distinct_source(located.insert(Arc::clone(path), at), unit, path)?;
        placed.push(PlacedSource {
            unit,
            source: SourceIdentity::new(Arc::clone(&plan.key), Arc::clone(path)),
        });
    }
    Ok(located)
}

/// One complete projection, ready for the assembler to mint identities for.
pub(crate) struct ProjectionPlan {
    /// The tier the report was produced at.
    pub(crate) tier: ResolutionTier,
    /// Every report unit, in report order.
    pub(crate) units: Box<[UnitPlan]>,
    /// Every source-unit fragment, grouped by unit in report order.
    pub(crate) fragments: Box<[PlacedFragment]>,
    /// Where each report definition sits, in report order.
    pub(crate) definitions: Box<[FragmentSlot]>,
    /// Where each report reference sits, in report order.
    pub(crate) references: Box<[FragmentSlot]>,
    /// Every snapshot dependency edge, in snapshot order.
    pub(crate) dependencies: Box<[DependencyProjection]>,
    /// How many records the inputs state, counted before one is allocated.
    pub(crate) capacity: ProjectionCapacity,
}

impl ProjectionPlan {
    /// The definition one report-order slot names.
    pub(crate) fn definition(&self, at: FragmentSlot) -> Option<&DefinitionProjection> {
        self.fragment(at.fragment)?
            .definitions
            .get(crate::id::index_of(at.slot))
    }

    /// The reference one report-order slot names.
    pub(crate) fn reference(&self, at: FragmentSlot) -> Option<&ReferenceProjection> {
        self.fragment(at.fragment)?
            .references
            .get(crate::id::index_of(at.slot))
    }

    /// The fragment one position holds, beside the unit that placed it.
    pub(crate) fn placed(&self, fragment: u32) -> Option<&PlacedFragment> {
        self.fragments.get(crate::id::index_of(fragment))
    }

    /// The source one fragment answers for.
    pub(crate) fn source(&self, fragment: u32) -> Option<&SourceIdentity> {
        self.fragment(fragment).map(|held| &held.source)
    }

    /// The projection one fragment position holds.
    fn fragment(&self, fragment: u32) -> Option<&SourceFragment> {
        self.placed(fragment).map(|placed| placed.fragment.as_ref())
    }
}
