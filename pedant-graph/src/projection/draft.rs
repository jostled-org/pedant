//! The graph-neutral drafts one projection plan is made of.
//!
//! A fragment is everything one unit's instantiation of one source contributes
//! to a graph, stated without a single dense identity. Cross-fragment joins —
//! logical parents, enclosing definitions, candidate targets — travel as the
//! stable identities of [`super::placement`], so a fragment stays true while the
//! graph around it is renumbered.
//!
//! Nothing here reads a language. An adapter fills these records in from its own
//! report; what they mean to a graph is decided by the one assembler beside
//! them.

use std::sync::Arc;

use pedant_types::{
    Language, ResolutionGap, ResolutionRecord, ResolutionTier, SourceSpan, SymbolReference,
};

use crate::edge::{DependencyEvidence, EdgeDraft, GraphCertainty, GraphEdgeKind, GraphEdgeOrigin};
use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, GraphReferenceId};
use crate::node::{GraphNodeKind, GraphNodeLocation, NodeDraft};
use crate::reference::{GraphReferenceKind, ReferenceDraft};

use super::placement::{DefinitionIdentity, DefinitionTable, SourceIdentity};
use super::state::ProjectionCapacity;
use super::validation;

/// The container one plan mints for a unit nothing else names.
///
/// A Cargo target is declared by a manifest: nothing among the sources it
/// compiles states it, so the plan supplies the name and the container level
/// itself. A unit whose own sources declare it states no container here — see
/// [`UnitDeclaration`].
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StatedContainer {
    /// The unit's declared name.
    pub(crate) name: Arc<str>,
    /// The container level the bound build unit takes.
    pub(crate) kind: GraphNodeKind,
}

/// One unit rooted at a definition its own sources declare.
///
/// A Go package clause is written inside the package it opens, and the report
/// states it as a definition, which already earns a node. Minting a container
/// beside it would state one entity twice and leave the graph with two nodes
/// nothing tells apart, so the declaration's node is the unit's container and
/// the plan mints none.
pub(crate) struct UnitDeclaration {
    /// The plan-order position of the unit this declaration roots.
    pub(crate) unit: u32,
    /// The report-order position of the definition that declares it.
    pub(crate) definition: u32,
}

/// One report unit's container and the sources it instantiates.
pub(crate) struct UnitPlan {
    /// The stable key this unit is identified by across reports.
    pub(crate) key: Arc<str>,
    /// The language of every node this unit contributes.
    pub(crate) language: Language,
    /// The container this plan mints for it, unless a declaration roots it.
    pub(crate) container: Option<StatedContainer>,
    /// The unit that logically owns this one, when the plan nests it.
    pub(crate) parent: Option<u32>,
    /// Every source this unit instantiates, in snapshot order.
    pub(crate) sources: Box<[Arc<str>]>,
}

impl UnitPlan {
    /// The node this unit's root container is minted from, when the plan mints
    /// one at all.
    pub(crate) fn container_draft(&self) -> Option<NodeDraft> {
        self.container.as_ref().map(|stated| NodeDraft {
            language: self.language,
            name: Arc::clone(&stated.name),
            kind: stated.kind.clone(),
            location: None,
        })
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
    /// Every candidate one answer offered, in stated order.
    ///
    /// The target travels as the stable identity the current report's own table
    /// minted, so an adapter states no join of its own and two adapters cannot
    /// disagree about what a candidate names.
    pub(crate) fn stated(
        table: &DefinitionTable,
        answered: (&ResolutionRecord, GraphEdgeKind),
    ) -> Result<Box<[Self]>, GraphBuildError> {
        let (record, kind) = answered;
        record
            .candidates()
            .iter()
            .map(|candidate| {
                let target =
                    validation::definition_identity(table, candidate.definition().index())?;
                Ok(Self {
                    target: Arc::clone(target),
                    kind,
                    certainty: GraphCertainty::of(candidate.certainty()),
                })
            })
            .collect()
    }

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
    /// One reference site and every candidate its answer offered, at the graph
    /// kind the adapter's own vocabulary named for it.
    ///
    /// Only the kind is the adapter's. The site, the answer's gaps, the
    /// enclosing definition, and the candidates are the shared report's, so
    /// every adapter copies them the one way rather than each stating its own
    /// reading of the same record.
    pub(crate) fn stated(
        table: &DefinitionTable,
        reported: (&SymbolReference, &ResolutionRecord),
        kind: GraphReferenceKind,
    ) -> Result<Self, GraphBuildError> {
        let (reference, record) = reported;
        Ok(Self {
            language: reference.language(),
            kind,
            text: Arc::from(reference.text()),
            span: SymbolReference::span(reference).clone(),
            gaps: record.gaps().into(),
            enclosing: validation::optional_identity(
                table,
                reference
                    .enclosing_definition()
                    .map(|enclosing| enclosing.index()),
            )?,
            candidates: CandidateProjection::stated(
                table,
                (record, GraphEdgeKind::of_reference(kind)),
            )?,
        })
    }

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
/// holds is asked of the current report by the adapter that derived it, column
/// for column, and a derived equality beside it would be a second definition of
/// the same question that no compiler holds to the first.
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

/// Where one record sits: which fragment holds it, and where in that fragment.
#[derive(Clone, Copy)]
pub(crate) struct FragmentSlot {
    /// The fragment's position in the plan.
    pub(crate) fragment: u32,
    /// The record's position inside that fragment.
    pub(crate) slot: u32,
}

/// One complete projection, ready for the assembler to mint identities for.
pub(crate) struct ProjectionPlan {
    /// The tier the report was produced at.
    pub(crate) tier: ResolutionTier,
    /// Every report unit, in report order.
    pub(crate) units: Box<[UnitPlan]>,
    /// Every unit rooted at a definition its own sources declare.
    pub(crate) declarations: Box<[UnitDeclaration]>,
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
