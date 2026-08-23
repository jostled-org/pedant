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
    Language, ReferenceKind, ResolutionGap, ResolutionRecord, ResolutionTier, SourceSpan,
    SymbolDefinition, SymbolReference,
};

use crate::edge::{DependencyEvidence, EdgeDraft, GraphCertainty, GraphEdgeKind, GraphEdgeOrigin};
use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, GraphReferenceId, position};
use crate::node::{GraphNodeKind, GraphNodeLocation, NodeDraft};
use crate::reference::{GraphReferenceKind, ReferenceDraft};

use super::placement::{
    DefinitionIdentity, DefinitionTable, PlacedSource, SourceIdentity, SourceRecords,
};
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
    /// One report definition, at the graph kind the adapter's own reading named
    /// for it.
    ///
    /// Only the kind is the adapter's. The identity, the language, and the
    /// logical owner are the shared report's, so every adapter copies them the
    /// one way rather than each stating its own reading of the same record.
    pub(crate) fn stated<Named>(
        table: &DefinitionTable,
        reported: (u32, &SymbolDefinition),
        named: Named,
    ) -> Result<Self, GraphBuildError>
    where
        Named: Fn(&SymbolDefinition) -> Result<GraphNodeKind, GraphBuildError>,
    {
        let (at, definition) = reported;
        Ok(Self {
            identity: Arc::clone(validation::definition_identity(table, at)?),
            language: definition.language(),
            kind: named(definition)?,
            parent: validation::optional_identity(
                table,
                definition.parent().map(|parent| parent.index()),
            )?,
        })
    }

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
///
/// The edge kind is not held: it is decided by the referring site, so every
/// candidate of one record would store the same value and a reader would have
/// two statements of one fact to keep in step.
pub(crate) struct CandidateProjection {
    /// The definition this candidate names.
    pub(crate) target: Arc<DefinitionIdentity>,
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
        record: &ResolutionRecord,
    ) -> Result<Box<[Self]>, GraphBuildError> {
        record
            .candidates()
            .iter()
            .map(|candidate| {
                let target =
                    validation::definition_identity(table, candidate.definition().index())?;
                Ok(Self {
                    target: Arc::clone(target),
                    certainty: GraphCertainty::of(candidate.certainty()),
                })
            })
            .collect()
    }

    /// The edge this candidate is minted from, at the kind its site produces.
    pub(crate) fn draft(
        &self,
        site: (GraphNodeId, GraphReferenceId),
        target: GraphNodeId,
        kind: GraphEdgeKind,
    ) -> EdgeDraft {
        let (source, reference) = site;
        EdgeDraft {
            source,
            target,
            kind,
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
    ///
    /// Shared rather than owned: a retained fragment drafts its records again
    /// on every build that reuses it, and copying the answer each time would
    /// spend on the one path that exists to spend nothing.
    pub(crate) gaps: Arc<[ResolutionGap]>,
    /// The definition the site sits inside, when the report states one.
    pub(crate) enclosing: Option<Arc<DefinitionIdentity>>,
    /// Every candidate the answer offered, in stated order.
    pub(crate) candidates: Box<[CandidateProjection]>,
}

impl ReferenceProjection {
    /// One reference site and every candidate its answer offered, at the graph
    /// kind the adapter's own reading named for it.
    ///
    /// Only the naming is the adapter's, and the refusal a kind it does not
    /// name earns is taken here: both reference paths reach one call rather
    /// than each stating the same refusal before it. The site, the answer's
    /// gaps, the enclosing definition, and the candidates are the shared
    /// report's, so every adapter copies them the one way.
    pub(crate) fn stated(
        table: &DefinitionTable,
        reported: (&SymbolReference, &ResolutionRecord),
        named: Option<GraphReferenceKind>,
    ) -> Result<Self, GraphBuildError> {
        let (reference, record) = reported;
        Ok(Self {
            language: reference.language(),
            kind: validation::stated_reference_kind(named, reference)?,
            text: Arc::from(reference.text()),
            span: SymbolReference::span(reference).clone(),
            gaps: record.gaps().into(),
            enclosing: validation::optional_identity(
                table,
                reference
                    .enclosing_definition()
                    .map(|enclosing| enclosing.index()),
            )?,
            candidates: CandidateProjection::stated(table, record)?,
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
            gaps: Arc::clone(&self.gaps),
        }
    }
}

/// What one adapter's own dependency edge declares, before a plan position
/// exists.
///
/// The two endpoints arrive already looked up: which snapshot identity an edge
/// names and which table answers for it is the adapter's, and what a graph
/// cannot do with an endpoint nothing answers for is the same in every
/// language.
pub(crate) struct StatedDependency {
    /// The plan positions the depending and depended-on endpoints bound.
    pub(crate) bound: (Option<u32>, Option<u32>),
    /// How much the declaration is known.
    pub(crate) certainty: GraphCertainty,
    /// The declaration that is its own evidence.
    pub(crate) evidence: DependencyEvidence,
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
    /// One projection per stated dependency edge, in the order they are stated.
    ///
    /// The edge's own position and the refusal an unbound endpoint earns belong
    /// to every adapter alike, so they are stated once here and the adapter
    /// supplies only what its own snapshot declares.
    pub(crate) fn stated<Edge, Declared>(
        edges: &[Edge],
        declared: Declared,
    ) -> Result<Box<[Self]>, GraphBuildError>
    where
        Declared: Fn(&Edge) -> StatedDependency,
    {
        edges
            .iter()
            .enumerate()
            .map(|(index, edge)| Self::bound(position(index), declared(edge)))
            .collect()
    }

    /// One projection, with both endpoints proved against the plan.
    fn bound(edge: u32, declared: StatedDependency) -> Result<Self, GraphBuildError> {
        let (depending, depended) = declared.bound;
        let source = validation::dependency_unit(depending, (edge, declared.evidence.alias()))?;
        let target = validation::dependency_unit(depended, (edge, declared.evidence.alias()))?;
        Ok(Self {
            source,
            target,
            certainty: declared.certainty,
            evidence: declared.evidence,
        })
    }

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

impl SourceFragment {
    /// Everything one placed source contributes to a graph, derived from the
    /// report that placed it.
    ///
    /// Two decisions are the adapter's and nothing else is: which graph node
    /// kind one report definition takes, and what one report reference kind
    /// denotes. Both arrive as the adapter's own reading, so the walk over the
    /// placed records, every join through the current report's identity table,
    /// and every refusal those joins earn are written once for every language.
    pub(crate) fn derived<Named>(
        placed: (&PlacedSource, &DefinitionTable),
        records: &SourceRecords<'_>,
        named: (Named, fn(ReferenceKind) -> Option<GraphReferenceKind>),
    ) -> Result<Self, GraphBuildError>
    where
        Named: Fn(&SymbolDefinition) -> Result<GraphNodeKind, GraphBuildError>,
    {
        let (source, table) = placed;
        let (definition_kind, reference_kind) = named;
        Ok(Self {
            source: source.source.shared(),
            definitions: records
                .definitions
                .iter()
                .copied()
                .map(|reported| DefinitionProjection::stated(table, reported, &definition_kind))
                .collect::<Result<_, GraphBuildError>>()?,
            references: records
                .references
                .iter()
                .copied()
                .map(|reported| stated_reference(table, reported, reference_kind))
                .collect::<Result<_, GraphBuildError>>()?,
        })
    }
}

/// One placed reference, at the kind the adapter's own reading named for it.
fn stated_reference(
    table: &DefinitionTable,
    reported: (&SymbolReference, &ResolutionRecord),
    named: fn(ReferenceKind) -> Option<GraphReferenceKind>,
) -> Result<ReferenceProjection, GraphBuildError> {
    let (reference, _) = reported;
    ReferenceProjection::stated(table, reported, named(reference.kind()))
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
