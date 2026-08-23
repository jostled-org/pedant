//! Where each stated record sits, and the stable identity it takes.
//!
//! Graph identities are dense positions in one complete graph, so inserting a
//! record can renumber every later one. A projection that is going to be reused
//! across repository states therefore cannot join through them. These
//! identities are derived from one report and the sources it was placed over,
//! survive renumbering, and never reach a `CodeGraph`: the assembler resolves
//! each of them to an identity minted for the graph it is building.
//!
//! Placement is the other half of the same subject. One entry exists per
//! unit-and-source pair before any record is projected, so a source that
//! contributes no definition and no reference is still a source this plan knows
//! the unit reads, and every record the report states is placed in exactly one
//! of them.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{
    ResolutionRecord, ResolutionReport, SourceSpan, SymbolDefinition, SymbolKind, SymbolReference,
};

use crate::error::GraphBuildError;
use crate::id::{index_of, position};

use super::draft::{FragmentSlot, UnitPlan};
use super::validation;

/// One source, identified by the unit reading it and its normalized path.
///
/// A path alone is not a source identity: two units may instantiate the same
/// file, and each reads it as its own node.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SourceIdentity {
    unit: Arc<str>,
    path: Arc<str>,
}

impl SourceIdentity {
    /// The identity of one unit's instantiation of one normalized path.
    pub(crate) fn new(unit: Arc<str>, path: Arc<str>) -> Self {
        Self { unit, path }
    }

    /// A second identity naming the same source.
    pub(crate) fn shared(&self) -> Self {
        Self {
            unit: Arc::clone(&self.unit),
            path: Arc::clone(&self.path),
        }
    }

    /// The normalized repository-relative path.
    pub(crate) fn path(&self) -> &Arc<str> {
        &self.path
    }
}

/// One definition's stable identity across reports.
///
/// The occurrence ordinal is required rather than decorative: the report
/// contract permits two definitions to agree on every other field, and without
/// it two distinct nodes would join through one identity.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DefinitionIdentity {
    source: SourceIdentity,
    span: SourceSpan,
    kind: SymbolKind,
    name: Arc<str>,
    occurrence: u32,
}

impl DefinitionIdentity {
    /// The identity one stated definition takes before it is counted.
    fn stated(source: SourceIdentity, definition: &SymbolDefinition) -> Self {
        Self {
            source,
            span: SymbolDefinition::span(definition).clone(),
            kind: definition.kind(),
            name: Arc::from(definition.name()),
            occurrence: 0,
        }
    }

    /// The same identity at one occurrence among equal preceding fields.
    fn at(&self, occurrence: u32) -> Self {
        Self {
            source: self.source.shared(),
            span: self.span.clone(),
            kind: self.kind,
            name: Arc::clone(&self.name),
            occurrence,
        }
    }

    /// The source this definition is declared in.
    pub(crate) fn source(&self) -> &SourceIdentity {
        &self.source
    }

    /// The exact declaration range.
    pub(crate) fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// The declared name.
    pub(crate) fn name(&self) -> &Arc<str> {
        &self.name
    }
}

/// One report definition's identity beside the fragment holding it.
///
/// The identity is held behind one shared handle. Every join a report states —
/// a logical parent, an enclosing definition, a candidate target, and the
/// assembler's own node table — names the identity the table minted rather than
/// copying its four strings and its span into a projection of its own.
struct PlacedDefinition {
    fragment: u32,
    identity: Arc<DefinitionIdentity>,
}

/// Every report definition's stable identity, in validated report order.
///
/// Derived once. Definition drafts, logical parents, enclosing definitions, and
/// candidate targets all join through this one table, so a report index can
/// never be read as two different identities on two different passes.
pub(crate) struct DefinitionTable {
    placed: Box<[PlacedDefinition]>,
}

impl DefinitionTable {
    /// Identify every definition the report states, refusing every join the
    /// unit it names cannot answer for.
    pub(crate) fn new(
        report: &ResolutionReport,
        sources: &SourceSet,
    ) -> Result<Self, GraphBuildError> {
        let mut occurrences: BTreeMap<DefinitionIdentity, u32> = BTreeMap::new();
        let mut placed = Vec::with_capacity(report.definitions().len());
        for definition in report.definitions() {
            let reported = definition.unit().index();
            let file = SymbolDefinition::span(definition).file();
            let (fragment, source) = validation::instantiated_source(sources, reported, file)?;
            let stated = DefinitionIdentity::stated(source.shared(), definition);
            let occurrence = occurrences.get(&stated).copied().unwrap_or_default();
            placed.push(PlacedDefinition {
                fragment,
                identity: Arc::new(stated.at(occurrence)),
            });
            occurrences.insert(stated, occurrence.saturating_add(1));
        }
        Ok(Self {
            placed: placed.into_boxed_slice(),
        })
    }

    /// The identity one report definition takes, if the report states it.
    pub(crate) fn identity(&self, definition: u32) -> Option<&Arc<DefinitionIdentity>> {
        self.placed
            .get(index_of(definition))
            .map(|placed| &placed.identity)
    }

    /// The fragment one report definition belongs to, if the report states it.
    pub(crate) fn fragment(&self, definition: u32) -> Option<u32> {
        self.placed
            .get(index_of(definition))
            .map(|placed| placed.fragment)
    }
}

/// One source one unit instantiates, before anything is projected for it.
///
/// This is what a plan knows about a source before it derives anything: which
/// unit reads it, and the unit-qualified identity it is read under. Both are
/// stated by the adapter's own snapshot and report, so the key that selects a
/// retained projection is known here, before a single record of that source is
/// projected.
pub(crate) struct PlacedSource {
    /// The unit's position in the current plan.
    pub(crate) unit: u32,
    /// The unit-qualified identity of the source itself.
    pub(crate) source: SourceIdentity,
}

/// Every source one plan states, and the units that instantiate them.
///
/// The set holds no projection: what a source contributes is decided per
/// source, after its key has been stated.
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
        let scope = self.located.get(index_of(unit))?;
        let source = *scope.get(path)?;
        let placed = self.placed.get(index_of(source))?;
        Some((source, &placed.source))
    }

    /// The planned units, once every source has been projected.
    pub(crate) fn finish(self) -> Box<[UnitPlan]> {
        self.units
    }
}

/// Every record one source states, in report order.
///
/// The records are borrowed from the report rather than copied out of it: this
/// is what one source's projection is derived from, and — for an adapter that
/// retains projections — what a retained one is compared against. Both readings
/// must be over the one placement.
#[derive(Default)]
pub(crate) struct SourceRecords<'a> {
    /// Every definition declared in the source, beside its report position.
    pub(crate) definitions: Vec<(u32, &'a SymbolDefinition)>,
    /// Every reference stated in the source, beside the record that answered it.
    pub(crate) references: Vec<(&'a SymbolReference, &'a ResolutionRecord)>,
}

/// Where every report record sits, and what each source therefore states.
///
/// Placing a record costs its position and nothing else, so this runs for every
/// source of every adapter, reused or not, and the slots the assembler reads are
/// the report's own order either way.
pub(crate) struct RecordPlacement<'a> {
    /// Where each report definition sits, in report order.
    pub(crate) definitions: Box<[FragmentSlot]>,
    /// Where each report reference sits, in report order.
    pub(crate) references: Box<[FragmentSlot]>,
    /// The records each placed source states, in placement order.
    pub(crate) stated: Box<[SourceRecords<'a>]>,
}

impl<'a> RecordPlacement<'a> {
    /// Place every definition the report states and every reference its answer
    /// paired, in the source each of them names.
    pub(crate) fn stated(
        report: &'a ResolutionReport,
        resolved: &[(&'a SymbolReference, &'a ResolutionRecord)],
        placed: (&SourceSet, &DefinitionTable),
    ) -> Result<Self, GraphBuildError> {
        let (sources, table) = placed;
        let mut stated: Box<[SourceRecords<'a>]> = sources
            .placed()
            .iter()
            .map(|_| SourceRecords::default())
            .collect();
        let definitions = place_definitions(report, table, &mut stated)?;
        let references = place_references(resolved, sources, &mut stated)?;
        Ok(Self {
            definitions,
            references,
            stated,
        })
    }
}

/// One slot per report definition, in the source the identity table placed it
/// in.
fn place_definitions<'a>(
    report: &'a ResolutionReport,
    table: &DefinitionTable,
    stated: &mut [SourceRecords<'a>],
) -> Result<Box<[FragmentSlot]>, GraphBuildError> {
    let mut placed = Vec::with_capacity(report.definitions().len());
    for (index, definition) in report.definitions().iter().enumerate() {
        let at = position(index);
        let fragment = validation::definition_fragment(table, at)?;
        let identity = validation::definition_identity(table, at)?;
        let held = stated
            .get_mut(index_of(fragment))
            .map(|records| &mut records.definitions);
        placed.push(validation::placed_slot(
            placed_record(held, fragment, (at, definition)),
            definition.unit().index(),
            identity.source().path(),
        )?);
    }
    Ok(placed.into_boxed_slice())
}

/// One slot per report reference, in the source its site sits in.
fn place_references<'a>(
    resolved: &[(&'a SymbolReference, &'a ResolutionRecord)],
    sources: &SourceSet,
    stated: &mut [SourceRecords<'a>],
) -> Result<Box<[FragmentSlot]>, GraphBuildError> {
    let mut placed = Vec::with_capacity(resolved.len());
    for (reference, record) in resolved.iter().copied() {
        let reported = reference.unit().index();
        let file = SymbolReference::span(reference).file();
        let (fragment, source) = validation::instantiated_source(sources, reported, file)?;
        let held = stated
            .get_mut(index_of(fragment))
            .map(|records| &mut records.references);
        placed.push(validation::placed_slot(
            placed_record(held, fragment, (reference, record)),
            reported,
            source.path(),
        )?);
    }
    Ok(placed.into_boxed_slice())
}

/// Place one record in the source that states it, answering with its slot.
///
/// The slot is the record's position among that source's own records, which is
/// the order the report states them in, so a retained projection and a freshly
/// derived one are read through the same positions.
fn placed_record<T>(stated: Option<&mut Vec<T>>, fragment: u32, record: T) -> Option<FragmentSlot> {
    let held = stated?;
    let slot = position(held.len());
    held.push(record);
    Some(FragmentSlot { fragment, slot })
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
