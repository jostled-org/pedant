//! The stable identities a source-unit projection states its joins through.
//!
//! Graph identities are dense positions in one complete graph, so inserting a
//! record can renumber every later one. A projection that is going to be reused
//! across repository states therefore cannot join through them. These
//! identities are derived from the report and the snapshot alone, survive
//! renumbering, and never reach a `CodeGraph`: the assembler resolves each of
//! them to an identity minted for the graph it is building.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{ResolutionReport, SourceSpan, SymbolDefinition, SymbolKind};

use crate::error::GraphBuildError;
use crate::id::index_of;

use super::fragment::SourceSet;
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
