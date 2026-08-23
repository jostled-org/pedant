//! The borrowed reading surface Go name resolution works over.
//!
//! A snapshot answers "which sources exist and which units instantiate them";
//! this joins those answers into the lookups every later stage needs — the
//! source behind a unit's path, the names that source's imports bind, and the
//! package behind an import path — so no stage rebuilds them per reference.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::resolution::go::condition::GoBuildCondition;
use crate::resolution::go::snapshot::GoResolutionSnapshot;
use crate::resolution::go::source::GoSource;
use crate::resolution::go::unit::{GoPackageContext, GoResolutionUnit};

use super::error::GoResolutionError;
use super::imports::FileImports;

/// One source of one package context, joined to everything a stage reads it
/// through.
///
/// The import table travels beside the source because it is file-scoped and
/// every stage that walks a source needs it: the definition pass resolves
/// embedded types through it, the signature pass canonicalizes terms through
/// it, and the reference pass classifies qualifiers through it.
#[derive(Clone, Copy)]
pub(super) struct UnitSource<'a> {
    /// The repository-relative path the unit names.
    pub(super) path: &'a Arc<str>,
    /// The stored source at that path.
    pub(super) source: &'a GoSource,
    /// The names that source's own import specifications bind.
    pub(super) imports: &'a FileImports<'a>,
}

/// One snapshot, indexed by the keys resolution joins on.
pub(super) struct Corpus<'a> {
    snapshot: &'a GoResolutionSnapshot,
    /// Import path to the unit that compiles the package's production context.
    ///
    /// Production alone, because an import names the package a build compiles,
    /// and a test context is never what another package imports.
    packages: BTreeMap<&'a str, usize>,
    sources: BTreeMap<&'a str, &'a GoSource>,
    /// One import table per stored source, read once for every stage that
    /// joins on one. Every input it needs is here, and three passes over one
    /// source would otherwise build the same table three times.
    imports: BTreeMap<&'a str, FileImports<'a>>,
}

impl<'a> Corpus<'a> {
    /// Index one snapshot.
    pub(super) fn of(snapshot: &'a GoResolutionSnapshot) -> Self {
        let mut corpus = Self {
            snapshot,
            packages: snapshot
                .units()
                .iter()
                .enumerate()
                .filter(|(_, unit)| unit.context() == GoPackageContext::Production)
                .map(|(index, unit)| (unit.import_path(), index))
                .collect(),
            sources: snapshot
                .sources()
                .iter()
                .map(|source| (source.path(), source))
                .collect(),
            imports: BTreeMap::new(),
        };
        corpus.imports = read_imports(&corpus);
        corpus
    }

    /// Every package unit, in snapshot order.
    pub(super) fn units(&self) -> &'a [GoResolutionUnit] {
        self.snapshot.units()
    }

    /// The unit at one snapshot-local position.
    pub(super) fn unit(&self, index: usize) -> Option<&'a GoResolutionUnit> {
        self.snapshot.units().get(index)
    }

    /// The unit compiling the package one import path names, when the snapshot
    /// holds it.
    pub(super) fn package(&self, import_path: &str) -> Option<usize> {
        self.packages.get(import_path).copied()
    }

    /// Every source one package context instantiates, in the order it names
    /// them.
    ///
    /// A named source the snapshot does not hold refuses here rather than being
    /// passed over. Every declaration, signature, and reference that source
    /// states would otherwise leave the report with nothing said, while the
    /// package clause of the same unit already refuses for the identical
    /// condition.
    pub(super) fn sources_of<'held>(
        &'held self,
        unit: &'held GoResolutionUnit,
    ) -> Result<Box<[UnitSource<'held>]>, GoResolutionError> {
        unit.sources()
            .iter()
            .map(|path| self.held(unit, path))
            .collect()
    }

    /// One named source of one package context, refused when the snapshot does
    /// not hold it.
    fn held<'held>(
        &'held self,
        unit: &GoResolutionUnit,
        path: &'held Arc<str>,
    ) -> Result<UnitSource<'held>, GoResolutionError> {
        let stated = self
            .sources
            .get(&**path)
            .copied()
            .zip(self.imports.get(&**path));
        let (source, imports) = stated.ok_or_else(|| GoResolutionError::UnitMapping {
            unit: unit.id().index(),
            reason: Box::from("a source of this package context is not held by the snapshot"),
        })?;
        Ok(UnitSource {
            path,
            source,
            imports,
        })
    }
}

/// One import table per stored source, built once against the package table.
fn read_imports<'a>(corpus: &Corpus<'a>) -> BTreeMap<&'a str, FileImports<'a>> {
    corpus
        .sources
        .iter()
        .map(|(path, source)| (*path, FileImports::of(corpus, source.facts())))
        .collect()
}

/// Whether an unevaluated build predicate governs one source.
///
/// The test predicate is not one of them. A package context is exactly the
/// build a test source is compiled by, so the unit the source sits in has
/// already answered it; the remaining predicates name a host this tier never
/// learns, so they stay unevaluated and make every candidate possible.
pub(super) fn conditional(source: &GoSource) -> bool {
    source
        .conditions()
        .iter()
        .any(|condition| !matches!(condition, GoBuildCondition::TestContext))
}
