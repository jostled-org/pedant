//! The borrowed reading surface Go name resolution works over.
//!
//! A snapshot answers "which sources exist and which units instantiate them";
//! this joins those answers into the two lookups every later stage needs — the
//! source behind a unit's path, and the package behind an import path — so no
//! stage rebuilds them per reference.

use std::collections::BTreeMap;

use crate::resolution::go::condition::GoBuildCondition;
use crate::resolution::go::snapshot::GoResolutionSnapshot;
use crate::resolution::go::source::GoSource;
use crate::resolution::go::unit::{GoPackageContext, GoResolutionUnit};

/// One snapshot, indexed by the two keys resolution joins on.
pub(super) struct Corpus<'a> {
    snapshot: &'a GoResolutionSnapshot,
    /// Import path to the unit that compiles the package's production context.
    ///
    /// Production alone, because an import names the package a build compiles,
    /// and a test context is never what another package imports.
    packages: BTreeMap<&'a str, usize>,
    sources: BTreeMap<&'a str, &'a GoSource>,
}

impl<'a> Corpus<'a> {
    /// Index one snapshot.
    pub(super) fn of(snapshot: &'a GoResolutionSnapshot) -> Self {
        Self {
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
        }
    }

    /// Every package unit, in snapshot order.
    pub(super) fn units(&self) -> &'a [GoResolutionUnit] {
        self.snapshot.units()
    }

    /// The unit at one snapshot-local position.
    pub(super) fn unit(&self, index: usize) -> Option<&'a GoResolutionUnit> {
        self.snapshot.units().get(index)
    }

    /// The stored source at one repository-relative path.
    pub(super) fn source(&self, path: &str) -> Option<&'a GoSource> {
        self.sources.get(path).copied()
    }

    /// The unit compiling the package one import path names, when the snapshot
    /// holds it.
    pub(super) fn package(&self, import_path: &str) -> Option<usize> {
        self.packages.get(import_path).copied()
    }
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
