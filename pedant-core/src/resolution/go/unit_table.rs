//! The unit table one snapshot builds beneath its own ceiling.
//!
//! Split from the snapshot it produces: the snapshot is a sealed value a
//! consumer reads, and this is the growing state that produces it. Keeping them
//! apart leaves exactly one body that grows the table, which is what makes the
//! ceiling stated there dominate every unit a snapshot holds.

use super::discovery::GoPackageDirectory;
use super::limits::GoResolutionLimits;
use super::packages::{PackageSite, UnitDraft, directory_units};
use super::snapshot_error::GoSnapshotError;
use super::store::GoSourceStore;

/// The unit table one snapshot builds, and the ceiling it grows beneath.
pub(super) struct UnitTable {
    limits: GoResolutionLimits,
    pub(super) drafts: Vec<UnitDraft>,
}

impl UnitTable {
    /// An empty table bounded by one snapshot's ceilings.
    pub(super) fn new(limits: GoResolutionLimits) -> Self {
        Self {
            limits,
            drafts: Vec::new(),
        }
    }

    /// Retain every unit one module's package directories state.
    pub(super) fn retain_module(
        &mut self,
        store: &mut GoSourceStore,
        site: &PackageSite<'_>,
        directories: &[GoPackageDirectory],
    ) -> Result<(), GoSnapshotError> {
        for directory in directories.iter() {
            self.retain_directory(store, site, directory)?;
        }
        Ok(())
    }

    /// Retain every unit one directory states.
    fn retain_directory(
        &mut self,
        store: &mut GoSourceStore,
        site: &PackageSite<'_>,
        directory: &GoPackageDirectory,
    ) -> Result<(), GoSnapshotError> {
        for draft in directory_units(store, site, directory)?.into_vec() {
            self.retain_unit(draft)?;
        }
        Ok(())
    }

    /// Retain one unit, checking the ceiling before the insertion.
    ///
    /// The one body that grows the unit table, so the ceiling stated here
    /// dominates every unit a snapshot ever holds.
    fn retain_unit(&mut self, draft: UnitDraft) -> Result<(), GoSnapshotError> {
        check_unit_capacity(self.drafts.len(), self.limits)?;
        self.drafts.push(draft);
        Ok(())
    }
}

/// One more package unit must still fit under the configured ceiling.
fn check_unit_capacity(held: usize, limits: GoResolutionLimits) -> Result<(), GoSnapshotError> {
    let ceiling = usize::try_from(limits.max_units).unwrap_or(usize::MAX);
    match held.saturating_add(1) > ceiling {
        true => Err(GoSnapshotError::UnitLimitExceeded {
            limit: limits.max_units,
        }),
        false => Ok(()),
    }
}
