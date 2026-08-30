//! The unit table one snapshot builds beneath its own ceiling.
//!
//! Split from the snapshot it produces: the snapshot is a sealed value a
//! consumer reads, and this is the growing state that produces it. Keeping them
//! apart leaves exactly one body that grows the table, which is what makes the
//! ceiling stated there dominate every unit a snapshot holds.

use crate::resolution::capacity::admits_one_more;
use crate::resolution::supply::SourceSupply;

use super::discovery::GoPackageDirectory;
use super::fault::GoSourceFault;
use super::inventory::GoFileInventory;
use super::limits::GoResolutionLimits;
use super::packages::{PackageSite, UnitDraft, directory_units};
use super::snapshot_error::GoSnapshotError;
use super::store::GoSourceStore;

/// The unit table one snapshot builds, and the ceiling it grows beneath.
///
/// The drafts are private. A sibling that could push onto them directly would
/// bypass the one ceiling check below, which is the whole invariant this module
/// claims, and the only reader wants the finished table rather than the growing
/// one.
pub(super) struct UnitTable {
    limits: GoResolutionLimits,
    drafts: Vec<UnitDraft>,
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
    pub(super) fn retain_module<P: SourceSupply<GoFileInventory, GoSourceFault>>(
        &mut self,
        store: &mut GoSourceStore,
        provider: &mut P,
        site: &PackageSite<'_>,
        directories: &[GoPackageDirectory],
    ) -> Result<(), GoSnapshotError> {
        for directory in directories.iter() {
            self.retain_directory(store, provider, site, directory)?;
        }
        Ok(())
    }

    /// Retain every unit one directory states.
    fn retain_directory<P: SourceSupply<GoFileInventory, GoSourceFault>>(
        &mut self,
        store: &mut GoSourceStore,
        provider: &mut P,
        site: &PackageSite<'_>,
        directory: &GoPackageDirectory,
    ) -> Result<(), GoSnapshotError> {
        for draft in directory_units(store, provider, site, directory)?.into_vec() {
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

    /// Every retained unit, in the order the walk found them.
    ///
    /// Consuming, because the table stops growing where the snapshot starts
    /// sealing: a caller that could read the drafts and keep the table would be
    /// holding a table it may still add to behind a snapshot that already
    /// counted them.
    pub(super) fn finish(self) -> Vec<UnitDraft> {
        self.drafts
    }
}

/// One more package unit must still fit under the configured ceiling.
fn check_unit_capacity(held: usize, limits: GoResolutionLimits) -> Result<(), GoSnapshotError> {
    match admits_one_more(held, limits.max_units) {
        true => Ok(()),
        false => Err(GoSnapshotError::UnitLimitExceeded {
            limit: limits.max_units,
        }),
    }
}
