//! Deliberately restated unit bindings for downstream join refusals.
//!
//! `RustTargetResolution::try_new` binds every report unit by its stable key,
//! so the joins a graph consumer must still refuse have no other construction
//! path. Each adapter here restates only the bindings; the validated report and
//! the retained snapshot identity are the ones the real resolver produced.
//!
//! An adapter answers `None` when the resolution it is handed binds too few
//! units to perturb. Returning that resolution unchanged would hand a consumer
//! a valid value under a name that promises a malformed one, and the refusal
//! the caller was proving would never be reached.

use crate::resolution::rust::resolve::{RustTargetResolution, RustUnitBinding};
use crate::resolution::rust::snapshot::RustSnapshotUnitId;

/// The same validated result with one report unit's binding removed.
///
/// `None` when the resolution binds no unit, because there is then no binding
/// to drop.
pub fn resolution_without_unit_binding(
    resolution: &RustTargetResolution,
) -> Option<RustTargetResolution> {
    let bound = resolution.units().len().checked_sub(1)?;
    let units: Box<[RustUnitBinding]> = resolution.units().iter().copied().take(bound).collect();
    Some(resolution.with_unit_bindings(units))
}

/// The same validated result with its first two unit bindings pointed at each
/// other's snapshot units.
///
/// Every site those units state then names a source the bound unit does not
/// instantiate, which is the join a consumer must refuse rather than skip.
/// `None` when the resolution binds fewer than two units.
pub fn resolution_with_swapped_unit_sources(
    resolution: &RustTargetResolution,
) -> Option<RustTargetResolution> {
    let (first, second) = leading_snapshot_units(resolution.units())?;
    let mut units: Vec<RustUnitBinding> = resolution.units().to_vec();
    units[0] = units[0].rebound(second);
    units[1] = units[1].rebound(first);
    Some(resolution.with_unit_bindings(units.into_boxed_slice()))
}

/// The same validated result with its first two report units bound to one
/// snapshot unit.
///
/// Two report units then claim ownership of one unit-qualified source, which a
/// consumer building a containment forest must refuse. `None` when the
/// resolution binds fewer than two units.
pub fn resolution_with_shared_unit_binding(
    resolution: &RustTargetResolution,
) -> Option<RustTargetResolution> {
    let (first, _) = leading_snapshot_units(resolution.units())?;
    let mut units: Vec<RustUnitBinding> = resolution.units().to_vec();
    units[1] = units[1].rebound(first);
    Some(resolution.with_unit_bindings(units.into_boxed_slice()))
}

/// The snapshot units the first two bindings select, when both exist.
fn leading_snapshot_units(
    units: &[RustUnitBinding],
) -> Option<(RustSnapshotUnitId, RustSnapshotUnitId)> {
    match units {
        [first, second, ..] => Some((first.snapshot_unit(), second.snapshot_unit())),
        _ => None,
    }
}
