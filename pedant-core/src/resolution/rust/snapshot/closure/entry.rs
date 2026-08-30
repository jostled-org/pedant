//! The Cargo target input that starts one module-closure walk.

use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::target::RustTarget;

/// The Cargo target one closure starts from.
pub(in crate::resolution::rust::snapshot) struct ClosureEntry<'a> {
    pub(in crate::resolution::rust::snapshot) target_name: &'a str,
    pub(in crate::resolution::rust::snapshot) entry_path: &'a str,
    pub(in crate::resolution::rust::snapshot) edition: CargoEdition,
}

impl<'target> ClosureEntry<'target> {
    /// The three fields of a Cargo target that open its closure.
    ///
    /// Stated here, so which fields of a target start a walk is one answer
    /// rather than one per snapshot shape that takes one. The multi-unit
    /// snapshot starts from a selected unit rather than a target and builds its
    /// own, which is why the fields stay reachable beside this.
    pub(in crate::resolution::rust::snapshot) fn of_target(target: &'target RustTarget) -> Self {
        Self {
            target_name: target.name(),
            entry_path: target.entry_path(),
            edition: target.edition(),
        }
    }
}
