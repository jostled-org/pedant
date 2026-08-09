//! The Cargo target input that starts one module-closure walk.

use crate::resolution::rust::edition::CargoEdition;

/// The Cargo target one closure starts from.
pub(in crate::resolution::rust::snapshot) struct ClosureEntry<'a> {
    pub(in crate::resolution::rust::snapshot) target_name: &'a str,
    pub(in crate::resolution::rust::snapshot) entry_path: &'a str,
    pub(in crate::resolution::rust::snapshot) edition: CargoEdition,
}
