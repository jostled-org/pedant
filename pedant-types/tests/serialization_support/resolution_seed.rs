//! One builder holding exactly one unit, one definition, and one reference.
//!
//! The handle and capacity cases need a builder whose every local index is
//! zero, so a handle passed to the wrong builder still names a valid record
//! there. That is a different fixture from the report the schema cases mutate,
//! and it lives apart from it.

use std::sync::Arc;

use pedant_types::Language;
use pedant_types::resolution::{
    DefinitionHandle, ReferenceHandle, ReferenceKind, ResolutionReportBuilder,
    ResolutionReportLimits, ResolutionTier, ResolutionUnitHandle, SymbolKind,
};

use crate::resolution_fixture::{UNIT_A_KEY, span};

/// A builder plus the handles it issued at local index zero.
pub struct SeededBuilder {
    /// The builder itself, holding one unit, one definition, one reference.
    pub builder: ResolutionReportBuilder,
    /// The unit handle at local index zero.
    pub unit: ResolutionUnitHandle,
    /// The definition handle at local index zero.
    pub definition: DefinitionHandle,
    /// The reference handle at local index zero.
    pub reference: ReferenceHandle,
}

/// A builder holding exactly one unit, one definition, and one reference, each
/// at local index zero, under the supplied limits.
pub fn seeded_builder(limits: ResolutionReportLimits) -> SeededBuilder {
    let mut builder = ResolutionReportBuilder::new(ResolutionTier::Syntactic, limits);
    let unit = builder
        .add_unit(Language::Rust, Arc::from(UNIT_A_KEY), Arc::from("alpha"))
        .expect("the first unit is admitted");
    let definition = builder
        .add_definition(
            &unit,
            SymbolKind::Module,
            Arc::from("alpha"),
            span("a/src/lib.rs", 0, 0, 1),
            None,
        )
        .expect("the first definition is admitted");
    let reference = builder
        .add_reference(
            &unit,
            ReferenceKind::Import,
            Arc::from("std::fmt"),
            span("a/src/lib.rs", 1, 4, 12),
            None,
        )
        .expect("the first reference is admitted");
    SeededBuilder {
        builder,
        unit,
        definition,
        reference,
    }
}
