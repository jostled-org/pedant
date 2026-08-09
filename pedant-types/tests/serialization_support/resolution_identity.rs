//! External proofs for the branded handle and dense identifier families.

use std::any::TypeId;
use std::mem::needs_drop;

use pedant_types::resolution::{
    DefinitionHandle, DefinitionId, ReferenceHandle, ReferenceId, ResolutionUnitHandle,
    ResolutionUnitId,
};

use crate::resolution_fixture::valid_report;

/// Prove each public name remains a distinct type with its promised ownership.
pub fn assert_distinct_identity_families() {
    assert_copy::<ResolutionUnitId>();
    assert_copy::<DefinitionId>();
    assert_copy::<ReferenceId>();
    assert_clone::<ResolutionUnitHandle>();
    assert_clone::<DefinitionHandle>();
    assert_clone::<ReferenceHandle>();

    assert_distinct::<ResolutionUnitId, DefinitionId>();
    assert_distinct::<ResolutionUnitId, ReferenceId>();
    assert_distinct::<DefinitionId, ReferenceId>();
    assert_distinct::<ResolutionUnitHandle, DefinitionHandle>();
    assert_distinct::<ResolutionUnitHandle, ReferenceHandle>();
    assert_distinct::<DefinitionHandle, ReferenceHandle>();

    assert!(needs_drop::<ResolutionUnitHandle>());
    assert!(needs_drop::<DefinitionHandle>());
    assert!(needs_drop::<ReferenceHandle>());
}

/// Prove every identifier's JSON is byte-for-byte its bare decimal `u32`.
pub fn assert_transparent_identifier_wire_shape() {
    let report = valid_report();
    let unit = report.units()[0].id();
    let definition = report.definitions()[0].id();
    let reference = report.references()[0].id();

    assert_wire_bytes(unit, unit.index());
    assert_wire_bytes(definition, definition.index());
    assert_wire_bytes(reference, reference.index());

    let unit: ResolutionUnitId = serde_json::from_slice(b"7").expect("unit ID decodes from u32");
    let definition: DefinitionId =
        serde_json::from_slice(b"7").expect("definition ID decodes from u32");
    let reference: ReferenceId =
        serde_json::from_slice(b"7").expect("reference ID decodes from u32");
    assert_eq!(
        (unit.index(), definition.index(), reference.index()),
        (7, 7, 7)
    );
}

fn assert_copy<T: Copy>() {}

fn assert_clone<T: Clone>() {}

fn assert_distinct<Left: 'static, Right: 'static>() {
    assert_ne!(TypeId::of::<Left>(), TypeId::of::<Right>());
}

fn assert_wire_bytes(value: impl serde::Serialize, index: u32) {
    let bytes = serde_json::to_vec(&value).expect("identifier serializes");
    assert_eq!(bytes, index.to_string().as_bytes());
}
