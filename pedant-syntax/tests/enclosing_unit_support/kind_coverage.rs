//! Every declaration kind the boundary model declares is produced by some
//! backend's table.
//!
//! The per-backend tables prove what each grammar recognizes. This proves the
//! union of them covers [`SourceUnitKind`], so a variant added to the model
//! without a backend that extracts it fails here rather than shipping as a kind
//! nothing returns.

use pedant_syntax::SourceUnitKind;

use crate::fixtures::ALL_KINDS;

#[test]
fn every_kind_is_extracted_by_some_backend() {
    let extracted: Box<[SourceUnitKind]> = crate::rust::ROWS
        .iter()
        .chain(crate::python::ROWS.iter())
        .chain(crate::javascript::ROWS.iter())
        .chain(crate::typescript::ROWS.iter())
        .chain(crate::typescript::TSX_ROWS.iter())
        .chain(crate::go::ROWS.iter())
        .chain(crate::bash::ROWS.iter())
        .map(|row| row.kind)
        .collect();

    for kind in ALL_KINDS {
        assert!(
            extracted.contains(&kind),
            "{kind:?} is a declaration kind no backend table extracts"
        );
    }
}
