//! Every configured graph and analysis ceiling, proved through the consumed
//! owners' own typed refusals.
//!
//! Each row lowers one ceiling below the corpus's exact count, requires the
//! refusal before any verdict is evaluated, then requires the equality boundary
//! to succeed.

use crate::fixture::{boundary_field, simple_project};

/// One ceiling, the exact count the corpus needs, and the refusal it states.
struct CeilingRow {
    field: &'static str,
    exact: u32,
    refusal: &'static str,
}

/// The `simple_project` corpus counts, measured through the production owners.
const CEILING_ROWS: &[CeilingRow] = &[
    CeilingRow {
        field: "max-nodes",
        exact: 8,
        refusal: "the node collection cannot exceed",
    },
    CeilingRow {
        field: "max-references",
        exact: 3,
        refusal: "the reference collection cannot exceed",
    },
    CeilingRow {
        field: "max-edges",
        exact: 3,
        refusal: "the edge collection cannot exceed",
    },
    CeilingRow {
        field: "max-selected-edges",
        exact: 3,
        refusal: "the selection admits",
    },
];

/// Every configured ceiling refuses before a verdict is evaluated, and the
/// equality boundary succeeds.
pub(crate) fn applies_every_resource_ceiling_before_verdicts() {
    for row in CEILING_ROWS {
        let fixture = simple_project();
        fixture.write(
            ".pedant.toml",
            &boundary_field(row.field, &(row.exact - 1).to_string()),
        );
        let refused = fixture.project_gate(&[]);
        assert_eq!(
            refused.code(),
            Some(2),
            "{}: one below the exact count must refuse: {}",
            row.field,
            refused.transcript()
        );
        assert!(
            refused.stderr.contains(row.refusal),
            "{}: the consumed owner's typed refusal reaches stderr: {}",
            row.field,
            refused.stderr
        );
        assert!(
            refused.stdout.is_empty(),
            "{}: a refusal emits no verdict or success payload: {}",
            row.field,
            refused.stdout
        );

        fixture.write(
            ".pedant.toml",
            &boundary_field(row.field, &row.exact.to_string()),
        );
        let admitted = fixture.project_gate(&[]);
        assert!(
            admitted.success(),
            "{}: the equality boundary must succeed: {}",
            row.field,
            admitted.transcript()
        );
    }
}
