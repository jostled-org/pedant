//! Inputs a completion proof must refuse.
//!
//! Each row states one defect and the phrase the refusal owes. A validator that
//! accepted absent evidence — no HEAD, no package set, no summary, a receipt
//! path it did not own — would let a run certify nothing, so every row here is
//! a way that could happen.

use crate::receipt_fixture::Fixture;

/// One defective input set.
pub(crate) struct InputCase {
    /// What this row is called when it fails.
    pub(crate) label: &'static str,
    /// The single defect it introduces.
    pub(crate) defect: fn(&mut Fixture),
    /// A phrase the refusal must name, so a generic error cannot stand in.
    pub(crate) names: &'static str,
}

pub(crate) const INPUT_CASES: &[InputCase] = &[
    InputCase {
        label: "absent HEAD",
        defect: |fixture| fixture.inputs.head_sha = "".into(),
        names: "head_sha",
    },
    InputCase {
        label: "abbreviated HEAD",
        defect: |fixture| fixture.inputs.head_sha = "0123456".into(),
        names: "head_sha",
    },
    InputCase {
        label: "HEAD that is not hexadecimal",
        defect: |fixture| fixture.inputs.head_sha = "z".repeat(40).into(),
        names: "head_sha",
    },
    InputCase {
        label: "empty package set",
        defect: |fixture| fixture.inputs.test_scope = Vec::new().into_boxed_slice(),
        names: "test_scope",
    },
    InputCase {
        label: "repeated package",
        defect: |fixture| {
            fixture.inputs.test_scope =
                Box::from([Box::from("pedant-core"), Box::from("pedant-core")]);
        },
        names: "test_scope",
    },
    InputCase {
        label: "absent terminal summary",
        defect: |fixture| fixture.inputs.terminal_summary = "   ".into(),
        names: "terminal_summary",
    },
    InputCase {
        label: "root that is not canonical",
        defect: |fixture| fixture.inputs.root = fixture.inputs.root.join("pedant-mcp/.."),
        names: "canonical",
    },
    InputCase {
        label: "root that holds no manifest",
        defect: |fixture| fixture.inputs.root = fixture.dir(),
        names: "Cargo.toml",
    },
    InputCase {
        label: "absent runner directory",
        defect: |fixture| fixture.inputs.proof_output_dir = fixture.dir().join("absent"),
        names: "PROOF_OUTPUT_DIR",
    },
    InputCase {
        label: "receipt path outside the runner directory",
        defect: |fixture| fixture.inputs.receipt_path = fixture.inputs.root.join("receipt.json"),
        names: "beneath",
    },
    InputCase {
        label: "receipt path that already holds a document",
        defect: |fixture| {
            std::fs::write(&fixture.inputs.receipt_path, "{}")
                .expect("the stale receipt should be writable");
        },
        names: "already exists",
    },
];

/// Refuse the defective inputs, and name the field that was wrong.
pub(crate) fn assert_input_case_is_rejected(case: &InputCase) {
    let mut fixture = Fixture::valid();
    (case.defect)(&mut fixture);
    let error = fixture
        .inputs
        .validate()
        .expect_err(case.label)
        .to_lowercase();
    assert!(
        error.contains(&case.names.to_lowercase()),
        "{}: the refusal {error:?} does not name {:?}",
        case.label,
        case.names
    );
}
