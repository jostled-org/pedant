//! The published Rust report's exact bytes.
//!
//! Split from the malformed table beside it for the source-file budget alone,
//! the way `resolution_asserts` sits beside `resolution_cases`. Every case
//! there states one mutation of this document, so its shape is already the
//! contract they are read against; here the document is a published claim in
//! its own right — a language added to the shared vocabulary must leave the
//! Rust encoding, its field order, and its enum tokens byte for byte where they
//! were.

use pedant_types::resolution::ResolutionReport;

use crate::resolution_fixture::valid_report;

/// The exact bytes the retained Rust fixture report serializes to.
pub const LEGACY_RUST_REPORT_JSON: &str = concat!(
    r#"{"tier":"syntactic","#,
    r#""units":[{"id":0,"language":"rust","key":"a/Cargo.toml#lib:alpha","name":"alpha"},"#,
    r#"{"id":1,"language":"rust","key":"b/Cargo.toml#lib:beta","name":"beta"}],"#,
    r#""definitions":[{"id":0,"unit":0,"language":"rust","kind":"module","name":"alpha","#,
    r#""span":{"file":"a/src/lib.rs","start":{"line":0,"column":0},"end":{"line":0,"column":1}},"#,
    r#""parent":null},"#,
    r#"{"id":1,"unit":0,"language":"rust","kind":"function","name":"run","#,
    r#""span":{"file":"a/src/lib.rs","start":{"line":2,"column":4},"end":{"line":2,"column":20}},"#,
    r#""parent":0},"#,
    r#"{"id":2,"unit":1,"language":"rust","kind":"function","name":"helper","#,
    r#""span":{"file":"b/src/lib.rs","start":{"line":1,"column":0},"end":{"line":1,"column":18}},"#,
    r#""parent":null}],"#,
    r#""references":[{"id":0,"unit":0,"language":"rust","kind":"import","text":"std::fmt","#,
    r#""span":{"file":"a/src/lib.rs","start":{"line":1,"column":4},"end":{"line":1,"column":12}},"#,
    r#""enclosing_definition":null},"#,
    r#"{"id":1,"unit":0,"language":"rust","kind":"call","text":"beta::helper","#,
    r#""span":{"file":"a/src/lib.rs","start":{"line":3,"column":8},"end":{"line":3,"column":22}},"#,
    r#""enclosing_definition":1}],"#,
    r#""resolutions":[{"reference":0,"candidates":[],"gaps":["external_definition"]},"#,
    r#"{"reference":1,"candidates":[{"definition":2,"certainty":"resolved"}],"gaps":[]}]}"#,
);

/// The definition and reference tokens no Rust report may ever carry.
const GO_ONLY_TOKENS: &[&str] = &[
    "\"kind\":\"package\"",
    "\"kind\":\"interface\"",
    "\"kind\":\"defined_type\"",
    "\"kind\":\"variable\"",
    "\"kind\":\"field\"",
    "\"kind\":\"value\"",
];

/// The published Rust report keeps its exact bytes, tokens, and record order,
/// and still decodes through the same validator.
pub fn assert_legacy_rust_report_bytes_stay_exact() {
    let encoded = serde_json::to_string(&valid_report()).expect("the fixture report serializes");
    assert_eq!(
        encoded, LEGACY_RUST_REPORT_JSON,
        "the published Rust report's bytes changed"
    );

    let restored: ResolutionReport = serde_json::from_str(LEGACY_RUST_REPORT_JSON)
        .expect("the published bytes survive the validator");
    assert_eq!(
        restored,
        valid_report(),
        "the published bytes decode to the report they were taken from"
    );

    for token in GO_ONLY_TOKENS {
        assert!(
            !encoded.contains(token),
            "a Rust report may not carry {token}: {encoded}"
        );
    }
}
