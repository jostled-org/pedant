//! Written receipts that disagree with the inputs that produced them.
//!
//! The journey writes the document, so only a reader holding it to the runner's
//! stated identity can catch a receipt about another tree, another commit, or
//! an index that answered nothing.

use serde_json::{Value, json};

use crate::receipt::{self};
use crate::receipt_fixture::Fixture;

/// One receipt document that disagrees with the inputs that produced it.
pub(crate) struct DocumentCase {
    /// What this row is called when it fails.
    pub(crate) label: &'static str,
    /// The single edit it makes to the written document.
    pub(crate) edit: fn(&mut Value),
    /// A phrase the refusal must name.
    pub(crate) names: &'static str,
}

pub(crate) const DOCUMENT_CASES: &[DocumentCase] = &[
    DocumentCase {
        label: "unknown schema version",
        edit: |document| document["receipt_version"] = json!(2),
        names: "version",
    },
    DocumentCase {
        label: "absent HEAD field",
        edit: |document| drop_field(document, "head_sha"),
        names: "head_sha",
    },
    DocumentCase {
        label: "absent query list",
        edit: |document| drop_field(document, "queries"),
        names: "queries",
    },
    DocumentCase {
        label: "another repository's root",
        edit: |document| document["root"] = json!("/somewhere/else"),
        names: "root",
    },
    DocumentCase {
        label: "another commit",
        edit: |document| document["head_sha"] = json!("f".repeat(40)),
        names: "head_sha",
    },
    DocumentCase {
        label: "another summary",
        edit: |document| document["terminal_summary"] = json!("everything passed"),
        names: "terminal_summary",
    },
    DocumentCase {
        label: "another package set",
        edit: |document| document["test_scope"] = json!(["pedant-core"]),
        names: "test_scope",
    },
    DocumentCase {
        label: "a typed query that was never asked",
        edit: |document| truncate_queries(document),
        names: "typed queries",
    },
    DocumentCase {
        label: "typed queries in another order",
        edit: |document| reverse_queries(document),
        names: "typed queries",
    },
    DocumentCase {
        label: "an index that answered nothing at all",
        edit: |document| zero_every_result(document),
        names: "empty result",
    },
];

fn zero_every_result(document: &mut Value) {
    for query in query_list(document) {
        query["results"] = json!(0);
    }
}

fn drop_field(document: &mut Value, field: &str) {
    document
        .as_object_mut()
        .expect("the receipt is a JSON object")
        .remove(field);
}

fn truncate_queries(document: &mut Value) {
    let queries = query_list(document);
    queries.pop();
}

fn reverse_queries(document: &mut Value) {
    query_list(document).reverse();
}

fn query_list(document: &mut Value) -> &mut Vec<Value> {
    document["queries"]
        .as_array_mut()
        .expect("the receipt carries a query list")
}

/// Write a valid receipt, damage it one way, and require the stated refusal.
pub(crate) fn assert_document_case_is_rejected(case: &DocumentCase) {
    let fixture = Fixture::valid();
    fixture.write_receipt().expect(case.label);
    let path = &fixture.inputs.receipt_path;
    let raw = std::fs::read_to_string(path).expect(case.label);
    let mut document: Value = serde_json::from_str(&raw).expect(case.label);
    (case.edit)(&mut document);
    std::fs::write(path, document.to_string()).expect(case.label);

    let error = receipt::validate(&fixture.inputs)
        .expect_err(case.label)
        .to_lowercase();
    assert!(
        error.contains(&case.names.to_lowercase()),
        "{}: the refusal {error:?} does not name {:?}",
        case.label,
        case.names
    );
}
