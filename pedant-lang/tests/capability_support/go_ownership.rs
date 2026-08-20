//! Who owns the Go grammar, proven from tracked source rather than output.
//!
//! "One inventory answers both consumers" is a claim about ownership: a second
//! walker can produce identical findings today and disagree with the resolver
//! tomorrow. So these cases read this crate's modules, and the one module in
//! `pedant-syntax` the Go dispatch was removed from, instead of their answers.
//!
//! The scan and the module discovery belong to [`ownership`](crate::ownership),
//! which asks the same questions of the same closure; only the Go claims live
//! here.

use std::path::Path;

use crate::ownership::{Closure, discover_closure, member, members_naming};

/// The one module that may build a Go fact inventory.
const GO_BACKEND: &str = "go.rs";

/// The one module that may ask an inventory or a session for a declaration.
const ANCHOR_AUTHORITY: &str = "attribution/anchors.rs";

/// The module that turns those declarations into symbol profiles.
const PROJECTION_MODULE: &str = "attribution/symbols.rs";

/// The exported Go grammar authority.
const FACT_INVENTORY: &str = "GoFileFacts";

/// The one call that builds it.
const FACT_QUERY: &str = "go_file_facts(";

/// The compatibility ceiling capability analysis runs beneath.
const COMPATIBILITY_LIMIT: &str = "GoFactLimits::UNBOUNDED";

/// The bound-parse entry point.
const BOUND_PARSE: &str = "parse_bound(";

/// The batch declaration question, which only the anchor authority may ask.
const ANCHOR_QUERY: &str = "enclosing_unit_anchors(";

/// Grammar and traversal routes a second Go mapper would need.
///
/// Every other structured backend still owns its own grammar, so this claim is
/// scoped to the Go module: what moved is Go, and only Go.
const GO_GRAMMAR_ROUTES: &[&str] = &[
    "import_spec",
    "call_expression",
    "selector_expression",
    "walk_descendants",
    "node_text",
    "child_by_field_name",
    "start_position",
    "BTreeMap",
];

/// Go grammar node kinds the shared declaration recognizer must no longer name.
const REMOVED_FROM_RECOGNIZER: &[&str] = &[
    "type_spec",
    "method_declaration",
    "package_clause",
    "import_spec",
    "selector_expression",
];

/// The shared recognizer, read from the sibling crate that owns it.
///
/// A cross-crate read because the claim is cross-crate: one inventory answers
/// `pedant-lang` and `pedant-core`, and it can only be the sole authority if
/// the generic walk in `pedant-syntax` states no Go declaration either.
fn recognizer_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("pedant-syntax")
        .join("src")
        .join("extract")
        .join("ts.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()))
}

/// 2.T7 (Invariant 1): one exported inventory owns the Go grammar, and neither
/// this crate nor the shared recognizer holds a second mapping.
#[test]
fn go_capability_and_resolution_share_one_fact_authority() {
    let closure = discover_closure();

    assert_eq!(
        &*members_naming(&closure, FACT_INVENTORY),
        &[ANCHOR_AUTHORITY, GO_BACKEND],
        "only the Go backend and the anchor authority may name `{FACT_INVENTORY}`"
    );
    assert_eq!(
        &*members_naming(&closure, FACT_QUERY),
        &[GO_BACKEND],
        "only {GO_BACKEND} may build a Go fact inventory"
    );

    let backend = member(&closure, GO_BACKEND);
    for route in GO_GRAMMAR_ROUTES {
        assert_eq!(
            backend.occurrences(route),
            0,
            "{GO_BACKEND} must map no Go grammar of its own, but names `{route}`"
        );
    }

    let recognizer = recognizer_source();
    for kind in REMOVED_FROM_RECOGNIZER {
        assert!(
            !recognizer.contains(&format!("\"{kind}\"")),
            "the shared declaration recognizer must state no Go grammar, but names `{kind}`"
        );
    }
}

/// 2.T8 (Invariant 2): the capability path parses once, extracts facts once,
/// and every projection borrows that one inventory.
#[test]
fn go_capability_uses_one_parse_and_fact_inventory() {
    let closure = discover_closure();
    let backend = member(&closure, GO_BACKEND);

    assert_eq!(
        backend.occurrences(BOUND_PARSE),
        1,
        "{GO_BACKEND} must bind exactly one parse session"
    );
    assert_eq!(
        backend.occurrences(FACT_QUERY),
        1,
        "{GO_BACKEND} must extract facts exactly once"
    );
    assert_eq!(
        backend.occurrences(COMPATIBILITY_LIMIT),
        1,
        "{GO_BACKEND} must run beneath the one compatibility ceiling"
    );
    assert_eq!(
        backend.occurrences(ANCHOR_QUERY),
        0,
        "{GO_BACKEND} must ask no declaration question itself"
    );

    assert_borrowed_projections(backend);
    assert_anchor_authority_is_sole(&closure);
}

/// Every Go projection reads the inventory the analysis already built.
///
/// A projection taking the inventory by value would be free to build another,
/// so the borrow is the claim: import detection and call detection both receive
/// one `&GoFileFacts` rather than a source to walk again.
fn assert_borrowed_projections(backend: &crate::ownership::Code) {
    let borrowed = format!("facts: &{FACT_INVENTORY}");
    assert!(
        backend.occurrences(&borrowed) >= 2,
        "{GO_BACKEND} must hand the same inventory to import and call detection, \
         got {} borrowing projections",
        backend.occurrences(&borrowed)
    );
}

/// One module asks for declarations, and the projection asks it rather than a
/// parser.
fn assert_anchor_authority_is_sole(closure: &Closure) {
    assert_eq!(
        &*members_naming(closure, ANCHOR_QUERY),
        &[ANCHOR_AUTHORITY],
        "only {ANCHOR_AUTHORITY} may ask for declaration anchors"
    );
    let projection = member(closure, PROJECTION_MODULE);
    assert_eq!(
        projection.occurrences(".anchors("),
        1,
        "{PROJECTION_MODULE} must read anchors through the authority in one place"
    );
    assert_eq!(
        projection.occurrences(BOUND_PARSE),
        0,
        "{PROJECTION_MODULE} must bind no parse session of its own"
    );
}
