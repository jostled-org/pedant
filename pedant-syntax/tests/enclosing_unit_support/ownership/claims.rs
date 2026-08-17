//! Who in this crate may build a parser, and what a bound session may do.
//!
//! It reads the crate's own tracked source rather than its behavior, because
//! "this analysis parsed the source once" is a claim about ownership: a second
//! parse can produce identical output and still be a second parse.
//!
//! The claims live here and the subjects they are asked of live beside them,
//! one sibling each: the discovered module closure, the `mod` resolution that
//! finds it, and the single walk that answers what a parsed source names.

use super::closure::{Member, crate_path, discover_closure, member, parse_rust_file};
use super::scan::{SourceScan, free_function, impl_method};

/// Every production source `lib.rs` owns, written out rather than derived.
///
/// [`discover_closure`] finds the same set independently by resolving `mod`
/// declarations, and the two must agree, so a new or moved module fails here
/// instead of arriving unscanned.
const MODULE_INVENTORY: &[&str] = &[
    "classify.rs",
    "extract/dispatch.rs",
    "extract/index.rs",
    "extract/mod.rs",
    "extract/rust.rs",
    "extract/select.rs",
    "extract/ts.rs",
    "language.rs",
    "lib.rs",
    "location.rs",
    "span.rs",
    "tree_sitter/mod.rs",
    "tree_sitter/parser.rs",
    "tree_sitter/session.rs",
    "tree_sitter/traversal.rs",
    "unit.rs",
];

/// The sole parser owner.
const PARSER_MODULE: &str = "tree_sitter/parser.rs";

/// The sole session owner.
const SESSION_MODULE: &str = "tree_sitter/session.rs";

/// The tree-sitter parser type. Only [`PARSER_MODULE`] may name it.
const PARSER_TYPE: &str = "Parser";

/// The shared declaration recognizer a session delegates to.
const RECOGNIZER: &str = "offer_declarations";

/// The shared checked source index, reached through the one selector route
/// that resolves a whole batch of locations against a single index.
const SELECTOR_ROUTE: &str = "UnitSelector::over";

/// The session method that answers every declaration question at once.
const ANCHOR_METHOD: &str = "enclosing_unit_anchors";

/// The single-location form, which must delegate rather than select again.
const SINGLE_ANCHOR_METHOD: &str = "enclosing_unit_anchor";

/// The two parse entry points a session must not call.
const PARSE_ROUTES: &[&str] = &["parse", "parse_bound"];

/// Ways a body could invent a tree instead of reporting absence.
const FALLBACK_ROUTES: &[&str] = &[
    "unwrap",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "expect",
    "default",
];

/// 4.T2 (Invariants 9 and 17): the production module universe is exactly the
/// hand-written inventory, one module constructs the parser, and the session
/// owner parses nothing and delegates to the shared recognizer and index.
#[test]
fn parsed_syntax_attribution_owner_inventory_is_exact() {
    let discovered = discover_closure();
    assert!(
        !discovered.is_empty(),
        "the production module universe must not be empty"
    );
    let relative: Box<[&str]> = discovered.iter().map(|member| &*member.label).collect();
    assert_eq!(
        &*relative, MODULE_INVENTORY,
        "the discovered module universe must equal the hand-written inventory"
    );

    assert_parser_is_owned_once(&discovered);
    assert_session_parses_nothing(&discovered);
    assert_session_delegates_once(&discovered);
}

/// One module builds parsers, and it builds exactly one.
fn assert_parser_is_owned_once(closure: &[Member]) {
    let naming: Box<[&str]> = closure
        .iter()
        .filter(|member| member.scan.names(PARSER_TYPE))
        .map(|member| member.label.as_ref())
        .collect();
    assert_eq!(
        &*naming,
        &[PARSER_MODULE],
        "only {PARSER_MODULE} may name `{PARSER_TYPE}`"
    );
    assert_eq!(
        member(closure, PARSER_MODULE)
            .scan
            .constructions(PARSER_TYPE),
        1,
        "{PARSER_MODULE} must hold exactly one `{PARSER_TYPE}::new` call"
    );
}

/// The session owner constructs no parser and reaches no parse entry point.
///
/// A free call and a method call are both reaches: `self.inner.parse(...)`
/// lands in `method_calls` and would otherwise pass a free-call count alone.
fn assert_session_parses_nothing(closure: &[Member]) {
    let session = member(closure, SESSION_MODULE);
    assert_eq!(
        session.scan.constructions(PARSER_TYPE),
        0,
        "{SESSION_MODULE} must construct no parser"
    );
    for route in PARSE_ROUTES {
        assert_eq!(
            session.scan.reaches(route),
            0,
            "{SESSION_MODULE} must not reach `{route}`"
        );
    }
}

/// The batch answer runs the shared recognizer and the shared index once, and
/// the single-location answer asks that batch rather than selecting again.
fn assert_session_delegates_once(closure: &[Member]) {
    let file = &member(closure, SESSION_MODULE).file;
    let batch = impl_method(file, ANCHOR_METHOD)
        .unwrap_or_else(|| panic!("{SESSION_MODULE} should declare `{ANCHOR_METHOD}`"));
    let scan = SourceScan::of_block(&batch.block);

    assert_eq!(
        scan.calls(RECOGNIZER),
        1,
        "`{ANCHOR_METHOD}` must offer declarations through `{RECOGNIZER}` exactly once"
    );
    assert_eq!(
        scan.associated_calls(SELECTOR_ROUTE),
        1,
        "`{ANCHOR_METHOD}` must resolve every location through one `{SELECTOR_ROUTE}`"
    );
    assert!(
        scan.reads("tree"),
        "`{ANCHOR_METHOD}` must answer from the bound tree"
    );
    assert!(
        scan.reads("source"),
        "`{ANCHOR_METHOD}` must index the bound source"
    );

    let single = impl_method(file, SINGLE_ANCHOR_METHOD)
        .unwrap_or_else(|| panic!("{SESSION_MODULE} should declare `{SINGLE_ANCHOR_METHOD}`"));
    let single_scan = SourceScan::of_block(&single.block);
    assert_eq!(
        single_scan.method_calls(ANCHOR_METHOD),
        1,
        "`{SINGLE_ANCHOR_METHOD}` must answer through `{ANCHOR_METHOD}` exactly once"
    );
    assert_eq!(
        single_scan.calls(RECOGNIZER),
        0,
        "`{SINGLE_ANCHOR_METHOD}` must recognize no declaration of its own"
    );
    assert_eq!(
        single_scan.associated_calls(SELECTOR_ROUTE),
        0,
        "`{SINGLE_ANCHOR_METHOD}` must resolve no location of its own"
    );
}

/// 4.T7 (Invariant 10): `parse_bound` reports `Parser::parse` absence as `None`
/// and synthesizes no fallback tree.
///
/// A behavioral claim is not available here: production configures no
/// cancellation flag, timeout, or invalid included range, so nothing can force
/// `Parser::parse` to answer `None` deterministically. The ownership boundary
/// is where the propagation is decided, so it is proven where it is written.
#[test]
fn parse_bound_propagates_parser_failure_as_absence() {
    let parser_source = crate_path("src").join(PARSER_MODULE);
    let file = parse_rust_file(&parser_source);

    let bound = free_function(&file, "parse_bound")
        .unwrap_or_else(|| panic!("{PARSER_MODULE} should declare `parse_bound`"));
    let bound_scan = SourceScan::of_block(&bound.block);
    assert_eq!(
        bound_scan.calls("parse"),
        1,
        "`parse_bound` must take the one parse route exactly once"
    );
    assert_eq!(
        bound_scan.try_expressions, 1,
        "`parse_bound` must propagate that route's absence with `?`"
    );
    assert_no_fallback(&bound_scan, "parse_bound");

    let parse = free_function(&file, "parse")
        .unwrap_or_else(|| panic!("{PARSER_MODULE} should declare `parse`"));
    let parse_scan = SourceScan::of_block(&parse.block);
    assert_eq!(
        parse_scan.method_calls("parse"),
        1,
        "`parse` must call `Parser::parse` exactly once"
    );
    assert_no_fallback(&parse_scan, "parse");
}

/// No body on the absence path may invent a value in place of `None`.
fn assert_no_fallback(scan: &SourceScan, label: &str) {
    for route in FALLBACK_ROUTES {
        assert_eq!(
            scan.reaches(route),
            0,
            "`{label}` must not reach for `{route}` in place of absence"
        );
    }
}
