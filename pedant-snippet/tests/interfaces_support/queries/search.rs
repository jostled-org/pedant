//! Which named structures a search states, and in which order.

use pedant_snippet::{CodeIntelligenceError, CodeIntelligenceState, MatchMode, SymbolQuery};
use pedant_types::{Language, StructureKind, StructureSpan};

use super::paging::{CEILING, whole_result};
use super::support::{
    SEARCH_LABEL, first_page, mixed, page, search, symbols_page, the_envelope_round_trips,
};

/// Every mode and filter returns all and only what it names, in one order.
#[test]
fn symbol_search_modes_filters_and_order_are_exact() {
    let (_repository, state) = mixed();

    every_mode_states_its_own_matches(&state);
    every_filter_narrows_and_narrows_only(&state);
    matching_is_case_sensitive(&state);
    an_unmatched_query_is_an_empty_success(&state);
    the_order_is_path_extent_kind_then_name(&state);
    only_named_structures_are_symbols(&state);
    an_unnormalized_path_prefix_refuses(&state);
    the_paged_search_envelope_round_trips(&state);
}

/// The one navigation answer that is both paged and a list of structures
/// survives its wire form, cursor included.
///
/// The page is deliberately smaller than the result, so the envelope under test
/// carries a continuation. `next_page` is the one field a whole answer never
/// states, and a cursor that did not survive the wire would strand every caller
/// on the first page.
fn the_paged_search_envelope_round_trips(state: &CodeIntelligenceState) {
    let response = state
        .search_symbols(&search("", MatchMode::Contains), &page(Some(1), None))
        .expect("a page of one answers");
    assert!(
        response.next_page().is_some(),
        "a page of one over the mixed fixture leaves a continuation to round trip"
    );
    the_envelope_round_trips(&response);
}

/// Every structure named `Job`, wherever the repository declares one.
///
/// Six sites in five files: a Rust struct, a Go struct, the embedded Go field
/// that names it, and a class in each of Python, JavaScript, and TypeScript.
/// Spelled out rather than counted, because the claim is that a search states
/// all of them and nothing else.
const EVERY_JOB: &[&str] = &[
    "crate-a/src/lib.rs::inner::Job",
    "main.go::Job",
    "main.go::Special::Job",
    "scripts/tool.py::Job",
    "web/app.js::Job",
    "web/app.ts::Job",
];

/// Exact, prefix, and contains each select what they name and nothing else.
fn every_mode_states_its_own_matches(state: &CodeIntelligenceState) {
    assert_eq!(
        &*found(state, &search("Job", MatchMode::Exact)),
        EVERY_JOB,
        "an exact search states every structure declared under that name"
    );
    assert_eq!(
        &*found(state, &search("Jo", MatchMode::Prefix)),
        EVERY_JOB,
        "a prefix search states every name that opens with it"
    );
    assert_eq!(
        &*found(state, &search("ob", MatchMode::Contains)),
        EVERY_JOB,
        "a contains search states every name that holds it anywhere"
    );
    assert!(
        found(state, &search("Jo", MatchMode::Exact)).is_empty(),
        "an exact search is not a prefix search"
    );
    assert!(
        found(state, &search("ob", MatchMode::Prefix)).is_empty(),
        "a prefix search is not a contains search"
    );
}

/// Each filter removes exactly the rows it excludes and no others.
fn every_filter_narrows_and_narrows_only(state: &CodeIntelligenceState) {
    let rows: &[(&str, SymbolQuery, &[&str])] = &[
        (
            "language",
            SymbolQuery {
                language: Some(Language::Go),
                ..search("Job", MatchMode::Exact)
            },
            &["main.go::Job", "main.go::Special::Job"],
        ),
        (
            "kind",
            SymbolQuery {
                kind: Some(StructureKind::Struct),
                ..search("Job", MatchMode::Exact)
            },
            &["crate-a/src/lib.rs::inner::Job", "main.go::Job"],
        ),
        (
            "owner name",
            SymbolQuery {
                owner_name: Some(Box::from("Special")),
                ..search("Job", MatchMode::Exact)
            },
            &["main.go::Special::Job"],
        ),
        (
            "path prefix",
            SymbolQuery {
                path_prefix: Some(Box::from("web")),
                ..search("Job", MatchMode::Exact)
            },
            &["web/app.js::Job", "web/app.ts::Job"],
        ),
        (
            "every filter at once",
            SymbolQuery {
                language: Some(Language::TypeScript),
                kind: Some(StructureKind::Class),
                path_prefix: Some(Box::from("web/app.ts")),
                ..search("Job", MatchMode::Exact)
            },
            &["web/app.ts::Job"],
        ),
        (
            "a filter no row satisfies",
            SymbolQuery {
                language: Some(Language::Bash),
                ..search("Job", MatchMode::Exact)
            },
            &[],
        ),
    ];

    for (label, query, expected) in rows {
        assert_eq!(&*found(state, query), *expected, "{label}");
    }

    // The owner filter names the nearest *named* owner, which is why a Rust
    // method inside an unnamed impl block answers to the module above it.
    assert_eq!(
        &*found(
            state,
            &SymbolQuery {
                owner_name: Some(Box::from("Run")),
                ..search("run", MatchMode::Exact)
            }
        ),
        ["crate-a/src/lib.rs::inner::Run::run"],
        "a trait method is owned by the trait that declares it"
    );
}

/// Every supported language has case-sensitive identifiers, so search does too.
fn matching_is_case_sensitive(state: &CodeIntelligenceState) {
    for spelling in ["job", "JOB", "jOB"] {
        assert!(
            found(state, &search(spelling, MatchMode::Exact)).is_empty(),
            "{spelling} is not the name the sources declare"
        );
        assert!(
            found(state, &search(spelling, MatchMode::Contains)).is_empty(),
            "{spelling} is not held by any declared name"
        );
    }
}

/// A query nothing matches succeeds and states nothing.
fn an_unmatched_query_is_an_empty_success(state: &CodeIntelligenceState) {
    let response = state
        .search_symbols(&search("Absent", MatchMode::Exact), &first_page())
        .expect("a query nothing matches is an answer, not a failure");
    assert!(response.result().is_empty(), "and it states no structure");
    assert!(
        response.next_page().is_none(),
        "an empty result has no continuation"
    );
    assert_eq!(response.state_revision(), state.revision());
    assert_eq!(response.health(), state.health());
}

/// Results sort by path, then extent, then kind, then name.
fn the_order_is_path_extent_kind_then_name(state: &CodeIntelligenceState) {
    let response = state
        .search_symbols(&search("", MatchMode::Contains), &page(Some(CEILING), None))
        .expect("an unfiltered contains search answers");
    let matched = response.result();
    assert!(
        matched.len() > 20,
        "the mixed repository states a corpus worth ordering: {}",
        matched.len()
    );

    let keys: Box<[(&str, StructureSpan, StructureKind, &str)]> = matched
        .iter()
        .map(|structure| {
            (
                structure.path(),
                structure.span(),
                structure.kind(),
                structure.name().unwrap_or_default(),
            )
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys, sorted,
        "results sort by normalized path, start byte, end byte, kind, then name"
    );
}

/// A structure its grammar leaves unnamed is not a symbol.
fn only_named_structures_are_symbols(state: &CodeIntelligenceState) {
    let unnamed = state
        .index()
        .structures()
        .iter()
        .filter(|structure| structure.name().is_none())
        .count();
    assert!(
        unnamed > 0,
        "the fixture declares an unnamed structure — the Rust impl blocks"
    );

    let response = state
        .search_symbols(&search("", MatchMode::Contains), &page(Some(CEILING), None))
        .expect("an unfiltered contains search answers");
    assert!(
        response
            .result()
            .iter()
            .all(|structure| structure.name().is_some()),
        "an unnamed structure has no name to match, so no search states it"
    );
    assert_eq!(
        response.result().len() + unnamed,
        state.index().structures().len(),
        "and every named structure is stated"
    );
}

/// A path prefix that is not a repository spelling refuses before any lookup.
fn an_unnormalized_path_prefix_refuses(state: &CodeIntelligenceState) {
    for spelling in ["/web", "../web", "web/..", ""] {
        let query = SymbolQuery {
            path_prefix: Some(Box::from(spelling)),
            ..search("Job", MatchMode::Exact)
        };
        match state.search_symbols(&query, &first_page()) {
            Err(CodeIntelligenceError::PathEscape { path }) => assert_eq!(&*path, spelling),
            Ok(answer) => panic!(
                "{spelling} is not a path prefix, but stated {} rows",
                answer.result().len()
            ),
            Err(other) => panic!("{spelling} refuses as an unnormalized path, not: {other}"),
        }
    }
}

/// Every qualified name one query states, in the order it states them.
///
/// Taken through the shared whole-result helper rather than through a maximum
/// page of its own. That helper already refuses a result the maximum page cuts
/// short, and a second copy of that refusal here was a second place the claim
/// "this is every match" could be weakened for one root and not the other.
fn found(state: &CodeIntelligenceState, query: &SymbolQuery) -> Box<[String]> {
    whole_result(SEARCH_LABEL, &|request| symbols_page(state, query, request))
}
