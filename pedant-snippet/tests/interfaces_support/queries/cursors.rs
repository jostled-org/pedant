//! What a symbol-search page cursor is bound to, one parameter at a time.
//!
//! The two revisions are not stated here. Neither is a parameter this operation
//! selects by, so both belong to the shared contract; what this root supplies is
//! the fixtures — a second index of its own records, and one index told two
//! different things.

use pedant_snippet::{CodeIntelligenceState, MatchMode, PageRequest, SymbolQuery};
use pedant_types::{Language, StructureKind};

use super::paging::{
    Paged, Revisions, assert_cursor_refused, opening_cursor, paged_contract_holds,
};
use super::support::{SEARCH_LABEL, degraded_mixed, mixed, projects_page, search, symbols_page};
use crate::index::fixture::Repository;
use crate::index::harness::indexed;

/// Two named structures, so a page of one always leaves a continuation.
const PAIR: (&str, &str) = (
    "a.py",
    "def a():\n    return 1\n\n\ndef b():\n    return 2\n",
);

/// The size every drift row mints its cursor at, and replays it at.
///
/// One page, so a cursor is always left behind, and one page again on the
/// replay: a cursor replayed at another size would drift for two reasons at
/// once, and the size is a dimension the shared contract owns.
const MINTED_AT: u32 = 1;

/// A search cursor traverses every match once and continues nothing it was not
/// minted for.
#[test]
fn paged_navigation_cursors_bind_state_query_and_offset() {
    let (_repository, state) = mixed();
    let base = search("", MatchMode::Contains);

    // A repository sharing no source with the mixed one, so its index is
    // another index, and it states enough symbols to leave a continuation.
    let pair_tree = Repository::of(&[PAIR]);
    let elsewhere = indexed(&pair_tree);
    let (_degraded_tree, degraded) = degraded_mixed();

    paged_contract_holds(&Paged {
        label: SEARCH_LABEL,
        call: |request| symbols_page(&state, &base, request),
        revisions: Revisions::of(&state),
        other: |request| projects_page(&state, request),
        elsewhere: |request| symbols_page(&elsewhere, &base, request),
        elsewhere_revisions: Revisions::of(&elsewhere),
        degraded: |request| symbols_page(&degraded, &base, request),
        degraded_revisions: Revisions::of(&degraded),
        // The mixed repository declares more named structures than one default
        // page holds, so the shared contract's default-cursor continuation row
        // is taken here rather than owed elsewhere. The contract checks this
        // against the result it took, so a fixture that fell under fifty fails
        // rather than going quiet.
        outruns_default: true,
    });

    every_query_parameter_binds_its_cursor(&state, &base);
}

/// Changing any search parameter invalidates a cursor minted under the old one.
///
/// "Any" is proved rather than counted. The destructure below names every field
/// of a [`SymbolQuery`], so a seventh parameter stops this file compiling; the
/// array it fills then outruns the table until that parameter has a drift row of
/// its own. Each entry also states that the base holds its parameter at the
/// widest setting, which is what makes every row differ from the base by exactly
/// the one it names — a base that already filtered by language would let the
/// language row refuse for a reason it does not claim.
fn every_query_parameter_binds_its_cursor(state: &CodeIntelligenceState, base: &SymbolQuery) {
    let parameters = assert_base_is_the_widest_search(base);
    let cursor = opening_cursor(
        SEARCH_LABEL,
        &|request| symbols_page(state, base, request),
        MINTED_AT,
    );
    let drifted = drifted_queries(base);
    assert_eq!(
        drifted.len(),
        parameters,
        "{SEARCH_LABEL}: one drift row per parameter a symbol query selects by"
    );

    for (parameter, query) in &*drifted {
        let drifted_call = |request: &PageRequest| symbols_page(state, query, request);
        assert_cursor_refused(
            SEARCH_LABEL,
            &drifted_call,
            cursor,
            MINTED_AT,
            &format!("a cursor minted before the {parameter} changed"),
        );
    }
}

/// The base holds every parameter at its widest setting, and how many there are.
///
/// The destructure names every field of a [`SymbolQuery`], so a seventh
/// parameter stops this file compiling. The count it returns is what the drift
/// table is then held to, so a parameter added without a row of its own fails
/// rather than going unexercised.
fn assert_base_is_the_widest_search(base: &SymbolQuery) -> usize {
    let SymbolQuery {
        text,
        mode,
        language,
        kind,
        owner_name,
        path_prefix,
    } = base;
    let widest = [
        text.is_empty(),
        *mode == MatchMode::Contains,
        language.is_none(),
        kind.is_none(),
        owner_name.is_none(),
        path_prefix.is_none(),
    ];
    assert!(
        widest.iter().all(|held| *held),
        "{SEARCH_LABEL}: the base is the unfiltered contains search every row below drifts from"
    );
    widest.len()
}

/// One query per parameter, each differing from the base by that one alone.
fn drifted_queries(base: &SymbolQuery) -> Box<[(&'static str, SymbolQuery)]> {
    Box::new([
        (
            "query text",
            SymbolQuery {
                text: Box::from("Job"),
                ..base.clone()
            },
        ),
        (
            "match mode",
            SymbolQuery {
                mode: MatchMode::Prefix,
                ..base.clone()
            },
        ),
        (
            "language filter",
            SymbolQuery {
                language: Some(Language::Rust),
                ..base.clone()
            },
        ),
        (
            "kind filter",
            SymbolQuery {
                kind: Some(StructureKind::Struct),
                ..base.clone()
            },
        ),
        (
            "owner-name filter",
            SymbolQuery {
                owner_name: Some(Box::from("Job")),
                ..base.clone()
            },
        ),
        (
            "path-prefix filter",
            SymbolQuery {
                path_prefix: Some(Box::from("web")),
                ..base.clone()
            },
        ),
    ])
}
