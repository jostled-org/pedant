//! What a relation cursor is bound to.
//!
//! The shared page contract owns the size, the offset, the traversal, the
//! range, the two revisions, and the refusal a foreign cursor earns. It is
//! handed the fixtures its revision rows need, because only this root knows
//! what a second index of relation records looks like. What is stated here is
//! the drift table over the parameters this operation selects by — the seed,
//! the project, the direction, the edge kinds, the certainties, and the depth —
//! because those are its own and the shared contract does not know them.
//!
//! Every row holds every other dimension equal and replays the cursor at the
//! size it was minted for, so a refusal is explained by the dimension the row
//! names and by nothing else.

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceState, EdgeCertainty, EdgeKind, PageRequest,
    RelationDirection, RelationQuery,
};

use crate::index::harness::indexed;
use crate::queries::answer::Answer;
use crate::queries::paging::{Paged, Revisions, assert_cursor_refused, paged_contract_holds};
use crate::queries::support::{page, search, symbols_page};

use super::fixture::{
    LIBRARY_SOURCE, LIBRARY_UNIT, handle, indexed_graph, other_revision, project, repository,
};
use super::selection::{certainties, everything, kinds};

/// The size every drift row mints its cursor at.
const MINTED_AT: u32 = 1;

/// Every parameter of a relation query binds its cursor.
#[test]
fn relation_pages_bind_every_revision_parameter_and_offset() {
    let (_repository, state) = indexed_graph();
    let base = base_query(&state);

    // A second index of the same records, one declaration longer. The seed is
    // appended after, so the two indexes claim different identities while the
    // seed keeps its position — and a cursor is bound to a seed's position
    // rather than to its revision.
    let (_elsewhere_tree, elsewhere) = other_revision(&state);
    let elsewhere_query = base_query(&elsewhere);
    assert_eq!(
        elsewhere_query.structure.id(),
        base.structure.id(),
        "the seed sits at one position in both, so no query parameter drifted"
    );

    // One index, two healths. The added source states no complete inventory,
    // so neither index holds it and both claim the same identity — while the
    // two callers are told different things.
    let degraded_tree = repository();
    degraded_tree.write("recovered.py", "def broken(:\n    return\n");
    let degraded = indexed(&degraded_tree);
    let degraded_query = base_query(&degraded);

    paged_contract_holds(&Paged {
        label: "query_relations",
        call: |request| relations(&state, &base, request),
        revisions: Revisions::of(&state),
        other: |request| {
            symbols_page(
                &state,
                &search("e", pedant_snippet::MatchMode::Contains),
                request,
            )
        },
        elsewhere: |request| relations(&elsewhere, &elsewhere_query, request),
        elsewhere_revisions: Revisions::of(&elsewhere),
        degraded: |request| relations(&degraded, &degraded_query, request),
        degraded_revisions: Revisions::of(&degraded),
        outruns_default: true,
    });

    every_query_parameter_binds_the_cursor(&state, &base);
}

/// The relation query every row here drifts one dimension of.
fn base_query(state: &CodeIntelligenceState) -> RelationQuery {
    RelationQuery {
        structure: handle(state, LIBRARY_SOURCE, "build"),
        project: None,
        direction: RelationDirection::Outgoing,
        edges: everything(),
        max_depth: 2,
    }
}

/// One page of relations, reduced to what the shared contract reads.
fn relations(
    state: &CodeIntelligenceState,
    query: &RelationQuery,
    request: &PageRequest,
) -> Result<Answer, CodeIntelligenceError> {
    state.query_relations(query, request).map(|response| {
        let next = response.next_page();
        Answer {
            identities: response
                .result()
                .iter()
                .map(|held| format!("{}:{}", held.project().id().position(), held.seed().index()))
                .collect(),
            next,
        }
    })
}

/// Each parameter, drifted alone, refuses the cursor the base query minted.
///
/// One table over all six dimensions. The certainties row used to sit beside
/// the table with its own copy of the mint-and-replay body, which was a second
/// place the replay size and the refusal could drift from the five rows above
/// it — and a dimension answering to a weaker rule than its neighbors is the
/// one this table exists to catch.
///
/// The row count is the array's own length rather than a counter the loop
/// raises. The body states no branch and no `continue`, so a row the table
/// stopped holding fails to compile against the stated width instead of going
/// quiet at run time.
fn every_query_parameter_binds_the_cursor(state: &CodeIntelligenceState, base: &RelationQuery) {
    let drifted: [(&str, RelationQuery); 6] = [
        (
            "seed",
            RelationQuery {
                structure: handle(state, LIBRARY_SOURCE, "make"),
                ..base.clone()
            },
        ),
        (
            "project",
            RelationQuery {
                project: Some(project(state, LIBRARY_UNIT)),
                ..base.clone()
            },
        ),
        (
            "direction",
            RelationQuery {
                direction: RelationDirection::Incoming,
                ..base.clone()
            },
        ),
        (
            "edge kinds",
            RelationQuery {
                edges: kinds(&[EdgeKind::Call]),
                ..base.clone()
            },
        ),
        (
            "certainties",
            RelationQuery {
                edges: certainties(&[EdgeCertainty::Resolved]),
                ..base.clone()
            },
        ),
        (
            "max depth",
            RelationQuery {
                max_depth: base.max_depth + 1,
                ..base.clone()
            },
        ),
    ];
    for (field, other) in drifted {
        let cursor = opened(state, base);
        assert_cursor_refused(
            "query_relations",
            &|request| relations(state, &other, request),
            cursor,
            MINTED_AT,
            &format!("a cursor minted before the {field} changed continues nothing"),
        );
    }
}

/// The cursor one page of `MINTED_AT` items leaves.
fn opened(state: &CodeIntelligenceState, query: &RelationQuery) -> pedant_snippet::PageCursor {
    relations(state, query, &page(Some(MINTED_AT), None))
        .expect("the first page answers")
        .next
        .expect("a page of one leaves a continuation")
}
