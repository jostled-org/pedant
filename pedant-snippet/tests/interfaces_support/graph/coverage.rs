//! What a graph query says when there is no graph to answer from.
//!
//! Never an empty answer. A Python function that calls nothing and a Python
//! function this build resolves no project for produce the same empty
//! neighborhood and state opposite facts, so absence is returned as a typed
//! refusal that names the evidence the entity does have.
//!
//! The two absences are told apart. A source no project slice reached is
//! syntax-only. A source a slice did reach, whose declaration no graph node
//! states, is unavailable.
//!
//! Four of the six languages this build parses resolve no project, and one Cargo
//! package in the repository states a manifest no loader can read. Every one of
//! those refuses here, per language and per failure, because "syntax-only" is a
//! claim about a source rather than a property of one grammar: a build that
//! refused Python honestly and quietly fabricated a graph for TypeScript would
//! pass a row that named Python alone.

use std::collections::BTreeSet;

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceState, PathQuery, RelationDirection, RelationQuery,
    StructureCoverage, StructureHandle,
};

use super::fixture::{
    GO_UNIT, INERT_CONFIGURATIONS, LIBRARY_SOURCE, SYNTAX_ONLY_SOURCES, declaration, handle,
    indexed_graph, other_revision, project, whole_page,
};
use super::selection::everything;

/// A query with no graph behind it refuses, and says which absence it is.
#[test]
fn syntax_only_coverage_refuses_graph_queries_honestly() {
    let (_repository, state) = indexed_graph();

    the_table_names_every_language_without_a_graph_producer(&state);
    every_unresolved_language_states_syntax_only(&state);
    a_failed_project_slice_strands_its_source_without_fabricating_one(&state);
    the_javascript_configurations_state_no_project_and_no_coverage(&state);
    a_path_from_a_syntax_only_declaration_refuses(&state);
    an_unrepresented_rust_declaration_states_unavailable(&state);
    a_project_that_states_no_node_for_the_seed_refuses(&state);
    a_stale_handle_refuses_before_any_graph_is_read(&state);
    an_empty_edge_selection_refuses_before_any_lookup(&state);
}

/// One relation query for one handle, over every edge.
fn relations_for(
    state: &CodeIntelligenceState,
    structure: StructureHandle,
) -> Result<(), CodeIntelligenceError> {
    state
        .query_relations(
            &RelationQuery {
                structure,
                project: None,
                direction: RelationDirection::Outgoing,
                edges: everything(),
                max_depth: 2,
            },
            &whole_page(),
        )
        .map(|_| ())
}

/// The coverage a refusal states, or a panic naming what answered instead.
fn refused_coverage(outcome: Result<(), CodeIntelligenceError>, why: &str) -> StructureCoverage {
    match outcome {
        Err(CodeIntelligenceError::UnavailableCoverage { coverage, .. }) => coverage,
        Err(other) => panic!("{why}: refused for another reason: {other}"),
        Ok(()) => panic!("{why}: answered instead of refusing"),
    }
}

/// The table below names every language this build parses and produces no graph
/// for.
///
/// `SYNTAX_ONLY_SOURCES` is hand-written and the row after this one iterates it,
/// so a language dropped from it is a language this file stops making its claim
/// about while the rows that remain still report green. The set it is held
/// against is the published coverage list and the admitted corpus — neither of
/// which the table writes: every language a source was admitted for, less the
/// ones a graph producer covers.
///
/// A subset rather than an equality. The table carries one row past the
/// uncovered set on purpose, the Rust source under the manifest no loader could
/// read, whose absence is its slice's rather than its language's.
fn the_table_names_every_language_without_a_graph_producer(state: &CodeIntelligenceState) {
    let index = state.index();
    let uncovered: BTreeSet<pedant_types::Language> = index
        .files()
        .iter()
        .map(|file| file.language())
        .filter(|language| !index.graph_coverage().contains(language))
        .collect();
    assert!(
        uncovered.len() > 1,
        "the fixture admits sources in several languages no graph producer covers: {uncovered:?}"
    );
    let named: BTreeSet<pedant_types::Language> = SYNTAX_ONLY_SOURCES
        .iter()
        .map(|(path, name)| declaration(state, path, name).language())
        .collect();
    assert!(
        uncovered.is_subset(&named),
        "and the table states a refusal for each of them: {uncovered:?} against {named:?}"
    );
}

/// Every language this build parses and resolves no project for refuses at the
/// same classification, through both graph operations, and says so in the record
/// a search already hands back.
///
/// One table over every one of them rather than a row per language: a row that
/// aborts on the first panic can only ever show the first language moving, and
/// this claim is about all of them at once.
///
/// The route's far endpoint is resolved once above the table. It is the same
/// declaration for every row, and resolving it inside the loop searched the
/// whole index for one constant answer per language.
fn every_unresolved_language_states_syntax_only(state: &CodeIntelligenceState) {
    let target = handle(state, LIBRARY_SOURCE, "make");
    let stated: Vec<String> = SYNTAX_ONLY_SOURCES
        .iter()
        .map(|(path, name)| {
            let found = declaration(state, path, name);
            let relations = refused_coverage(
                relations_for(state, found.handle()),
                &format!("{path} states no graph"),
            );
            let route = refused_coverage(
                state
                    .find_path(&PathQuery {
                        from: found.handle(),
                        to: target,
                        project: None,
                        edges: everything(),
                    })
                    .map(|_| ()),
                &format!("a route out of {path} states no graph"),
            );
            format!("{path}|{:?}|{:?}|{:?}", found.coverage(), relations, route)
        })
        .collect();
    let required: Vec<String> = SYNTAX_ONLY_SOURCES
        .iter()
        .map(|(path, _)| {
            format!(
                "{path}|{:?}|{:?}|{:?}",
                StructureCoverage::SyntaxOnly,
                StructureCoverage::SyntaxOnly,
                StructureCoverage::SyntaxOnly
            )
        })
        .collect();
    assert_eq!(
        stated, required,
        "no project slice reached any of these sources, so an outline is all any of them has"
    );
}

/// The package whose manifest no loader can read states no slice, records the
/// refusal, and leaves its source navigable and honestly uncovered.
///
/// The absence is the failed slice's rather than the language's: Rust is the
/// language this build resolves projects and builds graphs for, and the same
/// source under a manifest that loaded would answer with a graph.
fn a_failed_project_slice_strands_its_source_without_fabricating_one(
    state: &CodeIntelligenceState,
) {
    let index = state.index();
    assert!(
        !index.projects().is_empty(),
        "the repository resolves the slices this row says one manifest is absent from"
    );
    assert!(
        index
            .projects()
            .iter()
            .all(|slice| slice.key().authority() != "broken/Cargo.toml"),
        "a manifest that did not load states no slice: {:?}",
        index
            .projects()
            .iter()
            .map(|slice| slice.key().authority().to_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        state.issues().iter().any(|issue| {
            issue.scope().name() == "broken/Cargo.toml"
                && issue.stage() == pedant_snippet::IssueStage::Authority
        }),
        "the failure is recorded against the authority that stated it: {:?}",
        state
            .issues()
            .iter()
            .map(|issue| issue.scope().name().to_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        index
            .files()
            .iter()
            .any(|file| file.path() == "broken/src/lib.rs"),
        "while the source it would have compiled is still admitted"
    );
    assert!(
        declaration(state, "broken/src/lib.rs", "stranded")
            .projects()
            .is_empty(),
        "and belongs to no project, which is what its coverage says"
    );
}

/// The two configuration files are present, admitted as nothing, and select no
/// project — so no graph coverage is claimed for the sources beside them.
///
/// The languages this build does cover are named first. "No TypeScript
/// extractor has landed" is a claim about a coverage list, and an empty list
/// states it as readily as the real one — which is the same absence a build
/// that produced no graph at all would report.
fn the_javascript_configurations_state_no_project_and_no_coverage(state: &CodeIntelligenceState) {
    let index = state.index();
    assert!(
        index
            .graph_coverage()
            .contains(&pedant_types::Language::Rust)
            && index.graph_coverage().contains(&pedant_types::Language::Go),
        "this build covers the two languages it has extractors for: {:?}",
        index.graph_coverage()
    );
    assert!(
        !index.projects().is_empty() && !index.files().is_empty(),
        "and it resolved the projects and admitted the sources these rows are about"
    );
    for path in INERT_CONFIGURATIONS {
        assert!(
            index
                .projects()
                .iter()
                .all(|slice| slice.key().authority() != *path),
            "{path} is not a project authority this build recognizes"
        );
        assert!(
            index.files().iter().all(|file| file.path() != *path),
            "{path} is not a source this build admits either"
        );
    }
    assert!(
        !index
            .graph_coverage()
            .contains(&pedant_types::Language::TypeScript),
        "and no TypeScript extractor has landed for either of them to select: {:?}",
        index.graph_coverage()
    );
    assert!(
        !index
            .graph_coverage()
            .contains(&pedant_types::Language::JavaScript),
        "nor a JavaScript one: {:?}",
        index.graph_coverage()
    );
}

/// The same absence stops a path query, at the same classification.
fn a_path_from_a_syntax_only_declaration_refuses(state: &CodeIntelligenceState) {
    let outcome = state
        .find_path(&PathQuery {
            from: handle(state, "tool.py", "build"),
            to: handle(state, LIBRARY_SOURCE, "make"),
            project: None,
            edges: everything(),
        })
        .map(|_| ());
    assert_eq!(
        refused_coverage(outcome, "a syntax-only endpoint states no graph"),
        StructureCoverage::SyntaxOnly,
        "and a route needs a graph to run in"
    );
}

/// A Rust `impl` block sits in a resolved source and states no definition, so
/// the graph holds no node for it: that is unavailable, not syntax-only.
fn an_unrepresented_rust_declaration_states_unavailable(state: &CodeIntelligenceState) {
    let index = state.index();
    let block = index
        .structures()
        .iter()
        .find(|structure| {
            structure.kind() == pedant_types::StructureKind::Impl
                && structure.path() == LIBRARY_SOURCE
        })
        .expect("the library states an impl block");
    let seed = pedant_snippet::StructureHandle::new(index.revision(), block.id().position());
    assert_eq!(
        refused_coverage(
            relations_for(state, seed),
            "an impl block states no definition"
        ),
        StructureCoverage::Unavailable,
        "a resolved source with no node for this declaration is unavailable"
    );
}

/// A declaration that is in one graph and not another refuses for the graph it
/// is not in.
fn a_project_that_states_no_node_for_the_seed_refuses(state: &CodeIntelligenceState) {
    let outcome = state
        .query_relations(
            &RelationQuery {
                structure: handle(state, LIBRARY_SOURCE, "make"),
                project: Some(project(state, GO_UNIT)),
                direction: RelationDirection::Outgoing,
                edges: everything(),
                max_depth: 2,
            },
            &whole_page(),
        )
        .map(|_| ());
    assert_eq!(
        refused_coverage(outcome, "a Go module states no Rust declaration"),
        StructureCoverage::Unavailable,
        "the named graph holds a node for no such declaration"
    );
}

/// A handle from another index refuses before a position is read.
///
/// The other index is over a repository whose library states one more
/// declaration, so the two revisions are demonstrably different before the
/// handle is offered — a foreign handle taken from a byte-identical repository
/// would name the same revision and prove nothing.
fn a_stale_handle_refuses_before_any_graph_is_read(state: &CodeIntelligenceState) {
    let (_elsewhere, foreign) = other_revision(state);
    let stale = handle(&foreign, LIBRARY_SOURCE, "make");
    assert!(
        matches!(
            relations_for(state, stale),
            Err(CodeIntelligenceError::StaleRevision)
        ),
        "a handle another revision issued names nothing here"
    );
}

/// A selection that admits no edge is a question about nothing, and is refused
/// before a handle is even resolved.
fn an_empty_edge_selection_refuses_before_any_lookup(state: &CodeIntelligenceState) {
    let outcome = state.query_relations(
        &RelationQuery {
            structure: handle(state, "tool.py", "build"),
            project: None,
            direction: RelationDirection::Outgoing,
            edges: pedant_snippet::EdgeSelection {
                kinds: Box::new([]),
                certainties: Box::from(super::selection::EVERY_CERTAINTY),
            },
            max_depth: 2,
        },
        &whole_page(),
    );
    assert!(
        matches!(
            outcome,
            Err(CodeIntelligenceError::InvalidQuerySelection { .. })
        ),
        "an empty edge selection refuses ahead of the coverage the seed would state"
    );
}
