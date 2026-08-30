//! The repository's graph ceilings, and the charges a project owner keeps to
//! itself.
//!
//! Graph records are retained records like any other, so the repository bounds
//! them across every slice at once — a ceiling one project could exhaust by
//! splitting its graph across two would bound nothing. The ceiling is clamped
//! into each construction rather than measured after it, which is what makes
//! "before the first excess record" checkable: at exactly the count the
//! repository retains, every slice still resolves; one below it, a slice
//! refuses and the index retains no more than the ceiling allowed.

use pedant_snippet::{
    CapacityCollection, CapacityOwner, CodeIntelligenceState, IssueCode, IssueStage,
    RepositoryLimits,
};

use super::accounting::{Observed, assert_capacity};
use super::fixture::Repository;
use super::harness::{adjusted, built, issue_rows, lowered, paths, project_keys};
use super::sources::MIXED_SOURCES;

/// How many graph records one index retained across every slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Retained {
    nodes: u32,
    references: u32,
    edges: u32,
}

/// One repository-wide graph ceiling, and the count it bounds.
struct Ceiling {
    token: &'static str,
    collection: CapacityCollection,
    write: fn(&mut RepositoryLimits, u32),
    read: fn(Retained) -> u32,
}

impl Ceiling {
    /// How many of the records this ceiling bounds one index retained.
    ///
    /// A ceiling and the count it bounds are one statement: a row that named a
    /// limit field but read another counter would compare two different numbers
    /// and still go green.
    fn counted(&self, retained: Retained) -> u32 {
        (self.read)(retained)
    }
}

/// Every repository-wide graph ceiling, one row each.
///
/// A fixed array rather than a slice, so the arity is in the type: a walk over
/// a slice reports success on no rows at all, and the three ceilings this
/// module is about are the three the repository publishes.
const GRAPH_CEILINGS: [Ceiling; 3] = [
    Ceiling {
        token: "repository.max_graph_nodes",
        collection: CapacityCollection::GraphNode,
        write: |limits, value| limits.max_graph_nodes = value,
        read: |retained| retained.nodes,
    },
    Ceiling {
        token: "repository.max_graph_references",
        collection: CapacityCollection::GraphReference,
        write: |limits, value| limits.max_graph_references = value,
        read: |retained| retained.references,
    },
    Ceiling {
        token: "repository.max_graph_edges",
        collection: CapacityCollection::GraphEdge,
        write: |limits, value| limits.max_graph_edges = value,
        read: |retained| retained.edges,
    },
];

/// Every graph ceiling refuses before the first excess record, and a project
/// owner's own ceilings are charged apart from the repository's.
///
/// The unperturbed repository and its index are supplied rather than built
/// here: no row below mutates either, and three helpers each writing an
/// eighteen-file tree and resolving its graphs paid for the same answer three
/// times.
pub fn graph_ceilings_and_independent_charges_are_exact(
    repository: &Repository,
    base: &CodeIntelligenceState,
) {
    graph_ceilings_refuse_before_the_first_excess(repository, base);
    a_shared_source_is_charged_to_the_repository_once(repository, base);
    an_owner_ceiling_is_charged_apart_from_the_repository(repository, base);
}

/// At the count it retains, every slice resolves; one below it, a slice
/// refuses and nothing past the ceiling is retained.
fn graph_ceilings_refuse_before_the_first_excess(
    repository: &Repository,
    base: &CodeIntelligenceState,
) {
    let base_records = records(base);
    assert!(
        base_records.nodes > 1 && base_records.references > 1 && base_records.edges > 1,
        "the mixed repository resolves graphs to bound: {base_records:?}"
    );

    for ceiling in GRAPH_CEILINGS {
        let count = ceiling.counted(base_records);
        let exact = built(
            repository,
            &[],
            lowered(|limits| (ceiling.write)(limits, count)),
        )
        .unwrap_or_else(|error| panic!("{}: {error}", ceiling.token));
        assert_eq!(
            project_keys(&exact),
            project_keys(base),
            "{}: a ceiling at exactly what the repository retains admits every slice",
            ceiling.token
        );
        assert_eq!(
            records(&exact),
            base_records,
            "{}: and retains exactly the same graph records",
            ceiling.token
        );
        assert!(
            !refused_graphs(&exact),
            "{}: nothing refused at the exact ceiling",
            ceiling.token
        );

        let short = built(
            repository,
            &[],
            lowered(|limits| (ceiling.write)(limits, count - 1)),
        )
        .expect_err("a repository graph ceiling is a fatal global capacity refusal");
        // The repository owns every graph ceiling, and the counts are the
        // global first excess. That is the same four-field claim every other
        // capacity row makes, so it is made through the same guard rather than
        // through a twin that differed only in the wording of its panic.
        assert_capacity(
            &short,
            CapacityOwner::Repository,
            ceiling.collection,
            Observed::Exactly(u64::from(count)),
            u64::from(count - 1),
        );
    }
}

/// One physical source two slices reach is charged to the repository once.
///
/// The ceiling is the observer. Set to exactly the bytes the index retains,
/// every source is still admitted — which cannot hold if a source reached by
/// two project slices were charged twice. One byte below it, something is
/// refused, so the ceiling is not merely generous.
fn a_shared_source_is_charged_to_the_repository_once(
    repository: &Repository,
    base: &CodeIntelligenceState,
) {
    let admitted: u64 = base
        .index()
        .files()
        .iter()
        .map(|file| file.text().len() as u64)
        .sum();
    assert!(admitted > 0, "the mixed repository retains source text");

    let exact = built(
        repository,
        &[],
        lowered(|limits| limits.max_total_source_bytes = admitted),
    )
    .expect("a total-byte ceiling at the retained total admits the whole corpus");
    assert_eq!(
        &*paths(&exact),
        MIXED_SOURCES,
        "one physical charge per source, however many slices reached it"
    );
    assert_eq!(
        project_keys(&exact),
        project_keys(base),
        "and every project still resolved beneath it"
    );

    let short = built(
        repository,
        &[],
        lowered(|limits| limits.max_total_source_bytes = admitted - 1),
    )
    .expect("a total-byte ceiling degrades the corpus rather than ending the build");
    assert!(
        paths(&short).len() < MIXED_SOURCES.len(),
        "one byte below the retained total refuses a source: {:?}",
        paths(&short)
    );
}

/// A project owner's ceiling refuses that owner's snapshot and charges nothing
/// to the repository's own counters.
///
/// The two counters measure different things on purpose: the repository counts
/// each physical record once, and an owner counts the corpus its own snapshot
/// selected — which includes every source it reached, whether or not the store
/// had already read it for someone else.
fn an_owner_ceiling_is_charged_apart_from_the_repository(
    repository: &Repository,
    base: &CodeIntelligenceState,
) {
    // The library target's snapshot selects one source; the binary's selects
    // two, its own and the library it links. The repository holds those two
    // physical files once between them, which is why an owner ceiling of two
    // admits every slice and one refuses exactly the snapshot that needed both.
    let admitted = owner_bounded(repository, 2);
    assert_eq!(
        project_keys(&admitted),
        project_keys(base),
        "an owner ceiling at what its widest snapshot selects admits every slice"
    );
    assert!(
        admitted.issues().is_empty(),
        "and refuses nothing: {:?}",
        issue_rows(&admitted)
    );

    let refused = owner_bounded(repository, 1);
    assert_eq!(
        &*paths(&refused),
        MIXED_SOURCES,
        "one below it the repository still admits every physical source"
    );
    assert_eq!(
        &*project_keys(&refused),
        [
            "Rust|Cargo.toml|crate-a::lib::crate_a",
            "Go|go.mod|example.com/main",
            "Go|nested/go.mod|example.com/nested",
        ],
        "while the one snapshot that selected two sources refuses and its owner's other slice stands"
    );
    // The whole issue list rather than a predicate over it. An `all` beside
    // this row restated the stage and the code the row already spells, and it
    // is the weaker half of the pair: a predicate over a set holds of the empty
    // set, so it can only ever agree with an exact inventory that already ran.
    assert_eq!(
        &*issue_rows(&refused),
        ["project:Cargo.toml|snapshot|snapshot_refused|false"],
        "recorded against the stage that refused, and nothing charged to the repository's own \
         counters"
    );
}

/// The mixed repository indexed with only the Rust owner's source ceiling
/// lowered.
fn owner_bounded(repository: &Repository, ceiling: u32) -> CodeIntelligenceState {
    built(
        repository,
        &[],
        adjusted(|limits| limits.rust.max_source_files = ceiling),
    )
    .expect("an owner ceiling degrades its own project, not the build")
}

/// How many graph records one state's slices retained in total.
fn records(state: &CodeIntelligenceState) -> Retained {
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    state.index().projects().iter().fold(
        Retained {
            nodes: 0,
            references: 0,
            edges: 0,
        },
        |total, project| Retained {
            nodes: total.nodes + count(project.graph().nodes().len()),
            references: total.references + count(project.graph().references().len()),
            edges: total.edges + count(project.graph().edges().len()),
        },
    )
}

/// Whether any project refused at the graph stage.
fn refused_graphs(state: &CodeIntelligenceState) -> bool {
    state
        .issues()
        .iter()
        .any(|issue| issue.stage() == IssueStage::Graph && issue.code() == IssueCode::GraphRefused)
}
