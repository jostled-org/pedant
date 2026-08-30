//! What the defaults are, where each ceiling first refuses, and who is charged
//! for a source two project slices share.
//!
//! The two rows about the project seam live in [`owners`](super::owners) and
//! the behavioral capacity proofs beside them.
//! What stays here is what the repository itself decides: the published
//! defaults, the ceilings on the walk and on retention, and the one physical
//! charge two slices reach.

use pedant_snippet::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, CodeIntelligenceLimits,
    CodeIntelligenceState,
};

use super::fixture::Repository;
use super::graphs::graph_ceilings_and_independent_charges_are_exact;
use super::harness::{built, indexed, issue_rows, lowered, paths};
use super::owners::{
    language_and_graph_capacity_owners_remain_typed, project_loader_ceilings_remain_typed_and_fatal,
};
use super::sources::{KEPT, MIXED_REPOSITORY, SECOND};

/// The two clean Python sources every retention row is taken over.
///
/// One list, so the forward and reversed write orders below are the same rows
/// in two orders rather than two hand-written lists nothing compares.
const PAIRED_SOURCES: &[(&str, &str)] = &[KEPT, SECOND];

/// The published defaults, the first-excess refusal of every counter, and one
/// physical charge for a source two slices reach.
///
/// The mixed repository and its index are built once here and lent to every row
/// that reads them unperturbed. Nothing below mutates either, and each rebuild
/// was an eighteen-file tree write and a full graph resolution for an answer
/// already in hand.
#[test]
fn code_intelligence_limits_and_shared_source_accounting_are_exact() {
    let mixed = Repository::of(MIXED_REPOSITORY);
    let state = indexed(&mixed);

    defaults_are_published();
    walk_ceilings_are_fatal(&mixed);
    retention_ceilings_refuse_before_the_first_excess();
    project_loader_ceilings_remain_typed_and_fatal();
    language_and_graph_capacity_owners_remain_typed();
    a_ceiling_refuses_the_same_source_in_either_write_order();
    one_physical_charge_across_two_slices(&state);
    graph_ceilings_and_independent_charges_are_exact(&mixed, &state);
}

/// Every default this contract publishes, spelled out rather than derived.
fn defaults_are_published() {
    let limits = CodeIntelligenceLimits::default();
    let repository = limits.repository;
    assert_eq!(repository.max_directory_entries, 262_144);
    assert_eq!(repository.max_authorities, 4_096);
    assert_eq!(repository.max_files, 65_536);
    assert_eq!(repository.max_source_file_bytes, 8 * 1_024 * 1_024);
    assert_eq!(repository.max_total_source_bytes, 512 * 1_024 * 1_024);
    assert_eq!(repository.max_structures, 1_048_576);
    assert_eq!(repository.max_slices, 16_384);
    assert_eq!(repository.max_graph_nodes, 1_000_000);
    assert_eq!(repository.max_graph_references, 4_000_000);
    assert_eq!(repository.max_graph_edges, 4_000_000);
    assert_eq!(repository.max_page_items, 200);
    assert_eq!(limits.syntax.max_syntax_depth(), 256);
    assert_eq!(limits.syntax.max_structures_per_source(), 262_144);

    #[cfg(feature = "graph-rust")]
    {
        // The graph builder publishes no ceiling of its own. That is the
        // design rather than an omission: the repository allowance above is
        // clamped into every construction, so a second number here could only
        // disagree with it.
        assert_eq!(limits.graph_build.max_nodes(), u32::MAX);
        assert_eq!(limits.graph_build.max_references(), u32::MAX);
        assert_eq!(limits.graph_build.max_edges(), u32::MAX);
        assert_eq!(limits.graph_analysis.max_nodes(), 100_000);
        assert_eq!(limits.graph_analysis.max_selected_edges(), 400_000);
        assert_eq!(limits.graph_analysis.max_depth(), 256);
        assert_eq!(limits.graph_analysis.max_betweenness_work(), 50_000_000);
        assert_eq!(limits.graph_cache.max_source_projections(), 4_096);
        assert_eq!(limits.graph_cache.max_exact_graphs(), 64);
        assert_eq!(limits.graph_cache.max_selected_indexes_per_graph(), 16);
        assert_eq!(limits.graph_cache.max_derived_products_per_graph(), 256);
    }
}

/// A ceiling on the walk itself refuses the whole build, because a walk that
/// stopped early would state a corpus the repository does not have.
fn walk_ceilings_are_fatal(repository: &Repository) {
    let entries = built(
        repository,
        &[],
        lowered(|limits| limits.max_directory_entries = 3),
    )
    .expect_err("a directory-entry ceiling refuses before the walk completes");
    assert_capacity(
        &entries,
        CapacityOwner::Repository,
        CapacityCollection::DirectoryEntry,
        Observed::AboveLimit,
        3,
    );

    let authorities = built(
        repository,
        &[],
        lowered(|limits| limits.max_authorities = 1),
    )
    .expect_err("an authority ceiling refuses before the first excess candidate is opened");
    assert_capacity(
        &authorities,
        CapacityOwner::Repository,
        CapacityCollection::Authority,
        Observed::AboveLimit,
        1,
    );

    let slices = built(repository, &[], lowered(|limits| limits.max_slices = 1))
        .expect_err("a slice ceiling refuses before the index retains the first excess slice");
    assert_capacity(
        &slices,
        CapacityOwner::Repository,
        CapacityCollection::Slice,
        Observed::AboveLimit,
        1,
    );
}

/// A ceiling on a retained record refuses that record, records the refusal, and
/// leaves everything the ceiling still admits.
fn retention_ceilings_refuse_before_the_first_excess() {
    let repository = Repository::of(PAIRED_SOURCES);

    let files = built(&repository, &[], lowered(|limits| limits.max_files = 1))
        .expect("a file ceiling degrades the corpus rather than ending the build");
    assert_eq!(
        &*paths(&files),
        [KEPT.0],
        "the ceiling admits its first file and refuses the next"
    );
    assert_eq!(
        &*issue_rows(&files),
        [format!("file:{}|source|capacity_refused|false", SECOND.0)],
        "and the refusal is recorded against the source that was refused, and nothing else is"
    );

    let bytes = built(
        &repository,
        &[],
        lowered(|limits| limits.max_source_file_bytes = 4),
    )
    .expect("a per-file ceiling degrades the corpus");
    assert!(
        paths(&bytes).is_empty(),
        "no source under a four-byte ceiling is retained: {:?}",
        paths(&bytes)
    );
    assert_eq!(
        &*issue_rows(&bytes),
        [
            format!("file:{}|source|capacity_refused|false", KEPT.0),
            format!("file:{}|source|capacity_refused|false", SECOND.0),
        ],
        "both refusals are recorded, each naming its own source"
    );

    let total = built(
        &repository,
        &[],
        lowered(|limits| limits.max_total_source_bytes = 25),
    )
    .expect("a total-byte ceiling degrades the corpus");
    assert_eq!(
        &*paths(&total),
        [KEPT.0],
        "the total ceiling admits what fits and refuses the byte that would pass it"
    );

    a_structure_ceiling_admits_one_whole_inventory(&repository);
}

/// A structure ceiling admits the sources whose whole inventories fit and
/// refuses the one that would pass it.
///
/// The ceiling is the whole inventory of the first source, and that inventory
/// is stated here rather than counted out of the subject. A count read back
/// from the index is a count the index agrees with by construction: a syntax
/// owner that started reporting something else for `def a(): return 1` would
/// re-derive its own ceiling and stay green.
fn a_structure_ceiling_admits_one_whole_inventory(repository: &Repository) {
    let admitted = indexed(repository);
    let stated: Box<[(String, Option<&str>)]> = admitted
        .index()
        .file_structures(admitted.index().file(KEPT.0).expect("the first source"))
        .iter()
        .map(|structure| (format!("{:?}", structure.kind()), structure.name()))
        .collect();
    assert_eq!(
        *stated,
        [
            ("Module".to_owned(), None),
            ("Function".to_owned(), Some("a")),
        ],
        "the fixture source states the module every Python file is and the one function it declares"
    );
    let first = stated.len();

    let structures = built(
        repository,
        &[],
        lowered(|limits| limits.max_structures = first as u32),
    )
    .expect("a structure ceiling degrades the corpus");
    assert_eq!(
        structures.index().structures().len(),
        first,
        "the index retains what the ceiling admits and refuses the source that would pass it"
    );
    assert_eq!(
        &*paths(&structures),
        [KEPT.0],
        "a source whose inventory would pass the ceiling is not admitted at all"
    );
    assert_eq!(
        &*issue_rows(&structures),
        [format!(
            "file:{}|inventory|capacity_refused|false",
            SECOND.0
        )],
        "and the refusal is recorded against the source whose inventory would have passed it, \
         at the stage that recognizes one"
    );
}

/// Which source a ceiling refuses is decided by the corpus, not by the order
/// the repository was written in.
///
/// The only handle a test has on enumeration order is the order the tree was
/// created in, so both orders are written and the same source is refused in
/// each. A walk that admitted in enumeration order would refuse `a.py` in one
/// of them.
fn a_ceiling_refuses_the_same_source_in_either_write_order() {
    let forwards = Repository::of(PAIRED_SOURCES);
    let backwards = Repository::of_reversed(PAIRED_SOURCES);

    for repository in [&forwards, &backwards] {
        let files = built(repository, &[], lowered(|limits| limits.max_files = 1))
            .expect("a file ceiling degrades the corpus rather than ending the build");
        assert_eq!(
            &*paths(&files),
            [KEPT.0],
            "the ceiling admits the first source in normalized path order"
        );
    }
    assert_eq!(
        indexed(&forwards).index().revision(),
        indexed(&backwards).index().revision(),
        "and the whole corpus states one identity in either order"
    );
}

/// One physical source two slices reach is one admitted record, and both slices
/// still state that they reached it.
fn one_physical_charge_across_two_slices(state: &CodeIntelligenceState) {
    let shared = "crate-a/src/lib.rs";
    assert_eq!(
        paths(state).iter().filter(|path| *path == shared).count(),
        1,
        "the repository holds one copy of the shared source, so the index holds one record"
    );

    let reaching: Box<[&str]> = state
        .index()
        .projects()
        .iter()
        .filter(|project| project.sources().iter().any(|source| &**source == shared))
        .map(|project| project.key().unit())
        .collect();
    assert_eq!(
        *reaching,
        ["crate-a::bin::crate-a", "crate-a::lib::crate_a"],
        "both slices selected it, and each states its own corpus"
    );

    let structures = state
        .index()
        .structures()
        .iter()
        .filter(|structure| structure.path() == shared)
        .count();
    assert!(
        structures > 0,
        "the shared source states its structures once"
    );
    assert_eq!(
        state
            .index()
            .file_structures(state.index().file(shared).expect("the shared record"))
            .len(),
        structures,
        "and the file record reaches exactly those"
    );
}

/// What a row states about the count a refusal names.
///
/// The one dimension the capacity rows differ in. A ceiling set to zero or one
/// refuses the first record, so the count is a number the row can write down; a
/// ceiling reached part-way through a walk is not, and the honest claim there
/// is that the refusal names a count the ceiling would not have admitted.
#[derive(Clone, Copy, Debug)]
pub(super) enum Observed {
    /// The exact count the refusal must name.
    Exactly(u64),
    /// Some count above the ceiling, where the walk that reached it fixes none.
    AboveLimit,
}

impl Observed {
    /// Whether one refusal's count is the count this row states.
    fn admits(self, observed: u64, limit: u64) -> bool {
        match self {
            Self::Exactly(count) => observed == count,
            Self::AboveLimit => observed > limit,
        }
    }
}

/// One refusal, held to its owner, its collection, its ceiling, and the count
/// it names.
///
/// Published to the index tree rather than kept here: [`owners`](super::owners)
/// makes ten claims through it, and [`graphs`](super::graphs) held a
/// hand-written twin that differed from it only in the wording of its panic.
///
/// One guard rather than a fixed-count one beside a bounded-count one. The
/// difference was never the assertion but how much of the count the row could
/// state, and the weaker of the two also wrote its owner into its body, so it
/// could never be given a third.
pub(super) fn assert_capacity(
    error: &CodeIntelligenceError,
    expected_owner: CapacityOwner,
    expected_collection: CapacityCollection,
    expected_observed: Observed,
    expected_limit: u64,
) {
    match error {
        CodeIntelligenceError::Capacity {
            owner,
            collection,
            observed,
            limit,
        } => {
            assert_eq!(
                (*owner, *collection, *limit),
                (expected_owner, expected_collection, expected_limit),
                "{error}"
            );
            assert!(
                expected_observed.admits(*observed, *limit),
                "a refusal names {expected_observed:?} for the count that would have passed \
                 the ceiling: {error}"
            );
        }
        other => panic!("expected a {expected_collection} capacity refusal, got {other}"),
    }
}
