//! Structural resolution states one answer per corpus, whatever order the
//! corpus was written in.
//!
//! Implementation is a whole-corpus comparison, so it is the stage with the
//! most room to inherit an enumeration order: which type is compared first,
//! which interface answers first, which implementor a dispatch names first. A
//! report whose bytes moved with the order the fixture happened to be written
//! in would make every other claim here unrepeatable.

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionLimits};
use pedant_types::ResolutionRecord;

use crate::resolution::fixture::FixtureFile;
use crate::resolution::go::fixture::resolve;
use crate::resolution::go::resolution_interface_fixtures::{DISPATCH, INTERFACES};
use crate::resolution::go::resolution_views::kind_answers;
use crate::resolution::go::views::borrowed;

/// The relations whose concrete type a build predicate governs.
///
/// Read as a whole list rather than as a count: a resolver that stopped
/// conditioning its relations would state this row resolved, and one that
/// conditioned every relation would state the rest of the corpus's rows here
/// too.
const CONDITIONED: &[&str] = &[
    "Implementation|Tuned|plat_linux.go:2|possible|Named@shape/shape.go:8|ConditionalCompilation",
];

/// 10.T5 (Invariants 19, 21): equal corpora state equal report bytes whatever
/// order they were enumerated in, and every conditioned relation stays
/// possible.
#[test]
fn go_interface_resolution_is_order_independent() {
    let forward: Box<[FixtureFile]> = INTERFACES.iter().copied().collect();
    let mut backward = forward.to_vec();
    backward.reverse();
    assert_eq!(
        report_bytes(&forward),
        report_bytes(&backward),
        "equal project bytes state equal report bytes whatever order the tree was written in"
    );

    assert_conditioned_relations_stay_possible();
    assert_candidate_identities_are_sorted();
}

/// Every relation stated from a conditioned source is possible and says which
/// family of predicate kept it so.
fn assert_conditioned_relations_stay_possible() {
    let (tree, snapshot, resolution) = resolve(INTERFACES, GoResolutionLimits::default());
    let resolution =
        resolution.unwrap_or_else(|error| panic!("the fixture should resolve: {error}"));
    let conditioned: Box<[Box<str>]> = kind_answers(&resolution, "Implementation")
        .iter()
        .filter(|row| row.contains("ConditionalCompilation"))
        .cloned()
        .collect();
    assert_eq!(
        &*borrowed(&conditioned),
        CONDITIONED,
        "a relation a build predicate governs stays possible"
    );
    drop(resolution);
    drop(snapshot);
    drop(tree);
}

/// Every record names its candidates at strictly ascending identifiers,
/// whichever order the corpus was compared in.
///
/// Both corpora are read, because a dispatch collects its targets from every
/// implementor the comparison found while the rest of the report collects
/// candidates from lookup, and a sorted identity claim that skipped either
/// would leave one collector free to publish the order it happened to walk in.
fn assert_candidate_identities_are_sorted() {
    for files in [INTERFACES, DISPATCH] {
        let (tree, snapshot, resolution) = resolve(files, GoResolutionLimits::default());
        let resolution =
            resolution.unwrap_or_else(|error| panic!("the fixture should resolve: {error}"));
        let unsorted = descending_records(&resolution);
        assert_eq!(
            &*borrowed(&unsorted),
            &[] as &[&str],
            "every record names its candidates at ascending identifiers"
        );
        drop(resolution);
        drop(snapshot);
        drop(tree);
    }
}

/// Every reference whose record names candidates out of order or twice.
fn descending_records(resolution: &GoProjectResolution) -> Box<[Box<str>]> {
    let report = resolution.report();
    report
        .references()
        .iter()
        .zip(report.resolutions())
        .filter(|(_, record)| !ascends(record))
        .map(|(reference, _)| Box::from(reference.text()))
        .collect()
}

/// Whether one record names its candidates at strictly ascending identifiers.
fn ascends(record: &ResolutionRecord) -> bool {
    let named: Box<[u32]> = record
        .candidates()
        .iter()
        .map(|candidate| candidate.definition().index())
        .collect();
    named.windows(2).all(|pair| pair[0] < pair[1])
}

/// The exact bytes one fixture's validated report serializes to.
fn report_bytes(files: &[FixtureFile]) -> Box<str> {
    let (tree, snapshot, resolution) = resolve(files, GoResolutionLimits::default());
    let resolution =
        resolution.unwrap_or_else(|error| panic!("the fixture should resolve: {error}"));
    let rendered = serde_json::to_string(resolution.report())
        .expect("a validated report serializes")
        .into_boxed_str();
    drop(resolution);
    drop(snapshot);
    drop(tree);
    rendered
}
