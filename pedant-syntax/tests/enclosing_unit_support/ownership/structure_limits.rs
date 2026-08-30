//! Where the structure walk checks its ceilings, read from the production
//! source.
//!
//! The sibling of [`super::go_facts`], asking the same question of the other
//! walk. "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back — nor from one that walked the whole tree and compared
//! the deepest level it reached. So the owners are parsed and their statements
//! are read: the depth check precedes every descent, the structure check
//! precedes the one insertion, and neither the descent nor the insertion has a
//! second site that could take an unchecked route.
//!
//! Its own case, the way its Go sibling is. It reads nothing from the
//! behavioral limit rows beside it, and as a case the harness names it, so a
//! deleted call site can no longer retire the whole structural claim in
//! silence — and the claim then runs in the configuration it needs rather than
//! only in the six-feature one its former caller lived in.

use super::closure::{Member, discover_closure, member, members_under};
use super::scan::{
    DESCENT_ROUTE, INSERTION_ROUTE, SourceScan, assert_check_precedes, assert_single_owner,
    method_owner, owner,
};

/// The one builder every backend retains through.
const BUILDER_MODULE: &str = "structure/builder.rs";

/// The shared tree-sitter declaration walk.
const TS_MODULE: &str = "structure/ts.rs";

/// The loose-Rust declaration walk.
const RUST_MODULE: &str = "structure/rust.rs";

/// The backend router, which is where the Go fact walk is given its ceilings.
const BOUND_MODULE: &str = "structure/bound.rs";

/// The label prefix every structure module carries, which is where a second
/// descent or insertion would hide.
const STRUCTURE_FAMILY: &str = "structure/";

/// The check that must dominate every descent.
const DEPTH_CHECK: &str = "admit_depth";

/// The check that must dominate the insertion.
const STRUCTURE_CHECK: &str = "admit_structure";

/// The owner that derives the Go fact walk's ceiling from the source it walks.
const FACT_CEILING: &str = "fact_ceiling";

/// The narrowed Go extraction this route takes: declarations, the scopes that
/// place them, and the package clause.
const STRUCTURE_EXTRACTION: &str = "structure_facts";

/// The whole-inventory extraction it must not take.
///
/// That walk retains imports, references, bindings, and signature terms, and
/// every one of them is charged against the fact ceiling this route runs
/// beneath — so taking it spends this route's own ceiling on facts the
/// projection then drops.
const FULL_EXTRACTION: &str = "GoFileFacts::extract";

/// The unbounded spellings no ceiling handed to a walk may be.
///
/// Both name the same number: `GoFactLimits::UNBOUNDED` is `u32::MAX` in each
/// of its fields, so a route that reached for either would waive the ceiling it
/// was written to state.
const UNBOUNDED: [&str; 2] = ["MAX", "UNBOUNDED"];

/// How a ceiling is measured: the source's own length, converted fallibly.
const SOURCE_LENGTH: &str = "len";

/// The fallible conversion that measurement is taken through.
const MEASUREMENT: &str = "u32::try_from";

/// The only numbers this router may write down.
///
/// A source no `u32` can measure states no ceiling, so the walk is handed the
/// floor. The `1` beside it is the one fact the walk opens with — the file
/// scope, which it retains before it reads a node and which no byte of the
/// source pays for — so every ceiling measured from a source covers it. Without
/// that term a valid empty file states a ceiling of zero and is refused at its
/// own base fact. Every other number would be a ceiling this module chose
/// instead of measured.
const DERIVED_CEILING: [&str; 2] = ["0", "1"];

/// 2.T4 (Invariant 14): both ceilings are checked before the walk spends what
/// they bound, and the Go route's fact ceiling is derived rather than waived.
#[test]
fn structure_limit_checks_dominate_descent_and_retention() {
    let closure = discover_closure();
    let structure = members_under(&closure, STRUCTURE_FAMILY);
    assert!(
        !structure.is_empty(),
        "the structure inventory must own at least one production module"
    );

    assert_single_owner(&structure, DESCENT_ROUTE, &[TS_MODULE]);
    assert_single_owner(&structure, INSERTION_ROUTE, &[BUILDER_MODULE, TS_MODULE]);
    assert_single_owner(&structure, DEPTH_CHECK, &[RUST_MODULE, TS_MODULE]);
    assert_eq!(
        member(&closure, BUILDER_MODULE)
            .scan
            .reaches(INSERTION_ROUTE),
        1,
        "{BUILDER_MODULE} must retain a structure in exactly one place"
    );

    assert_single_owner(&structure, STRUCTURE_CHECK, &[BUILDER_MODULE]);

    let builder = &member(&closure, BUILDER_MODULE).file;
    let retain = method_owner(builder, "retain", BUILDER_MODULE);
    assert_check_precedes(
        &retain.block,
        (BUILDER_MODULE, "retain"),
        STRUCTURE_CHECK,
        INSERTION_ROUTE,
    );

    let ts = &member(&closure, TS_MODULE).file;
    let descend = owner(ts, "descend", TS_MODULE);
    assert_check_precedes(
        &descend.block,
        (TS_MODULE, "descend"),
        DEPTH_CHECK,
        DESCENT_ROUTE,
    );

    // The Rust walk is recursive, so its descent is the call that enters the
    // body rather than a cursor move, and its retention is the builder call in
    // the same body. One check has to dominate both.
    let rust = &member(&closure, RUST_MODULE).file;
    let enter = method_owner(rust, "enter", RUST_MODULE);
    assert_check_precedes(&enter.block, (RUST_MODULE, "enter"), DEPTH_CHECK, "descend");
    assert_check_precedes(&enter.block, (RUST_MODULE, "enter"), DEPTH_CHECK, "retain");

    let bound = member(&closure, BOUND_MODULE);
    go_facts_are_bounded_by_the_source_they_are_taken_from(bound);
    go_facts_are_taken_at_the_scope_the_projection_reads(bound);
}

/// The Go route hands its fact walk a ceiling measured from the source, and no
/// route in that module can state another one.
///
/// The structure ceiling cannot be that ceiling — a fact is not a structure —
/// so the claim is about where the number comes from. Reading the caller alone
/// cannot make it: an owner that measures the source, drops the measurement,
/// and answers `u32::MAX` is `GoFactLimits::UNBOUNDED` spelled one function
/// lower, and it waives the ceiling while the caller still reads as bounded. A
/// behavioral row cannot make it either, because a waived ceiling refuses
/// nothing and every source that fits in memory passes beneath it.
///
/// So the module is read whole — it names no unbounded ceiling and writes down
/// no number but the two the measurement itself needs — and its ceiling owner
/// is handed the source and nothing else. The only value left for that owner to
/// answer with is the measurement it took, or the floor that refuses at the
/// first fact the source states.
fn go_facts_are_bounded_by_the_source_they_are_taken_from(bound: &Member) {
    let route = go_route(bound);
    assert_eq!(
        route.associated_calls("GoFactLimits::new"),
        1,
        "the Go route must build the fact walk's limits in exactly one place"
    );
    assert_eq!(
        route.reaches(FACT_CEILING),
        1,
        "the Go route must take its fact ceiling from `{FACT_CEILING}`"
    );

    let ceiling = owner(&bound.file, FACT_CEILING, BOUND_MODULE);
    assert_eq!(
        ceiling.sig.inputs.len(),
        1,
        "`{FACT_CEILING}` must be handed the source it measures and nothing else"
    );
    let derived = SourceScan::of_block(&ceiling.block);
    assert_eq!(
        derived.reaches(SOURCE_LENGTH),
        1,
        "`{FACT_CEILING}` must measure the source it bounds exactly once"
    );
    assert_eq!(
        derived.associated_calls(MEASUREMENT),
        1,
        "`{FACT_CEILING}` must take that measurement through one fallible \
         conversion, so a length no ceiling can hold is refused rather than cut \
         down to one"
    );

    for spelling in UNBOUNDED {
        assert!(
            !bound.scan.names(spelling),
            "{BOUND_MODULE} must hand no walk an unbounded ceiling, and it names `{spelling}`"
        );
    }
    let chosen: Box<[&str]> = bound
        .scan
        .integers()
        .iter()
        .copied()
        .filter(|written| !DERIVED_CEILING.contains(written))
        .collect();
    assert!(
        chosen.is_empty(),
        "{BOUND_MODULE} must state no ceiling of its own choosing, and it writes {chosen:?}"
    );
}

/// The Go route walks for the facts its projection reads and no others.
///
/// The narrowing is not observable from outside. Every fact a walk retains is
/// anchored at a node, a node covers at least one byte, and the ceiling is the
/// source's own length — so a wider scope refuses nothing a narrower one
/// admits, and no source separates the two by its answer. What separates them
/// is the ceiling they spend: the whole-inventory walk charges this route's
/// ceiling for imports, references, bindings, and signature terms the
/// projection never reads. That is a claim about which walk is asked for, so it
/// is read where the asking is written.
///
/// The answer the narrowed walk gives is proved beside this, behaviorally: the
/// structure cases take the same Go source through both walks and require the
/// same rows.
fn go_facts_are_taken_at_the_scope_the_projection_reads(bound: &Member) {
    let route = go_route(bound);
    assert_eq!(
        route.calls(STRUCTURE_EXTRACTION),
        1,
        "the Go route must extract through `{STRUCTURE_EXTRACTION}` exactly once"
    );
    assert_eq!(
        route.associated_calls(FULL_EXTRACTION),
        0,
        "the Go route must not take the whole-inventory route `{FULL_EXTRACTION}`"
    );
}

/// What the Go route in the backend router names.
fn go_route(bound: &Member) -> SourceScan {
    SourceScan::of_block(&owner(&bound.file, "go", BOUND_MODULE).block)
}
