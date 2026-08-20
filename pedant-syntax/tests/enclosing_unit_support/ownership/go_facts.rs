//! Where the Go fact walk checks its ceilings, read from the production source.
//!
//! "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back. So the walk owner is parsed and its statements are
//! read: the depth check precedes the descent, the capacity check precedes the
//! insertion, and neither the descent nor the insertion has a second site that
//! could take an unchecked route.

use super::closure::{Member, crate_path, discover_closure, member, parse_rust_file};
use super::scan::{SourceScan, free_function, statement_naming};

/// The sole Go fact walk owner.
const WALK_MODULE: &str = "go/walk.rs";

/// The one function that descends into a node's children.
const DESCENT: &str = "descend";

/// The one function that retains a fact.
const INSERTION: &str = "admit";

/// The tree-sitter route that moves a cursor one level deeper.
const DESCENT_ROUTE: &str = "goto_first_child";

/// The route that retains one fact.
const INSERTION_ROUTE: &str = "push";

/// The frame stack, which is the other collection the walk grows.
///
/// Named rather than left implicit: it is the one place besides fact retention
/// that pushes, and stating it is what lets the claim below say the walk owner
/// pushes a fact in exactly one place.
const FRAME_MODULE: &str = "go/frame.rs";

/// The checks that must dominate them.
const DEPTH_CHECK: &str = "check_depth";
const CAPACITY_CHECK: &str = "check_capacity";

/// Every Go fact module, which is where a second descent or insertion would
/// hide.
fn go_members(closure: &[Member]) -> Box<[&Member]> {
    closure
        .iter()
        .filter(|member| member.label.starts_with("go/"))
        .collect()
}

/// 2.T3 (Invariant 5): the syntax-depth check dominates every descent and the
/// fact-capacity check dominates every insertion.
#[test]
fn go_fact_limit_checks_dominate_descent_and_insertion() {
    let closure = discover_closure();
    let go = go_members(&closure);
    assert!(
        !go.is_empty(),
        "the Go fact inventory must own at least one production module"
    );

    assert_single_owner(&go, DESCENT_ROUTE, &[WALK_MODULE]);
    assert_single_owner(&go, INSERTION_ROUTE, &[FRAME_MODULE, WALK_MODULE]);
    assert_eq!(
        member(&closure, WALK_MODULE).scan.reaches(INSERTION_ROUTE),
        1,
        "{WALK_MODULE} must retain a fact in exactly one place"
    );

    let walk = parse_rust_file(&crate_path("src").join(WALK_MODULE));
    assert_check_precedes(&walk, DESCENT, DEPTH_CHECK, DESCENT_ROUTE);
    assert_check_precedes(&walk, INSERTION, CAPACITY_CHECK, INSERTION_ROUTE);

    assert_eq!(
        member(&closure, WALK_MODULE).scan.reaches(DEPTH_CHECK),
        1,
        "{WALK_MODULE} must check syntax depth in exactly one place"
    );
    assert_eq!(
        member(&closure, WALK_MODULE).scan.reaches(CAPACITY_CHECK),
        1,
        "{WALK_MODULE} must check fact capacity in exactly one place"
    );
}

/// Exactly the named modules may take `route`.
fn assert_single_owner(go: &[&Member], route: &str, owners: &[&str]) {
    let naming: Box<[&str]> = go
        .iter()
        .filter(|member| member.scan.reaches(route) > 0)
        .map(|member| member.label.as_ref())
        .collect();
    assert_eq!(&*naming, owners, "only {owners:?} may reach `{route}`");
}

/// The statement that checks a ceiling precedes the statement that spends it.
fn assert_check_precedes(file: &syn::File, owner: &str, check: &str, route: &str) {
    let function = free_function(file, owner)
        .unwrap_or_else(|| panic!("{WALK_MODULE} should declare `{owner}`"));
    let scan = SourceScan::of_block(&function.block);
    assert_eq!(
        scan.reaches(check),
        1,
        "`{owner}` must reach `{check}` exactly once"
    );
    assert_eq!(
        scan.reaches(route),
        1,
        "`{owner}` must reach `{route}` exactly once"
    );

    let checked = statement_naming(&function.block, check)
        .unwrap_or_else(|| panic!("`{owner}` should state `{check}` as a statement"));
    let spent = statement_naming(&function.block, route)
        .unwrap_or_else(|| panic!("`{owner}` should state `{route}` as a statement"));
    assert!(
        checked < spent,
        "`{owner}` must check with `{check}` (statement {checked}) before reaching `{route}` (statement {spent})"
    );
}
