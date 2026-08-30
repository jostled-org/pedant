//! Where the Go fact walk checks its ceilings, read from the production source.
//!
//! "Refused before the excess was retained" is a claim about order, and a
//! behavioral case cannot tell a check that ran first from one that ran after a
//! push and rolled back. So the walk owner is parsed and its statements are
//! read: the depth check precedes the descent, the capacity check precedes the
//! insertion, and neither the descent nor the insertion has a second site that
//! could take an unchecked route.
//!
//! The two ceilings sit in two owners, because they bound two different things:
//! the walk owns the descent it pays for, and the inventory owns the retention
//! it pays for. Each claim below is read from the owner that makes it.

use super::closure::{discover_closure, member, members_under};
use super::scan::{
    DESCENT_ROUTE, INSERTION_ROUTE, assert_check_precedes, assert_single_owner, owner,
};

/// The sole Go fact walk owner.
const WALK_MODULE: &str = "go/walk.rs";

/// The sole Go fact retention owner.
const INVENTORY_MODULE: &str = "go/inventory.rs";

/// The one function that descends into a node's children.
const DESCENT: &str = "descend";

/// The one function that retains a fact.
const INSERTION: &str = "admit";

/// The frame stack, which is the other collection the walk grows.
///
/// Named rather than left implicit: it is the one place besides fact retention
/// that pushes, and stating it is what lets the claim below say the walk owner
/// pushes a fact in exactly one place.
const FRAME_MODULE: &str = "go/frame.rs";

/// The checks that must dominate them.
const DEPTH_CHECK: &str = "check_depth";
const CAPACITY_CHECK: &str = "check_capacity";

/// The label prefix every Go fact module carries, which is where a second
/// descent or insertion would hide.
const GO_FAMILY: &str = "go/";

/// 2.T3 (Invariant 5): the syntax-depth check dominates every descent and the
/// fact-capacity check dominates every insertion.
#[test]
fn go_fact_limit_checks_dominate_descent_and_insertion() {
    let closure = discover_closure();
    let go = members_under(&closure, GO_FAMILY);
    assert!(
        !go.is_empty(),
        "the Go fact inventory must own at least one production module"
    );

    assert_single_owner(&go, DESCENT_ROUTE, &[WALK_MODULE]);
    assert_single_owner(&go, INSERTION_ROUTE, &[FRAME_MODULE, INVENTORY_MODULE]);
    assert_eq!(
        member(&closure, INVENTORY_MODULE)
            .scan
            .reaches(INSERTION_ROUTE),
        1,
        "{INVENTORY_MODULE} must retain a fact in exactly one place"
    );

    let walk = &member(&closure, WALK_MODULE).file;
    assert_check_precedes(
        &owner(walk, DESCENT, WALK_MODULE).block,
        (WALK_MODULE, DESCENT),
        DEPTH_CHECK,
        DESCENT_ROUTE,
    );
    let inventory = &member(&closure, INVENTORY_MODULE).file;
    assert_check_precedes(
        &owner(inventory, INSERTION, INVENTORY_MODULE).block,
        (INVENTORY_MODULE, INSERTION),
        CAPACITY_CHECK,
        INSERTION_ROUTE,
    );

    assert_eq!(
        member(&closure, WALK_MODULE).scan.reaches(DEPTH_CHECK),
        1,
        "{WALK_MODULE} must check syntax depth in exactly one place"
    );
    assert_eq!(
        member(&closure, INVENTORY_MODULE)
            .scan
            .reaches(CAPACITY_CHECK),
        1,
        "{INVENTORY_MODULE} must check fact capacity in exactly one place"
    );
}
