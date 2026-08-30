//! Shared process-tree containment and fixtures for pedant integration tests.

mod containment;
mod fixture;
mod poll;

pub use containment::{
    ChildContainment, ContainedProcessTree, ContainmentError, adopt_child, configure_child,
    tree_is_live, wait_until_gone, wait_until_released,
};
pub use fixture::{
    FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV, FIXTURE_ROLE_ENV,
    FIXTURE_STDIO_ENV, FIXTURE_TEST_ENV, FixtureError, descendant_pid, run_fixture,
};
