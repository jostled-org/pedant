//! Shared process-tree containment and fixtures for pedant integration tests.

mod containment;
mod fixture;

pub use containment::{
    ContainedProcessTree, ContainmentError, configure_child, process_is_running, wait_until_gone,
};
pub use fixture::{
    FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV, FIXTURE_ROLE_ENV,
    FIXTURE_TEST_ENV, FixtureError, run_fixture,
};
