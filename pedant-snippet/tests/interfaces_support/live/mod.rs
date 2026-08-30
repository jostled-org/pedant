//! The live index cases: what a repository that keeps changing publishes.
//!
//! Every module here opens a Cargo workspace beside a Go module, so all of them
//! sit behind the shared complete-profile gate for the reason the graph cases
//! do: a claim about a project slice appearing and disappearing is unanswerable
//! by a build that links no project loader.

use crate::profile_gate::complete_profile_modules;

complete_profile_modules!(
    batches,
    failure,
    harness,
    probe,
    rediscovery,
    teardown,
    transactions,
    tree,
);

#[cfg(feature = "test-support")]
complete_profile_modules!(rescan,);
