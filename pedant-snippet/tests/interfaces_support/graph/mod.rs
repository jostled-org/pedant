//! The graph-backed navigation cases.
//!
//! Every module here indexes the same Cargo workspace and Go module, so all of
//! them sit behind the shared complete-profile gate: a claim about a Rust graph
//! beside a Go graph is unanswerable by a build that links one of them.
//!
//! The fixture is this tree's own rather than the mixed six-language
//! repository. A page over neighborhoods needs a declaration that appears in
//! more than two project graphs, and the mixed repository states one library
//! and one binary.

use crate::profile_gate::complete_profile_modules;

complete_profile_modules!(
    cache, coverage, fixture, join, limits, oracles, paging, paths, relations, selection,
    vocabulary,
);

#[cfg(feature = "test-support")]
complete_profile_modules!(reuse,);
