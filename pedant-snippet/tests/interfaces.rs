//! Contract tests for every `pedant-snippet` interface.
//!
//! This root owns the library boundary, the spawned CLI, the real stdio MCP
//! server, the repository index, and the navigation questions that index
//! answers. It stays the crate's only integration executable: the fixtures, the
//! bounded child harness, both transport journeys, the index cases, and the
//! query cases reach it through `#[path]` support modules, which Cargo links
//! into this same binary instead of a second one.
//!
//! One repository is the authority for all of it. The index cases build it, the
//! navigation cases query it, and the transport journeys spawn a CLI and a
//! server over the same tree — so a claim one layer makes about a declaration is
//! a claim about the declaration the other layers answered for.

#[path = "interfaces_support/profile_gate.rs"]
mod profile_gate;

use crate::profile_gate::complete_profile_path_modules;

// The spawned-child harness the transport journeys reach the binary through,
// and the three modules beside it: the command builder, the contained process
// tree, and the typed setup failure.
//
// Gated with the journeys rather than beside them. Every consumer of all four
// sits inside `journeys`, which compiles only where the whole closed language
// and graph selection is linked — so in a reduced profile these would be four
// modules nothing calls, which is a warning the `--all-targets` lint of that
// profile refuses.
complete_profile_path_modules!(
    "interfaces_support/cases.rs" => cases,
    "interfaces_support/child.rs" => child,
    "interfaces_support/command.rs" => command,
    "interfaces_support/contained.rs" => contained,
    "interfaces_support/failure.rs" => failure,
);

#[path = "interfaces_support/graph/mod.rs"]
mod graph;

#[path = "interfaces_support/index/mod.rs"]
mod index;

#[path = "interfaces_support/journeys/mod.rs"]
mod journeys;

#[path = "interfaces_support/live/mod.rs"]
mod live;

#[path = "interfaces_support/queries/mod.rs"]
mod queries;

/// The lingering process tree one containment row needs something to observe.
///
/// `pedant-process-guard` builds its fixture out of whichever test executable
/// asks for it: the parent role starts a descendant that outlives it and then
/// exits, and the descendant role sleeps. The role arrives in the environment,
/// so an ordinary run of this root — which sets none — passes straight through.
///
/// This is what makes the process-tree observation falsifiable rather than
/// merely asserted. Every journey here requires its child to leave nothing
/// behind, and a run that has never seen the observation report a survivor has
/// not established that it could.
#[test]
fn process_tree_fixture() {
    pedant_process_guard::run_fixture().expect("the process fixture runs the role it was given");
}
