//! Every Go owner is declared, every Go predicate is registered once, and every
//! Go configuration is reachable from a tracked command.
//!
//! The three failures this rejects all look like a passing repository:
//!
//!   * a production module that joined a Go tree and no inventory names, so
//!     every structural claim silently stops covering it;
//!   * a predicate written twice, or renamed out of the identity a plan bullet
//!     and the step verifier select it by, so an exact filter picks zero rows
//!     and the run reports success;
//!   * a default-off feature nothing lints, documents, or executes, which is
//!     the state both Go features would be in if the tracked checks below were
//!     not registered in the workflow and ShellCheck inventory.
//!
//! Compiles under `go-resolution` alone, because the configuration a consumer
//! selects must be able to prove this.
//!
//! One process is run, and only one: the tracked ShellCheck inventory's own
//! `--list`. The inventory derives its subjects from the directories that hold
//! them, so it names no path a text scan could find, and a coverage clause read
//! out of the file would report every script as unlinted. `--list` prints the
//! same expansion the lint run hands the analyser, so the answer is the coverage
//! rather than a second copy of it. Everything else here is tracked text.

use std::collections::BTreeSet;

use crate::resolution::authority_scan::read_text;
use crate::resolution::go::registration_model::{
    GO_CHECKS, GO_CONFIGURATION_CHECK, GO_CONFIGURATIONS, GO_FEATURES, GO_GRAMMAR_EDGE,
    GO_LINT_COMMANDS, REGISTERED_PREDICATES,
};
use crate::resolution::go::support_trees::{GO_MODULE_PREFIX, GO_SUPPORT, SupportTree};
use crate::resolution::go::surface::production_sources;
use crate::resolution::manifest_reader::{
    default_features, dependency_edge, feature_selection, manifest_table, string_array,
};
use crate::resolution::production_tree::{assert_directory_holds_exactly, nested_sources};
use crate::resolution::root_inventory::assert_exact_integration_roots;
use crate::resolution::test_identity::{declaration_sites, workspace_test_sources};
use crate::resolution::tracked_index::is_tracked;
use crate::resolution::tracked_script::assert_checks_are_executable_linted_and_in_ci;
use crate::resolution::tracked_script::tracked_path;

/// 13.T3 (Invariant 25): the complete Go owner, predicate, feature, and check
/// registration matches the tracked tree, and the root count is unchanged.
#[test]
fn go_test_and_feature_ownership_is_exact() {
    let sources = production_sources();
    assert!(
        sources.len() > GO_SUPPORT.len(),
        "the production inventory must be the larger half of the surface"
    );
    assert_support_trees_are_exactly_modelled();
    assert_every_predicate_is_registered_once();
    assert_feature_edges_are_default_off_and_exact();
    assert_checks_are_executable_linted_and_in_ci(GO_CHECKS);
    assert_the_matrix_states_every_configuration();
    assert_exact_integration_roots();
}

/// Each root's Go support modules are exactly the modelled ones.
fn assert_support_trees_are_exactly_modelled() {
    for tree in GO_SUPPORT {
        assert!(
            is_tracked(tree.root),
            "{} must be a tracked integration root",
            tree.root
        );
        let modelled: BTreeSet<String> = tree.modules.iter().map(|it| (*it).to_owned()).collect();
        assert_eq!(
            modelled.len(),
            tree.modules.len(),
            "{} names a support module twice",
            tree.directory
        );
        assert_eq!(
            claimed_modules(tree),
            modelled,
            "{} must hold exactly the modelled Go support modules",
            tree.directory
        );
    }
}

/// The Go modules one support directory actually holds.
///
/// A directory a root shares with other languages is filtered by the module
/// prefix, and one this plan owns end to end is claimed whole. The second form
/// is the stronger claim and is used wherever it is true, because a prefix
/// filter cannot see a Go module that was named without the prefix.
fn claimed_modules(tree: &SupportTree) -> BTreeSet<String> {
    let directory = tracked_path(tree.directory);
    let found = nested_sources(&directory);
    match tree.whole {
        true => {
            let names: Box<[&str]> = tree.modules.iter().copied().collect();
            assert_directory_holds_exactly(&directory, &names);
            found
        }
        false => found
            .into_iter()
            .filter(|path| file_name(path).starts_with(GO_MODULE_PREFIX))
            .collect(),
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Every registered predicate is declared once in the workspace, in the file the
/// model names.
///
/// The universe is every member's `tests/` tree rather than the modelled files,
/// because "declared once" is a claim about the workspace: a second copy inside
/// a root the model never mentions is exactly the duplicate this rejects.
fn assert_every_predicate_is_registered_once() {
    let sources = workspace_test_sources();
    assert!(
        sources.len() > REGISTERED_PREDICATES.len(),
        "the workspace holds more test sources than registered predicates"
    );
    let mut wrong: Vec<String> = Vec::new();
    for (name, owner) in REGISTERED_PREDICATES {
        let sites = declaration_sites(sources, name);
        match &*sites {
            [only] if *only == *owner => {}
            _ => wrong.push(format!(
                "{name} is declared at {sites:?}, and the model says {owner}"
            )),
        }
    }
    assert!(
        wrong.is_empty(),
        "every registered Go predicate is declared exactly once, where its owner says: {wrong:?}"
    );
}

/// Both Go features select exactly what the model says and neither is on by
/// default.
fn assert_feature_edges_are_default_off_and_exact() {
    for edge in GO_FEATURES {
        let manifest = manifest_table(&format!("{}/Cargo.toml", edge.package));
        assert_eq!(
            &*feature_selection(manifest, edge.package, edge.feature),
            edge.selects,
            "{}'s `{}` feature must select exactly the modelled set",
            edge.package,
            edge.feature
        );
        assert!(
            !default_features(manifest).contains(&edge.feature),
            "{}'s `{}` feature must stay default-off",
            edge.package,
            edge.feature
        );
    }
    assert_the_grammar_edge_is_optional_and_narrow();
}

/// The one dependency `go-resolution` selects is optional, versioned, and asks
/// for the Go grammar alone.
fn assert_the_grammar_edge_is_optional_and_narrow() {
    let (package, dependency, grammar) = GO_GRAMMAR_EDGE;
    let manifest = manifest_table(&format!("{package}/Cargo.toml"));
    let edge = dependency_edge(manifest, package, dependency);
    assert_eq!(
        edge.get("optional").and_then(toml::Value::as_bool),
        Some(true),
        "{package}'s {dependency} edge must be optional"
    );
    assert_eq!(
        edge.get("default-features").and_then(toml::Value::as_bool),
        Some(false),
        "{package}'s {dependency} edge must select no default feature"
    );
    assert!(
        edge.get("version").and_then(toml::Value::as_str).is_some(),
        "{package}'s {dependency} edge must carry a published version"
    );
    assert_eq!(
        &*string_array(edge.get("features")),
        [grammar],
        "{package}'s {dependency} edge must ask for the Go grammar alone"
    );
}

/// The matrix check states every modelled configuration and every lint command.
fn assert_the_matrix_states_every_configuration() {
    let matrix = GO_CONFIGURATION_CHECK;
    let text = read_text(matrix);
    for (label, arguments) in GO_CONFIGURATIONS {
        assert!(
            text.contains(&format!("check_root {label} ")),
            "{matrix} must state the {label} configuration"
        );
        assert!(
            text.contains(arguments),
            "{matrix}'s {label} row must run `cargo test {arguments}`"
        );
    }
    for command in GO_LINT_COMMANDS {
        assert!(
            text.contains(command),
            "{matrix} must run `{command}`, which no other job reaches"
        );
    }
}
