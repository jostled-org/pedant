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
//!     not registered in the workflow, the ShellCheck inventory, and the
//!     manifest.
//!
//! Reads tracked text and runs nothing. Compiles under `go-resolution` alone,
//! because the configuration a consumer selects must be able to prove this.

use std::collections::BTreeSet;

use crate::resolution::go::registration_model::{
    CI_WORKFLOW, DOCUMENTATION_CONTRACT, FeatureEdge, GO_CHECKS, GO_CONFIGURATIONS, GO_FEATURES,
    GO_GRAMMAR_EDGE, GO_LINT_COMMANDS, MANIFEST, REGISTERED_PREDICATES, SHELLCHECK_INVENTORY,
};
use crate::resolution::go::support_trees::{GO_MODULE_PREFIX, GO_SUPPORT, SupportTree};
use crate::resolution::go::surface::{
    assert_directory_holds_exactly, nested_sources, production_sources, tracked_path, tracked_text,
};
use crate::resolution::root_inventory::{assert_exact_integration_roots, workspace_members};

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
    assert_every_check_is_tracked_and_registered();
    assert_the_matrix_states_every_configuration();
    assert_the_documentation_contract_holds();
    assert_exact_integration_roots();
}

/// Each root's Go support modules are exactly the modelled ones.
fn assert_support_trees_are_exactly_modelled() {
    for tree in GO_SUPPORT {
        assert!(
            tracked_path(tree.root).is_file(),
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
    let mut wrong: Vec<String> = Vec::new();
    for (name, owner) in REGISTERED_PREDICATES {
        let sites = declaration_sites(&sources, name);
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

/// Every tracked test file that declares one predicate, once per declaration.
///
/// Once per declaration rather than once per file, because two copies inside one
/// support module are the same duplicate as two copies across two roots, and a
/// set would report them as one.
fn declaration_sites<'read>(sources: &'read [(String, String)], name: &str) -> Box<[&'read str]> {
    let needle = format!("fn {name}(");
    sources
        .iter()
        .flat_map(|(path, text)| std::iter::repeat_n(path.as_str(), text.matches(&needle).count()))
        .collect()
}

/// Every `.rs` file beneath every workspace member's `tests/` directory, read
/// once, as its repository-relative path and its text.
///
/// Read once rather than once per predicate: fifty-odd predicates over two
/// hundred sources is ten thousand file reads, and the answer does not change
/// between them.
fn workspace_test_sources() -> Box<[(String, String)]> {
    let root = crate::resolution::root_inventory::workspace_root();
    let mut sources: Vec<(String, String)> = Vec::new();
    for member in workspace_members(&root) {
        let tests = root.join(&member).join("tests");
        if !tests.is_dir() {
            continue;
        }
        sources.extend(nested_sources(&tests).into_iter().map(|path| {
            let relative = format!("{member}/tests/{path}");
            let text = tracked_text(&relative);
            (relative, text)
        }));
    }
    assert!(
        sources.len() > REGISTERED_PREDICATES.len(),
        "the workspace holds more test sources than registered predicates"
    );
    sources.into_boxed_slice()
}

/// Both Go features select exactly what the model says and neither is on by
/// default.
fn assert_feature_edges_are_default_off_and_exact() {
    for edge in GO_FEATURES {
        let manifest = manifest_table(&format!("{}/Cargo.toml", edge.package));
        assert_eq!(
            &*feature_selection(&manifest, edge),
            edge.selects,
            "{}'s `{}` feature must select exactly the modelled set",
            edge.package,
            edge.feature
        );
        assert!(
            !default_features(&manifest).contains(&edge.feature.to_owned()),
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
    let edge = manifest
        .get("dependencies")
        .and_then(|table| table.get(dependency))
        .unwrap_or_else(|| panic!("{package} declares a {dependency} dependency"));
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
        [grammar.to_owned()],
        "{package}'s {dependency} edge must ask for the Go grammar alone"
    );
}

/// One package's `[features]` entry, as the list it selects.
fn feature_selection(manifest: &toml::Table, edge: &FeatureEdge) -> Box<[String]> {
    let features = manifest
        .get("features")
        .unwrap_or_else(|| panic!("{} declares a [features] table", edge.package));
    string_array(features.get(edge.feature))
}

/// One package's default feature list, which is empty when it declares none.
fn default_features(manifest: &toml::Table) -> Box<[String]> {
    string_array(
        manifest
            .get("features")
            .and_then(|features| features.get("default")),
    )
}

fn string_array(value: Option<&toml::Value>) -> Box<[String]> {
    value
        .and_then(toml::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .expect("a manifest feature entry is a string")
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn manifest_table(relative: &str) -> toml::Table {
    toml::from_str(&tracked_text(relative))
        .unwrap_or_else(|error| panic!("{relative} should parse as TOML: {error}"))
}

/// Each Go check is a tracked executable and is registered in all three places
/// that would otherwise let it stop running.
fn assert_every_check_is_tracked_and_registered() {
    let workflow = tracked_text(CI_WORKFLOW);
    let shellcheck = tracked_text(SHELLCHECK_INVENTORY);
    let manifest = manifest_table(MANIFEST);
    let identities = manifest
        .get("ci")
        .and_then(toml::Value::as_table)
        .expect("the manifest declares a [ci] table");
    for (identity, script) in GO_CHECKS {
        assert_executable(script);
        assert_eq!(
            workflow.matches(&format!("- run: {script}")).count(),
            1,
            "{CI_WORKFLOW} must run {script} exactly once"
        );
        assert!(
            shellcheck.contains(script),
            "{SHELLCHECK_INVENTORY} must lint {script}"
        );
        assert_eq!(
            identities.get(*identity).and_then(toml::Value::as_str),
            Some(*script),
            "{MANIFEST} must register [ci].{identity} as {script}"
        );
    }
}

/// A tracked check is a file the workflow can execute.
#[cfg(unix)]
fn assert_executable(script: &str) {
    use std::os::unix::fs::PermissionsExt;

    let path = tracked_path(script);
    let mode = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("{script}: {error}"))
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o111,
        0o111,
        "{script} must be executable; the workflow invokes it directly"
    );
}

/// The mode bit is a POSIX fact, and no job on this repository's Windows runner
/// compiles this root. The file must still be tracked and readable.
#[cfg(not(unix))]
fn assert_executable(script: &str) {
    assert!(
        tracked_path(script).is_file(),
        "{script} must be a tracked file"
    );
}

/// The matrix check states every modelled configuration and every lint command.
fn assert_the_matrix_states_every_configuration() {
    let (_, matrix) = GO_CHECKS
        .iter()
        .find(|(identity, _)| *identity == "go_configurations")
        .expect("the model names the configuration matrix check");
    let text = tracked_text(matrix);
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

/// Each tracked document carries the exact sentence the contract names.
fn assert_the_documentation_contract_holds() {
    for (document, sentence) in DOCUMENTATION_CONTRACT {
        assert!(
            tracked_text(document).lines().any(|line| line == *sentence),
            "{document} must carry the contract sentence `{sentence}` on a line of its own"
        );
    }
}
