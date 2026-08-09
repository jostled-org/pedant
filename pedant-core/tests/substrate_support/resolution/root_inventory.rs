//! The fixed model of this workspace's cargo integration-test executables.
//!
//! The set is written down, never discovered: a discovered count would agree
//! with whatever the tree happens to contain, so it could not reject a root
//! that reappeared.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The complete set of top-level cargo integration-test executables after
/// `pedant-core/tests/workspace_members.rs` is removed. Each entry is
/// `<crate>/tests/<root>.rs`.
pub const INTEGRATION_ROOTS: &[&str] = &[
    "pedant-core/tests/capability.rs",
    "pedant-core/tests/config_discovery.rs",
    "pedant-core/tests/gate.rs",
    "pedant-core/tests/hash.rs",
    "pedant-core/tests/integration.rs",
    "pedant-core/tests/ir_extraction.rs",
    "pedant-core/tests/json_output.rs",
    "pedant-core/tests/nesting_depth.rs",
    "pedant-core/tests/pattern.rs",
    "pedant-core/tests/project.rs",
    "pedant-core/tests/semantic.rs",
    "pedant-core/tests/smoke.rs",
    "pedant-core/tests/substrate.rs",
    "pedant-core/tests/type_footprint.rs",
    "pedant/tests/attestation.rs",
    "pedant/tests/common.rs",
    "pedant/tests/config_precedence.rs",
    "pedant/tests/diff.rs",
    "pedant/tests/gate_cli.rs",
    "pedant/tests/github_format.rs",
    "pedant/tests/input_resolution.rs",
    "pedant/tests/integration.rs",
    "pedant/tests/supply_chain.rs",
    "pedant-mcp/tests/config_pipeline.rs",
    "pedant-mcp/tests/index.rs",
    "pedant-mcp/tests/integration.rs",
    "pedant-mcp/tests/tools.rs",
    "pedant-mcp/tests/watcher.rs",
    "pedant-lang/tests/capability.rs",
    "pedant-lang/tests/detection.rs",
    "pedant-snippet/tests/interfaces.rs",
    "pedant-syntax/tests/enclosing_unit.rs",
    "pedant-types/tests/serialization.rs",
];

/// The root that the removed executable used to own; it must not reappear.
pub const REMOVED_ROOT: &str = "pedant-core/tests/workspace_members.rs";

/// The workspace directory this crate sits inside.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant-core sits inside the workspace root")
        .to_path_buf()
}

/// The workspace links exactly the modelled executables, and the removed root
/// has not come back.
///
/// One implementation, two registered owners: the Step 2 transition predicate
/// and the indexed authority proof both state this, and a second copy could
/// pass one while the other drifted. A membership check would not do — it
/// agrees with a tree that grew a thirty-fourth root — so the comparison is
/// between the written-down set and the discovered one.
pub fn assert_exact_integration_roots() {
    let root = workspace_root();
    let modelled: BTreeSet<String> = INTEGRATION_ROOTS
        .iter()
        .map(|path| (*path).into())
        .collect();
    assert_eq!(
        modelled.len(),
        33,
        "the model must name 33 distinct integration executables"
    );
    assert_eq!(
        discovered_integration_roots(&root),
        modelled,
        "the workspace must link exactly the modelled integration-test executables"
    );
    assert!(
        !root.join(REMOVED_ROOT).exists(),
        "{REMOVED_ROOT} must stay removed once its cases moved into the substrate root"
    );
}

/// Every `.rs` file cargo would link as a test executable, across every
/// workspace member.
///
/// The universe is the workspace, not the model. Enumerating the `tests/`
/// directories the model already names would make the search set a function of
/// the answer: a thirty-fourth root inside a crate the model knows would fail,
/// but the same root inside a newly added member would be invisible to a check
/// whose claim is about the whole workspace.
fn discovered_integration_roots(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for member in workspace_members(root) {
        collect_test_roots(root, &root.join(member).join("tests"), &mut found);
    }
    found
}

fn collect_test_roots(root: &Path, directory: &Path, found: &mut BTreeSet<String>) {
    // A member with no integration tests carries no `tests/` directory. An
    // unreadable one is a different fact and still panics below.
    if !directory.is_dir() {
        return;
    }
    let listing =
        fs::read_dir(directory).unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    for file in listing
        .map(|entry| entry.unwrap_or_else(|error| panic!("{}: {error}", directory.display())))
    {
        let path = file.path();
        let is_root = path.is_file() && path.extension().is_some_and(|ext| ext == "rs");
        if is_root {
            found.insert(relative_text(root, &path));
        }
    }
}

/// The workspace members, as the root manifest declares them.
///
/// A member pattern would leave the search set unresolved without running
/// cargo, and this workspace declares literal paths; one that appeared would be
/// an unproven universe, so it fails here rather than narrowing the scan.
fn workspace_members(root: &Path) -> Vec<String> {
    let manifest_path = root.join("Cargo.toml");
    let text = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));
    let manifest: toml::Table = toml::from_str(&text).expect("the root Cargo.toml should parse");
    let members: Vec<String> = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .expect("the root Cargo.toml declares [workspace] members")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("a workspace member is a path string")
                .to_owned()
        })
        .collect();
    let globbed: Vec<&String> = members.iter().filter(|it| it.contains('*')).collect();
    assert!(
        globbed.is_empty(),
        "the root inventory enumerates literal members, and these are patterns: {globbed:?}"
    );
    assert!(
        members.len() >= 7,
        "the workspace declares {} members, so the scan is not reading it",
        members.len()
    );
    members
}

fn relative_text(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or_else(|error| {
        panic!(
            "{} is outside integration-root scan {}: {error}",
            path.display(),
            root.display()
        )
    });
    relative
        .to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .replace('\\', "/")
}
