//! Incremental reindexing: a changed file, a new file, a removed file, and the
//! gate verdicts each of those has to leave correct.

use std::fs;

use pedant_mcp::index::WorkspaceIndex;
use pedant_types::Capability;

use crate::workspace_fixtures::make_nested_workspace;
use crate::writable_fixture::copy_fixture_to_temp;

// ---------------------------------------------------------------------------
// 4.T1: file change triggers reindex
// ---------------------------------------------------------------------------

#[test]
fn test_file_change_triggers_reindex() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let mut index = WorkspaceIndex::build(tmp.path(), None).unwrap();

    // lib-a/src/lib.rs has std::net — verify Network present
    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    assert!(
        profile.capabilities().contains(&Capability::Network),
        "expected Network before change"
    );

    // Remove the std::net import from lib.rs
    let lib_rs = tmp.path().join("lib-a/src/lib.rs");
    fs::write(&lib_rs, "pub fn placeholder() {}\n").unwrap();
    index.reindex_file(&lib_rs).unwrap();

    // Also clear build.rs (it has reqwest which contributes Network)
    let build_rs = tmp.path().join("lib-a/build.rs");
    fs::write(
        &build_rs,
        "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n",
    )
    .unwrap();
    index.reindex_file(&build_rs).unwrap();

    // Clear non-Rust network sources (Python script with `import requests`)
    let fetch_py = tmp.path().join("lib-a/scripts/fetch_data.py");
    if fetch_py.exists() {
        fs::write(&fetch_py, "# no capabilities\n").unwrap();
        index.reindex_file(&fetch_py).unwrap();
    }

    // Clear manifest hook findings (package.json postinstall)
    let pkg_json = tmp.path().join("lib-a/package.json");
    if pkg_json.exists() {
        fs::write(&pkg_json, "{}\n").unwrap();
        index.reindex_file(&pkg_json).unwrap();
    }

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    assert!(
        !profile.capabilities().contains(&Capability::Network),
        "expected Network gone after removing all network imports"
    );
}

// ---------------------------------------------------------------------------
// 4.T2: new file added to index
// ---------------------------------------------------------------------------

#[test]
fn test_new_file_added_to_index() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let mut index = WorkspaceIndex::build(tmp.path(), None).unwrap();

    // Add a new file with std::fs import to lib-a
    let new_file = tmp.path().join("lib-a/src/extra.rs");
    fs::write(
        &new_file,
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    )
    .unwrap();

    index.reindex_file(&new_file).unwrap();

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    assert!(
        profile.capabilities().contains(&Capability::FileRead),
        "expected FileRead after adding file with std::fs"
    );
}

// ---------------------------------------------------------------------------
// 4.T3: file deleted from index
// ---------------------------------------------------------------------------

#[test]
fn test_file_deleted_from_index() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let mut index = WorkspaceIndex::build(tmp.path(), None).unwrap();

    // lib-a/src/other.rs has std::fs — verify FileRead present
    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    assert!(
        profile.capabilities().contains(&Capability::FileRead),
        "expected FileRead before delete"
    );

    // Delete other.rs (sole source of FileRead)
    let other_rs = tmp.path().join("lib-a/src/other.rs");
    fs::remove_file(&other_rs).unwrap();
    index.remove_file(&other_rs);

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    assert!(
        !profile.capabilities().contains(&Capability::FileRead),
        "expected FileRead gone after deleting other.rs"
    );
}

// ---------------------------------------------------------------------------
// 4.T4: gate verdicts recomputed after change
// ---------------------------------------------------------------------------

#[test]
fn test_gate_verdicts_recomputed_after_change() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let mut index = WorkspaceIndex::build(tmp.path(), None).unwrap();

    // lib-a has build.rs using reqwest — gate rule should fire
    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Box<[&str]> = verdicts
        .iter()
        .map(|v| v.rule)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        rules.contains(&"build-script-network"),
        "expected build-script-network verdict before change, found: {rules:?}"
    );

    // Replace build.rs to remove the network import
    let build_rs = tmp.path().join("lib-a/build.rs");
    fs::write(
        &build_rs,
        "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n",
    )
    .unwrap();

    index.reindex_file(&build_rs).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Box<[&str]> = verdicts
        .iter()
        .map(|v| v.rule)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        !rules.contains(&"build-script-network"),
        "expected build-script-network verdict gone after change, found: {rules:?}"
    );
}

#[test]
fn test_reindex_file_prefers_most_specific_crate_root() {
    let tmp = make_nested_workspace();
    let mut index = WorkspaceIndex::build(tmp.path(), None).unwrap();
    let nested_extra = tmp.path().join("shared/nested/src/extra.rs");
    fs::write(
        &nested_extra,
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    )
    .unwrap();

    index.reindex_file(&nested_extra).unwrap();

    let nested_caps = index.crate_profile("nested").unwrap().capabilities();
    let shared_caps = index.crate_profile("shared").unwrap().capabilities();

    assert!(nested_caps.contains(&Capability::FileRead));
    assert!(!shared_caps.contains(&Capability::FileRead));
}

// ---------------------------------------------------------------------------
// Step 4: Reindex preserves results through summary-based gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn mcp_reindex_preserves_gate_verdicts_through_summary_evaluation() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let mut index = WorkspaceIndex::build(tmp.path(), None).unwrap();

    // lib-a has build.rs with reqwest — gate rule fires initially.
    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    assert!(
        verdicts.iter().any(|v| v.rule == "build-script-network"),
        "expected build-script-network verdict before reindex"
    );

    // Reindex an unrelated file — gate verdicts must still be present.
    let lib_rs = tmp.path().join("lib-a/src/lib.rs");
    fs::write(&lib_rs, "use std::net::TcpStream;\npub fn net() {}\n").unwrap();
    index.reindex_file(&lib_rs).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    assert!(
        verdicts.iter().any(|v| v.rule == "build-script-network"),
        "build-script-network verdict must survive reindex of unrelated file"
    );

    // Reindex degraded file handling: mark a file degraded, verify it tracks.
    let bad_path = tmp.path().join("lib-a/src/nonexistent.rs");
    let err = index.reindex_file(&bad_path).unwrap_err();
    index.mark_file_degraded(&bad_path, &err);

    let degraded: Box<[_]> = index
        .crate_degraded_files("lib-a")
        .unwrap()
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        !degraded.is_empty(),
        "degraded file should be tracked after failed reindex"
    );
}
