use std::fs;
use std::path::Path;

use pedant_core::Config;
use pedant_mcp::index::{WorkspaceIndex, discover_workspace_root};
use pedant_types::Capability;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Copy a fixture workspace into a temp directory for mutation tests.
fn copy_fixture_to_temp(name: &str) -> tempfile::TempDir {
    let src = fixture_path(name);
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    copy_dir_recursive(&src, tmp.path()).expect("failed to copy fixture");
    tmp
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        match entry.file_type()?.is_dir() {
            true => {
                fs::create_dir_all(&target)?;
                copy_dir_recursive(&entry.path(), &target)?;
            }
            false => {
                fs::copy(entry.path(), &target)?;
            }
        }
    }
    Ok(())
}

#[test]
fn test_index_discovers_workspace_crates() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config).unwrap();

    let names: Vec<&str> = index.crate_names().collect();
    assert!(names.contains(&"lib-a"), "missing lib-a: {names:?}");
    assert!(names.contains(&"lib-b"), "missing lib-b: {names:?}");
}

#[test]
fn test_index_caches_analysis_results() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config).unwrap();

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    let caps = profile.capabilities();
    assert!(
        caps.contains(&Capability::Network),
        "expected Network capability in lib-a, found: {caps:?}"
    );
}

#[test]
fn test_index_aggregates_crate_profile() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config).unwrap();

    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    let caps = profile.capabilities();
    assert!(
        caps.contains(&Capability::Network),
        "expected Network in lib-a, found: {caps:?}"
    );
    assert!(
        caps.contains(&Capability::FileRead),
        "expected FileRead in lib-a, found: {caps:?}"
    );
}

#[test]
fn test_index_empty_workspace() {
    let root = fixture_path("empty_workspace");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config).unwrap();

    let names: Vec<&str> = index.crate_names().collect();
    assert!(names.is_empty(), "expected no crates, found: {names:?}");
}

#[test]
fn test_index_gate_verdicts() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Vec<&str> = verdicts.iter().map(|v| v.rule).collect();
    assert!(
        rules.contains(&"build-script-network"),
        "expected build-script-network verdict, found: {rules:?}"
    );
}

#[test]
fn test_workspace_discovery_from_subdirectory() {
    let root = fixture_path("multi_crate");
    let subdir = root.join("lib-a/src");

    let discovered =
        discover_workspace_root(&subdir).expect("should discover workspace root from subdirectory");

    assert_eq!(
        discovered.canonicalize().unwrap(),
        root.canonicalize().unwrap(),
    );
}

// ---------------------------------------------------------------------------
// 4.T1: file change triggers reindex
// ---------------------------------------------------------------------------

#[test]
fn test_file_change_triggers_reindex() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config).unwrap();

    // lib-a/src/lib.rs has std::net — verify Network present
    let profile = index.crate_profile("lib-a").expect("lib-a not indexed");
    assert!(
        profile.capabilities().contains(&Capability::Network),
        "expected Network before change"
    );

    // Remove the std::net import from lib.rs
    let lib_rs = tmp.path().join("lib-a/src/lib.rs");
    fs::write(&lib_rs, "pub fn placeholder() {}\n").unwrap();
    index.reindex_file(&lib_rs, &config).unwrap();

    // Also clear build.rs (it has reqwest which contributes Network)
    let build_rs = tmp.path().join("lib-a/build.rs");
    fs::write(
        &build_rs,
        "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n",
    )
    .unwrap();
    index.reindex_file(&build_rs, &config).unwrap();

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
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config).unwrap();

    // Add a new file with std::fs import to lib-a
    let new_file = tmp.path().join("lib-a/src/extra.rs");
    fs::write(
        &new_file,
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    )
    .unwrap();

    index.reindex_file(&new_file, &config).unwrap();

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
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config).unwrap();

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
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config).unwrap();

    // lib-a has build.rs using reqwest — gate rule should fire
    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Vec<&str> = verdicts.iter().map(|v| v.rule).collect();
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

    index.reindex_file(&build_rs, &config).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Vec<&str> = verdicts.iter().map(|v| v.rule).collect();
    assert!(
        !rules.contains(&"build-script-network"),
        "expected build-script-network verdict gone after change, found: {rules:?}"
    );
}
