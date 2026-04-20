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

fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

fn make_nested_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"shared\", \"shared/nested\"]\n",
    );
    fs::create_dir_all(tmp.path().join("shared/src")).unwrap();
    fs::create_dir_all(tmp.path().join("shared/nested/src")).unwrap();
    write_file(
        &tmp.path().join("shared/Cargo.toml"),
        "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &tmp.path().join("shared/src/lib.rs"),
        "pub fn shared() {}\n",
    );
    write_file(
        &tmp.path().join("shared/nested/Cargo.toml"),
        "[package]\nname = \"nested\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &tmp.path().join("shared/nested/src/lib.rs"),
        "pub fn nested() {}\n",
    );
    tmp
}

fn make_single_crate_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[package]\nname = \"single-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &tmp.path().join("src/lib.rs"),
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    );
    tmp
}

fn make_workspace_with_go_generator() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("tools")).unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[package]\nname = \"go-generator\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(&tmp.path().join("src/lib.rs"), "pub fn rust_side() {}\n");
    write_file(
        &tmp.path().join("tools/main.go"),
        "package main\nimport \"net/http\"\n//go:generate stringer -type=Foo\nfunc main() {}\n",
    );
    tmp
}

fn make_glob_workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    write_file(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*-util\"]\n",
    );
    for crate_name in ["http-util", "fs-util", "http-core"] {
        let crate_dir = tmp.path().join("crates").join(crate_name);
        fs::create_dir_all(crate_dir.join("src")).unwrap();
        write_file(
            &crate_dir.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            ),
        );
        write_file(&crate_dir.join("src/lib.rs"), "pub fn marker() {}\n");
    }
    tmp
}

#[test]
fn test_index_discovers_workspace_crates() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config, None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert!(names.contains(&"lib-a"), "missing lib-a: {names:?}");
    assert!(names.contains(&"lib-b"), "missing lib-b: {names:?}");
}

#[test]
fn test_index_caches_analysis_results() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config, None).unwrap();

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
    let index = WorkspaceIndex::build(&root, &config, None).unwrap();

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
    let index = WorkspaceIndex::build(&root, &config, None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert!(names.is_empty(), "expected no crates, found: {names:?}");
}

#[test]
fn test_index_builds_single_crate_workspace() {
    let root = make_single_crate_workspace();
    let config = Config::default();
    let index = WorkspaceIndex::build(root.path(), &config, None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert_eq!(&*names, &["single-crate"]);
}

#[test]
fn test_index_analyzes_go_source_and_generate_directives() {
    let root = make_workspace_with_go_generator();
    let config = Config::default();
    let index = WorkspaceIndex::build(root.path(), &config, None).unwrap();

    let profile = index
        .crate_profile("go-generator")
        .expect("go-generator not indexed");

    assert!(
        profile.capabilities().contains(&Capability::Network),
        "expected Go import capability in aggregate profile"
    );
    assert!(
        profile.findings.iter().any(|finding| {
            finding.capability == Capability::ProcessExec
                && finding.execution_context == Some(pedant_types::ExecutionContext::Generator)
        }),
        "expected go:generate finding in aggregate profile"
    );
}

#[test]
fn test_index_builds_glob_workspace_member_patterns() {
    let root = make_glob_workspace();
    let config = Config::default();
    let index = WorkspaceIndex::build(root.path(), &config, None).unwrap();

    let names: Box<[&str]> = index.crate_names().collect::<Vec<_>>().into_boxed_slice();
    assert_eq!(&*names, &["fs-util", "http-util"]);
}

#[test]
fn test_index_gate_verdicts() {
    let root = fixture_path("multi_crate");
    let config = Config::default();
    let index = WorkspaceIndex::build(&root, &config, None).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    let rules: Box<[&str]> = verdicts
        .iter()
        .map(|v| v.rule)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    assert!(
        rules.contains(&"build-script-network"),
        "expected build-script-network verdict, found: {rules:?}"
    );
}

#[test]
fn test_workspace_discovery_from_subdirectory() {
    let root = fixture_path("multi_crate");
    let subdir = root.join("lib-a/src");

    let discovered = discover_workspace_root(&subdir)
        .unwrap()
        .expect("should discover workspace root from subdirectory");

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
    let mut index = WorkspaceIndex::build(tmp.path(), &config, None).unwrap();

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

    // Clear non-Rust network sources (Python script with `import requests`)
    let fetch_py = tmp.path().join("lib-a/scripts/fetch_data.py");
    if fetch_py.exists() {
        fs::write(&fetch_py, "# no capabilities\n").unwrap();
        index.reindex_file(&fetch_py, &config).unwrap();
    }

    // Clear manifest hook findings (package.json postinstall)
    let pkg_json = tmp.path().join("lib-a/package.json");
    if pkg_json.exists() {
        fs::write(&pkg_json, "{}\n").unwrap();
        index.reindex_file(&pkg_json, &config).unwrap();
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
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config, None).unwrap();

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
    let mut index = WorkspaceIndex::build(tmp.path(), &config, None).unwrap();

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
    let mut index = WorkspaceIndex::build(tmp.path(), &config, None).unwrap();

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

    index.reindex_file(&build_rs, &config).unwrap();

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
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config, None).unwrap();
    let nested_extra = tmp.path().join("shared/nested/src/extra.rs");
    fs::write(
        &nested_extra,
        "use std::fs;\npub fn read_it() -> std::io::Result<String> { fs::read_to_string(\"x\") }\n",
    )
    .unwrap();

    index.reindex_file(&nested_extra, &config).unwrap();

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
    let config = Config::default();
    let mut index = WorkspaceIndex::build(tmp.path(), &config, None).unwrap();

    // lib-a has build.rs with reqwest — gate rule fires initially.
    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    assert!(
        verdicts.iter().any(|v| v.rule == "build-script-network"),
        "expected build-script-network verdict before reindex"
    );

    // Reindex an unrelated file — gate verdicts must still be present.
    let lib_rs = tmp.path().join("lib-a/src/lib.rs");
    fs::write(&lib_rs, "use std::net::TcpStream;\npub fn net() {}\n").unwrap();
    index.reindex_file(&lib_rs, &config).unwrap();

    let verdicts = index.crate_verdicts("lib-a").expect("lib-a not indexed");
    assert!(
        verdicts.iter().any(|v| v.rule == "build-script-network"),
        "build-script-network verdict must survive reindex of unrelated file"
    );

    // Reindex degraded file handling: mark a file degraded, verify it tracks.
    let bad_path = tmp.path().join("lib-a/src/nonexistent.rs");
    let err = index.reindex_file(&bad_path, &config).unwrap_err();
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
