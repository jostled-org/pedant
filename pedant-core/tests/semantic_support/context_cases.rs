//! Loading a workspace and answering type questions about it.
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use pedant_core::SemanticContext;

use crate::fixtures::fixture_workspace_root;

const TARGET_DIR_CHILD: &str = "PEDANT_SEMANTIC_TARGET_DIR_CHILD";
const TARGET_DIR_WORKSPACE: &str = "PEDANT_SEMANTIC_TARGET_DIR_WORKSPACE";

#[test]
fn test_semantic_load_overrides_inherited_target_dir() {
    if std::env::var_os(TARGET_DIR_CHILD).is_some() {
        let root = PathBuf::from(
            std::env::var_os(TARGET_DIR_WORKSPACE)
                .expect("child semantic workspace should be provided"),
        );
        crate::fixtures::load_fresh_semantic_context(&root).expect("workspace should load");
        return;
    }

    let inherited_target = tempfile::tempdir().expect("inherited target directory should exist");
    let inherited_profile = inherited_target.path().join("debug");
    std::fs::create_dir_all(&inherited_profile).expect("inherited profile should exist");
    let inherited_lock = std::fs::File::create(inherited_profile.join(".cargo-lock"))
        .expect("inherited target lock should be creatable");
    inherited_lock
        .lock()
        .expect("inherited target lock should be held by this test");

    let workspace = semantic_workspace();
    let workspace_profile = workspace.path().join("target").join("debug");
    std::fs::create_dir_all(&workspace_profile).expect("workspace target profile should exist");
    let workspace_lock = std::fs::File::create(workspace_profile.join(".cargo-lock"))
        .expect("target lock file should be creatable");
    workspace_lock
        .lock()
        .expect("workspace target lock should be held by this test");

    let child = Command::new(std::env::current_exe().expect("test executable should have a path"))
        .arg("context_cases::test_semantic_load_overrides_inherited_target_dir")
        .arg("--exact")
        .env(TARGET_DIR_CHILD, "1")
        .env(TARGET_DIR_WORKSPACE, workspace.path())
        .env("CARGO_TARGET_DIR", inherited_target.path())
        .spawn()
        .expect("child semantic test should start");
    let status = wait_for_child(child, Duration::from_secs(15));

    assert!(
        status.success(),
        "semantic load child should ignore the inherited target directory"
    );
}

fn semantic_workspace() -> tempfile::TempDir {
    let workspace = tempfile::tempdir().expect("temporary semantic workspace should exist");
    std::fs::create_dir(workspace.path().join("src")).expect("workspace source should exist");
    std::fs::write(
        workspace.path().join("Cargo.toml"),
        "[package]\nname = \"semantic-target-lock\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .expect("workspace manifest should be writable");
    std::fs::write(
        workspace.path().join("src").join("lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )
    .expect("workspace source should be writable");
    workspace
}

fn wait_for_child(mut child: Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match (child.try_wait(), Instant::now() >= deadline) {
            (Ok(Some(status)), _) => return status,
            (Ok(None), true) => {
                child.kill().expect("timed-out child should stop");
                child.wait().expect("stopped child should be reaped");
                panic!("semantic load child exceeded {timeout:?}");
            }
            (Ok(None), false) => std::thread::sleep(Duration::from_millis(10)),
            (Err(error), _) => panic!("semantic load child status failed: {error}"),
        }
    }
}

#[test]
fn test_semantic_context_loads_simple_workspace() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root);
    assert!(
        ctx.is_some(),
        "SemanticContext::load should succeed for a valid workspace"
    );
}

#[test]
fn test_resolve_type_through_alias() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let lib_path = root.join("src").join("lib.rs");
    let file = lib_path.to_str().expect("path should be valid UTF-8");

    // Line 11 (1-based): `pub fn foo() -> MyArc {`
    // MyArc starts at column 16 (0-based).
    // resolve_type should resolve through the alias to Arc<String>.
    let resolved = ctx.resolve_type(file, 11, 16);
    assert!(
        resolved.is_some(),
        "resolve_type should return Some for a type alias in return position"
    );
    let resolved_str = resolved.unwrap();
    assert!(
        resolved_str.contains("Arc"),
        "resolved type should contain 'Arc', got: {resolved_str}"
    );
}

#[test]
fn test_resolve_type_unknown_position_returns_none() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let lib_path = root.join("src").join("lib.rs");
    let file = lib_path.to_str().expect("path should be valid UTF-8");

    // Line 21 (1-based): `/// A comment line for testing unknown position.`
    // No type at a comment position.
    let resolved = ctx.resolve_type(file, 21, 0);
    assert!(
        resolved.is_none(),
        "resolve_type should return None for a comment position"
    );
}

#[test]
fn test_is_copy_for_primitive() {
    assert!(SemanticContext::is_copy("i32"), "i32 should implement Copy");
}

#[test]
fn test_is_copy_for_string() {
    assert!(
        !SemanticContext::is_copy("String"),
        "String should not implement Copy"
    );
}

#[test]
fn test_load_missing_workspace_returns_none() {
    let parent = tempfile::tempdir().expect("temporary parent should exist");
    let nonexistent = parent.path().join("missing");
    let ctx = crate::fixtures::load_fresh_semantic_context(&nonexistent);
    assert!(
        ctx.is_none(),
        "SemanticContext::load should return None for a missing workspace"
    );
}

#[test]
fn test_load_invalid_workspace_returns_none() {
    let temporary = tempfile::tempdir().expect("temporary invalid workspace should exist");
    let workspace_dir = temporary.path();
    std::fs::write(workspace_dir.join("Cargo.toml"), "[invalid\nbroken toml").unwrap();

    let loaded = crate::fixtures::load_fresh_semantic_context(workspace_dir);
    assert!(
        loaded.is_none(),
        "SemanticContext::load should return None for a malformed workspace"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_load_non_utf8_workspace_returns_none() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let parent = tempfile::tempdir().expect("temporary workspace parent should exist");
    let root = parent
        .path()
        .join(OsString::from_vec(vec![b's', b'e', b'm', 0x80]));
    std::fs::create_dir(&root).expect("non-UTF-8 workspace should exist");
    std::fs::create_dir(root.join("src")).expect("non-UTF-8 workspace source should exist");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-non-utf8\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .expect("non-UTF-8 workspace manifest should be writable");
    std::fs::write(
        root.join("src").join("lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )
    .expect("non-UTF-8 workspace source should be writable");

    let loaded = crate::fixtures::load_fresh_semantic_context(&root);

    assert!(
        loaded.is_none(),
        "semantic loading should refuse a workspace whose target path cannot be represented"
    );
}
