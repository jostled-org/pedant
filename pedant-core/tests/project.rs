use std::path::Path;

use pedant_core::check_config::CheckConfig;
use pedant_core::project::{ProjectContext, check_project};
use pedant_core::violation::ViolationType;

fn conflicting_config() -> CheckConfig {
    CheckConfig {
        check_conflicting_module_root: true,
        ..CheckConfig::default()
    }
}

fn paths(root: &Path, rels: &[&str]) -> Vec<String> {
    rels.iter()
        .map(|rel| root.join(rel).to_string_lossy().into_owned())
        .collect()
}

fn conflicts(files: &[String], root: &Path, config: &CheckConfig) -> Vec<String> {
    let ctx = ProjectContext {
        rust_files: files,
        workspace_root: root,
    };
    check_project(&ctx, config)
        .into_iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ConflictingModuleRoot))
        .map(|v| v.file_path.to_string())
        .collect()
}

#[test]
fn test_conflicting_module_root_flags_stem_beside_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/foo")).unwrap();
    std::fs::write(root.join("src/foo.rs"), "").unwrap();
    std::fs::write(root.join("src/foo/mod.rs"), "").unwrap();
    std::fs::write(root.join("src/bar.rs"), "").unwrap();

    let files = paths(root, &["src/foo.rs", "src/bar.rs", "src/foo/mod.rs"]);
    let hits = conflicts(&files, root, &conflicting_config());
    // foo.rs conflicts with foo/; bar.rs has no sibling dir; mod.rs is exempt.
    assert_eq!(hits.len(), 1);
    assert!(hits[0].ends_with("foo.rs"));
}

#[test]
fn test_conflicting_module_root_exempts_mod_and_lib() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/lib")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "").unwrap();
    std::fs::create_dir_all(root.join("nested/mod")).unwrap();
    std::fs::write(root.join("nested/mod.rs"), "").unwrap();

    let files = paths(root, &["src/lib.rs", "nested/mod.rs"]);
    assert!(conflicts(&files, root, &conflicting_config()).is_empty());
}

#[test]
fn test_conflicting_module_root_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/foo")).unwrap();
    std::fs::write(root.join("src/foo.rs"), "").unwrap();

    let files = paths(root, &["src/foo.rs"]);
    assert!(conflicts(&files, root, &CheckConfig::default()).is_empty());
}
