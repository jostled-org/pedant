#![cfg(feature = "checks")]
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use pedant_core::check_config::{ConfigError, find_config_file};
use pedant_core::{LintError, discover_workspace_root};

#[test]
fn discover_workspace_root_follows_package_workspace_pointer() {
    let temp_root = create_temp_dir("workspace-pointer");
    let workspace_root = temp_root.join("workspace");
    let package_root = temp_root.join("package");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&workspace_root).unwrap();
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        workspace_root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"../package\"]\n",
    )
    .unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"pointed-member\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2024\"\n",
            "workspace = \"../workspace\"\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();

    let discovered = discover_workspace_root(&src_dir.join("lib.rs")).unwrap();

    assert_eq!(discovered, Some(workspace_root));
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_pointer_overrides_an_ancestor_workspace() {
    let temp_root = create_temp_dir("workspace-pointer-override");
    let workspace_root = temp_root.join("alternate");
    let package_root = temp_root.join("packages/member");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&workspace_root).unwrap();
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(temp_root.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(workspace_root.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"pointed-member\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../../alternate\"\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();

    let discovered = discover_workspace_root(&src_dir.join("lib.rs")).unwrap();

    assert_eq!(discovered, Some(workspace_root));
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_rejects_non_string_workspace_pointer() {
    let temp_root = create_temp_dir("workspace-pointer-type");
    let package_root = temp_root.join("package");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"invalid-pointer\"\n",
            "version = \"0.1.0\"\n",
            "workspace = 7\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();
    let expected_manifest = package_root.join("Cargo.toml");

    let error = discover_workspace_root(&src_dir.join("lib.rs")).unwrap_err();

    match error {
        LintError::WorkspacePointerNotString { path } => assert_eq!(path, expected_manifest),
        unexpected => panic!("expected an invalid workspace-pointer error, got {unexpected:?}"),
    }
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_rejects_local_workspace_with_pointer() {
    let temp_root = create_temp_dir("workspace-pointer-contradiction");
    let package_root = temp_root.join("package");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"contradictory-workspace\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../alternate\"\n",
            "[workspace]\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();
    let expected_manifest = package_root.join("Cargo.toml");

    let error = discover_workspace_root(&src_dir.join("lib.rs")).unwrap_err();

    match error {
        LintError::WorkspacePointerWithLocalWorkspace { path } => {
            assert_eq!(path, expected_manifest);
        }
        unexpected => panic!("expected a contradictory-workspace error, got {unexpected:?}"),
    }
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_reports_missing_pointed_workspace() {
    let temp_root = create_temp_dir("workspace-pointer-missing");
    let package_root = temp_root.join("package");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"missing-workspace\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../workspace\"\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();
    let expected_manifest = temp_root.join("workspace/Cargo.toml");

    let error = discover_workspace_root(&src_dir.join("lib.rs")).unwrap_err();

    match error {
        LintError::PointedWorkspaceRead { path, source } => {
            assert_eq!(path, expected_manifest);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        unexpected => panic!("expected a pointed-workspace read error, got {unexpected:?}"),
    }
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_reports_malformed_pointed_workspace() {
    let temp_root = create_temp_dir("workspace-pointer-malformed");
    let workspace_root = temp_root.join("workspace");
    let package_root = temp_root.join("package");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&workspace_root).unwrap();
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(workspace_root.join("Cargo.toml"), "[workspace\n").unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"malformed-workspace\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../workspace\"\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();
    let expected_manifest = workspace_root.join("Cargo.toml");

    let error = discover_workspace_root(&src_dir.join("lib.rs")).unwrap_err();

    match error {
        LintError::PointedWorkspaceParse { path, .. } => assert_eq!(path, expected_manifest),
        unexpected => panic!("expected a pointed-workspace parse error, got {unexpected:?}"),
    }
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_rejects_pointed_manifest_without_workspace() {
    let temp_root = create_temp_dir("workspace-pointer-not-workspace");
    let workspace_root = temp_root.join("not-workspace");
    let package_root = temp_root.join("package");
    let src_dir = package_root.join("src");
    fs::create_dir_all(&workspace_root).unwrap();
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        workspace_root.join("Cargo.toml"),
        "[package]\nname = \"not-a-workspace\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"pointed-member\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../not-workspace\"\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn member() {}\n").unwrap();
    let expected_manifest = workspace_root.join("Cargo.toml");

    let error = discover_workspace_root(&src_dir.join("lib.rs")).unwrap_err();

    match error {
        LintError::PointedWorkspaceDeclarationMissing { path } => {
            assert_eq!(path, expected_manifest);
        }
        unexpected => panic!("expected a non-workspace pointer error, got {unexpected:?}"),
    }
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_normalizes_pointer_from_relative_start() {
    let temp_root = create_temp_dir("workspace-pointer-relative");
    let workspace_root = temp_root.join("workspace");
    let package_root = temp_root.join("nested/package");
    let src_file = package_root.join("src/lib.rs");
    fs::create_dir_all(&workspace_root).unwrap();
    fs::create_dir_all(src_file.parent().unwrap()).unwrap();
    fs::write(workspace_root.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(
        package_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"relative-member\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../../workspace\"\n",
        ),
    )
    .unwrap();
    fs::write(&src_file, "pub fn member() {}\n").unwrap();
    let current_dir = std::env::current_dir().unwrap();
    let relative_source = relative_path(&current_dir, &src_file);
    let relative_workspace = relative_path(&current_dir, &workspace_root);

    let discovered = discover_workspace_root(&relative_source).unwrap();

    assert_eq!(discovered, Some(relative_workspace));
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_ignores_workspace_substrings_in_package_values() {
    let temp_root = create_temp_dir("workspace-detect");
    let crate_root = temp_root.join("crate");
    let src_dir = crate_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_root.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"demo\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2024\"\n",
            "description = \"mentions [workspace] but is not one\"\n",
        ),
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn demo() {}\n").unwrap();

    let discovered = discover_workspace_root(&src_dir.join("lib.rs")).unwrap();

    assert_eq!(discovered, Some(crate_root));
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn discover_workspace_root_returns_parse_error_for_invalid_manifest() {
    let temp_root = create_temp_dir("workspace-parse-error");
    let crate_root = temp_root.join("crate");
    let src_dir = crate_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        crate_root.join("Cargo.toml"),
        "[package\nname = \"broken\"\n",
    )
    .unwrap();
    fs::write(src_dir.join("lib.rs"), "pub fn broken() {}\n").unwrap();

    let error = discover_workspace_root(&src_dir.join("lib.rs")).unwrap_err();

    assert!(matches!(error, pedant_core::LintError::TomlParseError(_)));
    fs::remove_dir_all(temp_root).unwrap();
}

#[test]
fn find_config_file_returns_current_dir_error() {
    let original_dir = std::env::current_dir().unwrap();
    let temp_root = create_temp_dir("config-discovery");
    let missing_dir = temp_root.join("missing-cwd");
    fs::create_dir_all(&missing_dir).unwrap();
    std::env::set_current_dir(&missing_dir).unwrap();
    fs::remove_dir(&missing_dir).unwrap();

    let result = find_config_file();

    std::env::set_current_dir(&original_dir).unwrap();
    fs::remove_dir_all(temp_root).unwrap();

    assert!(matches!(result, Err(ConfigError::Read(_))));
}

fn create_temp_dir(prefix: &str) -> PathBuf {
    let unique_suffix = unique_suffix();
    let temp_dir = std::env::temp_dir().join(format!("pedant-core-{prefix}-{unique_suffix}"));
    fs::create_dir_all(&temp_dir).unwrap();
    temp_dir
}

fn unique_suffix() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{}", std::process::id(), timestamp)
}

fn relative_path(from: &std::path::Path, to: &std::path::Path) -> PathBuf {
    let from_parts = from.components().collect::<Vec<_>>();
    let to_parts = to.components().collect::<Vec<_>>();
    let shared = from_parts
        .iter()
        .zip(&to_parts)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in shared..from_parts.len() {
        relative.push("..");
    }
    for part in &to_parts[shared..] {
        relative.push(part.as_os_str());
    }
    relative
}
