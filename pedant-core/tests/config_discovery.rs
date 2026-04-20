use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use pedant_core::check_config::{ConfigError, find_config_file};
use pedant_core::discover_workspace_root;

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
