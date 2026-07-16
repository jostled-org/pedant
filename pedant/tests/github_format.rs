use std::fs;

mod common;

/// Source with a depth-3 nest, which trips `max-depth` at `-d 2`.
const NESTED: &str = concat!(
    "fn deep(a: bool, b: bool, c: bool) -> u8 {\n",
    "    match a {\n",
    "        true => match b {\n",
    "            true => match c {\n",
    "                true => 1,\n",
    "                false => 2,\n",
    "            },\n",
    "            false => 3,\n",
    "        },\n",
    "        false => 4,\n",
    "    }\n",
    "}\n",
);

const CLEAN: &str = "fn tidy() -> u8 {\n    1\n}\n";

#[test]
fn test_check_github_format_emits_error_annotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested.rs");
    fs::write(&path, NESTED).unwrap();

    let output = common::run_subcommand(
        "check",
        &["-d", "2", "-f", "github", path.to_str().unwrap()],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("::error "),
        "expected an ::error annotation, got:\n{stdout}"
    );
    assert!(
        stdout.contains("title=max-depth"),
        "expected the check code as annotation title, got:\n{stdout}"
    );
    assert!(
        stdout.contains(",line=") && stdout.contains(",col="),
        "expected line and col properties, got:\n{stdout}"
    );
    assert!(
        stdout.contains("nested.rs"),
        "expected the file path, got:\n{stdout}"
    );
}

#[test]
fn test_check_github_format_uses_warning_for_warn_severity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rs");
    fs::write(&path, CLEAN).unwrap();

    // The file clears the warn ceiling but not the 1000-line deny default,
    // so `large-source-file` reports at Warn.
    let output = common::run_subcommand(
        "check",
        &[
            "--warn-source-file-lines",
            "2",
            "-f",
            "github",
            path.to_str().unwrap(),
        ],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("::warning "),
        "expected a ::warning annotation for Warn severity, got:\n{stdout}"
    );
    assert!(
        stdout.contains("title=large-source-file"),
        "expected the large-source-file title, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("::error "),
        "Warn severity must not emit ::error, got:\n{stdout}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "Warn severity must not fail the run, got:\n{stdout}"
    );
}

#[test]
fn test_check_github_format_escapes_property_separators() {
    let dir = tempfile::tempdir().unwrap();
    // A comma in the path would terminate the `file=` property early.
    let nested_dir = dir.path().join("od,d");
    fs::create_dir(&nested_dir).unwrap();
    let path = nested_dir.join("nested.rs");
    fs::write(&path, NESTED).unwrap();

    let output = common::run_subcommand(
        "check",
        &["-d", "2", "-f", "github", path.to_str().unwrap()],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("od%2Cd"),
        "expected the comma in the path escaped as %2C, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("od,d"),
        "raw comma must not survive into a property value, got:\n{stdout}"
    );
}

#[test]
fn test_check_github_format_clean_file_emits_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clean.rs");
    fs::write(&path, CLEAN).unwrap();

    let output = common::run_subcommand(
        "check",
        &["-d", "2", "-f", "github", path.to_str().unwrap()],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.trim().is_empty(),
        "expected no annotations and no summary, got:\n{stdout}"
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_check_github_format_preserves_deny_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested.rs");
    fs::write(&path, NESTED).unwrap();

    let output = common::run_subcommand(
        "check",
        &["-d", "2", "-f", "github", path.to_str().unwrap()],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "github format must not change the deny exit code"
    );
}

fn write_build_script_crate(root: &std::path::Path) {
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "fn lib_fn() {}\n").unwrap();
    fs::write(
        root.join("build.rs"),
        concat!(
            "use reqwest;\n",
            "use std::process::Command;\n",
            "fn main() { Command::new(\"cc\"); }\n",
        ),
    )
    .unwrap();
}

#[test]
fn test_gate_github_format_emits_error_annotation() {
    let dir = tempfile::tempdir().unwrap();
    write_build_script_crate(dir.path());
    let lib_path = dir.path().join("src/lib.rs");

    let output =
        common::run_subcommand("gate", &["-f", "github", lib_path.to_str().unwrap()], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("::error "),
        "expected an ::error annotation for a deny verdict, got:\n{stdout}"
    );
    assert!(
        stdout.contains("title=build-script-download-exec"),
        "expected the rule name as annotation title, got:\n{stdout}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "github format must not change the gate deny exit code"
    );
}

#[test]
fn test_gate_github_format_uses_warning_for_warn_severity() {
    let dir = tempfile::tempdir().unwrap();
    write_build_script_crate(dir.path());
    let lib_path = dir.path().join("src/lib.rs");

    let output =
        common::run_subcommand("gate", &["-f", "github", lib_path.to_str().unwrap()], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // build-script-exec is a warn-severity rule and fires on this crate.
    assert!(
        stdout.contains("::warning title=build-script-exec"),
        "expected a ::warning annotation for the warn-severity rule, got:\n{stdout}"
    );
}

#[test]
fn test_gate_github_format_clean_crate_emits_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(dir.path().join("src/lib.rs"), CLEAN).unwrap();
    let lib_path = dir.path().join("src/lib.rs");

    let output =
        common::run_subcommand("gate", &["-f", "github", lib_path.to_str().unwrap()], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.trim().is_empty(),
        "expected no annotations for a clean crate, got:\n{stdout}"
    );
    assert_eq!(output.status.code(), Some(0));
}
