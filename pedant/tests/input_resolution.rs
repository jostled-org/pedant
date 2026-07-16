//! Directory and path resolution for CLI file arguments.

use std::fs;
use std::path::Path;

mod common;

/// Trips `nested-match` twice and `max-depth` once at `-d 2`.
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

fn write(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

/// Count annotations naming a given file, using the github format so each
/// violation carries its `file=` property.
fn annotations_for(stdout: &str, needle: &str) -> usize {
    stdout
        .lines()
        .filter(|line| line.contains(&format!("file={needle},")))
        .count()
}

fn check_github(paths: &[&str], cwd: &Path) -> std::process::Output {
    let mut args = vec!["check", "--config", "/dev/null", "-d", "2", "-f", "github"];
    args.extend_from_slice(paths);
    common::run_pedant_in(cwd, &args, None)
}

#[test]
fn test_check_directory_recurses_into_subdirectories() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/top.rs"), NESTED);
    write(&dir.path().join("src/a/b/deep.rs"), NESTED);

    let output = check_github(&["src"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        annotations_for(&stdout, "src/top.rs") > 0,
        "expected the top-level file to be analyzed, got:\n{stdout}"
    );
    assert!(
        annotations_for(&stdout, "src/a/b/deep.rs") > 0,
        "expected the deeply nested file to be analyzed, got:\n{stdout}"
    );
}

#[test]
fn test_check_directory_is_not_a_silent_no_op() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/top.rs"), NESTED);

    let output = check_github(&["src"], dir.path());

    assert_eq!(
        output.status.code(),
        Some(1),
        "a directory holding violations must fail, not silently pass"
    );
}

#[test]
fn test_check_overlapping_roots_do_not_double_report() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/inner/deep.rs"), NESTED);

    let once = check_github(&["src"], dir.path());
    let twice = check_github(&["src", "src/inner"], dir.path());

    let once_out = String::from_utf8_lossy(&once.stdout);
    let twice_out = String::from_utf8_lossy(&twice.stdout);

    assert_eq!(
        annotations_for(&once_out, "src/inner/deep.rs"),
        annotations_for(&twice_out, "src/inner/deep.rs"),
        "a file reachable from two roots must be analyzed once\nonce:\n{once_out}\ntwice:\n{twice_out}"
    );
}

#[test]
fn test_check_duplicate_file_arguments_do_not_double_report() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/top.rs"), NESTED);

    let once = check_github(&["src/top.rs"], dir.path());
    let twice = check_github(&["src/top.rs", "src/top.rs"], dir.path());

    let once_out = String::from_utf8_lossy(&once.stdout);
    let twice_out = String::from_utf8_lossy(&twice.stdout);

    assert_eq!(
        annotations_for(&once_out, "src/top.rs"),
        annotations_for(&twice_out, "src/top.rs"),
        "the same file listed twice must be analyzed once"
    );
}

#[test]
fn test_check_nonexistent_path_errors() {
    let dir = tempfile::tempdir().unwrap();

    let output = check_github(&["nope"], dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "a nonexistent path must be an error, not a silent pass"
    );
    assert!(
        stderr.contains("nope"),
        "expected the offending path named on stderr, got:\n{stderr}"
    );
}

#[test]
fn test_check_directory_with_no_analyzable_files_errors() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/README.md"), "# not source\n");

    let output = check_github(&["src"], dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "finding nothing to analyze must be an error, not a silent pass"
    );
    assert!(
        stderr.contains("src"),
        "expected the searched path named on stderr, got:\n{stderr}"
    );
}

#[test]
fn test_check_recursion_skips_cachedir_tagged_and_hidden_and_node_modules() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/real.rs"), NESTED);

    // Cargo marks its build directory with CACHEDIR.TAG.
    write(&dir.path().join("src/build_out/bad.rs"), NESTED);
    write(
        &dir.path().join("src/build_out/CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    write(&dir.path().join("src/.hidden/bad.rs"), NESTED);
    write(&dir.path().join("src/node_modules/bad.rs"), NESTED);

    let output = check_github(&["src"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        annotations_for(&stdout, "src/real.rs") > 0,
        "real source must still be analyzed, got:\n{stdout}"
    );
    for skipped in ["build_out", ".hidden", "node_modules"] {
        assert!(
            !stdout.contains(skipped),
            "recursion must skip {skipped}/, got:\n{stdout}"
        );
    }
}

#[test]
fn test_check_target_named_module_is_not_skipped() {
    let dir = tempfile::tempdir().unwrap();
    // A crate may legitimately have a module named `target`. Only a CACHEDIR.TAG
    // marks a build directory, so this must still be analyzed.
    write(&dir.path().join("src/target/mod.rs"), NESTED);

    let output = check_github(&["src"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        annotations_for(&stdout, "src/target/mod.rs") > 0,
        "a source module named `target` must not be mistaken for a build dir, got:\n{stdout}"
    );
}

#[test]
fn test_check_explicit_file_under_skipped_dir_is_honored() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("build_out/bad.rs"), NESTED);
    write(
        &dir.path().join("build_out/CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );

    let output = check_github(&["build_out/bad.rs"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        annotations_for(&stdout, "build_out/bad.rs") > 0,
        "an explicitly named file must be analyzed even inside a skipped dir, got:\n{stdout}"
    );
}

#[test]
fn test_check_explicit_file_list_still_works() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("src/one.rs"), NESTED);
    write(&dir.path().join("src/two.rs"), NESTED);

    let output = check_github(&["src/one.rs", "src/two.rs"], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(annotations_for(&stdout, "src/one.rs") > 0);
    assert!(annotations_for(&stdout, "src/two.rs") > 0);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_capabilities_directory_recurses_across_languages() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("proj/lib.rs"),
        "fn f() { std::env::var(\"X\"); }\n",
    );
    write(
        &dir.path().join("proj/tool.py"),
        "import os\nos.getenv('X')\n",
    );
    write(
        &dir.path().join("proj/deploy.sh"),
        "#!/bin/bash\ncurl https://example.com\n",
    );

    let output = common::run_pedant_in(dir.path(), &["capabilities", "proj"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    for expected in ["lib.rs", "tool.py", "deploy.sh"] {
        assert!(
            stdout.contains(expected),
            "expected {expected} discovered by directory recursion, got:\n{stdout}"
        );
    }
}
