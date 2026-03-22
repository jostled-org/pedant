use std::path::PathBuf;

#[cfg(feature = "semantic")]
use std::fs;

mod common;

/// Collect all `.rs` files under a directory, recursively.
fn collect_rs_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return files,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match path.is_dir() {
            true => files.extend(collect_rs_files(&path)),
            false => {
                if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
    }
    files
}

#[test]
fn test_self_analysis_gate_clean() {
    // Locate workspace root from pedant crate manifest dir
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant crate should be in workspace")
        .to_path_buf();

    let src_dirs = [
        workspace_root.join("pedant-core/src"),
        workspace_root.join("pedant-types/src"),
        workspace_root.join("pedant/src"),
    ];

    let mut args: Vec<String> = Vec::new();
    for dir in &src_dirs {
        for file in collect_rs_files(dir) {
            args.push(file.to_string_lossy().into_owned());
        }
    }
    args.push("--gate".to_owned());

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = common::run_pedant(&arg_refs, None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // No deny-level verdicts should fire on pedant's own source.
    // Warn/info verdicts (like key-material-network) are acceptable.
    assert!(
        !stdout.contains("deny"),
        "expected no deny-level gate verdicts on self-analysis, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn test_let_underscore_result_in_list_checks() {
    let output = common::run_pedant(&["--list-checks"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("let-underscore-result"),
        "expected --list-checks to include let-underscore-result, got:\n{stdout}"
    );
}

#[test]
fn test_let_underscore_result_explain() {
    let output = common::run_pedant(&["--explain", "let-underscore-result"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("Result"),
        "expected --explain output to mention Result, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Silently discarding"),
        "expected --explain output to contain the problem description, got:\n{stdout}"
    );
}

// --- Semantic CLI tests (feature-gated) ---

#[cfg(feature = "semantic")]
#[test]
fn test_semantic_cli_flag_exists() {
    let output = common::run_pedant(&["--help"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--semantic"),
        "expected --help to list --semantic flag, got:\n{stdout}"
    );
}

#[cfg(feature = "semantic")]
#[test]
fn test_semantic_cli_with_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"sem-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() -> i32 { 42 }\n").unwrap();

    let lib_path = root.join("src/lib.rs");
    let output = common::run_pedant(
        &[lib_path.to_str().unwrap(), "--semantic", "--capabilities"],
        None,
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("semantic: loaded workspace"),
        "expected semantic loading message in stderr, got:\n{stderr}"
    );
}

#[cfg(feature = "semantic")]
#[test]
fn test_self_analysis_semantic() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant crate should be in workspace")
        .to_path_buf();

    let src_dirs = [
        workspace_root.join("pedant-core/src"),
        workspace_root.join("pedant-types/src"),
        workspace_root.join("pedant/src"),
    ];

    let mut files: Vec<String> = Vec::new();
    for dir in &src_dirs {
        for file in collect_rs_files(dir) {
            files.push(file.to_string_lossy().into_owned());
        }
    }

    // Run without --semantic to get baseline capabilities
    let mut base_args: Vec<&str> = files.iter().map(String::as_str).collect();
    base_args.push("--capabilities");
    let base_output = common::run_pedant(&base_args, None);
    assert!(
        base_output.status.success(),
        "base analysis failed, stderr: {}",
        String::from_utf8_lossy(&base_output.stderr)
    );
    let base_profile: pedant_types::CapabilityProfile =
        serde_json::from_slice(&base_output.stdout).expect("should parse base capabilities");

    // Run with --semantic
    let mut sem_args: Vec<&str> = files.iter().map(String::as_str).collect();
    sem_args.push("--capabilities");
    sem_args.push("--semantic");
    let sem_output = common::run_pedant(&sem_args, None);

    let stderr = String::from_utf8_lossy(&sem_output.stderr);
    assert!(
        sem_output.status.success(),
        "semantic analysis failed, stderr: {stderr}"
    );

    let sem_profile: pedant_types::CapabilityProfile =
        serde_json::from_slice(&sem_output.stdout).expect("should parse semantic capabilities");

    // Semantic analysis should detect the same set of capabilities as syntactic.
    // Collect unique capability kinds from each run.
    let base_caps: std::collections::BTreeSet<_> =
        base_profile.findings.iter().map(|f| f.capability).collect();
    let sem_caps: std::collections::BTreeSet<_> =
        sem_profile.findings.iter().map(|f| f.capability).collect();

    assert_eq!(
        base_caps, sem_caps,
        "semantic and syntactic runs should detect the same capability kinds"
    );
}

#[cfg(feature = "semantic")]
#[test]
fn test_semantic_cli_no_workspace_warns() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("test.rs"), "fn main() {}\n").unwrap();

    let file_path = root.join("test.rs");
    let output = common::run_pedant(&[file_path.to_str().unwrap(), "--semantic"], None);

    assert!(
        output.status.success(),
        "expected exit 0 on graceful degradation, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("falling back"),
        "expected fallback warning in stderr, got:\n{stderr}"
    );
}
