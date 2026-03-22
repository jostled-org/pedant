use std::path::PathBuf;

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
