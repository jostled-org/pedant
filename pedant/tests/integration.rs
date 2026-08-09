use std::path::PathBuf;

mod common;
include!("integration_support/workspace_discovery.rs");

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

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
            false if path.extension().is_some_and(|e| e == "rs") => files.push(path),
            false => {}
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
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = common::run_subcommand("gate", &arg_refs, None);

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
    let output = common::run_pedant(&["list-checks"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("let-underscore-result"),
        "expected --list-checks to include let-underscore-result, got:\n{stdout}"
    );
}

#[test]
fn test_let_underscore_result_explain() {
    let output = common::run_pedant(&["explain", "let-underscore-result"], None);
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

#[test]
fn test_build_script_discovery_failure_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::create_dir(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"broken-build-discovery\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn analyze_me() {}\n").unwrap();

    let lib_path = root.join("src/lib.rs");
    let output = common::run_subcommand("check", &[lib_path.to_str().unwrap()], None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected build script discovery failure to return exit 2, stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("build script discovery"),
        "expected build script discovery error in stderr, got:\n{stderr}"
    );
}

#[test]
fn test_large_source_file_warn_tier_does_not_fail_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rs");
    let source: String = (0..15)
        .map(|i| format!("const N{i}: usize = {i};\n"))
        .collect();
    std::fs::write(&path, source).unwrap();

    // 15 lines: above the warn ceiling (10), below the denial ceiling (100).
    let output = common::run_subcommand(
        "check",
        &[
            "--warn-source-file-lines",
            "10",
            "--max-source-file-lines",
            "100",
            path.to_str().unwrap(),
        ],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "warn-tier finding must not fail the run; exit={:?}",
        output.status.code()
    );
    assert!(
        stdout.contains("large-source-file"),
        "expected the warning to be reported, got:\n{stdout}"
    );
}

#[test]
fn test_large_source_file_deny_tier_fails_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rs");
    let source: String = (0..15)
        .map(|i| format!("const N{i}: usize = {i};\n"))
        .collect();
    std::fs::write(&path, source).unwrap();

    // 15 lines exceeds the denial ceiling of 10.
    let output = common::run_subcommand(
        "check",
        &["--max-source-file-lines", "10", path.to_str().unwrap()],
        None,
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "denial-tier finding must fail the run"
    );
}

#[test]
fn test_conflicting_module_root_project_check_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/widgets")).unwrap();
    std::fs::write(root.join("src/widgets.rs"), "pub fn a() {}\n").unwrap();
    std::fs::write(root.join("src/widgets/mod.rs"), "pub fn b() {}\n").unwrap();

    let sibling = root.join("src/widgets.rs");
    let output = common::run_subcommand(
        "check",
        &["--no-conflicting-module-root", sibling.to_str().unwrap()],
        None,
    );
    assert!(
        output.status.success(),
        "disabled: no conflict finding expected"
    );

    // Enabling the project check via config surfaces the conflict.
    let cfg = root.join(".pedant.toml");
    std::fs::write(&cfg, "check_conflicting_module_root = true\n").unwrap();
    let output = common::run_subcommand(
        "check",
        &["-c", cfg.to_str().unwrap(), sibling.to_str().unwrap()],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout.contains("conflicting-module-root"), "got:\n{stdout}");
}

// --- Multi-language CLI tests ---

/// 5.T1: Running pedant --capabilities on a Python file produces findings with language metadata.
#[test]
fn test_cli_python_capabilities() {
    let fixture = fixtures_dir().join("network_subprocess.py");
    let output = common::run_subcommand("capabilities", &[fixture.to_str().unwrap()], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0, stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&stdout).expect("should parse capabilities JSON");
    let has_network = profile
        .findings
        .iter()
        .any(|f| f.capability == pedant_types::Capability::Network);
    let has_process = profile
        .findings
        .iter()
        .any(|f| f.capability == pedant_types::Capability::ProcessExec);
    let all_python = profile
        .findings
        .iter()
        .all(|f| f.language == Some(pedant_types::Language::Python));

    assert!(has_network, "expected Network finding, got:\n{stdout}");
    assert!(has_process, "expected ProcessExec finding, got:\n{stdout}");
    assert!(
        all_python,
        "expected all findings to have language python, got:\n{stdout}"
    );
}

/// 5.T5: Running pedant --capabilities on an unknown extension produces no error and no findings.
#[test]
fn test_cli_unknown_extension_skipped() {
    let fixture = fixtures_dir().join("clean.xyz");
    let output = common::run_subcommand("capabilities", &[fixture.to_str().unwrap()], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0, stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&stdout).expect("should parse capabilities JSON");
    assert!(
        profile.findings.is_empty(),
        "expected no findings for unknown extension, got:\n{stdout}"
    );
}

/// 5.T6: Running pedant --capabilities on a package.json with postinstall hook produces findings.
#[test]
fn test_cli_package_json_install_hook() {
    let fixture = fixtures_dir().join("npm_project/package.json");
    let output = common::run_subcommand("capabilities", &[fixture.to_str().unwrap()], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0, stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&stdout).expect("should parse capabilities JSON");
    let has_install_hook = profile.findings.iter().any(|f| {
        f.execution_context == Some(pedant_types::ExecutionContext::InstallHook)
            && f.capability == pedant_types::Capability::ProcessExec
    });
    assert!(
        has_install_hook,
        "expected ProcessExec finding with InstallHook context, got:\n{stdout}"
    );
}

/// 5.T7: Running pedant --capabilities on a Makefile produces findings with BuildHook context.
#[test]
fn test_cli_makefile_hook_entrypoint() {
    let fixture = fixtures_dir().join("makefile_project/Makefile");
    let output = common::run_subcommand("capabilities", &[fixture.to_str().unwrap()], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0, stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&stdout).expect("should parse capabilities JSON");
    let has_build_hook = profile
        .findings
        .iter()
        .any(|f| f.execution_context == Some(pedant_types::ExecutionContext::BuildHook));
    assert!(
        has_build_hook,
        "expected findings with BuildHook context, got:\n{stdout}"
    );
}

#[test]
fn test_cli_go_file_runs_source_and_manifest_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("main.go");
    std::fs::write(
        &fixture,
        "package main\nimport \"net/http\"\n//go:generate stringer -type=Foo\nfunc main() {}\n",
    )
    .unwrap();

    let output = common::run_subcommand("capabilities", &[fixture.to_str().unwrap()], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected exit 0, stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&stdout).expect("should parse capabilities JSON");
    assert!(
        profile
            .findings
            .iter()
            .any(|finding| finding.capability == pedant_types::Capability::Network),
        "expected Go source finding, got:\n{stdout}"
    );
    assert!(
        profile.findings.iter().any(|finding| {
            finding.capability == pedant_types::Capability::ProcessExec
                && finding.execution_context == Some(pedant_types::ExecutionContext::Generator)
        }),
        "expected go:generate manifest finding, got:\n{stdout}"
    );
}
