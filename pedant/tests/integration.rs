use std::path::PathBuf;

#[cfg(feature = "semantic")]
use std::fs;

mod common;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[cfg(feature = "semantic")]
fn extract_json_object(stdout: &str) -> &str {
    let json_start = stdout
        .find("\n{")
        .map(|index| index + 1)
        .or_else(|| stdout.starts_with('{').then_some(0))
        .expect("expected JSON object in stdout");
    &stdout[json_start..]
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
    let output = common::run_pedant(&[lib_path.to_str().unwrap()], None);
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
fn test_semantic_cli_discovers_workspace_from_any_requested_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let outside_path = root.join("standalone.rs");
    let workspace = root.join("workspace");

    fs::create_dir(&workspace).unwrap();
    fs::create_dir(workspace.join("src")).unwrap();
    fs::write(&outside_path, "pub fn standalone() {}\n").unwrap();
    fs::write(
        workspace.join("Cargo.toml"),
        "[package]\nname = \"sem-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    fs::write(
        workspace.join("src/lib.rs"),
        "pub fn inside_workspace() {}\n",
    )
    .unwrap();

    let workspace_file = workspace.join("src/lib.rs");
    let output = common::run_pedant(
        &[
            outside_path.to_str().unwrap(),
            workspace_file.to_str().unwrap(),
            "--semantic",
            "--capabilities",
        ],
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
    let base_stdout = String::from_utf8_lossy(&base_output.stdout);
    assert!(
        base_output.status.code() != Some(2),
        "base analysis failed, stderr: {}",
        String::from_utf8_lossy(&base_output.stderr)
    );
    let base_profile: pedant_types::CapabilityProfile =
        serde_json::from_str(extract_json_object(&base_stdout))
            .expect("should parse base capabilities");

    // Run with --semantic
    let mut sem_args: Vec<&str> = files.iter().map(String::as_str).collect();
    sem_args.push("--capabilities");
    sem_args.push("--semantic");
    let sem_output = common::run_pedant(&sem_args, None);

    let sem_stdout = String::from_utf8_lossy(&sem_output.stdout);
    let stderr = String::from_utf8_lossy(&sem_output.stderr);
    assert!(
        sem_output.status.code() != Some(2),
        "semantic analysis failed, stderr: {stderr}"
    );

    let sem_profile: pedant_types::CapabilityProfile =
        serde_json::from_str(extract_json_object(&sem_stdout))
            .expect("should parse semantic capabilities");

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

/// 7.T1: CLI --capabilities output includes "reachable" when semantic analysis annotates it.
#[cfg(feature = "semantic")]
#[test]
fn test_cli_capabilities_shows_reachable() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant crate should be in workspace")
        .to_path_buf();
    let lib_path = workspace_root.join("pedant-core/tests/fixtures/dataflow_workspace/src/lib.rs");

    let output = common::run_pedant(
        &[lib_path.to_str().unwrap(), "--semantic", "--capabilities"],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Exit code 1 is expected — the fixture intentionally contains patterns that
    // trigger style violations. Exit code 2 would mean an actual error.
    assert!(
        output.status.code() != Some(2),
        "expected no error exit, stderr:\n{stderr}"
    );

    // Parse the capabilities profile from stdout. The fixture has style violations
    // that produce text output before the JSON block; extract the JSON portion.
    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(extract_json_object(&stdout)).expect("should parse capabilities JSON");
    let has_reachable = profile.findings.iter().any(|f| f.reachable.is_some());
    assert!(
        has_reachable,
        "expected at least one finding with reachable annotated, stdout:\n{stdout}"
    );

    // Verify the JSON text contains the "reachable" key.
    assert!(
        stdout.contains("\"reachable\""),
        "expected JSON to contain \"reachable\" field, stdout:\n{stdout}"
    );
}

/// 7.T2: CLI --gate output includes flow-aware verdicts when data flows are detected.
#[cfg(feature = "semantic")]
#[test]
fn test_cli_gate_shows_flow_verdicts() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant crate should be in workspace")
        .to_path_buf();
    let lib_path = workspace_root.join("pedant-core/tests/fixtures/dataflow_workspace/src/lib.rs");

    let output = common::run_pedant(&[lib_path.to_str().unwrap(), "--semantic", "--gate"], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The fixture has an env→network flow in leak_env(), so the flow-aware
    // gate rule "env-to-network" should fire.
    assert!(
        stdout.contains("env-to-network"),
        "expected env-to-network flow verdict in gate output, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// 5.T1: CLI --gate output includes quality verdicts when semantic analysis detects issues.
#[cfg(feature = "semantic")]
#[test]
fn test_cli_gate_shows_quality_verdicts() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant crate should be in workspace")
        .to_path_buf();
    let lib_path = workspace_root.join("pedant-core/tests/fixtures/dataflow_workspace/src/lib.rs");

    let output = common::run_pedant(&[lib_path.to_str().unwrap(), "--semantic", "--gate"], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The fixture has a dead store in dead_store(), so the quality gate rule should fire.
    assert!(
        stdout.contains("dead-store"),
        "expected dead-store verdict in gate output, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// 5.T3: Self-analysis with semantic — no deny-level verdicts from quality/perf/concurrency rules.
#[cfg(feature = "semantic")]
#[test]
fn test_self_analysis_clean() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant crate should be in workspace")
        .to_path_buf();

    let src_dirs = [
        workspace_root.join("pedant-core/src"),
        workspace_root.join("pedant-types/src"),
        workspace_root.join("pedant/src"),
        workspace_root.join("pedant-mcp/src"),
    ];

    let mut files: Vec<String> = Vec::new();
    for dir in &src_dirs {
        for file in collect_rs_files(dir) {
            files.push(file.to_string_lossy().into_owned());
        }
    }

    let mut args: Vec<&str> = files.iter().map(String::as_str).collect();
    args.push("--semantic");
    args.push("--gate");
    let output = common::run_pedant(&args, None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Quality rules default to warn, performance to info, concurrency to deny.
    // Pedant's own code should not trigger any deny-level verdicts from new rules.
    let new_deny_rules = ["lock-across-await", "inconsistent-lock-order"];
    for rule in new_deny_rules {
        assert!(
            !stdout.contains(rule),
            "expected no {rule} verdict on self-analysis, stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

/// 8.T1: Self-analysis with DataFlow — no deny-level flow verdicts, reachability annotated.
#[cfg(feature = "semantic")]
#[test]
fn test_self_analysis_dataflow() {
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

    // Run with --semantic --gate: verify no deny-level flow verdicts.
    let mut gate_args: Vec<&str> = files.iter().map(String::as_str).collect();
    gate_args.push("--semantic");
    gate_args.push("--gate");
    let gate_output = common::run_pedant(&gate_args, None);

    let gate_stdout = String::from_utf8_lossy(&gate_output.stdout);
    let gate_stderr = String::from_utf8_lossy(&gate_output.stderr);

    assert!(
        !gate_stdout.contains("deny"),
        "expected no deny-level gate verdicts on self-analysis with DataFlow, stdout:\n{gate_stdout}\nstderr:\n{gate_stderr}"
    );

    // Run with --semantic --capabilities: verify reachability annotations are present.
    let mut cap_args: Vec<&str> = files.iter().map(String::as_str).collect();
    cap_args.push("--semantic");
    cap_args.push("--capabilities");
    let cap_output = common::run_pedant(&cap_args, None);

    let cap_stdout = String::from_utf8_lossy(&cap_output.stdout);
    let cap_stderr = String::from_utf8_lossy(&cap_output.stderr);
    assert!(
        cap_output.status.code() != Some(2),
        "semantic capabilities analysis failed, stderr:\n{cap_stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(extract_json_object(&cap_stdout))
            .expect("should parse capabilities JSON");
    let has_reachable = profile.findings.iter().any(|f| f.reachable.is_some());
    assert!(
        has_reachable,
        "expected reachability annotations on self-analysis findings, stdout:\n{cap_stdout}"
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

// --- Multi-language CLI tests ---

/// 5.T1: Running pedant --capabilities on a Python file produces findings with language metadata.
#[test]
fn test_cli_python_capabilities() {
    let fixture = fixtures_dir().join("network_subprocess.py");
    let output = common::run_pedant(&[fixture.to_str().unwrap(), "--capabilities"], None);

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
    let output = common::run_pedant(&[fixture.to_str().unwrap(), "--capabilities"], None);

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
    let output = common::run_pedant(&[fixture.to_str().unwrap(), "--capabilities"], None);

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
    let output = common::run_pedant(&[fixture.to_str().unwrap(), "--capabilities"], None);

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

    let output = common::run_pedant(&[fixture.to_str().unwrap(), "--capabilities"], None);
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
