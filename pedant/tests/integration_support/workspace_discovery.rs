#[cfg(feature = "semantic")]
use std::fs;

// --- Semantic CLI tests (feature-gated) ---

#[test]
fn test_project_checks_report_workspace_discovery_errors() {
    let dir = tempfile::tempdir().unwrap();
    let package = dir.path().join("package");
    let source = package.join("src/lib.rs");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(
        package.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"broken-workspace-pointer\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../missing-workspace\"\n",
        ),
    )
    .unwrap();
    std::fs::write(&source, "pub fn checked() {}\n").unwrap();

    let output = common::run_subcommand("check", &[source.to_str().unwrap()], None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "workspace discovery errors must fail the run, stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("failed to discover workspace root for")
            && stderr.contains("missing-workspace/Cargo.toml"),
        "expected the source and pointed manifest context, got:\n{stderr}"
    );
}

#[cfg(feature = "semantic")]
#[test]
fn test_semantic_cli_flag_exists() {
    let output = common::run_pedant(&["capabilities", "--help"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--semantic"),
        "expected capabilities --help to list --semantic flag, got:\n{stdout}"
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
    let output = common::run_subcommand(
        "capabilities",
        &[lib_path.to_str().unwrap(), "--semantic"],
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
    let output = common::run_subcommand(
        "capabilities",
        &[
            outside_path.to_str().unwrap(),
            workspace_file.to_str().unwrap(),
            "--semantic",
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
fn test_semantic_cli_does_not_mask_workspace_discovery_errors() {
    let dir = tempfile::tempdir().unwrap();
    let broken_package = dir.path().join("broken-package");
    let valid_package = dir.path().join("valid-package");
    let broken_source = broken_package.join("src/lib.rs");
    let valid_source = valid_package.join("src/lib.rs");
    fs::create_dir_all(broken_source.parent().unwrap()).unwrap();
    fs::create_dir_all(valid_source.parent().unwrap()).unwrap();
    fs::write(
        broken_package.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"broken-workspace-pointer\"\n",
            "version = \"0.1.0\"\n",
            "workspace = \"../missing-workspace\"\n",
        ),
    )
    .unwrap();
    fs::write(
        valid_package.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"valid-workspace\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2021\"\n",
            "\n[workspace]\n",
        ),
    )
    .unwrap();
    fs::write(&broken_source, "pub fn broken() {}\n").unwrap();
    fs::write(&valid_source, "pub fn valid() {}\n").unwrap();

    let output = common::run_subcommand(
        "capabilities",
        &[
            broken_source.to_str().unwrap(),
            valid_source.to_str().unwrap(),
            "--semantic",
        ],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("failed to discover workspace root for")
            && stderr.contains("broken-package/src/lib.rs"),
        "expected the first file's discovery error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("semantic: loaded workspace"),
        "a later valid root must not mask an earlier discovery error:\n{stderr}"
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

    // Run without --semantic to get baseline capabilities.
    let base_args: Vec<&str> = files.iter().map(String::as_str).collect();
    let base_output = common::run_subcommand("capabilities", &base_args, None);
    let base_stdout = String::from_utf8_lossy(&base_output.stdout);
    assert!(
        base_output.status.code() != Some(2),
        "base analysis failed, stderr: {}",
        String::from_utf8_lossy(&base_output.stderr)
    );
    let base_profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&base_stdout).expect("should parse base capabilities");

    // Run with --semantic.
    let mut sem_args: Vec<&str> = files.iter().map(String::as_str).collect();
    sem_args.push("--semantic");
    let sem_output = common::run_subcommand("capabilities", &sem_args, None);

    let sem_stdout = String::from_utf8_lossy(&sem_output.stdout);
    let stderr = String::from_utf8_lossy(&sem_output.stderr);
    assert!(
        sem_output.status.code() != Some(2),
        "semantic analysis failed, stderr: {stderr}"
    );

    let sem_profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&sem_stdout).expect("should parse semantic capabilities");

    // Semantic analysis should detect the same set of capabilities as syntactic.
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

    let output = common::run_subcommand(
        "capabilities",
        &[lib_path.to_str().unwrap(), "--semantic"],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Exit code 1 is expected when the fixture intentionally triggers style violations.
    assert!(
        output.status.code() != Some(2),
        "expected no error exit, stderr:\n{stderr}"
    );

    // Parse the capabilities profile and verify semantic reachability is exposed.
    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&stdout).expect("should parse capabilities JSON");
    let has_reachable = profile.findings.iter().any(|f| f.reachable.is_some());
    assert!(
        has_reachable,
        "expected at least one finding with reachable annotated, stdout:\n{stdout}"
    );
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

    let output = common::run_subcommand("gate", &[lib_path.to_str().unwrap(), "--semantic"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The fixture has an env-to-network flow in leak_env().
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

    let output = common::run_subcommand("gate", &[lib_path.to_str().unwrap(), "--semantic"], None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The fixture has a dead store in dead_store().
    assert!(
        stdout.contains("dead-store"),
        "expected dead-store verdict in gate output, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// 5.T3: Self-analysis with semantic has no deny-level quality or concurrency verdicts.
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
    let output = common::run_subcommand("gate", &args, None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Quality rules default to warn, performance to info, concurrency to deny.
    let new_deny_rules = ["lock-across-await", "inconsistent-lock-order"];
    for rule in new_deny_rules {
        assert!(
            !stdout.contains(rule),
            "expected no {rule} verdict on self-analysis, stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

/// 8.T1: Self-analysis with DataFlow has no deny verdicts and annotates reachability.
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

    // Gate mode must remain free of deny-level flow verdicts.
    let mut gate_args: Vec<&str> = files.iter().map(String::as_str).collect();
    gate_args.push("--semantic");
    let gate_output = common::run_subcommand("gate", &gate_args, None);
    let gate_stdout = String::from_utf8_lossy(&gate_output.stdout);
    let gate_stderr = String::from_utf8_lossy(&gate_output.stderr);

    assert!(
        !gate_stdout.contains("deny"),
        "expected no deny-level gate verdicts on self-analysis with DataFlow, stdout:\n{gate_stdout}\nstderr:\n{gate_stderr}"
    );

    // Capabilities mode must preserve reachability annotations.
    let mut cap_args: Vec<&str> = files.iter().map(String::as_str).collect();
    cap_args.push("--semantic");
    let cap_output = common::run_subcommand("capabilities", &cap_args, None);
    let cap_stdout = String::from_utf8_lossy(&cap_output.stdout);
    let cap_stderr = String::from_utf8_lossy(&cap_output.stderr);
    assert!(
        cap_output.status.code() != Some(2),
        "semantic capabilities analysis failed, stderr:\n{cap_stderr}"
    );

    let profile: pedant_types::CapabilityProfile =
        serde_json::from_str(&cap_stdout).expect("should parse capabilities JSON");
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
    let output =
        common::run_subcommand("check", &[file_path.to_str().unwrap(), "--semantic"], None);

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
