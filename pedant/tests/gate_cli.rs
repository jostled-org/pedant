use std::fs;
use std::path::PathBuf;

mod common;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_gate_cli_build_script_denied() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

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

    let lib_path = root.join("src/lib.rs");
    let output = common::run_pedant(
        &[
            lib_path.to_str().unwrap(),
            "--gate",
            "--attestation",
            "--crate-name",
            "test",
            "--crate-version",
            "0.1.0",
        ],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1 for deny verdict, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // With --attestation, gate text goes to stderr; stdout is clean JSON.
    assert!(
        stderr.contains("build-script-download-exec"),
        "expected 'build-script-download-exec' on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("deny"),
        "expected 'deny' on stderr, got:\n{stderr}"
    );
    // Stdout should be valid attestation JSON.
    assert!(
        stdout.contains("spec_version"),
        "expected attestation JSON on stdout, got:\n{stdout}"
    );
}

#[test]
fn test_gate_cli_clean_crate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "fn lib_fn() {}\n").unwrap();

    let lib_path = root.join("src/lib.rs");
    let output = common::run_pedant(&[lib_path.to_str().unwrap(), "--gate"], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "expected exit code 0 for clean crate, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn test_gate_cli_json_format() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

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

    let lib_path = root.join("src/lib.rs");
    let output = common::run_pedant(
        &[
            lib_path.to_str().unwrap(),
            "--gate",
            "--format",
            "json",
            "--attestation",
            "--crate-name",
            "test",
            "--crate-version",
            "0.1.0",
        ],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let verdicts = payload["gate_verdicts"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    assert!(
        !verdicts.is_empty(),
        "expected at least one gate verdict in JSON output, got:\n{stdout}"
    );

    let has_build_script_rule = verdicts.iter().any(|v| {
        v.get("rule")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| r.contains("build-script"))
    });
    assert!(
        has_build_script_rule,
        "expected a build-script verdict rule in parsed JSON, got: {verdicts:?}"
    );

    let first = &verdicts[0];
    assert!(
        first.get("severity").is_some(),
        "expected severity field in verdict, got: {first:?}"
    );
    assert!(
        first.get("rationale").is_some(),
        "expected rationale field in verdict, got: {first:?}"
    );
}

#[test]
fn test_gate_cli_warn_only_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "fn lib_fn() {}\n").unwrap();
    // build.rs with only process exec (no network) — triggers build-script-exec at warn
    fs::write(
        root.join("build.rs"),
        "use std::process::Command;\nfn main() { Command::new(\"cc\"); }\n",
    )
    .unwrap();

    let lib_path = root.join("src/lib.rs");
    let output = common::run_pedant(&[lib_path.to_str().unwrap(), "--gate"], None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "expected exit code 0 for warn-only verdicts, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("build-script-exec"),
        "expected 'build-script-exec' in output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("warn"),
        "expected 'warn' in output, got:\n{stdout}"
    );
}

#[test]
fn test_gate_cli_with_config_override() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "fn lib_fn() {}\n").unwrap();
    // build.rs with network access — normally triggers build-script-network at deny
    fs::write(root.join("build.rs"), "use reqwest;\nfn main() {}\n").unwrap();
    // Config that downgrades build-script-network from deny to info
    fs::write(
        root.join(".pedant.toml"),
        "[gate]\nbuild-script-network = \"info\"\nbuild-script-download-exec = \"info\"\n",
    )
    .unwrap();

    let lib_path = root.join("src/lib.rs");
    let output = common::run_pedant(
        &[
            lib_path.to_str().unwrap(),
            "--gate",
            "--config",
            root.join(".pedant.toml").to_str().unwrap(),
        ],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "expected exit code 0 after downgrade from deny to info, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// 5.T2: Gate verdicts are evaluated per language (no cross-language false positives).
///
/// A Rust file with env access and a Python file with network access should NOT
/// trigger `env-access-network` when evaluated per language (default).
#[test]
fn test_cli_mixed_rust_python_default_separate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Rust file with env access only.
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "fn f() { std::env::var(\"KEY\"); }\n",
    )
    .unwrap();

    // Python file with network only.
    fs::write(
        root.join("net.py"),
        "import requests\nrequests.get('https://example.com')\n",
    )
    .unwrap();

    let lib_path = root.join("src/lib.rs");
    let py_path = root.join("net.py");
    let output = common::run_pedant(
        &[
            lib_path.to_str().unwrap(),
            py_path.to_str().unwrap(),
            "--gate",
        ],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Per-language evaluation: Rust has env only, Python has network only.
    // Neither language alone has both, so env-access-network should NOT fire.
    assert!(
        !stdout.contains("env-access-network"),
        "expected no cross-language env-access-network verdict, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// 5.T3: Runtime and install-hook findings within the same language are not merged.
///
/// A JS runtime file with network and a package.json postinstall hook should NOT
/// trigger cross-context combination rules.
#[test]
fn test_cli_runtime_and_install_hook_same_language_separate() {
    let js_fixture = fixtures_dir().join("runtime.js");
    let pkg_fixture = fixtures_dir().join("npm_project/package.json");

    let output = common::run_pedant(
        &[
            js_fixture.to_str().unwrap(),
            pkg_fixture.to_str().unwrap(),
            "--gate",
            "--format",
            "json",
        ],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    let payload: serde_json::Value =
        serde_json::from_str(&stdout).expect("should parse JSON output");
    let verdicts = payload["gate_verdicts"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // The JS runtime file has Network. The package.json hook has ProcessExec.
    // These are in different execution contexts, so build-script-download-exec
    // (which checks build hook Network + ProcessExec) should NOT fire.
    let has_download_exec = verdicts.iter().any(|v| {
        v.get("rule")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| r == "build-script-download-exec")
    });

    assert!(
        !has_download_exec,
        "expected no build-script-download-exec when runtime and hook are separate, verdicts: {verdicts:?}"
    );
}

/// 5.T4: --cross-language merges findings from all languages for gate evaluation.
#[test]
fn test_cli_cross_language_flag() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Rust file with env access.
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "fn f() { std::env::var(\"KEY\"); }\n",
    )
    .unwrap();

    // Python file with network access.
    fs::write(
        root.join("net.py"),
        "import requests\nrequests.get('https://example.com')\n",
    )
    .unwrap();

    let lib_path = root.join("src/lib.rs");
    let py_path = root.join("net.py");
    let output = common::run_pedant(
        &[
            lib_path.to_str().unwrap(),
            py_path.to_str().unwrap(),
            "--gate",
            "--cross-language",
        ],
        None,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // With --cross-language, Rust env + Python network should combine to trigger
    // env-access-network.
    assert!(
        stdout.contains("env-access-network"),
        "expected env-access-network verdict with --cross-language, stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
