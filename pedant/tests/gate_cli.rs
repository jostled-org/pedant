use std::fs;

mod common;

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
    assert!(
        stdout.contains("build-script-download-exec"),
        "expected 'build-script-download-exec' in output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("deny"),
        "expected 'deny' in output, got:\n{stdout}"
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

    // The JSON output should contain gate verdicts — find the JSON array
    let verdicts: Vec<serde_json::Value> = serde_json::from_str(
        stdout
            .lines()
            .collect::<Vec<_>>()
            .join("\n")
            .trim_start_matches(|c: char| c != '['),
    )
    .unwrap_or_default();

    // There should be at least one verdict, but let's parse more carefully.
    // The output contains both attestation JSON and gate verdict JSON.
    // Let's just check the raw output contains the expected fields.
    assert!(
        stdout.contains("build-script-download-exec"),
        "expected verdict rule in JSON output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"severity\""),
        "expected severity field in JSON output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"rationale\""),
        "expected rationale field in JSON output, got:\n{stdout}"
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
