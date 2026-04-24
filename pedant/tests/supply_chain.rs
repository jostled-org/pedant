use std::fs;
use std::process::Command;

mod common;

fn write_test_crate(root: &std::path::Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"supply-chain-test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nserde = \"1\"\n",
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub fn demo() { let _ = serde::de::IgnoredAny; }\n",
    )
    .unwrap();
}

fn generate_lockfile(root: &std::path::Path) {
    let output = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(root)
        .output()
        .expect("failed to run cargo generate-lockfile");
    assert!(
        output.status.success(),
        "failed to generate lockfile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_workspace_dependency(root: &std::path::Path) {
    fs::create_dir_all(root.join("member/src")).unwrap();
    fs::create_dir_all(root.join("test_data/lexer/err")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n",
    )
    .unwrap();
    fs::write(
        root.join("member/Cargo.toml"),
        "[package]\nname = \"workspace-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("member/src/lib.rs"), "pub fn real_code() {}\n").unwrap();
    fs::write(
        root.join("test_data/lexer/err/byte_char_literals.rs"),
        "b'\n",
    )
    .unwrap();
}

#[test]
fn supply_chain_init_then_verify_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_test_crate(root);
    generate_lockfile(root);

    let baselines = root.join(".pedant/baselines");
    let init = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let verify = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        verify.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("All dependencies match baselines."));
}

#[test]
fn supply_chain_verify_reports_missing_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_test_crate(root);
    generate_lockfile(root);

    let baselines = root.join(".pedant/baselines");
    let verify = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
            "--fail-on",
            "new-dependency",
        ],
        None,
    );
    assert_eq!(verify.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("new-dependency") || stdout.contains("capabilities:"));
}

#[test]
fn supply_chain_verify_debug_package_emits_hashed_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_test_crate(root);
    generate_lockfile(root);

    let baselines = root.join(".pedant/baselines");
    let init = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
        None,
    );
    assert!(init.status.success());

    let verify = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
            "--debug-package",
            "serde",
        ],
        None,
    );

    assert!(verify.status.success());
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(
        stderr.contains("debug-package: serde@"),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("source_hash:"), "stderr was: {stderr}");
    assert!(stderr.contains("file: ./"), "stderr was: {stderr}");
    assert!(stderr.contains("sha256="), "stderr was: {stderr}");
}

#[test]
fn supply_chain_update_prunes_stale_versions_and_removed_crates() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_test_crate(root);
    generate_lockfile(root);

    let baselines = root.join(".pedant/baselines");
    let init = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
        None,
    );
    assert!(init.status.success());

    let serde_dir = baselines.join("cargo/serde");
    fs::write(serde_dir.join("0.0.0.json"), b"{}" as &[u8]).unwrap();
    let removed_dir = baselines.join("cargo/removed-crate");
    fs::create_dir_all(&removed_dir).unwrap();
    fs::write(removed_dir.join("9.9.9.json"), b"{}" as &[u8]).unwrap();

    let update = common::run_pedant_in(
        root,
        &[
            "supply-chain",
            "update",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        update.status.success(),
        "update failed: {}",
        String::from_utf8_lossy(&update.stderr)
    );

    assert!(serde_dir.is_dir(), "expected serde baseline dir to remain");
    assert!(
        !serde_dir.join("0.0.0.json").exists(),
        "expected stale serde version to be pruned"
    );
    assert!(
        !removed_dir.exists(),
        "expected removed crate baseline dir to be pruned"
    );
}

#[test]
fn supply_chain_ignores_invalid_fixture_rust_outside_workspace_targets() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    fs::create_dir_all(&vendor_root).unwrap();
    write_workspace_dependency(&vendor_root.join("workspace-dep"));

    let workspace = dir.path().join("consumer");
    write_test_crate(&workspace);
    generate_lockfile(&workspace);

    let baselines = workspace.join(".pedant/baselines");
    let real_cargo = Command::new("which")
        .arg("cargo")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| String::from("cargo"));

    let cargo_script = dir.path().join("cargo");
    fs::write(
        &cargo_script,
        format!(
            "#!/bin/sh\nif [ \"$1\" = vendor ]; then\n  mkdir -p \"$2\"\n  cp -R \"{}\"/. \"$2\"\n  exit 0\nfi\nexec {} \"$@\"\n",
            vendor_root.display(),
            real_cargo
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&cargo_script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&cargo_script, permissions).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_pedant"))
        .current_dir(&workspace)
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
