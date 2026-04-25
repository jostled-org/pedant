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

fn which_cargo() -> String {
    Command::new("which")
        .arg("cargo")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| String::from("cargo"))
}

fn write_fake_cargo_script(
    script_path: &std::path::Path,
    vendor_source: &std::path::Path,
    real_cargo: &str,
) {
    fs::write(
        script_path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = vendor ]; then\n  mkdir -p \"$2\"\n  cp -R \"{}\"/. \"$2\"\n  exit 0\nfi\nexec {} \"$@\"\n",
            vendor_source.display(),
            real_cargo
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_path, perms).unwrap();
    }
}

fn write_minimal_consumer(root: &std::path::Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "").unwrap();
    generate_lockfile(root);
}

fn run_with_fake_vendor(
    script_dir: &std::path::Path,
    consumer_root: &std::path::Path,
    vendor_source: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let real_cargo = which_cargo();
    let cargo_script = script_dir.join("cargo");
    write_fake_cargo_script(&cargo_script, vendor_source, &real_cargo);

    Command::new(env!("CARGO_BIN_EXE_pedant"))
        .current_dir(consumer_root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                script_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args(args)
        .output()
        .unwrap()
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
    let output = run_with_fake_vendor(
        dir.path(),
        &workspace,
        &vendor_root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );

    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn debug_package_ignores_invalid_unreachable_src_file() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    let crate_dir = vendor_root.join("test-lib");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"test-lib\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(crate_dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
    fs::write(crate_dir.join("src/minicore.rs"), "b'\n").unwrap();

    let consumer = dir.path().join("consumer");
    write_minimal_consumer(&consumer);
    let baselines = consumer.join(".pedant/baselines");

    let output = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
            "--debug-package",
            "test-lib",
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("debug-package: test-lib@"),
        "expected debug output, stderr was: {stderr}"
    );
    assert!(
        stderr.contains("file: ./src/lib.rs"),
        "expected lib.rs in debug output, stderr was: {stderr}"
    );
    assert!(
        !stderr.contains("minicore"),
        "unreachable minicore.rs should not appear in debug output, stderr was: {stderr}"
    );
}

#[test]
fn debug_package_includes_reachable_nested_modules_from_entry_file() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    let crate_dir = vendor_root.join("test-nested");
    fs::create_dir_all(crate_dir.join("src/nested")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"test-nested\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        "mod nested;\npub fn hello() {}\n",
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/nested/mod.rs"),
        "mod leaf;\npub fn mid() {}\n",
    )
    .unwrap();
    fs::write(crate_dir.join("src/nested/leaf.rs"), "pub fn deep() {}\n").unwrap();

    let consumer = dir.path().join("consumer");
    write_minimal_consumer(&consumer);
    let baselines = consumer.join(".pedant/baselines");

    let output = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
            "--debug-package",
            "test-nested",
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("debug-package: test-nested@"),
        "expected debug output, stderr was: {stderr}"
    );
    assert!(
        stderr.contains("file: ./src/lib.rs"),
        "expected lib.rs, stderr was: {stderr}"
    );
    assert!(
        stderr.contains("file: ./src/nested/mod.rs"),
        "expected nested/mod.rs, stderr was: {stderr}"
    );
    assert!(
        stderr.contains("file: ./src/nested/leaf.rs"),
        "expected nested/leaf.rs, stderr was: {stderr}"
    );
}

#[test]
fn debug_package_includes_autobin_entrypoints_without_scanning_entire_src_tree() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    let crate_dir = vendor_root.join("test-bins");
    fs::create_dir_all(crate_dir.join("src/bin")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"test-bins\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(crate_dir.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(crate_dir.join("src/bin/tool.rs"), "fn main() {}\n").unwrap();
    fs::write(crate_dir.join("src/fixture.rs"), "b'\n").unwrap();

    let consumer = dir.path().join("consumer");
    write_minimal_consumer(&consumer);
    let baselines = consumer.join(".pedant/baselines");

    let output = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
            "--debug-package",
            "test-bins",
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("debug-package: test-bins@"),
        "expected debug output, stderr was: {stderr}"
    );
    assert!(
        stderr.contains("file: ./src/main.rs"),
        "expected main.rs, stderr was: {stderr}"
    );
    assert!(
        stderr.contains("file: ./src/bin/tool.rs"),
        "expected bin/tool.rs, stderr was: {stderr}"
    );
    assert!(
        !stderr.contains("fixture"),
        "unreachable fixture.rs should not appear, stderr was: {stderr}"
    );
}

#[test]
fn verify_ignores_invalid_unreachable_src_file() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    let crate_dir = vendor_root.join("test-verify");
    fs::create_dir_all(crate_dir.join("src/inner")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"test-verify\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        "mod inner;\npub fn api() {}\n",
    )
    .unwrap();
    fs::write(crate_dir.join("src/inner/mod.rs"), "pub fn helper() {}\n").unwrap();
    // Invalid Rust outside the module graph
    fs::write(crate_dir.join("src/broken_fixture.rs"), "b'\n").unwrap();

    let consumer = dir.path().join("consumer");
    write_minimal_consumer(&consumer);
    let baselines = consumer.join(".pedant/baselines");

    // Init to create baselines
    let init = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    assert!(
        init.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    // Verify against the baseline
    let verify = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(
        verify.status.success(),
        "verify failed: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("All dependencies match baselines."),
        "expected clean verify, stdout={stdout}"
    );
    assert!(
        !stderr.contains("broken_fixture"),
        "invalid unreachable file should not appear, stderr={stderr}"
    );
}

#[test]
fn init_and_verify_round_trip_uses_only_reachable_files() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    let crate_dir = vendor_root.join("round-trip");
    fs::create_dir_all(crate_dir.join("src/sub")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"round-trip\"\nversion = \"0.2.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        crate_dir.join("src/lib.rs"),
        "mod sub;\npub fn entry() {}\n",
    )
    .unwrap();
    fs::write(crate_dir.join("src/sub/mod.rs"), "pub fn leaf() {}\n").unwrap();
    // Unreachable invalid Rust file
    fs::write(crate_dir.join("src/orphan.rs"), "b'\n").unwrap();

    let consumer = dir.path().join("consumer");
    write_minimal_consumer(&consumer);
    let baselines = consumer.join(".pedant/baselines");

    // Init
    let init = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Read the baseline to confirm only reachable files were hashed
    let baseline_path = baselines.join("cargo/round-trip/0.2.0.json");
    assert!(
        baseline_path.is_file(),
        "expected baseline file at {baseline_path:?}"
    );

    // Verify round-trip
    let verify = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(
        verify.status.success(),
        "verify failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        stdout.contains("All dependencies match baselines."),
        "expected clean verify, stdout={stdout}"
    );

    // Debug output should list only reachable files
    let debug = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
            "--debug-package",
            "round-trip",
        ],
    );
    let stderr = String::from_utf8_lossy(&debug.stderr);
    assert!(
        stderr.contains("file: ./src/lib.rs"),
        "expected lib.rs in debug output, stderr={stderr}"
    );
    assert!(
        stderr.contains("file: ./src/sub/mod.rs"),
        "expected sub/mod.rs in debug output, stderr={stderr}"
    );
    assert!(
        !stderr.contains("orphan"),
        "unreachable orphan.rs should not appear, stderr={stderr}"
    );
}

#[test]
fn update_prunes_and_rehashes_using_reachable_file_set() {
    let dir = tempfile::tempdir().unwrap();
    let vendor_root = dir.path().join("vendor");
    let crate_dir = vendor_root.join("evolving");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"evolving\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(crate_dir.join("src/lib.rs"), "pub fn v1() {}\n").unwrap();
    // Unreachable invalid file present in both versions
    fs::write(crate_dir.join("src/junk.rs"), "b'\n").unwrap();

    let consumer = dir.path().join("consumer");
    write_minimal_consumer(&consumer);
    let baselines = consumer.join(".pedant/baselines");

    // Init v0.1.0
    let init = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "init",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(baselines.join("cargo/evolving/0.1.0.json").is_file());

    // Evolve to v0.2.0: change manifest version, add a reachable module, keep invalid file
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"evolving\"\nversion = \"0.2.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::create_dir_all(crate_dir.join("src/extra")).unwrap();
    fs::write(crate_dir.join("src/lib.rs"), "mod extra;\npub fn v2() {}\n").unwrap();
    fs::write(crate_dir.join("src/extra/mod.rs"), "pub fn added() {}\n").unwrap();
    // junk.rs still present and invalid

    // Update
    let update = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "update",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    assert!(
        update.status.success(),
        "update failed: stderr={}",
        String::from_utf8_lossy(&update.stderr)
    );

    // Stale v0.1.0 baseline should be pruned
    assert!(
        !baselines.join("cargo/evolving/0.1.0.json").exists(),
        "stale v0.1.0 baseline should be pruned"
    );
    // New v0.2.0 baseline should exist
    assert!(
        baselines.join("cargo/evolving/0.2.0.json").is_file(),
        "expected v0.2.0 baseline"
    );

    // Verify the new baseline matches
    let verify = run_with_fake_vendor(
        dir.path(),
        &consumer,
        &vendor_root,
        &[
            "supply-chain",
            "verify",
            "--baseline-path",
            baselines.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(
        verify.status.success(),
        "verify after update failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        stdout.contains("All dependencies match baselines."),
        "expected clean verify after update, stdout={stdout}"
    );
}
