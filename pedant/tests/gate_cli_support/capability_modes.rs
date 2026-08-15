//! The eight retained file-mode capability and cross-language predicates.
//!
//! Every input and expectation is unchanged. Each child runs under the
//! package-shared process guard, so a row asserts after its whole tree is
//! killed, reaped, and drained; and each negative row first proves its corpus
//! still carries the capabilities the absent verdict is about.

use std::path::PathBuf;

use crate::fixture::{ProjectFixture, ROOT_MANIFEST, json_payload};

/// The build script that downloads and executes.
const DOWNLOAD_EXEC_BUILD_SCRIPT: &str = concat!(
    "use reqwest;\n",
    "use std::process::Command;\n",
    "fn main() { Command::new(\"cc\"); }\n",
);

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A crate whose build script states the given source, or none at all.
fn crate_with_build_script(build_script: Option<&str>) -> ProjectFixture {
    let fixture = ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "fn lib_fn() {}\n"),
    ]);
    if let Some(source) = build_script {
        fixture.write("build.rs", source);
    }
    fixture
}

pub(crate) fn test_gate_cli_build_script_denied() {
    let fixture = crate_with_build_script(Some(DOWNLOAD_EXEC_BUILD_SCRIPT));
    let run = fixture.gate_in_root(&[fixture.path_arg("src/lib.rs").as_str()]);

    assert_eq!(
        run.code(),
        Some(1),
        "expected exit code 1 for deny verdict, {}",
        run.transcript()
    );
    assert!(
        run.stdout.contains("build-script-download-exec"),
        "expected 'build-script-download-exec' in output, got:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("deny"),
        "expected 'deny' in output, got:\n{}",
        run.stdout
    );
}

pub(crate) fn test_gate_cli_clean_crate() {
    let fixture = crate_with_build_script(None);
    let run = fixture.gate_in_root(&[fixture.path_arg("src/lib.rs").as_str()]);

    assert!(
        run.success(),
        "expected exit code 0 for clean crate, {}",
        run.transcript()
    );
}

pub(crate) fn test_gate_cli_json_format() {
    let fixture = crate_with_build_script(Some(DOWNLOAD_EXEC_BUILD_SCRIPT));
    let run = fixture.gate_in_root(&[fixture.path_arg("src/lib.rs").as_str(), "--format", "json"]);

    let payload = json_payload(&run);
    let verdicts = payload["gate_verdicts"]
        .as_array()
        .expect("gate output reports gate_verdicts");

    assert!(
        !verdicts.is_empty(),
        "expected at least one gate verdict in JSON output, got:\n{}",
        run.stdout
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

    // The gate receives the flat profile and applies no symbol policy, so no
    // symbol field may reach its published JSON.
    for field in ["\"symbols\"", "\"symbol_attribution\""] {
        assert!(
            !run.stdout.contains(field),
            "gate JSON must not carry {field}:\n{}",
            run.stdout
        );
    }
}

pub(crate) fn test_gate_cli_warn_only_exit_zero() {
    // build.rs with only process exec (no network) — triggers build-script-exec at warn
    let fixture = crate_with_build_script(Some(
        "use std::process::Command;\nfn main() { Command::new(\"cc\"); }\n",
    ));
    let run = fixture.gate_in_root(&[fixture.path_arg("src/lib.rs").as_str()]);

    assert!(
        run.success(),
        "expected exit code 0 for warn-only verdicts, {}",
        run.transcript()
    );
    assert!(
        run.stdout.contains("build-script-exec"),
        "expected 'build-script-exec' in output, got:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("warn"),
        "expected 'warn' in output, got:\n{}",
        run.stdout
    );
}

pub(crate) fn test_gate_cli_with_config_override() {
    // build.rs with network access — normally triggers build-script-network at deny
    let fixture = crate_with_build_script(Some("use reqwest;\nfn main() {}\n"));
    // Config that downgrades build-script-network from deny to info
    fixture.write(
        ".pedant.toml",
        "[gate]\nbuild-script-network = \"info\"\nbuild-script-download-exec = \"info\"\n",
    );
    let run = fixture.gate_in_root(&[
        fixture.path_arg("src/lib.rs").as_str(),
        "--config",
        fixture.path_arg(".pedant.toml").as_str(),
    ]);

    assert!(
        run.success(),
        "expected exit code 0 after downgrade from deny to info, {}",
        run.transcript()
    );
}

/// Every capability the mixed-language corpus must still declare.
///
/// The verdict this row is about fires only where both are read together, so a
/// corpus that stopped declaring either would make the absence meaningless.
const MIXED_CAPABILITIES: &[&str] = &["env_access", "network"];

/// Every capability the runtime-and-hook corpus must still declare.
const RUNTIME_HOOK_CAPABILITIES: &[&str] = &["process_exec", "network"];

/// 5.T2: Gate verdicts are evaluated per language (no cross-language false positives).
///
/// A Rust file with env access and a Python file with network access should NOT
/// trigger `env-access-network` when evaluated per language (default).
pub(crate) fn test_cli_mixed_rust_python_default_separate() {
    let fixture = mixed_language_project();
    let inputs = [fixture.path_arg("src/lib.rs"), fixture.path_arg("net.py")];
    assert_capabilities_present(&fixture, &inputs, MIXED_CAPABILITIES);

    let run = fixture.gate_in_root(&[inputs[0].as_str(), inputs[1].as_str(), "--format", "json"]);
    assert!(
        run.success(),
        "per-language evaluation of a clean corpus exits 0, {}",
        run.transcript()
    );

    // Per-language evaluation: Rust has env only, Python has network only.
    // Neither language alone has both, so env-access-network should NOT fire.
    let payload = json_payload(&run);
    assert!(
        !reported_rules(&payload).contains(&"env-access-network"),
        "expected no cross-language env-access-network verdict, {}",
        run.transcript()
    );
}

/// 5.T3: Runtime and install-hook findings within the same language are not merged.
///
/// A JS runtime file with network and a package.json postinstall hook should NOT
/// trigger cross-context combination rules.
pub(crate) fn test_cli_runtime_and_install_hook_same_language_separate() {
    let fixture = ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "fn lib_fn() {}\n"),
    ]);
    let inputs = [
        crate::fixture::path_text(&fixtures_dir().join("runtime.js")),
        crate::fixture::path_text(&fixtures_dir().join("npm_project/package.json")),
    ];
    assert_capabilities_present(&fixture, &inputs, RUNTIME_HOOK_CAPABILITIES);

    let run = fixture.gate_in_root(&[inputs[0].as_str(), inputs[1].as_str(), "--format", "json"]);
    assert!(
        run.success(),
        "separate execution contexts produce no deny, {}",
        run.transcript()
    );

    // The JS runtime file has Network. The package.json hook has ProcessExec.
    // These are in different execution contexts, so build-script-download-exec
    // (which checks build hook Network + ProcessExec) should NOT fire.
    let payload = json_payload(&run);
    assert!(
        !reported_rules(&payload).contains(&"build-script-download-exec"),
        "expected no build-script-download-exec when runtime and hook are separate, {}",
        run.transcript()
    );
}

/// 5.T4: --cross-language merges findings from all languages for gate evaluation.
pub(crate) fn test_cli_cross_language_flag() {
    let fixture = mixed_language_project();
    let run = fixture.gate_in_root(&[
        fixture.path_arg("src/lib.rs").as_str(),
        fixture.path_arg("net.py").as_str(),
        "--cross-language",
    ]);

    // With --cross-language, Rust env + Python network should combine to trigger
    // env-access-network.
    assert!(
        run.stdout.contains("env-access-network"),
        "expected env-access-network verdict with --cross-language, {}",
        run.transcript()
    );
}

/// Every rule name one gate run reported, borrowed from its parsed payload.
fn reported_rules(payload: &serde_json::Value) -> Vec<&str> {
    payload["gate_verdicts"]
        .as_array()
        .expect("gate output reports gate_verdicts")
        .iter()
        .map(|verdict| verdict["rule"].as_str().expect("a rule name is a string"))
        .collect()
}

/// The same inputs, read through `pedant capabilities`, still declare every
/// capability the absent verdict would have combined.
fn assert_capabilities_present(fixture: &ProjectFixture, inputs: &[String], expected: &[&str]) {
    let mut args: Vec<&str> = vec!["capabilities"];
    args.extend(inputs.iter().map(String::as_str));
    let run = fixture.run(&args);
    assert!(
        run.success(),
        "the corpus must be readable: {}",
        run.transcript()
    );
    let payload = json_payload(&run);
    let found: Vec<&str> = payload["findings"]
        .as_array()
        .expect("the capability profile reports findings")
        .iter()
        .map(|finding| {
            finding["capability"]
                .as_str()
                .expect("a capability name is a string")
        })
        .collect();
    for capability in expected {
        assert!(
            found.contains(capability),
            "the corpus no longer declares {capability}, so the absent verdict proves nothing: {}",
            run.stdout
        );
    }
}

/// A Rust file with env access beside a Python file with network access.
fn mixed_language_project() -> ProjectFixture {
    ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "fn f() { std::env::var(\"KEY\"); }\n"),
        (
            "net.py",
            "import requests\nrequests.get('https://example.com')\n",
        ),
    ])
}
