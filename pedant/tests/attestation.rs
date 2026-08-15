use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::hash::compute_source_hash;
use pedant_types::{AnalysisTier, AttestationContent, Capability, CapabilityProfile};

mod common;

/// One temporary crate on disk and the CLI runs a case makes against it.
///
/// The `#[path]` is required. Default resolution would place the file in
/// `tests/attestation/`, which pedant's `conflicting-module-root` rule rejects
/// beside `attestation.rs`, and its advice — fold the root into
/// `attestation/mod.rs` — does not apply to a cargo test root, since cargo
/// builds a test executable per `tests/*.rs` and would stop building this one.
/// A sibling directory satisfies both: cargo declares no target for it, because
/// it holds no `main.rs`.
#[path = "attestation_support/crate_fixture.rs"]
mod crate_fixture;

use crate_fixture::{CrateFixture, FILE_READ_LIB, PLAIN_MANIFEST, PROCESS_BUILD_SCRIPT, decoded};

// --- Hash unit tests ---

#[test]
fn test_source_hash_deterministic() {
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("a.rs"), Arc::from("fn main() {}"));
    sources.insert(Arc::from("b.rs"), Arc::from("fn helper() {}"));

    let hash1 = compute_source_hash(&sources);
    let hash2 = compute_source_hash(&sources);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_source_hash_sorted_order() {
    let mut sources_a = BTreeMap::new();
    sources_a.insert(Arc::from("b.rs"), Arc::from("second"));
    sources_a.insert(Arc::from("a.rs"), Arc::from("first"));

    let mut sources_b = BTreeMap::new();
    sources_b.insert(Arc::from("a.rs"), Arc::from("first"));
    sources_b.insert(Arc::from("b.rs"), Arc::from("second"));

    assert_eq!(
        compute_source_hash(&sources_a),
        compute_source_hash(&sources_b)
    );
}

#[test]
fn test_source_hash_known_value() {
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("test.rs"), Arc::from("hello"));

    let hash = compute_source_hash(&sources);
    assert_eq!(
        hash.as_ref(),
        "1fd425805ca3337961be47d3ff75858708d9c19d92701bde9033e69a046fc0fc"
    );
}

#[test]
fn test_source_hash_empty() {
    let sources: BTreeMap<Arc<str>, Arc<str>> = BTreeMap::new();
    let hash = compute_source_hash(&sources);
    // SHA-256 of empty string
    assert_eq!(
        hash.as_ref(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// --- CLI integration tests ---

#[test]
fn test_attestation_cli_missing_args() {
    let output = common::run_subcommand("attestation", &["--stdin"], None);
    assert!(!output.status.success());
}

#[test]
fn test_attestation_cli_output_structure() {
    let output = common::run_subcommand(
        "attestation",
        &[
            "--stdin",
            "--crate-name",
            "test-crate",
            "--crate-version",
            "0.1.0",
        ],
        Some("fn main() {}\n"),
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let attestation: AttestationContent =
        serde_json::from_slice(&output.stdout).expect("should parse as AttestationContent");

    assert_eq!(attestation.spec_version.as_ref(), "0.1.0");
    assert_eq!(attestation.analysis_tier, AnalysisTier::Syntactic);
    assert_eq!(attestation.crate_name.as_ref(), "test-crate");
    assert_eq!(attestation.crate_version.as_ref(), "0.1.0");
    assert_eq!(attestation.source_hash.len(), 64);
    assert!(
        attestation
            .source_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
    assert!(
        attestation.profile.findings.is_empty(),
        "`fn main() {{}}` exercises no capability: {:?}",
        attestation.profile.findings
    );
    assert_no_symbol_fields(&output.stdout);
}

#[test]
fn test_attestation_has_findings() {
    let output = common::run_subcommand(
        "attestation",
        &[
            "--stdin",
            "--crate-name",
            "net-crate",
            "--crate-version",
            "1.0.0",
        ],
        Some("use std::net::TcpStream;\n"),
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let attestation: AttestationContent = serde_json::from_slice(&output.stdout).unwrap();

    assert!(
        attestation
            .profile
            .findings
            .iter()
            .any(|f| f.capability == pedant_types::Capability::Network)
    );
}

#[test]
fn test_capabilities_flag_unchanged() {
    let output = common::run_subcommand(
        "capabilities",
        &["--stdin"],
        Some("use std::net::TcpStream;\n"),
    );

    assert!(output.status.success());

    let profile: CapabilityProfile = serde_json::from_slice(&output.stdout)
        .expect("--capabilities should output CapabilityProfile, not AttestationContent");

    let rendered: Vec<(pedant_types::Capability, &str, usize, usize)> = profile
        .findings
        .iter()
        .map(|finding| {
            (
                finding.capability,
                &*finding.evidence,
                finding.location.line,
                finding.location.column,
            )
        })
        .collect();
    assert_eq!(
        rendered,
        [(
            pedant_types::Capability::Network,
            "std::net::TcpStream",
            1,
            1
        )],
        "the capability CLI prints exactly the flat profile it always did"
    );
    assert_no_symbol_fields(&output.stdout);
}

/// The published capability wire shapes carry no lexical symbol data: symbol
/// evidence is a library projection, not an operator or persisted surface.
fn assert_no_symbol_fields(payload: &[u8]) {
    let text = String::from_utf8_lossy(payload);
    for field in ["\"symbols\"", "\"symbol_attribution\""] {
        assert!(
            !text.contains(field),
            "output must not carry {field}: {text}"
        );
    }
}

#[test]
fn test_attestation_timestamp_reasonable() {
    let output = common::run_subcommand(
        "attestation",
        &[
            "--stdin",
            "--crate-name",
            "ts-crate",
            "--crate-version",
            "0.0.1",
        ],
        Some("fn main() {}\n"),
    );

    let attestation: AttestationContent = serde_json::from_slice(&output.stdout).unwrap();

    // 2024-01-01 to 2030-01-01 in unix seconds
    let min_ts: u64 = 1_704_067_200;
    let max_ts: u64 = 1_893_456_000;
    assert!(
        attestation.timestamp >= min_ts && attestation.timestamp <= max_ts,
        "timestamp {} not in reasonable range",
        attestation.timestamp
    );
}

// --- Build script discovery tests ---

#[test]
fn test_attestation_includes_build_script() {
    let fixture = CrateFixture::new(PLAIN_MANIFEST);
    fixture.write("src/lib.rs", FILE_READ_LIB);
    fixture.write("build.rs", PROCESS_BUILD_SCRIPT);

    let attestation: AttestationContent = decoded(&fixture.attest("src/lib.rs"));
    let findings = &attestation.profile.findings;

    // lib.rs should produce FileRead with no execution context
    assert!(
        findings
            .iter()
            .any(|f| f.capability == Capability::FileRead && f.execution_context.is_none()),
        "expected FileRead from lib.rs, findings: {findings:?}"
    );
    // build.rs should produce ProcessExec with BuildHook execution context
    assert!(
        findings
            .iter()
            .any(|f| f.capability == Capability::ProcessExec && f.is_build_hook()),
        "expected ProcessExec from build.rs, findings: {findings:?}"
    );
}

#[test]
fn test_attestation_custom_build_path() {
    let fixture = CrateFixture::new(
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"custom_build.rs\"\n",
    );
    fixture.write("src/lib.rs", "fn lib_fn() {}\n");
    fixture.write(
        "custom_build.rs",
        "use std::net::TcpStream;\nfn main() {}\n",
    );

    let attestation: AttestationContent = decoded(&fixture.attest("src/lib.rs"));

    assert!(
        attestation
            .profile
            .findings
            .iter()
            .any(|f| f.capability == Capability::Network && f.is_build_hook()),
        "expected Network from custom_build.rs, findings: {:?}",
        attestation.profile.findings
    );
}

#[test]
fn test_attestation_no_build_script() {
    let fixture = CrateFixture::new(PLAIN_MANIFEST);
    fixture.write("src/lib.rs", FILE_READ_LIB);
    // No build.rs

    let attestation: AttestationContent = decoded(&fixture.attest("src/lib.rs"));

    assert!(
        attestation
            .profile
            .findings
            .iter()
            .all(|f| f.execution_context.is_none()),
        "no findings should have an execution context"
    );
    assert!(
        !attestation.profile.findings.is_empty(),
        "normal analysis should still produce findings"
    );
}

#[test]
fn test_single_file_mode_unchanged() {
    let fixture = CrateFixture::new(PLAIN_MANIFEST);
    fixture.write("src/lib.rs", FILE_READ_LIB);
    fixture.write("build.rs", PROCESS_BUILD_SCRIPT);

    // Non-attestation mode: just run pedant on the file with `capabilities`.
    let profile: CapabilityProfile = decoded(&fixture.run("capabilities", "src/lib.rs"));

    // Should include build script findings (build scripts are always discovered)
    assert!(
        profile.findings.iter().any(|f| f.is_build_hook()),
        "capabilities mode should discover build scripts"
    );
    // Should also have non-build-script findings from lib.rs
    assert!(
        profile
            .findings
            .iter()
            .any(|f| f.execution_context.is_none()),
        "capabilities mode should include source file findings"
    );
}

#[test]
fn test_explicit_build_script_path_is_analyzed_as_build_hook() {
    let fixture = CrateFixture::new(PLAIN_MANIFEST);
    fixture.write("build.rs", PROCESS_BUILD_SCRIPT);

    let profile: CapabilityProfile = decoded(&fixture.run("capabilities", "build.rs"));
    assert!(
        profile.findings.iter().any(|f| f.is_build_hook()),
        "expected build-hook findings, got: {:?}",
        profile.findings
    );
}

// --- Semantic attestation tier tests ---

#[cfg(feature = "semantic")]
#[test]
fn test_semantic_attestation_tier() {
    let fixture = CrateFixture::new(
        "[package]\nname = \"tier-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    let lib_path = fixture.write("src/lib.rs", "pub fn f() {}\n");

    let output = common::run_subcommand(
        "attestation",
        &[
            lib_path.to_str().expect("a temporary path is valid UTF-8"),
            "--semantic",
            "--crate-name",
            "tier-test",
            "--crate-version",
            "0.1.0",
        ],
        None,
    );

    let attestation: AttestationContent = decoded(&output);

    assert_eq!(
        attestation.analysis_tier,
        AnalysisTier::Semantic,
        "expected semantic tier when --semantic is used"
    );
}

#[test]
fn attestation_cli_omits_rust_version_for_regular_cli_attestations() {
    let output = common::run_subcommand(
        "attestation",
        &[
            "--stdin",
            "--crate-name",
            "msrv-omitted",
            "--crate-version",
            "0.1.0",
        ],
        Some("fn main() {}\n"),
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let raw = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let attestation: AttestationContent =
        serde_json::from_str(&raw).expect("should parse as AttestationContent");

    assert!(
        attestation.rust_version.is_none(),
        "regular attestation CLI must not populate rust_version"
    );
    assert!(
        !raw.contains("rust_version"),
        "regular attestation JSON must omit rust_version, got: {raw}"
    );
}

#[test]
fn test_nonsemantic_attestation_tier_unchanged() {
    let output = common::run_subcommand(
        "attestation",
        &[
            "--stdin",
            "--crate-name",
            "syn-test",
            "--crate-version",
            "0.1.0",
        ],
        Some("fn main() {}\n"),
    );

    assert!(output.status.success());

    let attestation: AttestationContent =
        serde_json::from_slice(&output.stdout).expect("should parse as AttestationContent");

    assert_eq!(
        attestation.analysis_tier,
        AnalysisTier::Syntactic,
        "expected syntactic tier without --semantic"
    );
}
