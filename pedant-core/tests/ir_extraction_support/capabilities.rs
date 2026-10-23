//! The IR capability projection agrees with the capability visitor.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::capabilities::detect_capabilities;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir::extract;
use pedant_core::lint::analyze;
use pedant_types::Capability;

use super::{CAPABILITY_FIXTURES, permissive_config};

// 2.T1: IR capabilities match CapabilityVisitor output for all fixtures
#[test]
fn test_ir_capabilities_match_visitor() {
    let config = permissive_config();

    for (name, source) in CAPABILITY_FIXTURES {
        assert_ir_projection_matches_analyze(name, source, &config);
    }
}

/// One fixture's direct IR projection must equal what `analyze` reports: same
/// capability set, same finding count, and the same evidence strings.
fn assert_ir_projection_matches_analyze(name: &str, source: &str, config: &CheckConfig) {
    let baseline = analyze(name, source, config, None)
        .unwrap_or_else(|e| panic!("analyze failed for {name}: {e}"));
    let baseline_caps = baseline.capabilities.capabilities();

    let syntax = syn::parse_file(source).unwrap_or_else(|e| panic!("{name} should parse: {e}"));
    let ir = extract(name, &syntax, None);
    let ir_profile = detect_capabilities(&ir, None);
    let ir_caps = ir_profile.capabilities();

    assert_eq!(
        &*baseline_caps, &*ir_caps,
        "capability mismatch for fixture {name}: baseline={baseline_caps:?}, ir={ir_caps:?}"
    );
    assert_eq!(
        baseline.capabilities.profile.findings.len(),
        ir_profile.profile.findings.len(),
        "finding count mismatch for fixture {name}"
    );
    assert_eq!(
        sorted_evidence(&baseline.capabilities.profile.findings),
        sorted_evidence(&ir_profile.profile.findings),
        "evidence mismatch for fixture {name}"
    );
}

/// One profile's evidence strings, sorted for a stable comparison.
fn sorted_evidence(findings: &[pedant_types::CapabilityFinding]) -> Vec<&str> {
    let mut evidence: Vec<&str> = findings.iter().map(|f| f.evidence.as_ref()).collect();
    evidence.sort();
    evidence
}

// 2.T2: Network detection via IR
#[test]
fn test_ir_capabilities_network_detection() {
    let source = r#"
use std::net::TcpStream;

fn connect() {
    let _url = "https://api.example.com/data";
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir = extract("test.rs", &syntax, None);
    let analysis = detect_capabilities(&ir, None);
    let caps = analysis.capabilities();

    assert!(caps.contains(&Capability::Network));

    // Should have findings for both the use path and the URL string
    let net_findings: Vec<_> = analysis
        .profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::Network)
        .collect();
    assert!(net_findings.len() >= 2);
}

// 2.T3: Unsafe detection via IR
#[test]
fn test_ir_capabilities_unsafe_detection() {
    let source = r#"
struct MyType;

unsafe fn dangerous() -> i32 { 42 }

unsafe impl Send for MyType {}

fn uses_unsafe() {
    let _val = unsafe { 42 };
}
"#;
    let syntax = syn::parse_file(source).unwrap();
    let ir = extract("test.rs", &syntax, None);
    let analysis = detect_capabilities(&ir, None);
    let caps = analysis.capabilities();

    assert!(caps.contains(&Capability::UnsafeCode));

    let evidence: Vec<&str> = analysis
        .profile
        .findings
        .iter()
        .filter(|f| f.capability == Capability::UnsafeCode)
        .map(|f| f.evidence.as_ref())
        .collect();

    assert!(evidence.contains(&"unsafe block"));
    assert!(evidence.contains(&"unsafe fn"));
    assert!(evidence.contains(&"unsafe impl"));
}
