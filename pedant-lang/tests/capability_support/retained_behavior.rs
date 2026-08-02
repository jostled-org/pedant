use std::path::Path;

use pedant_lang::{analyze_file, detect_language};
use pedant_types::{Capability, CapabilityFinding, FindingOrigin};

fn analyze_detected(path: &str, source: &str) -> Box<[CapabilityFinding]> {
    let language = detect_language(Path::new(path), source)
        .unwrap_or_else(|| panic!("{path} must resolve to a supported language"));
    analyze_file(Path::new(path), source, language).findings
}

fn has_capability(findings: &[CapabilityFinding], capability: Capability) -> bool {
    findings
        .iter()
        .any(|finding| finding.capability == capability)
}

#[test]
fn jsx_and_cts_extensions_reach_capability_analysis() {
    let jsx = analyze_detected("view.jsx", "const client = require('axios');");
    assert!(
        has_capability(&jsx, Capability::Network),
        ".jsx must use JavaScript capability analysis: {jsx:?}"
    );

    let cts = analyze_detected("worker.cts", "const fs = require('fs');");
    assert!(
        has_capability(&cts, Capability::FileRead),
        ".cts must use TypeScript capability analysis: {cts:?}"
    );
}

#[cfg(feature = "ts-typescript")]
#[test]
fn tsx_capability_analysis_uses_the_tsx_grammar() {
    let source = "const view = <section>{require('child_process')}</section>;";
    let findings = analyze_detected("view.tsx", source);
    assert!(
        has_capability(&findings, Capability::ProcessExec),
        "a require call inside JSX must survive TSX parsing: {findings:?}"
    );
}

#[test]
fn bash_literals_report_endpoints_and_key_material() {
    let source = concat!(
        "endpoint=\"https://api.example.com/v1\"\n",
        "credential=\"AKIA1234567890ABCDEF\"\n",
    );
    let findings = analyze_detected("deploy.sh", source);

    assert!(
        findings.iter().any(|finding| {
            finding.capability == Capability::Network
                && finding.origin == Some(FindingOrigin::StringLiteral)
                && &*finding.evidence == "https://api.example.com/v1"
        }),
        "Bash endpoint literals must produce Network findings: {findings:?}"
    );
    assert!(
        findings.iter().any(|finding| {
            finding.capability == Capability::Crypto
                && finding.origin == Some(FindingOrigin::StringLiteral)
                && finding.evidence.starts_with("AKIA")
        }),
        "Bash credential literals must produce Crypto findings: {findings:?}"
    );
}

#[test]
fn shell_parameter_expansion_does_not_hide_a_later_literal() {
    let source = "name=${path##*/}; endpoint=\"https://api.example.com/v1\"";
    let findings = analyze_detected("deploy.sh", source);
    assert!(
        has_capability(&findings, Capability::Network),
        "the # characters in shell expansion must not open a comment: {findings:?}"
    );
}

#[cfg(feature = "ts-javascript")]
#[test]
fn javascript_module_findings_follow_source_order() {
    let source = concat!(
        "const child = require('child_process');\n",
        "import axios from 'axios';\n",
    );
    let findings = analyze_file(
        Path::new("worker.js"),
        source,
        pedant_types::Language::JavaScript,
    )
    .findings;
    let module_lines: Box<[usize]> = findings
        .iter()
        .filter(|finding| finding.origin == Some(FindingOrigin::Import))
        .map(|finding| finding.location.line)
        .collect();

    assert_eq!(
        &*module_lines,
        &[1, 2],
        "require and import findings must interleave by source position"
    );
}
