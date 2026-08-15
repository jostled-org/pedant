//! Symbol attribution consumes the `FileIr` the analysis parse produced.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::analyze;
use pedant_core::resolution::rust::ResolutionProbe;
use pedant_types::{Capability, CapabilitySymbolKind, SymbolAttributionStatus};

const FILE: &str = "one_ir.rs";

/// Two callables with evidence, one module import, and one callable with none.
const SOURCE: &str = r#"use std::process::Command;

pub fn fetch() {
    use std::net::TcpStream;
    let _ = TcpStream::connect("10.0.0.1:80");
}

pub fn store() {
    let _ = std::fs::write("out.txt", "data");
}

pub fn quiet() {}
"#;

/// 3.T4 (Invariant 8): `analyze` parses once, extracts once, and projects the
/// stored IR once — and that single pass carries the symbol attribution.
#[test]
fn rust_analysis_reuses_one_file_ir_for_symbol_attribution() {
    let probe = ResolutionProbe::install();
    let analysis = analyze(FILE, SOURCE, &CheckConfig::default(), None)
        .expect("the fixture source should parse")
        .capabilities;

    assert_one_pass_per_stage(&probe);
    assert_symbols_are_exact(&analysis);
}

/// The analysis parsed once, extracted once, and projected that stored IR once.
fn assert_one_pass_per_stage(probe: &ResolutionProbe) {
    assert_eq!(
        &*probe.parses(),
        [Box::<str>::from(FILE)],
        "one `syn` parse reaches the whole analysis"
    );
    assert_eq!(
        &*probe.site_visits(),
        [Box::<str>::from(FILE)],
        "one extraction walks that parse"
    );
    assert_eq!(
        &*probe.capability_projections(),
        [Box::<str>::from(FILE)],
        "one capability projection reads that stored IR"
    );
}

/// That single pass carries the complete symbol attribution.
fn assert_symbols_are_exact(analysis: &pedant_types::CapabilityAnalysis) {
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete
    );

    let symbols: Vec<(&str, CapabilitySymbolKind, usize, usize)> = analysis
        .symbols
        .iter()
        .map(|entry| {
            (
                &*entry.symbol.name,
                entry.symbol.kind,
                entry.symbol.declaration.line,
                entry.symbol.declaration.column,
            )
        })
        .collect();
    assert_eq!(
        symbols,
        [
            ("fetch", CapabilitySymbolKind::Function, 3, 8),
            ("store", CapabilitySymbolKind::Function, 8, 8),
        ],
        "the callables that own evidence, in declaration order"
    );

    let owned: Vec<Vec<(Capability, &str)>> = analysis
        .symbols
        .iter()
        .map(|entry| rendered(&entry.profile.findings))
        .collect();
    assert_eq!(
        owned,
        [
            vec![
                (Capability::Network, "std::net::TcpStream"),
                (Capability::Network, "10.0.0.1:80"),
            ],
            vec![(Capability::FileWrite, "std::fs::write")],
        ],
        "each callable owns exactly its own evidence, in flat detection order"
    );

    let flat = rendered(&analysis.profile.findings);
    assert!(
        flat.contains(&(Capability::ProcessExec, "std::process::Command")),
        "the module import stays flat evidence: {flat:?}"
    );
}

/// One profile's findings as capability-and-evidence pairs, in order.
fn rendered(findings: &[pedant_types::CapabilityFinding]) -> Vec<(Capability, &str)> {
    findings
        .iter()
        .map(|finding| (finding.capability, &*finding.evidence))
        .collect()
}
