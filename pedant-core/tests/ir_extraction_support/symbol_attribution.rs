//! Symbol attribution consumes the `FileIr` the analysis parse produced.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::analyze;
use pedant_core::resolution::ResolutionProbe;
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

const TRAIT_FILE: &str = "trait_ir.rs";

/// One trait method declared without a body and one with, each carrying the
/// same capability-bearing attribute.
const TRAIT_SOURCE: &str = r#"pub trait Loader {
    #[link(name = "ssl")]
    fn load();

    #[link(name = "crypto")]
    fn provide() {}
}
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
    assert_eq!(
        flat,
        [
            (Capability::ProcessExec, "std::process::Command"),
            (Capability::Network, "std::net::TcpStream"),
            (Capability::FileWrite, "std::fs::write"),
            (Capability::Network, "10.0.0.1:80"),
        ],
        "the flat profile keeps every occurrence in detection order, \
         the module import no callable owns included"
    );
}

/// One attributed symbol: its name, kind, declaration line, and the evidence it
/// owns.
type OwnedSymbol<'a> = (
    &'a str,
    CapabilitySymbolKind,
    usize,
    Vec<(Capability, &'a str)>,
);

/// 3.T4: a trait method declared without a body owns what is declared on it,
/// exactly as the same declaration with a body does.
#[test]
fn bodiless_trait_method_owns_its_own_attribute() {
    let analysis = analyze(TRAIT_FILE, TRAIT_SOURCE, &CheckConfig::default(), None)
        .expect("the fixture source should parse")
        .capabilities;

    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete
    );

    let owned: Vec<OwnedSymbol<'_>> = analysis
        .symbols
        .iter()
        .map(|entry| {
            (
                &*entry.symbol.name,
                entry.symbol.kind,
                entry.symbol.declaration.line,
                rendered(&entry.profile.findings),
            )
        })
        .collect();
    assert_eq!(
        owned,
        [
            (
                "load",
                CapabilitySymbolKind::Method,
                3,
                vec![(Capability::Ffi, "#[link]")],
            ),
            (
                "provide",
                CapabilitySymbolKind::Method,
                6,
                vec![(Capability::Ffi, "#[link]")],
            ),
        ],
        "the bodiless declaration and the defaulted one attribute alike"
    );
}

/// One profile's findings as capability-and-evidence pairs, in order.
fn rendered(findings: &[pedant_types::CapabilityFinding]) -> Vec<(Capability, &str)> {
    findings
        .iter()
        .map(|finding| (finding.capability, &*finding.evidence))
        .collect()
}
