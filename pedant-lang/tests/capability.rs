//! Contract tests for `pedant-lang` capability analysis.
//!
//! This root owns the crate's language boundary: which capabilities each
//! non-Rust scanner reports, what a manifest hook contributes, and what
//! `Language::Rust` does not. It stays one of the crate's two integration
//! executables — each language, the manifest surface, and the tree-sitter tier
//! own a file under `capability_support/` that this root declares with
//! `#[path]`, which Cargo links into this same binary instead of a new one.
//!
//! The Rust predicate stays at this root: Step 1.6 selects it by bare name and
//! the owner-registration table lists it unqualified, so a module path would
//! rename it.

use std::path::Path;

use pedant_lang::analyze_file;
use pedant_types::{Language, SymbolAttributionStatus};

/// The one path every language case takes into `analyze_file`.
#[path = "capability_support/language_probe.rs"]
mod language_probe;

/// What the Python scanner reports, at the regex tier.
#[path = "capability_support/python_cases.rs"]
mod python_cases;

/// What the JavaScript and TypeScript scanners report, at the regex tier.
#[path = "capability_support/javascript_cases.rs"]
mod javascript_cases;

/// What the Go scanner reports, at the regex tier.
#[path = "capability_support/go_cases.rs"]
mod go_cases;

/// What Go capability analysis publishes once one fact inventory owns the
/// grammar, in every configuration.
#[path = "capability_support/go_fact_cases.rs"]
mod go_fact_cases;

/// What the Bash scanner reports, at the regex tier.
#[path = "capability_support/bash_cases.rs"]
mod bash_cases;

/// What a manifest declares, and the execution context its hooks carry.
#[path = "capability_support/manifest_cases.rs"]
mod manifest_cases;

/// What the tree-sitter tier reports that the regex tier cannot.
#[path = "capability_support/tree_sitter_cases.rs"]
mod tree_sitter_cases;

/// Extension and detection behavior this crate must keep.
#[path = "capability_support/retained_behavior.rs"]
mod retained_behavior;

/// Which callable owns each finding: the tables every symbol case is written
/// in, the sources they read, and the assertions that read them.
///
/// The whole tree needs a linked grammar — a build with none reports attribution
/// as unavailable, which `availability_cases` owns — so the gate sits once at
/// this declaration and the tree's own `mod.rs` names its members. Only this
/// first hop out of the test root needs `#[path]`.
#[cfg(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
#[path = "capability_support/symbols/mod.rs"]
mod symbols;

/// What a build without a grammar, a recovery tree, and a fallback corpus all
/// report about symbol attribution.
#[path = "capability_support/availability_cases.rs"]
mod availability_cases;

/// One parse session per structured source analysis, proven from this crate's
/// own tracked source.
#[path = "capability_support/ownership.rs"]
mod ownership;

/// Who owns the Go grammar, proven from the same tracked source.
#[path = "capability_support/go_ownership.rs"]
mod go_ownership;

/// `pedant-lang` remains the non-Rust capability backend: asked directly about
/// `Language::Rust` it returns an empty profile rather than guessing with
/// another language's scanner. Rust capability extraction stays in
/// `pedant-core`.
///
/// 4.T9 (Invariant 11) adds the symbol claim: no callable inventory belongs to
/// this crate for Rust, so the status is `NotApplicable` rather than the
/// `Unavailable` a failed non-Rust parse reports.
#[test]
fn direct_rust_analysis_returns_empty_profile() {
    const SOURCE: &str =
        "use std::fs;\nuse std::process::Command;\nfn main() { let _ = fs::read(\"x\"); }\n";
    let analysis = analyze_file(Path::new("src/main.rs"), SOURCE, Language::Rust);
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::NotApplicable,
        "Rust callables belong to pedant-core, so this boundary claims none"
    );
    assert!(
        analysis.symbols.is_empty(),
        "direct Rust analysis claims no symbol, got {:?}",
        analysis.symbols
    );
    let profile = analysis.into_profile();
    assert!(
        profile.findings.is_empty(),
        "direct Rust analysis returns no findings, got {:?}",
        profile.findings
    );
}
