#![cfg(feature = "checks")]

// Each topic lives in `ir_extraction_support/`, and the `#[path]` on each module
// is required. Default resolution would place the files in `tests/ir_extraction/`,
// which pedant's `conflicting-module-root` rule rejects beside `ir_extraction.rs`,
// and its advice — fold the root into `ir_extraction/mod.rs` — does not apply to a
// cargo test root, since cargo builds a test executable per `tests/*.rs` and would
// stop building this one. A sibling directory satisfies both: cargo declares no
// target for it, because it holds no `main.rs`.

#[path = "ir_extraction_support/item_facts.rs"]
mod item_facts;

#[path = "ir_extraction_support/body_facts.rs"]
mod body_facts;

#[path = "ir_extraction_support/capabilities.rs"]
mod capabilities;

#[path = "ir_extraction_support/style.rs"]
mod style;

#[path = "ir_extraction_support/analyze_identity.rs"]
mod analyze_identity;

#[path = "ir_extraction_support/fingerprints.rs"]
mod fingerprints;

#[path = "ir_extraction_support/call_forms.rs"]
mod call_forms;

#[cfg(feature = "semantic")]
#[path = "ir_extraction_support/semantic_enrichment.rs"]
mod semantic_enrichment;

/// One-parse, one-extraction observation of Rust symbol attribution. The probe
/// exists only under the proof feature, so this module follows that gate.
#[cfg(feature = "resolution-test-support")]
#[path = "ir_extraction_support/symbol_attribution.rs"]
mod symbol_attribution;

use pedant_core::check_config::CheckConfig;
use pedant_core::ir::extract;

fn parse_and_extract(source: &str) -> pedant_core::ir::FileIr {
    let syntax = syn::parse_file(source).expect("parse failed");
    extract("test.rs", &syntax, None)
}

fn permissive_config() -> CheckConfig {
    CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

/// Every fixture carrying capability evidence, walked by both the capability
/// projection case and the analyze-versus-direct-IR equivalence case.
const CAPABILITY_FIXTURES: &[(&str, &str)] = &[
    (
        "network_capability.rs",
        include_str!("fixtures/network_capability.rs"),
    ),
    (
        "filesystem_capability.rs",
        include_str!("fixtures/filesystem_capability.rs"),
    ),
    (
        "process_capability.rs",
        include_str!("fixtures/process_capability.rs"),
    ),
    (
        "env_capability.rs",
        include_str!("fixtures/env_capability.rs"),
    ),
    (
        "ffi_capability.rs",
        include_str!("fixtures/ffi_capability.rs"),
    ),
    (
        "unsafe_capability.rs",
        include_str!("fixtures/unsafe_capability.rs"),
    ),
    (
        "endpoint_capability.rs",
        include_str!("fixtures/endpoint_capability.rs"),
    ),
    (
        "crypto_capability.rs",
        include_str!("fixtures/crypto_capability.rs"),
    ),
    (
        "proc_macro_capability.rs",
        include_str!("fixtures/proc_macro_capability.rs"),
    ),
    (
        "system_time_capability.rs",
        include_str!("fixtures/system_time_capability.rs"),
    ),
    ("clean.rs", include_str!("fixtures/clean.rs")),
];
