//! Rust callable ownership of capability evidence, through `pedant_core::analyze`.
//!
//! A submodule of `tests/capability.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: this directory carries no `main.rs`, so cargo
//! declares no test executable for it.
//!
//! Each case below is one source, one hand-written flat occurrence table, and
//! the claims [`crate::symbol_expectations`] derives from that table.

use std::collections::BTreeSet;

use pedant_types::{Capability, CapabilitySymbolKind, SymbolAttributionStatus};

use crate::symbol_expectations::{
    ExpectedFinding, ExpectedSymbol, FactFamily, analysis_of,
    assert_every_family_has_an_eligible_row, assert_flat_sequence_is_exact,
    assert_symbols_are_exactly_derived,
};

const ALL_FAMILIES_FILE: &str = "all_families.rs";

/// One source touching every capability-source fact family at module scope and
/// inside a callable, with a repeated equal finding and an `unsafe fn`.
const ALL_FAMILIES_SOURCE: &str = r#"use std::net::TcpStream;

#[link(name = "c")]
extern "C" {
    fn native_entry();
}

static MODULE_ENDPOINT: &str = "https://example.test/module";

pub fn connect_remote() {
    use std::fs;
    let _ = fs::metadata("/tmp");
    let _first = "https://example.test/a";
    let _second = "https://example.test/a";
}

pub struct Client;

impl Client {
    pub unsafe fn raw_call(&self) {
        #[link(name = "m")]
        extern "C" {
            fn cosf(value: f32) -> f32;
        }
        unsafe { native_entry() };
        let _token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    }
}

fn outer_helper() {
    fn inner_helper() {
        let _ = std::process::Command::new("ls");
    }
}
"#;

const CONNECT_REMOTE: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "connect_remote",
    line: 10,
    column: 8,
};

const RAW_CALL: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Method,
    name: "raw_call",
    line: 20,
    column: 19,
};

const INNER_HELPER: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "inner_helper",
    line: 31,
    column: 8,
};

/// The complete flat occurrence sequence [`ALL_FAMILIES_SOURCE`] produces:
/// use paths, then `unsafe` sites, then `extern` blocks, then attributes, then
/// string literals, each in source order.
const ALL_FAMILIES_EXPECTED: &[ExpectedFinding] = &[
    ExpectedFinding {
        family: FactFamily::UsePath,
        capability: Capability::Network,
        line: 1,
        column: 1,
        evidence: "std::net::TcpStream",
        owner: None,
    },
    ExpectedFinding {
        family: FactFamily::UsePath,
        capability: Capability::FileRead,
        line: 11,
        column: 5,
        evidence: "std::fs",
        owner: Some(CONNECT_REMOTE),
    },
    ExpectedFinding {
        family: FactFamily::UsePath,
        capability: Capability::ProcessExec,
        line: 32,
        column: 17,
        evidence: "std::process::Command::new",
        owner: Some(INNER_HELPER),
    },
    ExpectedFinding {
        family: FactFamily::Unsafe,
        capability: Capability::UnsafeCode,
        line: 20,
        column: 9,
        evidence: "unsafe fn",
        owner: Some(RAW_CALL),
    },
    ExpectedFinding {
        family: FactFamily::Unsafe,
        capability: Capability::UnsafeCode,
        line: 25,
        column: 9,
        evidence: "unsafe block",
        owner: Some(RAW_CALL),
    },
    ExpectedFinding {
        family: FactFamily::ExternBlock,
        capability: Capability::Ffi,
        line: 4,
        column: 1,
        evidence: "extern block",
        owner: None,
    },
    ExpectedFinding {
        family: FactFamily::ExternBlock,
        capability: Capability::Ffi,
        line: 22,
        column: 9,
        evidence: "extern block",
        owner: Some(RAW_CALL),
    },
    ExpectedFinding {
        family: FactFamily::Attribute,
        capability: Capability::Ffi,
        line: 3,
        column: 1,
        evidence: "#[link]",
        owner: None,
    },
    ExpectedFinding {
        family: FactFamily::Attribute,
        capability: Capability::Ffi,
        line: 21,
        column: 9,
        evidence: "#[link]",
        owner: Some(RAW_CALL),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 8,
        column: 32,
        evidence: "https://example.test/module",
        owner: None,
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 13,
        column: 18,
        evidence: "https://example.test/a",
        owner: Some(CONNECT_REMOTE),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 14,
        column: 19,
        evidence: "https://example.test/a",
        owner: Some(CONNECT_REMOTE),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Crypto,
        line: 26,
        column: 22,
        evidence: "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        owner: Some(RAW_CALL),
    },
];

/// 3.T1 (Invariants 1–3): every capability-source fact family attributes its
/// callable-contained evidence exactly, and leaves module evidence flat.
#[test]
fn rust_all_capability_fact_families_have_exact_callable_ownership() {
    assert_every_family_has_an_eligible_row(ALL_FAMILIES_EXPECTED);

    let analysis = analysis_of(ALL_FAMILIES_FILE, ALL_FAMILIES_SOURCE);
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "a parsed Rust source states a complete callable inventory"
    );
    assert_flat_sequence_is_exact(&analysis, ALL_FAMILIES_FILE, ALL_FAMILIES_EXPECTED);
    assert_symbols_are_exactly_derived(&analysis, ALL_FAMILIES_FILE, ALL_FAMILIES_EXPECTED);
}

const DUPLICATE_FILE: &str = "duplicates.rs";

/// Equal callable names at three declarations, plus a function nested inside a
/// method.
const DUPLICATE_SOURCE: &str = r#"pub fn handler() {
    let _ = std::process::Command::new("a");
}

pub mod inner {
    pub fn handler() {
        let _ = "https://inner.test/a";
    }
}

pub struct Runner;

impl Runner {
    pub fn handler(&self) {
        let _outer = "https://outer.test/x";
        fn nested_handler() {
            let _inner = "https://nested.test/y";
        }
    }
}
"#;

const FREE_HANDLER: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "handler",
    line: 1,
    column: 8,
};

const MODULE_HANDLER: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "handler",
    line: 6,
    column: 12,
};

const METHOD_HANDLER: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Method,
    name: "handler",
    line: 14,
    column: 12,
};

const NESTED_HANDLER: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "nested_handler",
    line: 16,
    column: 12,
};

const DUPLICATE_EXPECTED: &[ExpectedFinding] = &[
    ExpectedFinding {
        family: FactFamily::UsePath,
        capability: Capability::ProcessExec,
        line: 2,
        column: 13,
        evidence: "std::process::Command::new",
        owner: Some(FREE_HANDLER),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 7,
        column: 17,
        evidence: "https://inner.test/a",
        owner: Some(MODULE_HANDLER),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 15,
        column: 22,
        evidence: "https://outer.test/x",
        owner: Some(METHOD_HANDLER),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 17,
        column: 26,
        evidence: "https://nested.test/y",
        owner: Some(NESTED_HANDLER),
    },
];

/// 3.T2 (Invariants 4 and 5): equal names at distinct declarations are distinct
/// identities, and a nested callable owns its own evidence.
#[test]
fn rust_duplicate_and_nested_callables_have_exact_ownership() {
    let analysis = analysis_of(DUPLICATE_FILE, DUPLICATE_SOURCE);
    assert_flat_sequence_is_exact(&analysis, DUPLICATE_FILE, DUPLICATE_EXPECTED);
    assert_symbols_are_exactly_derived(&analysis, DUPLICATE_FILE, DUPLICATE_EXPECTED);

    let identities: BTreeSet<_> = analysis
        .symbols
        .iter()
        .map(|entry| {
            (
                entry.symbol.name.clone(),
                entry.symbol.declaration.line,
                entry.symbol.declaration.column,
            )
        })
        .collect();
    assert_eq!(
        identities.len(),
        4,
        "three callables named `handler` and one nested callable are four identities"
    );

    let nested = analysis
        .symbols
        .iter()
        .find(|entry| &*entry.symbol.name == "nested_handler")
        .expect("the nested callable owns a profile");
    let method = analysis
        .symbols
        .iter()
        .find(|entry| entry.symbol.declaration.line == METHOD_HANDLER.line)
        .expect("the enclosing method owns a profile");
    assert_eq!(
        &*nested.profile.findings[0].evidence,
        "https://nested.test/y"
    );
    assert!(
        method
            .profile
            .findings
            .iter()
            .all(|finding| &*finding.evidence != "https://nested.test/y"),
        "the lexical parent must not own its nested callable's evidence"
    );
}

const MODULE_EVIDENCE_FILE: &str = "module_evidence.rs";

/// One capability import above several callables, and one import inside a
/// callable.
const MODULE_EVIDENCE_SOURCE: &str = r#"use std::process::Command;

pub fn first() {
    let _ = "https://first.test/a";
}

pub fn second() {
    use std::net::TcpStream;
    let _ = TcpStream::connect("x");
}

pub fn third() {}
"#;

const FIRST: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "first",
    line: 3,
    column: 8,
};

const SECOND: ExpectedSymbol = ExpectedSymbol {
    kind: CapabilitySymbolKind::Function,
    name: "second",
    line: 7,
    column: 8,
};

const MODULE_EVIDENCE_EXPECTED: &[ExpectedFinding] = &[
    ExpectedFinding {
        family: FactFamily::UsePath,
        capability: Capability::ProcessExec,
        line: 1,
        column: 1,
        evidence: "std::process::Command",
        owner: None,
    },
    ExpectedFinding {
        family: FactFamily::UsePath,
        capability: Capability::Network,
        line: 8,
        column: 5,
        evidence: "std::net::TcpStream",
        owner: Some(SECOND),
    },
    ExpectedFinding {
        family: FactFamily::StringLiteral,
        capability: Capability::Network,
        line: 4,
        column: 13,
        evidence: "https://first.test/a",
        owner: Some(FIRST),
    },
];

/// 3.T3 (Invariants 6 and 7): module-level evidence stays flat, and a module
/// import gives no callable in the file that capability.
#[test]
fn rust_module_evidence_stays_flat_and_unpropagated() {
    let analysis = analysis_of(MODULE_EVIDENCE_FILE, MODULE_EVIDENCE_SOURCE);
    assert_flat_sequence_is_exact(&analysis, MODULE_EVIDENCE_FILE, MODULE_EVIDENCE_EXPECTED);
    assert_symbols_are_exactly_derived(&analysis, MODULE_EVIDENCE_FILE, MODULE_EVIDENCE_EXPECTED);

    assert!(
        analysis.symbols.iter().all(|entry| entry
            .profile
            .findings
            .iter()
            .all(|finding| finding.capability != Capability::ProcessExec)),
        "the module import must not reach any callable profile"
    );
    assert!(
        analysis
            .symbols
            .iter()
            .all(|entry| &*entry.symbol.name != "third"),
        "a callable with no evidence owns no profile"
    );
    let nested_import_owners: Vec<_> = analysis
        .symbols
        .iter()
        .filter(|entry| {
            entry
                .profile
                .findings
                .iter()
                .any(|finding| &*finding.evidence == "std::net::TcpStream")
        })
        .map(|entry| &*entry.symbol.name)
        .collect();
    assert_eq!(
        nested_import_owners,
        ["second"],
        "the nested import belongs to its own callable and to no other"
    );
}
