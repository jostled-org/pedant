//! Structural ownership of the Go adapter's own production sources.
//!
//! Two claims a passing behavioural run cannot tell from a lucky one: that the
//! Go pairing is proved and every ceiling reached before a draft or a record is
//! allocated, and that the two public adapters answer the same shapes while
//! each keeps its own language inside itself.
//!
//! Compiled under every feature profile. The inputs are compile-time source
//! text, so what a default build cannot run it can still be held to.

use std::collections::BTreeSet;

use super::go_model::{
    ASSEMBLY_OWNER, GO_ENTRY_OWNER, GO_PLANNER, GO_VOCABULARY_OWNER, MODULE_LEVEL, PACKAGE_LEVEL,
    PAIRED_ARGUMENT_TYPES, PAIRED_BUILDERS, RECORD_INSERTIONS, RUST_ENTRY_OWNER,
};
use super::inventory::{GO_SOURCES, RUST_SOURCES, SOURCES};
use super::ownership::assert_entry_orders;
use super::ownership_model::{ASSEMBLY_PASSES, GO_VOCABULARY, RUST_VOCABULARY, STATE_CONSTRUCTOR};
use super::scan::{code_only, function_body, naming, parsed, position_of, source};

/// The sources allowed to name a Go core type.
///
/// The adapter itself, and the crate root that declares it behind the feature.
/// Anything else naming one would put a Go type on a path a Go-free build still
/// compiles, or inside the Rust-only cache.
const GO_NAMING_SOURCES: &[&str] = &["src/lib.rs"];

/// The Go pairing is proved before a plan exists, and every ceiling is reached
/// before a record is allocated.
pub fn assert_validation_and_limits_dominate_draft_allocation() {
    assert_the_pairing_is_proved_first();
    assert_the_assembler_orders_every_pass();
    assert_the_adapter_allocates_no_record();
}

/// The Go entry proves the snapshot identity, then plans, then assembles.
fn assert_the_pairing_is_proved_first() {
    assert_entry_orders(
        GO_PLANNER,
        "check_snapshot_identity",
        "the Go projection entry",
    );
    let published = code_only(source(GO_ENTRY_OWNER));
    assert!(
        !published.contains("ProjectionPlan") && !published.contains("GraphRecords"),
        "{GO_ENTRY_OWNER} delegates rather than planning or allocating"
    );
}

/// The one assembler constructs its state before every pass, and runs the
/// passes in the one order a graph is minted by.
///
/// The sole reading of that order. Every pass is placed against the pass before
/// it rather than against the state construction alone, so a pass that moved
/// past its neighbour fails here instead of still sitting after the state.
fn assert_the_assembler_orders_every_pass() {
    let assembly = function_body(ASSEMBLY_OWNER, "assemble");
    let mut previous = position_of(
        &assembly,
        &STATE_CONSTRUCTOR.replace("::", " :: "),
        "the assembler",
    );
    for pass in ASSEMBLY_PASSES {
        let at = position_of(&assembly, pass, "the assembler");
        assert!(
            previous < at,
            "{pass} must run after everything the assembler states before it"
        );
        previous = at;
    }
}

/// No Go source mints an identity, inserts a record, or seals a graph.
///
/// Scanned with every space dropped, because the spellings are production
/// source text rather than the parsed token text a body is read as: the sealing
/// call is written `state.finish(...)` where it lives, and a scan looking for
/// the token form could never match a source at all.
fn assert_the_adapter_allocates_no_record() {
    let forbidden: Vec<&str> = RECORD_INSERTIONS
        .iter()
        .copied()
        .chain(["GraphRecords", "state.finish", "ProjectionState"])
        .collect();
    let offenders = naming(GO_SOURCES, &forbidden, "the allocation");
    assert!(
        offenders.is_empty(),
        "a language adapter states a plan and allocates nothing: {offenders:?}"
    );
}

/// The two public adapters answer parallel shapes, and each keeps its own
/// language vocabulary inside itself.
pub fn assert_public_api_shapes_are_parallel_and_language_specific() {
    assert_paired_builders_have_one_shape();
    assert_the_go_vocabulary_owns_its_container_levels();
    assert_each_adapter_keeps_its_own_language();
    assert_the_crate_root_publishes_both();
}

/// The two container levels a Go graph states are declared by the Go
/// vocabulary and by no other Go source.
///
/// A level is language-declared string vocabulary, so the moment a second Go
/// source spelled one of them the adapter would have two places deciding what a
/// Go container is called. The claim stops at the Go adapter deliberately: the
/// Rust vocabulary declares a `module` level of its own, and the two are
/// different languages' words that happen to be spelled alike.
fn assert_the_go_vocabulary_owns_its_container_levels() {
    let vocabulary = code_only(source(GO_VOCABULARY_OWNER));
    for level in [MODULE_LEVEL, PACKAGE_LEVEL] {
        assert!(
            vocabulary.contains(&format!("Arc::from(\"{level}\")")),
            "{GO_VOCABULARY_OWNER} declares the {level} container level"
        );
        let elsewhere: Vec<&str> = GO_SOURCES
            .iter()
            .copied()
            .filter(|path| *path != GO_VOCABULARY_OWNER)
            .filter(|path| code_only(source(path)).contains(&format!("\"{level}\"")))
            .collect();
        assert!(
            elsewhere.is_empty(),
            "only the Go vocabulary spells the {level} level: {elsewhere:?}"
        );
    }
}

/// Each Go builder states the argument positions and the result its Rust
/// counterpart states, with only the two snapshot-bound types differing.
fn assert_paired_builders_have_one_shape() {
    for (go, rust) in PAIRED_BUILDERS {
        let stated = elided(&declared_signature(GO_ENTRY_OWNER, go), 0);
        let paired = elided(&declared_signature(RUST_ENTRY_OWNER, rust), 1);
        assert_eq!(
            stated, paired,
            "{go} and {rust} must state one shape between them"
        );
    }
}

/// The exact declared signature of one public builder, as tokens.
fn declared_signature(path: &str, name: &str) -> String {
    let file = parsed(path);
    let found = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} declares no function named {name}"));
    format!(
        "{}{}",
        super::scan::token_text(&found.sig.inputs),
        super::scan::token_text(&found.sig.output)
    )
}

/// One signature with its own language's two snapshot-bound type names removed.
fn elided(signature: &str, side: usize) -> String {
    PAIRED_ARGUMENT_TYPES
        .iter()
        .fold(signature.to_owned(), |held, pair| {
            let named = match side {
                0 => pair.0,
                _ => pair.1,
            };
            held.replace(named, "«bound»")
        })
        .split_whitespace()
        .collect()
}

/// A Go source names no Rust vocabulary, a Rust source names no Go vocabulary,
/// and nothing outside the Go adapter names a Go core type.
fn assert_each_adapter_keeps_its_own_language() {
    let mut crossed = naming(GO_SOURCES, RUST_VOCABULARY, "the Rust spelling");
    crossed.extend(naming(RUST_SOURCES, GO_VOCABULARY, "the Go spelling"));
    assert!(
        crossed.is_empty(),
        "each adapter keeps its own language inside itself: {crossed:?}"
    );

    let allowed: BTreeSet<&str> = GO_SOURCES
        .iter()
        .chain(GO_NAMING_SOURCES.iter())
        .copied()
        .collect();
    let elsewhere: Vec<&str> = SOURCES
        .iter()
        .map(|entry| entry.path)
        .filter(|path| !allowed.contains(path))
        .collect();
    let leaked = naming(&elsewhere, GO_VOCABULARY, "the Go spelling");
    assert!(
        leaked.is_empty(),
        "only the Go adapter and the crate root may name a Go core type: {leaked:?}"
    );
}

/// The crate root publishes both builder pairs, and the Go pair only under the
/// feature that compiles it.
fn assert_the_crate_root_publishes_both() {
    let root = code_only(source("src/lib.rs"));
    assert!(
        root.contains("pub use go::{build_go_graph, build_go_graph_with_limits};"),
        "the crate root publishes both Go builders"
    );
    assert!(
        root.contains(
            "pub use rust::{GraphCache, build_rust_graph, build_rust_graph_with_limits};"
        ),
        "the crate root still publishes the Rust builders and the cache"
    );
    let declared = root
        .split_once("mod go;")
        .map(|(before, _)| before)
        .unwrap_or_else(|| panic!("src/lib.rs declares the Go adapter module"));
    assert!(
        declared.trim_end().ends_with("#[cfg(feature = \"go\")]"),
        "the Go adapter module is declared behind its own feature"
    );
    assert_eq!(
        root.matches("#[cfg(feature = \"go\")]").count(),
        2,
        "exactly the module and its re-export are behind the feature"
    );
}
