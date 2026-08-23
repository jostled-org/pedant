//! Structural ownership: what this crate's production sources may name, in
//! which order, and how many times.
//!
//! Behavioural cases own error values and payloads. These cases own only
//! reachability, dominance, and single ownership — the properties a passing
//! behavioural run cannot distinguish from a lucky one.

use std::collections::BTreeSet;

use super::go_model::RECORD_INSERTIONS;
use super::inventory::{PRODUCTION_SOURCES, SOURCES};
use super::scan::{
    code_only, declaring_sources, discovered_sources, function_body, method_body, naming, parsed,
    position_of, source,
};
use super::surface::{
    declared_error_variants, declared_items, derived_paths, public_constructors, public_fields,
};

use super::ownership_model::{
    ASSEMBLED_VALIDATORS, BOUND_VALIDATORS, CLAIMED_VALIDATORS, CONTAINMENT_OWNER,
    CONTAINMENT_VALIDATORS, DRAFTED_VALIDATORS, ERROR_OWNERS, FINGERPRINT_VALIDATORS,
    FORBIDDEN_ENTRY_POINTS, GO_PLACED_NEUTRAL_VALIDATORS, GO_PLACED_VALIDATORS,
    GO_PLANNED_VALIDATORS, GO_VALIDATION_OWNER, PANIC_SPELLINGS, PLACED_VALIDATORS,
    PLANNED_VALIDATORS, PROJECTED_VALIDATORS, RUST_CLAIMED_VALIDATORS, RUST_PLANNED_VALIDATORS,
    RUST_VALIDATION_OWNER, STATE_CONSTRUCTOR, STATE_CONSTRUCTOR_SIGNATURE, VALIDATION_OWNER,
};

/// The discovered source set equals the model, is non-empty, and names no
/// loader, snapshot, parser, semantic, or resolver entry point.
pub fn assert_pure_projection_sources() {
    let modelled: BTreeSet<String> = PRODUCTION_SOURCES
        .iter()
        .map(|path| (*path).into())
        .collect();
    assert!(!modelled.is_empty(), "the production source model is empty");
    assert_eq!(
        discovered_sources(),
        modelled,
        "the production source set must equal the written-down inventory"
    );
    assert_eq!(
        SOURCES
            .iter()
            .map(|entry| entry.path)
            .collect::<BTreeSet<_>>(),
        PRODUCTION_SOURCES.iter().copied().collect::<BTreeSet<_>>(),
        "every modelled source must carry its compile-time text"
    );

    let offenders = naming(
        PRODUCTION_SOURCES,
        FORBIDDEN_ENTRY_POINTS,
        "the entry point",
    );
    assert!(
        offenders.is_empty(),
        "graph production sources reach beyond their supplied facts: {offenders:?}"
    );
}

/// One planner entry proves its own pairing, then plans, then assembles.
///
/// The one reading of that order, for every adapter. Which fact a language
/// proves first is its own — a Rust build proves a root target and a snapshot
/// identity, a Go build proves a snapshot identity alone — but that the proof
/// dominates the plan and the plan dominates the assembly is nobody's language,
/// and a second copy per adapter would be the same claim read twice.
pub fn assert_entry_orders(planner: &str, proof: &str, subject: &str) {
    let entry = function_body(planner, "project");
    let proved = position_of(&entry, proof, subject);
    let planned = position_of(&entry, "plan (", subject);
    let assembled = position_of(&entry, "assembly :: assemble", subject);
    assert!(
        proved < planned && planned < assembled,
        "{subject} proves its pairing, then plans, then assembles"
    );
}

/// Both public builders delegate to one private projection entry over their
/// own `snapshot` and `resolution` parameters and nothing else.
pub fn assert_public_builders_delegate() {
    let ordinary = function_body("src/rust/entry.rs", "build_rust_graph");
    let bounded = function_body("src/rust/entry.rs", "build_rust_graph_with_limits");
    assert_eq!(
        ordinary, "{ projection :: project (snapshot , resolution , GraphLimits :: default ()) }",
        "the ordinary builder must delegate to the shared projection entry"
    );
    assert_eq!(
        bounded, "{ projection :: project (snapshot , resolution , limits) }",
        "the bounded builder must delegate to the shared projection entry"
    );
    let module = code_only(source("src/rust/mod.rs"));
    assert!(
        module.contains("pub use entry::{build_rust_graph, build_rust_graph_with_limits};"),
        "the Rust module root declares and re-exports only"
    );
    assert!(
        !module.contains("fn "),
        "the Rust module root must define no function"
    );
}

/// Both identity checks precede planning, and the assembly state has exactly
/// one constructor and one construction site.
///
/// Which passes the assembler runs after that state exists, and in which order,
/// is one claim about an owner no language owns, read once by
/// [`super::go_ownership`] over the whole modelled pass list.
pub fn assert_identity_checks_dominate() {
    assert_entry_orders(
        "src/rust/projection.rs",
        "validate (",
        "the Rust projection entry",
    );
    let checks = function_body("src/rust/projection.rs", "validate");
    let root = position_of(&checks, "check_root_target", "the identity checks");
    let identity = position_of(&checks, "check_snapshot_identity", "the identity checks");
    assert!(
        root < identity,
        "the root target is proved before the snapshot identity"
    );

    assert_eq!(
        declaring_sources(STATE_CONSTRUCTOR),
        vec!["src/projection/assembly.rs"],
        "the assembly state has exactly one construction site"
    );
    assert_eq!(
        code_only(source("src/projection/state.rs"))
            .matches(STATE_CONSTRUCTOR_SIGNATURE)
            .count(),
        1,
        "the assembly state has exactly one constructor, spelled {STATE_CONSTRUCTOR_SIGNATURE}"
    );
}

/// All three insertion owners mint their identity through one checked helper.
///
/// The insertions are the modelled ones rather than a second list of the same
/// three names, and each is read beside the collection it must bound: an owner
/// that admitted against another collection's ceiling would refuse the wrong
/// build and admit the one it was meant to stop.
pub fn assert_one_checked_insertion_owner() {
    let collections = [
        "GraphCollection::Node",
        "GraphCollection::Reference",
        "GraphCollection::Edge",
    ];
    assert_eq!(
        RECORD_INSERTIONS.len(),
        collections.len(),
        "every modelled insertion is read beside the collection it bounds"
    );
    for (method, collection) in RECORD_INSERTIONS.iter().zip(collections) {
        let body = method_body("src/graph.rs", method);
        let admit = position_of(&body, "self . admit", method);
        let mutation = position_of(&body, ". push (", method);
        assert!(
            admit < mutation,
            "{method} must admit an identity before it mutates the store"
        );
        assert!(
            body.contains(&collection.replace("::", " :: ")),
            "{method} must name {collection}"
        );
    }
    let admit = method_body("src/graph.rs", "admit");
    assert!(
        admit.contains("u32 :: try_from"),
        "the insertion owner must prove the fixed-width ceiling"
    );
    assert!(
        admit.contains("self . limits . ceiling (collection)"),
        "the insertion owner must prove the configured ceiling"
    );
}

/// Every defensive validator is reachable from the shared projection entry,
/// every error variant is built only by the source that owns it, and no
/// production source can abort instead of refusing.
pub fn assert_defensive_paths_are_wired() {
    assert_every_validator_is_reached();
    assert_every_refusal_has_its_owners();
    let aborting = naming(PRODUCTION_SOURCES, PANIC_SPELLINGS, "the aborting spelling");
    assert!(
        aborting.is_empty(),
        "a production source may refuse but never abort: {aborting:?}"
    );
}

/// Every modelled validator is declared by the owner the model names and
/// reached by the pass the model says reaches it.
fn assert_every_validator_is_reached() {
    for (owner, reader, validators) in [
        (
            VALIDATION_OWNER,
            "src/rust/projection.rs",
            PLANNED_VALIDATORS,
        ),
        (
            RUST_VALIDATION_OWNER,
            "src/rust/projection.rs",
            RUST_PLANNED_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/projection/placement.rs",
            PLACED_VALIDATORS,
        ),
        (VALIDATION_OWNER, "src/rust/source.rs", PROJECTED_VALIDATORS),
        (
            VALIDATION_OWNER,
            RUST_VALIDATION_OWNER,
            FINGERPRINT_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            GO_VALIDATION_OWNER,
            FINGERPRINT_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/projection/state.rs",
            BOUND_VALIDATORS,
        ),
        (VALIDATION_OWNER, "src/rust/claim.rs", CLAIMED_VALIDATORS),
        (
            RUST_VALIDATION_OWNER,
            "src/rust/claim.rs",
            RUST_CLAIMED_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/projection/assembly.rs",
            ASSEMBLED_VALIDATORS,
        ),
        (
            CONTAINMENT_OWNER,
            "src/projection/assembly.rs",
            CONTAINMENT_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/projection/draft.rs",
            DRAFTED_VALIDATORS,
        ),
        (
            GO_VALIDATION_OWNER,
            "src/go/projection.rs",
            GO_PLANNED_VALIDATORS,
        ),
        (
            GO_VALIDATION_OWNER,
            "src/go/placement.rs",
            GO_PLACED_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/go/placement.rs",
            GO_PLACED_NEUTRAL_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/go/projection.rs",
            PROJECTED_VALIDATORS,
        ),
    ] {
        assert_validators_are_reached(owner, reader, validators);
    }
}

/// Every declared refusal names the sources allowed to build it, and no other
/// source builds one.
fn assert_every_refusal_has_its_owners() {
    assert_eq!(
        declared_error_variants(),
        ERROR_OWNERS
            .iter()
            .map(|(variant, _)| variant
                .strip_prefix("GraphBuildError::")
                .unwrap_or_else(|| panic!("{variant} is not a GraphBuildError variant"))
                .to_owned())
            .collect::<BTreeSet<_>>(),
        "every declared refusal must state which sources may build it"
    );
    for (variant, owners) in ERROR_OWNERS {
        assert_eq!(
            declaring_sources(variant),
            *owners,
            "{variant} must be constructed by exactly its owning sources"
        );
    }
}

/// Every named validator is declared by the validation owner and called by the
/// source the model says reaches it.
///
/// A validator answering a borrow of what it was handed states its own
/// lifetime, so both spellings the declaration can take are admitted. The name
/// is still bound on both sides — by the opening parenthesis or by the opening
/// angle bracket — so a longer name that merely starts with a modelled one
/// answers for neither.
///
/// The reading half is a call through the module the owner is imported under,
/// not the bare name. Every reader reaches its validators through an alias, so
/// the qualified spelling is exact — and it is the only spelling that rejects
/// the two ways a bare substring passes for nothing: prose naming the validator,
/// and a reader that declares a same-named function of its own and calls that
/// one instead.
fn assert_validators_are_reached(owner: &str, reader: &str, validators: &[&str]) {
    let validation = source(owner);
    let text = code_only(source(reader));
    for validator in validators {
        let declarations = [
            format!("pub(crate) fn {validator}("),
            format!("pub(crate) fn {validator}<"),
        ];
        assert!(
            declarations
                .iter()
                .any(|declaration| validation.contains(declaration)),
            "{validator} is not declared by {owner}"
        );
        let called = format!("::{validator}(");
        assert!(
            text.contains(&called),
            "{reader} states no call spelled {called}"
        );
    }
}

/// Public records keep private fields and private constructors, and the graph
/// value implements neither `Clone` nor `Deserialize`.
pub fn assert_lifecycle_surface_is_closed() {
    let mut offenders: Vec<String> = Vec::new();
    for entry in SOURCES {
        let file = parsed(entry.path);
        let items = declared_items(&file.items);
        offenders.extend(public_fields(&items, entry.path));
        offenders.extend(public_constructors(&items, entry.path));
    }
    assert!(
        offenders.is_empty(),
        "public graph records must keep private fields and constructors: {offenders:?}"
    );

    assert_graph_value_derives();
    let graph = code_only(source("src/graph.rs"));
    for forbidden in ["impl Clone for CodeGraph", "impl<'de> Deserialize"] {
        assert!(
            !graph.contains(forbidden),
            "src/graph.rs must not carry {forbidden}"
        );
    }
    assert!(
        !SOURCES
            .iter()
            .any(|entry| code_only(entry.text).contains("Deserialize")),
        "no graph record may be deserializable"
    );
}

/// The graph value derives `Serialize` and neither `Clone` nor `Deserialize`.
///
/// Every attribute of the `CodeGraph` item is read, because a second
/// `#[derive(Clone)]` above the serializing one would ship a cloneable graph
/// against the documented decision while the serializing line stayed clean.
fn assert_graph_value_derives() {
    let file = parsed("src/graph.rs");
    let declared = declared_items(&file.items)
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Struct(found) if found.ident == "CodeGraph" => Some(found),
            _ => None,
        })
        .unwrap_or_else(|| panic!("src/graph.rs declares no CodeGraph struct"));
    let derived = derived_paths(&declared.attrs);
    assert!(
        derived.contains("Serialize"),
        "CodeGraph must derive Serialize, deriving {derived:?}"
    );
    for forbidden in ["Clone", "Deserialize"] {
        assert!(
            !derived.contains(forbidden),
            "CodeGraph must not derive {forbidden}, deriving {derived:?}"
        );
    }
}
