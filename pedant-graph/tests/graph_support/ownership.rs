//! Structural ownership: what this crate's production sources may name, in
//! which order, and how many times.
//!
//! Behavioural cases own error values and payloads. These cases own only
//! reachability, dominance, and single ownership — the properties a passing
//! behavioural run cannot distinguish from a lucky one.

use std::collections::BTreeSet;

use super::inventory::{PRODUCTION_SOURCES, SOURCES};
use super::scan::{
    code_only, discovered_sources, function_body, method_body, parsed, position_of, source,
};
use super::surface::{
    declared_error_variants, declared_items, derived_paths, public_constructors, public_fields,
};

use super::ownership_model::{
    ASSEMBLED_VALIDATORS, BOUND_VALIDATORS, CLAIMED_VALIDATORS, CONTAINMENT_OWNER,
    CONTAINMENT_VALIDATORS, ERROR_OWNERS, FORBIDDEN_ENTRY_POINTS, IDENTIFIED_VALIDATORS,
    INSERTION_OWNER, PANIC_SPELLINGS, PLACED_VALIDATORS, PLANNED_VALIDATORS, PROJECTED_VALIDATORS,
    STATE_CONSTRUCTOR, STATE_CONSTRUCTOR_SIGNATURE, VALIDATION_OWNER,
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

    let offenders = sources_naming(FORBIDDEN_ENTRY_POINTS);
    assert!(
        offenders.is_empty(),
        "graph production sources reach beyond their supplied facts: {offenders:?}"
    );
}

/// Every modelled source that names one of `spellings`, in [`SOURCES`] order.
///
/// Comments are dropped first, so prose describing a forbidden spelling does
/// not read as the thing it describes.
fn sources_naming(spellings: &[&str]) -> Vec<String> {
    let mut offenders: Vec<String> = Vec::new();
    for entry in SOURCES {
        let code = code_only(entry.text);
        offenders.extend(
            spellings
                .iter()
                .filter(|spelling| code.contains(**spelling))
                .map(|spelling| format!("{} names {spelling}", entry.path)),
        );
    }
    offenders
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

/// Both identity checks precede planning, and the sole assembly-state
/// constructor precedes every record-producing pass.
pub fn assert_identity_checks_dominate() {
    let entry = function_body("src/rust/projection.rs", "project");
    let validated = position_of(&entry, "validate", "the projection entry");
    let planned = position_of(&entry, "plan", "the projection entry");
    let assembled = position_of(&entry, "assembly :: assemble", "the projection entry");
    assert!(
        validated < planned && planned < assembled,
        "the projection entry validates, then plans, then assembles"
    );
    let checks = function_body("src/rust/projection.rs", "validate");
    let root = position_of(&checks, "check_root_target", "the identity checks");
    let identity = position_of(&checks, "check_snapshot_identity", "the identity checks");
    assert!(
        root < identity,
        "the root target is proved before the snapshot identity"
    );

    let assembly = function_body("src/rust/assembly.rs", "assemble");
    let construction = position_of(&assembly, &token_form(STATE_CONSTRUCTOR), "the assembler");
    for pass in [
        "assemble_containers",
        "assemble_sources",
        "assemble_definitions",
        "assemble_containment",
        "assemble_references",
        "assemble_dependencies",
        "assemble_candidates",
    ] {
        let at = position_of(&assembly, pass, "the assembler");
        assert!(
            construction < at,
            "{pass} must run after the assembly state exists"
        );
    }
    let sites: Vec<&str> = SOURCES
        .iter()
        .filter(|entry| code_only(entry.text).contains(STATE_CONSTRUCTOR))
        .map(|entry| entry.path)
        .collect();
    assert_eq!(
        sites,
        vec!["src/rust/assembly.rs"],
        "the assembly state has exactly one construction site"
    );
    assert_eq!(
        code_only(source("src/rust/index.rs"))
            .matches(STATE_CONSTRUCTOR_SIGNATURE)
            .count(),
        1,
        "the assembly state has exactly one constructor, spelled {STATE_CONSTRUCTOR_SIGNATURE}"
    );
}

/// One source spelling as the parsed body renders it.
fn token_form(spelling: &str) -> String {
    spelling.replace("::", " :: ")
}

/// All three insertion owners mint their identity through one checked helper.
pub fn assert_one_checked_insertion_owner() {
    for (method, collection) in [
        ("insert_node", "GraphCollection::Node"),
        ("insert_reference", "GraphCollection::Reference"),
        ("insert_edge", "GraphCollection::Edge"),
    ] {
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
    assert_eq!(
        code_only(source("src/graph.rs"))
            .matches(INSERTION_OWNER)
            .count(),
        1,
        "there is exactly one checked insertion owner, spelled {INSERTION_OWNER}"
    );
}

/// Every defensive validator is reachable from the shared projection entry,
/// every error variant is built only by the source that owns it, and no
/// production source can abort instead of refusing.
pub fn assert_defensive_paths_are_wired() {
    for (owner, reader, validators) in [
        (
            VALIDATION_OWNER,
            "src/rust/projection.rs",
            PLANNED_VALIDATORS,
        ),
        (
            VALIDATION_OWNER,
            "src/rust/identity.rs",
            IDENTIFIED_VALIDATORS,
        ),
        (VALIDATION_OWNER, "src/rust/source.rs", PROJECTED_VALIDATORS),
        (VALIDATION_OWNER, "src/rust/fragment.rs", PLACED_VALIDATORS),
        (VALIDATION_OWNER, "src/rust/index.rs", BOUND_VALIDATORS),
        (VALIDATION_OWNER, "src/rust/claim.rs", CLAIMED_VALIDATORS),
        (
            VALIDATION_OWNER,
            "src/rust/assembly.rs",
            ASSEMBLED_VALIDATORS,
        ),
        (
            CONTAINMENT_OWNER,
            "src/rust/assembly.rs",
            CONTAINMENT_VALIDATORS,
        ),
    ] {
        assert_validators_are_reached(owner, reader, validators);
    }
    let entry = function_body("src/rust/assembly.rs", "assemble");
    let finish = position_of(&entry, "state . finish", "the assembler");
    let forest = position_of(&entry, "check_containment_forest", "the assembler");
    assert!(
        forest < finish,
        "containment must be validated before the graph is constructed"
    );

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
        let sites: Vec<&str> = SOURCES
            .iter()
            .filter(|entry| code_only(entry.text).contains(variant))
            .map(|entry| entry.path)
            .collect();
        assert_eq!(
            sites, *owners,
            "{variant} must be constructed by exactly its owning sources"
        );
    }
    let aborting = sources_naming(PANIC_SPELLINGS);
    assert!(
        aborting.is_empty(),
        "a production source may refuse but never abort: {aborting:?}"
    );
}

/// Every named validator is declared by the validation owner and reached by the
/// source the model says reaches it.
///
/// A validator answering a borrow of what it was handed states its own
/// lifetime, so both spellings the declaration can take are admitted. The name
/// is still bound on both sides — by the opening parenthesis or by the opening
/// angle bracket — so a longer name that merely starts with a modelled one
/// answers for neither.
fn assert_validators_are_reached(owner: &str, reader: &str, validators: &[&str]) {
    let validation = source(owner);
    let text = source(reader);
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
        assert!(
            text.contains(validator),
            "{validator} is not reached from {reader}"
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
